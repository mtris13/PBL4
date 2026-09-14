# Chặng 2A — Git và Nginx thật trên Arch

Môi trường người dùng cung cấp: Arch x86_64, Python 3.14.7/pip, Nginx, UFW,
iptables, nftables và Git đã cài; có sudo; chưa có web service tự cấu hình.
Nginx/UFW/nftables/firewalld báo inactive. Trạng thái service không khẳng định
kernel không có luật firewall: cần xem ruleset trước khi đến bước enforcement.

## 1. Đồng bộ source giữa Windows và Arch

Remote do người dùng cung cấp: https://github.com/mtris13/PBL4.git.
Source được chuẩn bị ở D:\SEM5\PBL4. Git local đã init nhánh main và gắn origin.
Máy Windows hiện cần tên/email tác giả commit và xác thực GitHub trước push.
Không dùng mật khẩu GitHub trực tiếp làm mật khẩu HTTPS Git; dùng đăng nhập của
credential manager hoặc cấu hình SSH theo tài khoản. Không gửi credential qua chat.

**Chỉ clone sau khi source đã được push lên main.** Trên Arch, để code ở home/ext4,
không chạy venv hoặc SQLite trên các phân vùng NTFS dùng chung:

```bash
mkdir -p ~/projects
cd ~/projects
git clone https://github.com/mtris13/PBL4.git
cd PBL4
python -m venv .venv
.venv/bin/python -m pip install -r requirements-lock.txt
.venv/bin/python -m pip check
.venv/bin/python -m unittest discover -v
```

Không copy .venv hoặc runtime từ Windows. Tạo tài khoản demo mới trên Arch;
SQLite, session key và log mỗi hệ điều hành được giữ riêng, không đồng bộ qua Git.
Môi trường 3.14 của Arch cần chạy test thực tế; kết quả 3.12 Windows không thay thế nó.

Mỗi lần đổi hệ điều hành: commit/push trên hệ đang code, rồi pull trước khi code ở
hệ còn lại. Chọn file cụ thể để commit, kiểm tra diff; không reset --hard/force push
để giải quyết xung đột. Nếu git pull báo local changes, lưu/commit thay đổi trước.

```bash
git status
git pull --ff-only
# Sửa code và chạy test.
git add shop deploy docs tests security lab README.md requirements.txt requirements-lock.txt .gitignore .gitattributes .env.example
git diff --cached --stat
git commit -m "Describe the change"
git push origin main
```

Tên/email có thể cấu hình riêng cho repository bằng git config user.name và
user.email theo thông tin bạn chọn, không dùng giá trị mẫu làm tác giả.

## 2. Tạo cấu hình Linux theo đường dẫn clone

Từ thư mục PBL4 trên Arch:

```bash
.venv/bin/python -m deploy.arch.render
nginx -t -p "$PWD/runtime/arch/" -c "$PWD/runtime/arch/nginx.conf"
systemd-analyze --user verify runtime/arch/pbl4-shop.service runtime/arch/pbl4-nginx.service runtime/arch/pbl4-security.service
```

Bộ sinh cần đường dẫn tuyệt đối Linux không chứa dấu cách/ký tự đặc biệt; default
~/projects/PBL4 phù hợp với username thông thường. Nếu cổng bận, đổi cả bộ cấu hình:

```bash
.venv/bin/python -m deploy.arch.render --edge-port 9080 --origin-port 9082 --backend-port 9081
```

Runtime nằm ở runtime/arch, permission 700; key tự sinh, permission 600. Sinh lại
cấu hình bảo toàn key và database. Sau khi đổi đường dẫn clone phải tạo lại .venv,
render và cài lại user units. Bộ sinh chỉ ghi file, không bật service hoặc firewall.

## 3. Bật ba service riêng của user

Dừng lab.run cũ nếu nó đang chiếm cổng. Chỉ tiếp tục khi nginx -t đã thành công.

```bash
mkdir -p ~/.config/systemd/user
install -m 644 runtime/arch/pbl4-shop.service ~/.config/systemd/user/
install -m 644 runtime/arch/pbl4-nginx.service ~/.config/systemd/user/
install -m 644 runtime/arch/pbl4-security.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user start pbl4-shop pbl4-nginx pbl4-security
systemctl --user status pbl4-shop pbl4-nginx pbl4-security --no-pager
```

Không dùng sudo systemctl cho các unit này. Nginx chạy dưới chính user của bạn,
sử dụng complete config riêng bằng -p/-c, không dùng nginx.service hệ thống và
không sửa /etc/nginx/nginx.conf. File mime.types được đọc từ /etc/nginx/mime.types.
Service tự restart khi process lỗi, nhưng không đồng nghĩa application ready;
phải kiểm tra health và audit. Service user chỉ gắn với phiên user; chưa bật linger.

## 4. Kiểm chứng trên Arch

Luồng mặc định:

```text
Browser 127.0.0.1 → Nginx edge :8080 (mô phỏng ALB append XFF)
                 → Nginx origin :8082 (nhìn peer 127.0.0.2)
                 → Waitress/Flask :8081 → SQLite
Nginx origin → runtime/arch/access.jsonl → analyzer → runtime/arch/audit.jsonl
```

Mở http://127.0.0.1:8080, đăng ký/login và đặt đơn mô phỏng. Kiểm tra:

```bash
curl -i http://127.0.0.1:8080/healthz
curl -i http://127.0.0.1:8082/healthz
.venv/bin/python -m lab.demo --config runtime/arch/demo.json
tail -n 10 runtime/arch/audit.jsonl
```

Kỳ vọng ingress trả 200; truy cập origin trực tiếp từ 127.0.0.1 trả 403 bởi Nginx
allow/deny. Đây là ACL Nginx, không phải bằng chứng firewall kernel đã được triển khai.
Backend WSGI vẫn có thể truy cập bởi process trên cùng máy; tất cả cổng bind loopback,
không public. User local có khả năng bind 127.0.0.2 có thể giả peer, nên lab không phải
security boundary chống người dùng trên cùng host. Trên AWS cần Security Group thật.

Demo gửi 25 request chỉ đến loopback. Kỳ vọng đủ 4 attack types, source 127.0.0.1,
không chọn prefix XFF giả 192.0.2.66. Loopback luôn protected: flood sẽ bị suppressed,
không có block thật. Nginx có thể tự trả 400 cho một số URI trước khi proxy; ghi nhận
kết quả, không chỉnh expected result cho qua. Nếu demo không pass, gửi report và
các dòng audit liên quan để điều tra.

Kiểm tra restart cơ bản:

```bash
systemctl --user restart pbl4-shop pbl4-security
curl -i http://127.0.0.1:8080/healthz
journalctl --user -u pbl4-shop -u pbl4-nginx -u pbl4-security -n 40 --no-pager
```

Watcher hiện replay từ đầu khi restart: audit có thể lặp, flood/lease RAM được reset.
Chưa có checkpoint bền vững, TTL timer lúc idle hoặc reconcile sau crash; không dùng
chế độ này để gọi WAF thật. Sau khi xác nhận Nginx hoạt động, bước 2B sẽ xử lý các mục
này cùng login throttling, session hardening, rotation và health-check exclusion.

Dừng lab:

```bash
systemctl --user stop pbl4-security pbl4-nginx pbl4-shop
```

Chưa enable mặc định. Khi đã kiểm thử ổn mới có thể dùng systemctl --user enable cho
ba unit để chạy khi user đăng nhập; không hứa chạy lúc chưa đăng nhập sau reboot.

## 5. Log, firewall và phần chưa áp dụng

Nginx origin giữ encoded path gốc, chỉ q/category trong query; bỏ body, cookie,
Authorization và user agent. Không đưa secret vào path/q/category. Log error mức
crit để giảm raw request trong error log; vẫn coi mọi file runtime là dữ liệu riêng.
Nginx log timestamp có độ chính xác giây; một worker giữ write ordering đơn giản.
Chưa tự rotate log; lab cần theo dõi dung lượng, không chạy dài hạn như production.

Trước bước firewall, đọc ruleset (chỉ chạy lệnh có công cụ tương ứng):

```bash
sudo ufw status verbose
sudo nft list ruleset
sudo iptables -S
sudo ip6tables -S
```

Chưa chạy ufw enable/reset, iptables -F hoặc thay default policy. Sẽ chọn một công cụ
quản lý firewall và lập luật sau khi xem kết quả; không bật chồng UFW/nftables độc lập.
Linux firewall bảo vệ host/cổng; phương án HTTP sau ALB vẫn dùng WAF ở chặng sau.

Tài liệu tham chiếu: [Nginx command options](https://nginx.org/en/docs/switches.html),
[proxy_bind](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_bind),
[JSON access log](https://nginx.org/en/docs/http/ngx_http_log_module.html).

## Trạng thái kiểm chứng

Code/config generator có unit test trên Windows. Chưa chạy nginx -t, systemd hoặc
HTTP qua Nginx thật trên Arch trong phiên này. Chỉ đánh dấu 2A hoàn thành sau khi có
kết quả các bước trên từ Arch. Chưa tạo ALB/WAF, chưa sửa firewall thực tế.
