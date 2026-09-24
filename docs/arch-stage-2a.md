# Chặng 2A — Git và Nginx thật trên Arch

> Cập nhật 2026-09-24: Arch stack này sẽ làm máy server cho desktop client trên máy thứ
> hai. Loopback topology bên dưới là bằng chứng lịch sử và regression lab; bước LAN/TLS
> phải có cấu hình, firewall và kiểm chứng riêng, không tự coi là đã hoàn thành.

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
systemd-analyze --user verify runtime/arch/pbl4-shop.service runtime/arch/pbl4-nginx.service runtime/arch/pbl4-security.service runtime/arch/pbl4-logrotate.service runtime/arch/pbl4-logrotate.timer
```

Bộ sinh cần đường dẫn tuyệt đối Linux không chứa dấu cách/ký tự đặc biệt; default
~/projects/PBL4 phù hợp với username thông thường. Nếu cổng bận, đổi cả bộ cấu hình:

```bash
.venv/bin/python -m deploy.arch.render --edge-port 9080 --origin-port 9082 --backend-port 9081
```

Runtime nằm ở runtime/arch, permission 700; key tự sinh, permission 600. Các thư mục
temporary của Nginx (client body, proxy, FastCGI, SCGI và uWSGI) cũng nằm trong runtime
để user service không cần ghi vào `/var/lib/nginx`. Sinh lại cấu hình bảo toàn key và
database. Sau khi đổi đường dẫn clone phải tạo lại .venv, render và cài lại user units.
Bộ sinh chỉ ghi file, không bật service hoặc firewall.

## 3. Bật ba service và log-rotation timer của user

Dừng lab.run cũ nếu nó đang chiếm cổng. Chỉ tiếp tục khi nginx -t đã thành công.

```bash
mkdir -p ~/.config/systemd/user
install -m 644 runtime/arch/pbl4-shop.service ~/.config/systemd/user/
install -m 644 runtime/arch/pbl4-nginx.service ~/.config/systemd/user/
install -m 644 runtime/arch/pbl4-security.service ~/.config/systemd/user/
install -m 644 runtime/arch/pbl4-logrotate.service ~/.config/systemd/user/
install -m 644 runtime/arch/pbl4-logrotate.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user start pbl4-shop pbl4-nginx pbl4-security
systemctl --user enable --now pbl4-logrotate.timer
systemctl --user status pbl4-shop pbl4-nginx pbl4-security --no-pager
systemctl --user list-timers pbl4-logrotate.timer --no-pager
```

Không dùng sudo systemctl cho các unit này. Nginx chạy dưới chính user của bạn,
sử dụng complete config riêng bằng -p/-c, không dùng nginx.service hệ thống và
không sửa /etc/nginx/nginx.conf. File mime.types được đọc từ /etc/nginx/mime.types.
Ba service dài hạn tự restart khi process lỗi, nhưng không đồng nghĩa application ready;
phải kiểm tra health và audit. Timer chạy rotator oneshot mỗi 15 phút, mặc định file đạt
5 MiB mới rotate và giữ 8 thế hệ. Service user chỉ gắn với phiên user; chưa bật linger.

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

Arch service dùng `runtime/arch/watcher.checkpoint.json`. Restart bình thường tiếp tục từ
newline đã commit và thêm một `watch_started`. Checkpoint v2 còn giữ watermark, cửa sổ
flood và lease dry-run; watcher reconcile TTL theo wall clock khi idle. Checkpoint được ghi
sau audit nên crash ở khe giữa hai thao tác có thể lặp một số record thay vì mất log.
Không dùng cơ chế local này để gọi WAF thật: chưa có distributed lock, ownership hoặc đối
soát rule bên ngoài. Copytruncate vẫn có race; ưu tiên rotate bằng rename rồi Nginx reopen.

Dừng lab:

```bash
systemctl --user stop pbl4-security pbl4-nginx pbl4-shop
systemctl --user disable --now pbl4-logrotate.timer
```

Ba service dài hạn chưa enable mặc định. Timer rotation được enable sau kiểm thử; điều này
không hứa chạy lúc chưa đăng nhập sau reboot vì user linger vẫn chưa bật.

## 5. Log, firewall và phần chưa áp dụng

Nginx origin giữ encoded path gốc, chỉ q/category trong query; bỏ body, cookie,
Authorization và user agent. Không đưa secret vào path/q/category. Log error mức
crit để giảm raw request trong error log; vẫn coi mọi file runtime là dữ liệu riêng.
Nginx log timestamp có độ chính xác giây; một worker giữ write ordering đơn giản.
`pbl4-logrotate.timer` chạy mỗi 15 phút. Rotator dùng lock chống chạy chồng, chỉ xoay access
khi checkpoint bám đúng inode active, rename file rồi xác thực PID/cùng UID/tên Nginx trước
khi gửi `SIGUSR1`. File active/lock/rotated mode 0600; reopen lỗi được rollback. Audit dùng
rename tương tự; retention giữ 8 bản mỗi loại và không xóa inode checkpoint còn tham chiếu.
Không nén để tránh writer/follower đang giữ file descriptor. Đây là bounded retention theo
chu kỳ, nên active file vẫn có thể vượt 5 MiB giữa hai lần timer và không thay thế log shipper.

Trước bước firewall, đọc ruleset (chỉ chạy lệnh có công cụ tương ứng):

```bash
sudo ufw status verbose
sudo nft list ruleset
sudo iptables -S
sudo ip6tables -S
```

Ruleset phải được review trước khi bật hoặc đổi firewall; không dùng `ufw reset`,
`iptables -F` hay sửa các chain Docker tự quản lý. Sau lần review ngày 2026-09-15, UFW
được chọn làm công cụ quản lý host firewall và bật với default deny incoming. Chỉ lab
Docker bên dưới dùng một rule exact tạm thời trong chain `DOCKER-USER` dành cho quản trị.
Không bật chồng một nftables service độc lập. Linux firewall bảo vệ host/cổng; phương án
HTTP sau ALB vẫn dùng WAF ở chặng sau.

Trên Arch, `ufw enable` nạp rules hiện tại nhưng không tự bảo đảm systemd unit sẽ chạy ở
lần boot sau. Sau khi đã review rule và chắc chắn không khóa đường quản trị, bật cả runtime
lẫn boot persistence rồi kiểm tra lại:

```bash
sudo ufw enable
sudo systemctl enable --now ufw.service
sudo ufw status verbose
systemctl is-enabled ufw.service
```

Hai firewall lab đều fail closed nếu UFW chưa active, default incoming không phải deny
hoặc `ufw.service` chưa enabled. Máy hiện tại từng qua reboot với `ufw.conf` còn
`ENABLED=yes` nhưng unit disabled/inactive, vì vậy rules không được nạp cho đến khi service
được enable; chỉ nhìn file cấu hình không phải bằng chứng firewall kernel đang hoạt động.

### Kiểm thử UFW cô lập ở chặng 2B

Sau khi đã review ruleset và bật UFW với default deny incoming, chạy script từ tài khoản
user thường. Script cần sudo để tạo network namespace/veth và thêm rồi xóa một rule UFW
tạm thời:

```bash
sudo bash deploy/arch/firewall_lab.sh
```

Script dùng mạng benchmark `198.18.0.0/30`, interface và namespace có tên cố định, đồng
thời từ chối chạy nếu các tài nguyên đó đã tồn tại. Một HTTP server tạm chỉ bind địa chỉ
veth `198.18.0.1:19080`; không bind Wi-Fi hoặc các port PBL4. Ba bước kỳ vọng là deny
trước rule, allow đúng peer/port sau rule và deny lại sau khi xóa rule. `trap` dọn rule,
process, namespace, veth và file tạm khi thành công, lỗi hoặc bị ngắt. Script không flush
ruleset, không sửa chain Docker và không gửi request ra ngoài máy.

Sau khi chạy, kiểm tra không còn tài nguyên lab:

```bash
sudo ufw status verbose
sudo ip netns list
ip link show pbl4fw-host
```

`ip link` phải báo interface không tồn tại; namespace `pbl4-fw-client` và rule có comment
`PBL4 temporary firewall lab` không được còn lại. Nếu script báo không xóa được rule,
dùng `sudo ufw status numbered` để review chính xác trước khi xóa, không dùng `ufw reset`.

### Kiểm thử UFW với Docker published port

UFW `INPUT` không nhất thiết nhìn thấy port Docker đã DNAT qua `FORWARD`. Script thứ hai
dựng veth `198.18.0.5/30`–`198.18.0.6/30`, build local một image `FROM scratch` bằng binary
Go tĩnh và chỉ publish `198.18.0.5:19081`; không pull image, bind Wi-Fi hay gọi Internet:

```bash
sudo bash deploy/arch/docker_firewall_lab.sh
```

Pha đầu ghi nhận chính xác baseline là allow hay deny thay vì giả định. Pha hai thêm đúng
một rule tạm ở chain dành cho quản trị `DOCKER-USER`, match interface cùng original
destination/port bằng conntrack và xác nhận deny. Pha ba xóa rule rồi yêu cầu baseline cũ
quay lại. `trap` dọn container, image, namespace, veth, rule và thư mục build. Script từ
chối chạy nếu tên/IP/port/image đã tồn tại; không flush chain hoặc sửa cấu hình UFW.

Tài liệu tham chiếu: [Nginx command options](https://nginx.org/en/docs/switches.html),
[proxy_bind](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_bind),
[JSON access log](https://nginx.org/en/docs/http/ngx_http_log_module.html).

## Trạng thái kiểm chứng trên Arch — 2026-09-15

Đã kiểm chứng thực tế trên Arch x86_64, Python 3.14.7, Nginx 1.30.4 và Git 2.55.0:

- Clone sạch vào `/home/mtris/projects/PBL4`; local/upstream/remote HEAD cùng commit
  `2fdd004edec2f91e83b3118383dc7fca2e9ffdc6`. Danh tính Git được đặt riêng cho repo.
- Tạo `.venv` mới trên ext4, cài `requirements-lock.txt`, `pip check` không phát hiện
  dependency hỏng và 101/101 unittest vượt qua sau các test hồi quy bổ sung.
- `nginx -t` thành công và `systemd-analyze --user verify` không báo lỗi. Cấu hình ban
  đầu thất bại vì Nginx Arch muốn tạo `/var/lib/nginx/fastcgi`; generator đã được sửa
  để dùng đầy đủ temporary directory riêng trong `runtime/arch`.
- Ba user service `pbl4-shop`, `pbl4-nginx`, `pbl4-security` đều active nhưng vẫn
  disabled; `pbl4-logrotate.timer` active/enabled và chạy oneshot thành công. Chưa bật
  linger. Không dùng nginx system service hoặc sửa `/etc/nginx/nginx.conf`.
- Ingress `http://127.0.0.1:8080/healthz` trả 200; origin truy cập trực tiếp qua
  `127.0.0.1:8082` trả 403; backend loopback `127.0.0.1:8081` trả 200.
- Luồng HTTP thật đăng ký → đăng nhập → thêm giỏ → đặt đơn đã tạo một order đúng giá
  server-side trong SQLite runtime. Giao diện catalog thật render đủ 6 sản phẩm.
- Demo 25 request qua Nginx đạt `passed: true`: nhận diện SQLi, XSS, encoded path
  traversal và request flood; source là `127.0.0.1`; prefix XFF giả `192.0.2.66`
  không được chọn; loopback block bị `suppressed_protected_address`; không thực thi
  firewall và không gọi AWS. Demo trước đó lọc sai signature cùng giây vì timestamp
  Nginx không có microsecond; đã đổi sang đọc phần audit append sau byte offset và thêm
  test hồi quy.
- Trước khi có checkpoint, restart app/watcher từng làm audit tăng 153 dòng khi access
  chỉ tăng 2 dòng. Sau nâng cấp 2B, lần migration đầu replay 102 dòng cũ một lần và tạo
  checkpoint mode 0600 tại EOF. Restart security lần hai chỉ thêm đúng một record
  `watch_started` với `resume=checkpoint`, không xử lý lại request cũ. Checkpoint v1 khi
  đó chỉ lưu version/input path/device/inode/offset/line number, không chứa payload.
- Rotation Nginx thật bằng rename + reopen đã đổi inode, giữ lại file cũ 102 dòng và ghi
  request mới thành line 103. Audit tăng đúng ba record (`source_reset`, `decision`,
  `response`), checkpoint chuyển sang inode mới và offset 249. Test tự động còn kiểm tra
  dòng ghi muộn vào inode cũ, partial line qua restart và resume khi rotation xảy ra lúc
  watcher đang dừng. Copytruncate vẫn được nhận diện nhưng không tuyên bố hết race.
- Rotator định kỳ đã được triển khai và kiểm chứng live lần nữa: access inode 264107 với
  147 dòng được rename nguyên inode, Nginx mở inode mới 279560; request health kế tiếp
  thành watcher line 250 và checkpoint chuyển đúng inode/offset mới. Audit active ghi
  `source_reset`, `decision`, `response`, `state_reconciled`; access, audit, checkpoint,
  lock và rotated files đều mode 0600. Timer 15 phút đang active/enabled; lần mặc định
  dưới 5 MiB trả `below_threshold`. Unit test còn kiểm tra rollback khi reopen lỗi, chờ
  watcher, giới hạn thế hệ và bảo toàn inode checkpoint.
- Checkpoint v1 live đã tự nâng lên v2 mode 0600 tại EOF với `state_resume=legacy_reset`.
  Test tiếp theo gửi 10 request qua edge, checkpoint giữ cửa sổ 10; restart watcher báo
  `state_resume=checkpoint`; thêm 10 request trong cùng cửa sổ tạo size 20 và đúng một
  detection flood ở request thứ 20. Không có request mới, vòng idle sau đó ghi một
  `state_reconciled` và dọn source về 0. Test tự động còn chứng minh lease giữ idempotence
  xuyên restart, `would_unblock` được persist sau TTL, migration schema, state hỏng và
  policy mismatch đều fail closed. Engine state live đã nâng lên v2, bind với policy và
  adapter, báo `state_resume=checkpoint_upgrade`, vẫn ở EOF.
- Đã đọc ruleset trước khi bật firewall. Docker 29.7.2 đang quản lý các chain NAT/FORWARD
  qua iptables-nft; trước lab không có container chạy hoặc port container được publish.
  Không flush hay sửa chain Docker tự quản lý. UFW sau đó được bật với logging low, deny incoming, allow
  outgoing, deny routed và IPv6; INPUT policy thực tế là DROP cho cả IPv4/IPv6. Website
  loopback vẫn trả 200 và origin trực tiếp vẫn trả 403.
- Script `deploy/arch/firewall_lab.sh` đã chạy thật bằng sudo với network namespace ngày
  2026-09-15. Kết quả đủ ba pha: peer cô lập bị deny trước rule, được allow đúng IP/port
  bởi rule tạm, rồi bị deny lại sau khi xóa rule (`RESULT: PASS`). Script cũng xác nhận
  UFW còn active và chain `DOCKER-USER` vẫn tồn tại trước khi báo pass. Sau cleanup không
  còn namespace `pbl4-fw-client`, interface `pbl4fw-host`, listener TCP 19080 hoặc rule
  tạm trong file cấu hình UFW. Đây là bằng chứng INPUT allow/deny trên host; không phải
  bằng chứng UFW bảo vệ port do Docker publish và không liên quan nhận diện HTTP/XFF.
- Một reboot sau đó cho thấy `ufw.conf` vẫn `ENABLED=yes` nhưng `ufw.service` disabled và
  firewall inactive. Unit đã được `enable --now`; UFW hiện active/enabled với default deny
  incoming/routed. Cả hai lab giờ đều kiểm tra service enabled trước khi tạo tài nguyên.
- `deploy/arch/docker_firewall_lab.sh` đã chạy thật bằng sudo và build image scratch cục bộ.
  Peer veth truy cập được published port dù UFW INPUT default deny (`baseline_allowed=1`),
  chứng minh DNAT/FORWARD của Docker bypass lớp INPUT trên ruleset này. Một rule exact tạm
  trong `DOCKER-USER`, match ingress interface và original destination/port, đã chặn kết
  nối; xóa rule khôi phục baseline. Kết quả cuối `RESULT: PASS` có `cleanup=pass`; kiểm tra
  sau đó không còn interface `pbl4dk-host` hoặc listener 19081. Không cài rule lâu dài vì
  lab hiện không publish dịch vụ; container tương lai phải có policy `DOCKER-USER`/network
  riêng hoặc không publish ra interface ngoài, không được dựa riêng vào UFW INPUT.
- `/healthz` ban đầu phát session cookie vì hook CSRF chạy trên mọi request. Endpoint đã
  được tách khỏi việc đọc/tạo session và có test xác nhận health response không còn
  `Set-Cookie`. Analyzer cũng đã có ngoại lệ fail-closed: chỉ `GET /healthz` không query,
  từ peer tin cậy và không có XFF được loại khỏi flood, đồng thời ghi `policy_skip`.
  Test Nginx thật gửi 25 request từ `127.0.0.2` tạo đúng 25 `policy_skip`, không có
  `request_flood`, và checkpoint đạt EOF. Client qua edge có XFF vẫn được tính và demo
  25 request tiếp tục nhận diện đủ bốn loại, gồm flood; checkpoint lại đạt EOF.
- SQLite live đã migration thêm `login_throttle` và `browser_sessions` mà giữ nguyên user,
  order cũ; database mode 0600. Test HTTP qua Nginx tạo account lab: bốn mật khẩu sai đầu
  trả 401, restart `pbl4-shop`, lần thứ năm trả 429 với `Retry-After: 900`; mật khẩu đúng
  trong thời gian khóa cũng trả 429. Account lab thứ hai login/logout đều 303, sau logout
  DB còn 0 browser session và replay cookie cũ vào `/cart` bị redirect 302. Throttle chỉ
  lưu HMAC identity, session DB chỉ lưu HMAC token. Local HTTP không phát HSTS/Secure;
  production-mode test xác nhận cả hai bật và session không refresh theo mỗi request.

Chưa kiểm chứng hoặc chưa triển khai: email verification/password reset/MFA,
rate limit client-IP ở ingress,
multi-worker/distributed state, đối soát luật enforcement, ALB/SG/NACL,
AWS WAF hoặc tải production. Contract health check vẫn phải đối chiếu bằng access log target
thật trên AWS. Vì vậy phần Nginx local, host firewall, auth và checkpoint/rotation/state
dry-run nền tảng đã đạt, nhưng không dùng kết quả này để tuyên bố toàn bộ chặng 2 hay AWS
hoàn thành.
