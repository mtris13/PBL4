# PBL4 — Mộc Shop & Security Lab

**Kiến trúc đích đã chọn: website EC2 sau Application Load Balancer (ALB).**
Chặng 1 cung cấp website chạy local, proxy mô phỏng ALB append-mode, access log thật
và analyzer đọc liên tục ở chế độ dry-run. Đây chưa phải hệ thống đã triển khai AWS.

## Chạy ngay trên máy hiện tại

Trong PowerShell tại `D:\SEM5\PBL4`:

```powershell
.\.venv\Scripts\python.exe -m lab.run
```

Mở [Mộc Shop local](http://127.0.0.1:8080). Chọn **Đăng nhập → Tạo tài khoản**, dùng
email và mật khẩu chỉ dành cho lab. Không có tài khoản/mật khẩu mặc định. Có thể xem
sản phẩm, tìm kiếm/lọc, thêm giỏ hàng, bỏ sản phẩm và đặt đơn mô phỏng.
Không yêu cầu thẻ, địa chỉ thật hay thanh toán. Ctrl+C ở terminal để dừng cả lab.

Mở terminal thứ hai để chạy demo hoặc xem audit:

```powershell
.\.venv\Scripts\python.exe -m lab.demo
Get-Content -LiteralPath .\runtime\audit.jsonl -Tail 10 -Wait
```

Demo chỉ gửi **25 request cố định đến 127.0.0.1**, gồm request bình thường, ba mẫu
signature và 21 request health check để kiểm tra cửa sổ flood. IP giả ở đầu XFF phải
bị bỏ qua. Client thật là loopback nên quyết định block được **suppressed_protected_address**:
đây là kết quả an toàn đúng thiết kế, không phải lỗi chặn. Demo không sửa firewall.
Kết quả lưu ở `runtime/demo-report.json`; unit test riêng dùng IP tài liệu để chứng minh
`would_block`, lease và unblock preview.

## Cài trên máy khác

Cần Python 3.12+ có pip/venv. Không copy `.venv` giữa các máy:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe -m lab.run
```

Linux/macOS dùng `.venv/bin/python` thay cho `.venv\Scripts\python.exe`. Đây vẫn là
lab local; không dùng proxy Python này thay Nginx/ALB trên server.

Trên máy đang làm, `.venv` đã được tạo bằng Python 3.12.14. Lệnh `python` trên PATH
của máy này trỏ tới bản MSYS 3.14 không có pip, nên hãy dùng đúng `.venv` như trên.

## Cấu hình và dữ liệu

- `lab/local.json`: port proxy/backend, thư mục runtime, IP nguồn proxy và poll interval.
  Có thể dùng `--config path/to/local.json` cho cả `lab.run` và `lab.demo`.
- `security/config/`: luật và threshold dùng chung. Lab ghi đè trusted proxy bằng config
  local, không đổi policy mặc định của core.
- `runtime/shop.sqlite3`: users, products, cart, orders; giá là số nguyên VND, tính ở server.
- `runtime/session.key`: secret ngẫu nhiên tự tạo một lần; không commit hoặc chia sẻ.
- `runtime/access.jsonl`: access log tối giản theo contract parser.
- `runtime/audit.jsonl`: detection/decision/response; không chứa request payload.
- `requirements.txt`: dependency trực tiếp; `requirements-lock.txt`: phiên bản đã kiểm thử.

Runtime đã được gitignore. `.env.example` mô tả env production tương lai; code không
tự đọc `.env`. `lab.run` tạo cấu hình local riêng, cookie Secure=false chỉ vì local HTTP.
App factory mặc định Secure=true và từ chối secret ngắn/thiếu.

## Luồng local

```text
Browser 127.0.0.1 → proxy :8080 (append XFF)
                  → backend :8081, peer nguồn proxy 127.0.0.2
                  → Flask + SQLite
                  → access.jsonl → file watcher → security core → audit.jsonl
```

Proxy kết nối backend bằng **127.0.0.2**, còn trình duyệt là **127.0.0.1**. Hai IP khác
nhau để trust chain phân biệt proxy và client dù đều ở loopback. Chỉ 127.0.0.2 được tin
cho XFF. Nếu nối thẳng backend từ 127.0.0.1 rồi giả header, parser bỏ qua header đó.
Trên cùng máy, người có khả năng tự bind 127.0.0.2 vẫn có thể giả proxy; mô hình này
kiểm thử logic, không thay thế isolation mạng/SG thật.

Waitress không rewrite `REMOTE_ADDR`; giữ XFF thô cho parser. Flask không dùng ProxyFix,
không lấy identity/host/scheme từ forwarded headers. Host được validate; secret và DB
không nằm trong static directory. CSRF áp dụng cho các thao tác thay đổi dữ liệu,
mật khẩu băm scrypt, template autoescape và CSP cấm script. Checkout transaction kiểm
tra tồn kho, tính giá server-side và dùng key chống tạo đơn trùng. Đơn hàng chỉ chủ sở hữu
xem được. Tham khảo [Flask security](https://flask.palletsprojects.com/en/stable/web-security/)
và [proxy trust](https://flask.palletsprojects.com/en/stable/deploying/proxy_fix/).

## Log và giới hạn chặng 1

Access logger không lưu body, Cookie, Authorization hoặc user agent; chỉ giữ giá trị
query `q`, `category` phục vụ tìm kiếm, bỏ tên/giá trị query khác. Path và hai giá trị
này vẫn có thể chứa dữ liệu người dùng: chỉ dùng dữ liệu lab, không nhập secret vào URL.
Redaction có thể khiến detector bỏ sót dấu hiệu nằm trong tham số khác. Khi thay bằng
Nginx ở chặng 2 phải giữ quy tắc redaction, không copy raw log format vào production.

Watcher theo dõi một file/một writer, giữ dòng viết dở, bỏ qua dòng quá lớn/UTF-8 lỗi.
`lab.run` và Arch service dùng checkpoint metadata atomically để restart tiếp tục từ
newline đã commit; checkpoint không chứa request/payload. Rename/recreate giữ inode cũ
đến hai lần EOF ổn định trước khi chuyển file mới. Không chạy hai watcher cho cùng file;
copytruncate và nhiều rotation quá nhanh vẫn có race. Checkpoint được ghi sau khi fsync
audit nên crash có thể lặp ít dòng nhưng không ưu tiên bỏ mất log. Flood/lease vẫn trong
RAM, chưa có persistent state, timer TTL lúc idle hoặc vận hành đa worker. DB SQLite hiện
phù hợp một app instance, chưa hỗ trợ scale-out nhiều EC2. Session cookie đã ký vẫn có
thể replay đến khi hết hạn nếu bị đánh cắp; cần session revocation/login throttling sau.

App chưa có quản trị, thanh toán, gửi mail, quên mật khẩu hoặc upload. Proxy chỉ phục vụ
loopback lab, không phải reverse proxy chống DoS production. Cần Nginx/ALB/WAF cho AWS.

## Test và các chặng tiếp theo

```powershell
.\.venv\Scripts\python.exe -m unittest discover -v
.\.venv\Scripts\python.exe -m pip check
```

Test dùng SQLite tạm thời và socket loopback, không gọi AWS hay thay firewall.
Cấu trúc: `shop/` website, `lab/` công cụ local, `security/` core độc lập, `tests/`
website/live log/HTTP, `docs/` kiến trúc và tiến độ. Xem thêm:

- [Kiến trúc sau ALB và vai trò firewall/WAF](docs/architecture-alb.md)
- [Các chặng, đầu ra và điều kiện nghiệm thu](docs/milestones.md)
- [Security core và contract JSONL](security/README.md)

Chặng kế tiếp: dựng Nginx/Linux thật, cấu hình service, hardening log/identity và chuẩn
bị WAF adapter. Chưa cần tạo tài nguyên AWS để sử dụng chặng 1.

## Chặng 2A trên Arch Linux

Đã chuẩn bị [hướng dẫn Git + Nginx + user services](docs/arch-stage-2a.md).
Người dùng có Arch dual boot, không cần WSL. Cấu hình chờ nginx -t và kiểm thử
thực tế trên Arch; chưa phải trạng thái triển khai Linux thành công.
