# PBL4 — Mộc Shop Client–Server & Security Lab

**Kiến trúc đích hiện tại: desktop app trên máy client gọi REST API trên máy server Linux.**
Theo thay đổi yêu cầu ngày 2026-09-24, dự án không deploy thành website công khai. Flask
vẫn được giữ làm JSON API server; web/Jinja cũ chỉ còn là regression UI trong lúc chuyển
đổi. Hai máy giao tiếp qua LAN, server giữ SQLite, Nginx/UFW, access log và analyzer.


## Demo hai máy — bắt đầu tại đây

Bản demo hoàn chỉnh nằm trên nhánh **codex/demo-client-server**.
Đọc **[hướng dẫn từng bước cho người mới](docs/DEMO.md)**: bạn chạy server Linux,
một thành viên mở desktop client Windows/Linux. Có đăng ký/đăng nhập, sản phẩm,
giỏ hàng, đặt đơn và lịch sử. Client Windows nhấp đúp **run-client.cmd**;
server dùng **bash scripts/server.sh setup IP_SERVER** sau khi cài phần mềm trong hướng dẫn.
HTTP LAN dùng tài khoản giả; analyzer vẫn dry-run.

## Chạy ngay trên máy hiện tại

Trong PowerShell tại `D:\SEM5\PBL4`:

```powershell
.\.venv\Scripts\python.exe -m lab.run
```

Mở [Mộc Shop local](http://127.0.0.1:8080) để kiểm tra regression UI. Chọn
**Đăng nhập → Tạo tài khoản**, dùng
email và mật khẩu chỉ dành cho lab. Không có tài khoản/mật khẩu mặc định. Có thể xem
sản phẩm, tìm kiếm/lọc, thêm giỏ hàng, bỏ sản phẩm và đặt đơn mô phỏng.
Không yêu cầu thẻ, địa chỉ thật hay thanh toán. Ctrl+C ở terminal để dừng cả lab.

REST nền tảng dùng prefix `/api/v1`. Kiểm tra nhanh khi lab đang chạy:

```text
GET http://127.0.0.1:8080/api/v1/health
GET http://127.0.0.1:8080/api/v1/products
```

Contract dành cho hai nhóm nằm ở [docs/api-contract.md](docs/api-contract.md); hướng dẫn
nhóm server ở [docs/server-team-handoff.md](docs/server-team-handoff.md).

Mở terminal thứ hai để chạy demo hoặc xem audit:

```powershell
.\.venv\Scripts\python.exe -m lab.demo
Get-Content -LiteralPath .\runtime\audit.jsonl -Tail 10 -Wait
```

Demo chỉ gửi **25 request cố định đến 127.0.0.1**, gồm request bình thường, ba mẫu
signature và 21 request health check để kiểm tra cửa sổ flood. IP giả ở đầu XFF phải
bị bỏ qua. Các request này đi qua edge nên có XFF và vẫn được tính flood; chỉ health
check đến trực tiếp từ proxy tin cậy, không XFF và khớp đúng contract mới được bỏ qua.
Client thật là loopback nên quyết định block được **suppressed_protected_address**:
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
- `runtime/shop.sqlite3`: users, products, cart, orders, throttle, browser/API sessions;
  giá là số nguyên VND, tính ở server. Trên POSIX file được siết mode 0600.
- `runtime/session.key`: secret ngẫu nhiên tự tạo một lần; không commit hoặc chia sẻ.
- `runtime/access.jsonl`: access log tối giản theo contract parser.
- `runtime/audit.jsonl`: detection/decision/response; không chứa request payload.
- `requirements.txt`: dependency trực tiếp; `requirements-lock.txt`: phiên bản đã kiểm thử.

Runtime đã được gitignore. `.env.example` mô tả env production tương lai; code không
tự đọc `.env`. `lab.run` tạo cấu hình local riêng, cookie Secure=false và HSTS=false chỉ
vì local HTTP. App factory mặc định Secure=true, HSTS một năm và từ chối secret ngắn/thiếu.

## Luồng local

```text
Regression UI/API client 127.0.0.1 → proxy :8080 (append XFF)
                                    → backend :8081, peer nguồn proxy 127.0.0.2
                                    → Flask + SQLite
                                    → access.jsonl → security core → audit.jsonl
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

Login throttle dùng HMAC-SHA256 của email đã chuẩn hóa, không lưu email nhập sai: 5 lỗi
trong 15 phút khóa định danh 15 phút và trả 429 kèm `Retry-After`. Bảng tối đa 10.000 key,
dọn row cũ và sống qua restart SQLite. User tồn tại/không tồn tại dùng cùng thông báo và
dummy password hash. Thành công xóa throttle. Đây là giới hạn theo định danh, không phải
theo IP: app cố ý không tin XFF; rate limit chống password spraying/phân tán phải đặt tại
Nginx/WAF với nguồn đã xác thực.

Mỗi login phát token ngẫu nhiên; cookie ký giữ token thô, DB chỉ lưu HMAC token. Logout
thu hồi token nên cookie cũ replay không còn hợp lệ. Session có thời hạn cố định hai giờ,
không refresh mỗi request, tối đa 5 phiên/user và phiên cũ nhất bị thu hồi khi vượt giới
hạn. Secret rotation vô hiệu hóa cookie/token hiện có. SQLite phù hợp một app instance;
scale-out cần session/throttle store dùng chung. Đăng ký chưa có xác minh email, password
reset, MFA hay quản trị thiết bị đăng nhập.

Desktop API dùng token opaque riêng qua `Authorization: Bearer`, không dùng cookie hoặc
CSRF. DB chỉ lưu HMAC purpose-separated trong `api_sessions`; token sống cố định hai giờ,
tối đa 5 token/user và logout thu hồi ngay. Browser token không dùng thay API token. API
hiện có health, register/login/logout, `me`, product list/search/detail; cart và
order API đã triển khai transaction, ownership và idempotency cho desktop client.

## Log và giới hạn chặng 1

Access logger không lưu body, Cookie, Authorization hoặc user agent; chỉ giữ giá trị
query `q`, `category` phục vụ tìm kiếm, bỏ tên/giá trị query khác. Path và hai giá trị
này vẫn có thể chứa dữ liệu người dùng: chỉ dùng dữ liệu lab, không nhập secret vào URL.
Redaction có thể khiến detector bỏ sót dấu hiệu nằm trong tham số khác. Khi thay bằng
Nginx ở chặng 2 phải giữ quy tắc redaction, không copy raw log format vào production.

Watcher theo dõi một file/một writer, giữ dòng viết dở, bỏ qua dòng quá lớn/UTF-8 lỗi.
`lab.run` và Arch service dùng checkpoint v2 nguyên tử để giữ cả vị trí newline đã commit,
watermark, cửa sổ flood và lease dry-run. File mode 0600 chỉ chứa IP/timestamp cùng metadata
state, không chứa request target/header/payload; checkpoint v1 tự nâng cấp với state rỗng.
Rename/recreate giữ inode cũ đến hai lần EOF ổn định trước khi chuyển file mới. Không chạy
hai watcher cho cùng file. Arch timer kiểm tra mỗi 15 phút, rotate bằng rename khi file đạt
5 MiB và giữ 8 thế hệ mỗi loại. Access log chỉ rotate khi checkpoint đang tham chiếu đúng
inode active; rotator tạo file mode 0600 rồi yêu cầu đúng Nginx master cùng user reopen.
Nếu reopen lỗi, rename được rollback. Retention không xóa inode checkpoint còn dùng.
Copytruncate, nhiều writer và tăng trưởng trong khoảng giữa hai lần timer vẫn là giới hạn.
Checkpoint được ghi sau khi fsync audit nên crash có thể lặp ít dòng nhưng không ưu tiên bỏ
mất log. Watcher dọn TTL lúc idle và persist kết quả; đây chưa phải distributed state, lock
đa worker hay reconciliation với luật firewall/WAF thật. DB SQLite hiện phù hợp một app
instance, chưa hỗ trợ scale-out nhiều EC2.

App chưa có quản trị, thanh toán, gửi mail, quên mật khẩu hoặc upload. Proxy Python local chỉ phục
vụ loopback; Nginx có cấu hình LAN và desktop UI đã có. TLS và kiểm chứng hai máy thật là bước tiếp theo.
Lab Arch đã xác nhận Docker published port đi qua DNAT/FORWARD và bypass UFW INPUT trên
ruleset hiện tại. Container tương lai phải dùng policy `DOCKER-USER`/network riêng hoặc
không publish ra interface ngoài; không coi `ufw default deny incoming` là đủ cho Docker.

## Test và các chặng tiếp theo

```powershell
.\.venv\Scripts\python.exe -m unittest discover -v
.\.venv\Scripts\python.exe -m pip check
```

Test dùng SQLite tạm thời và socket loopback, không gọi dịch vụ ngoài hay thay firewall.
Cấu trúc: `client/` desktop app, `shop/` REST server + regression web UI, `lab/` công cụ
local, `security/` core độc lập, `tests/` API/web/live log/HTTP và `docs/`. Xem thêm:

- [API contract client–server](docs/api-contract.md)
- [Bàn giao nhóm shop server](docs/server-team-handoff.md)
- [Checklist demo hai máy](docs/two-machine-demo.md)
- [Các chặng, đầu ra và điều kiện nghiệm thu](docs/milestones.md)
- [Security core và contract JSONL](security/README.md)

Chặng Arch đã có Nginx/user services, firewall lab, persistent auth state và bounded log
rotation. Cart/order REST API và desktop client đã có trên nhánh demo; bước tiếp theo là kiểm thử trên hai máy LAN, TLS và enforcement.

## Chặng 2A trên Arch Linux

Xem [hướng dẫn Git + Nginx + user services](docs/arch-stage-2a.md) cùng bằng chứng đã
kiểm thử thực tế trên Arch. Đây vẫn là local lab, không phải triển khai AWS/production.
