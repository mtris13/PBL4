# Lộ trình theo từng chặng

Mục tiêu cuối sau thay đổi yêu cầu ngày 2026-09-24: desktop app trên một máy client gọi
REST API trên một máy server Linux, có đăng nhập, firewall và cơ chế phát hiện/phản ứng
với bằng chứng thực nghiệm trong lab được phép. Không deploy thành website công khai.

| Chặng | Đầu ra | Điều kiện xong |
| --- | --- | --- |
| **1. Bản web local (đã xong, giữ regression)** | Website + SQLite, proxy append XFF, access log, watcher, dry-run, test và README | Đăng ký → đăng nhập → mua hàng mô phỏng; bốn detector nhận request HTTP local; không tin XFF giả |
| **2. Linux và vận hành security** | Nginx thật, app service, analyzer service, log redaction/rotation, checkpoint + flood/lease state dry-run, health-check policy, login throttling/session hardening; WAF response plan | Reboot/restart có hành vi rõ ràng, log thật đúng contract; cấu hình firewall được review và kiểm thử trong lab |
| **3. REST API và desktop client** | API v1, opaque bearer token, cart/order transaction, desktop UI và config server URL | Máy client đăng nhập, xem sản phẩm, thao tác cart/order mà không truy cập DB trực tiếp |
| **4. Hai máy và enforcement LAN** | Nginx/TLS trên server, UFW chỉ allow luồng cần thiết, log IP client, controlled block/unblock | Client hợp lệ hoạt động; peer ngoài policy bị deny; có bằng chứng log/firewall và không tự khóa quản trị |
| **5. Báo cáo và demo** | Sơ đồ, bảng số liệu, kịch bản demo, ảnh/log đã lọc, phân công, giới hạn, cleanup | Thành viên khác chạy được theo README và giải thích được các lớp phòng thủ |

## Bàn giao chặng 1

- `shop/`: Flask/Jinja + SQLite, 6 sản phẩm mẫu, search/category, auth, cart, order;
  hiện mở rộng thành REST server trong khi giữ web UI làm regression.
- `lab/`: launcher, proxy loopback, target access logger, demo có giới hạn.
- `security/scripts/watch.py`: follow file liên tục với dry-run.
- `tests/`: auth/data isolation/CSRF/XSS/SQLi/stock/idempotence, file following và HTTP proxy thật.
- Giữ `security/` độc lập; các CLI giai đoạn core vẫn chạy như trước.

Chặng 1 không gọi AWS, sửa firewall máy chủ, cài WSL hoặc cấu hình máy khác. Báo cáo kiểm
thử lịch sử nằm trong `docs/stage-1-verification.md`.

## Phân công chặng hiện tại

- Nhóm server làm trên `feature/rest-api`, tuân thủ `docs/api-contract.md`.
- Nhóm client làm trên `feature/desktop-client`, chỉ giao tiếp HTTP JSON.
- Nhóm security giữ `security/`, Nginx/UFW/log contract và test hai máy.
- Tích hợp bằng pull request vào cùng repo; không copy database/runtime giữa máy.

## Nguyên tắc báo cáo

Phân biệt *đã viết code*, *đã kiểm thử loopback*, *đã kiểm thử Linux* và *đã kiểm thử hai
máy LAN*. Chỉ điền số liệu/ảnh thực sự thu được. Không hồi tố kết quả proxy/ALB mô phỏng
thành bằng chứng hai máy; phải ghi IP/port/topology và ruleset thật của buổi demo.
