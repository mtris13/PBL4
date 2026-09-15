# Kết quả kiểm chứng chặng 1

Thực hiện ngày 2026-09-10 trong `D:\SEM5\PBL4`, Windows, Python **3.12.14**.
Không có AWS resource, Linux/WSL hoặc firewall thật tham gia lần kiểm thử này.

## Kết quả đã chạy

| Kiểm tra | Kết quả thực tế |
| --- | --- |
| `.venv\Scripts\python.exe -m unittest discover -v` | **67 tests passed**, 21.458 giây |
| Security core ban đầu | 40 test tiếp tục vượt qua trên Python 3.12 |
| Website + live log + HTTP local | 27 test vượt qua |
| `.venv\Scripts\python.exe -m pip check` | No broken requirements found |
| `compileall -q shop lab security tests` | Exit code 0 |
| `python -m lab.demo` qua proxy local đang chạy | **passed: true**, 25 request |

Không có lint/type-check configuration từ repository ban đầu; chưa tuyên bố đạt
lint/type-check. Cú pháp được compile và hành vi được kiểm tra bằng unittest.

## Demo HTTP end-to-end

Request qua `127.0.0.1:8080`, proxy kết nối backend bằng source `127.0.0.2`.
Demo bắt đầu `2026-09-10T14:53:36.197744+00:00`:

- Request lành tính: HTTP 200.
- Query chứa mẫu SQLi: HTTP 200, analyzer nhận diện SQLi; truy vấn ở app dùng tham số.
- Query chứa mẫu XSS: HTTP 200, analyzer nhận diện XSS; test template xác nhận output escape.
- Double-encoded traversal: HTTP 404, analyzer nhận diện path traversal.
- 21 request health check: HTTP 200, analyzer phát hiện request flood theo threshold.
- XFF giả `192.0.2.66` không được chọn; IP nhận diện là client loopback `127.0.0.1`.
- Response gồm `recorded` và `suppressed_protected_address` vì loopback được bảo vệ.
- `aws_tested=false`, `firewall_executed=false`.

Chi tiết có thể tái tạo bằng `python -m lab.demo`; lần chạy gần nhất lưu ở
`runtime/demo-report.json`. File runtime không nằm trong source control, có thể thay
đổi khi người dùng chạy lại. Tài liệu này ghi đúng lần chạy nêu trên.

HTTP 200 của mẫu SQLi/XSS không chứng minh khai thác thành công. Nó cho thấy app vẫn
phản hồi khi security đang dry-run. Test riêng xác nhận không đăng nhập bằng SQLi,
output XSS được escape và traversal không đọc được file bên ngoài static.

## Các hành vi an toàn đã kiểm tra

- Đăng ký/login/logout, hash scrypt, secret bắt buộc, Secure mặc định/HttpOnly/SameSite.
  Chặng Arch sau đó bổ sung persistent login throttle, revocable session, fixed lifetime,
  giới hạn phiên và HSTS production; không hồi tố các mục này thành bằng chứng chặng 1.
- CSRF sai/thiếu/Unicode bị từ chối; token thay sau login.
- Host không tin cậy trả 400; forwarded host không chi phối ứng dụng.
- Giá/total từ client không được tin; checkout transaction giữ tồn kho và chống đơn trùng.
- Cart và order gắn theo user; người khác không đọc được đơn.
- Log không lưu body/cookie/token query; audit không lưu payload.
- Follower giữ partial line, không xử lý trùng khi file chưa đổi, phục hồi sau malformed,
  oversize, UTF-8 lỗi và truncate cơ bản.
- Proxy append XFF, bỏ hop-by-hop headers và forwarded host/proto giả.
- UFW/iptables vẫn chỉ preview, allowlist và lease test cũ tiếp tục vượt qua.

## Chưa kiểm chứng

ALB/SG/NACL thật, WAF block/unblock, TLS certificate, persistent state phân tán và đối soát
rule enforcement, scale-out, tải lớn và đánh giá false-positive trên traffic thực tế.
Checkpoint/lease local một watcher đã được kiểm chứng sau đó trên Arch; không hồi tố thành
bằng chứng WAF hoặc multi-worker cho chặng 1 này.
UI đã được kiểm tra response/render template qua HTTP, chưa có vòng kiểm thử tương tác
trực tiếp bằng trình duyệt. Các mục này không được tính là đã hoàn thành chặng AWS.
