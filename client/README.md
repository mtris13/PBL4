# Desktop client

Thư mục dành cho desktop app; chưa khóa toolkit UI. Khuyến nghị PySide6 vì client và server
cùng hệ Python, nhưng UI có thể dùng toolkit khác nếu vẫn tuân thủ `docs/api-contract.md`.

Nguyên tắc bắt buộc:

- Base URL lấy từ config local, ví dụ `http://192.168.1.20:8080/api/v1`; không hard-code IP.
- Không import `shop`, không mở SQLite và không dùng chung filesystem với server.
- Chỉ giao tiếp bằng HTTP JSON; timeout connect/read phải hữu hạn.
- Giữ bearer token trong RAM cho demo; logout xóa token kể cả khi network lỗi.
- Không log password, token hoặc toàn bộ Authorization header.
- Không tự retry POST order; replay chỉ dùng cùng `Idempotency-Key` theo contract.
- Hiển thị lỗi dựa trên HTTP status và `error.code`, không phụ thuộc nguyên văn message.
- HTTP LAN chỉ dùng tài khoản giả cho demo sơ bộ; bản cuối phải xác thực server bằng HTTPS.

Nhóm client làm trên branch `feature/desktop-client`. Trước khi code màn hình, hãy kiểm tra
được `/api/v1/health`, `/products`, login, `/me` và logout bằng một HTTP client tối giản.
