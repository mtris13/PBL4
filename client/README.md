# Mộc Shop desktop client

Ứng dụng Tkinter, chạy Windows/Linux, chỉ dùng thư viện chuẩn Python. Không cài Flask,
không import shop, không đọc SQLite. Chạy từ thư mục gốc bằng `python -m client`,
hoặc nhấp đúp `run-client.cmd` trên Windows / `bash run-client.sh` trên Linux.

Đọc [hướng dẫn demo từng bước](../docs/DEMO.md) để cài server và kết nối hai máy.
Nhánh demo: `codex/demo-client-server`.

Chức năng: đăng ký, đăng nhập/đăng xuất, tìm kiếm sản phẩm, giỏ hàng, đặt đơn, lịch sử
và chi tiết đơn. Giá/stock/ownership được kiểm tra bởi server. Token chỉ ở RAM;
config home `.pbl4-client.json` chỉ chứa server URL. Request có timeout 8 giây,
chạy ngoài luồng giao diện; không tự retry POST. Đơn mất response giữ Idempotency-Key
cho lần retry do người dùng bấm. Không đổi giỏ/đăng xuất khi kết quả đơn chưa xác nhận.
Đóng cưỡng bức ứng dụng làm mất key đang giữ trong RAM: đăng nhập lại và kiểm tra
lịch sử đơn trước khi tạo đơn khác.

Có thể truyền URL ban đầu:
```bash
python -m client --server http://192.168.1.20:8080
```

HTTP chỉ dùng cho LAN demo với tài khoản giả. HTTPS dùng certificate validation mặc định;
không có tùy chọn bỏ qua xác thực chứng chỉ. API contract: [docs/api-contract.md](../docs/api-contract.md).
