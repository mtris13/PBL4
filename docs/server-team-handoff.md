# Bàn giao cho nhóm shop server

## Quyết định đã khóa

- Repository chung: `https://github.com/mtris13/PBL4`, nhánh tích hợp là `main`.
- Dùng chung repository PBL4; không tạo repo server thứ hai.
- `shop/` là Flask server hiện tại, không phải desktop UI và chưa đổi tên trước demo.
- Desktop client sẽ nằm trong `client/`; `security/` tiếp tục là module độc lập đọc log.
- Contract duy nhất: `docs/api-contract.md`.
- Backend WSGI vẫn bind loopback sau Nginx; không public SQLite hoặc port Waitress.
- Nhóm integration/security cấu hình LAN theo `docs/two-machine-demo.md`; nhóm shop không
  đổi Waitress sang `0.0.0.0` và không tự thêm rule firewall rộng.

## Bắt đầu làm việc

Sau khi commit chuẩn bị REST đã có trên `main`:

```bash
git fetch origin
git switch -c feature/rest-api origin/main
python -m venv .venv
.venv/bin/python -m pip install -r requirements-lock.txt
.venv/bin/python -m unittest tests.test_api -v
```

Windows dùng `.venv\Scripts\python.exe`. Không copy `.venv`, `runtime/`, database, key
hoặc `.env` giữa hai máy. Không commit credential hay tài khoản demo.

Chạy full local lab để thử API qua proxy:

```bash
.venv/bin/python -m lab.run
curl http://127.0.0.1:8080/api/v1/health
```

## Phần đã có, không viết lại

- `GET /api/v1/health`.
- Register/login/logout, bearer token opaque, throttle, expiry và revoke.
- `GET /api/v1/me`.
- Product list/search/detail.
- SQLite schema, seed 6 sản phẩm và browser flow cũ để regression.
- Test API nền tảng trong `tests/test_api.py`.

## Việc nhóm server nhận

1. Triển khai cart API đúng contract: GET cart, PUT quantity cuối cùng, DELETE item.
2. Triển khai order API: transaction stock, server-side price, idempotency key và ownership.
3. Bổ sung test cho success, auth thiếu, user isolation, stock thay đổi và replay order.
4. Không sửa tên/shape endpoint đã khóa nếu chưa trao đổi với nhóm client.
5. Chạy toàn bộ `python -m unittest discover -v` trước khi mở pull request.

Definition of done cho demo sơ bộ:

- Hai máy gọi được `/api/v1/health` và catalog.
- Login trả token; `/me` hoạt động; logout làm token cũ trả 401.
- Client không cần cookie/CSRF và không truy cập SQLite.
- Không có password/token trong access/audit log.
- Cart/order test qua API và không tin giá/total/user_id từ client.
- Pull request ghi rõ commit, endpoint đã làm, lệnh test và giới hạn còn lại.

Baseline ngày 2026-09-24 đã chạy 107/107 unittest. Luồng live qua Nginx đạt register 201,
login 200, `/me` 200, logout 204 và replay token 401; API không phát cookie, token DB đã
được revoke sau logout. Nhóm server phải giữ baseline này xanh khi thêm cart/order.

## Quy tắc Git

- Làm trên `feature/rest-api`, không push trực tiếp `main` và không force-push shared branch.
- Chỉ commit source/test/docs cần thiết; runtime luôn nằm ngoài Git.
- Pull/rebase main trước khi bàn giao; giải quyết xung đột có review, không dùng reset hard.
- Nhóm client dùng `feature/desktop-client`; hai nhóm đồng bộ qua contract, không chờ copy
  source hoặc database của nhau.
