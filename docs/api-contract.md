# API contract v0.1 — desktop client ↔ shop server

Ngày khóa cho demo sơ bộ: 2026-09-24. File này là nguồn sự thật chung cho nhóm client và
server. Không tự đổi path, field, kiểu dữ liệu hoặc status code trên một nhánh riêng; mọi
thay đổi contract phải được cập nhật ở đây và có test tương ứng.

## Quy ước chung

- Base path: `/api/v1`. Base URL (scheme, IP, port) do cấu hình client cung cấp, không
  hard-code trong source.
- Request/response dùng JSON UTF-8 và `Content-Type: application/json`, trừ response 204.
- Giá là integer VND; ID sản phẩm/user là integer; ID đơn hàng là string opaque.
- Thời gian dùng ISO-8601 UTC khi xuất API.
- Desktop API không dùng browser cookie hoặc CSRF. Endpoint bảo vệ nhận
  `Authorization: Bearer <opaque-token>`.
- Token sống cố định 2 giờ, tối đa 5 token API/user, có thể logout/revoke. Client demo giữ
  token trong RAM, không ghi token vào source, log hoặc Git.
- Server không bật CORS chỉ để làm desktop client; CORS là cơ chế của browser.
- Bản cuối dùng HTTPS. HTTP chỉ được chấp nhận cho LAN demo cô lập với tài khoản giả.
- Nginx/access logger không ghi body, Cookie hoặc Authorization.

Mọi lỗi API có dạng:

```json
{
  "error": {
    "code": "invalid_credentials",
    "message": "Email or password is incorrect."
  }
}
```

Client phải quyết định theo `status` và `error.code`, không so khớp nguyên văn message.
Các response API có `Cache-Control: no-store` và `X-API-Version: 1`.

## Endpoint nền tảng đã triển khai

### Health

```http
GET /api/v1/health
```

```json
{"status":"ok"}
```

Trả 200, không cần token và không tạo cookie/session.

### Đăng ký

```http
POST /api/v1/auth/register
Content-Type: application/json

{"name":"Sinh viên","email":"student@example.test","password":"local-demo-password"}
```

Thành công trả 201:

```json
{"user":{"id":1,"name":"Sinh viên","email":"student@example.test"}}
```

Validation: tên 2–60 ký tự, email tối đa 254 ký tự và đúng dạng cơ bản, password 12–128
ký tự. Email trùng trả 409 `email_unavailable`.

### Đăng nhập

```http
POST /api/v1/auth/login
Content-Type: application/json

{"email":"student@example.test","password":"local-demo-password"}
```

Thành công trả 200:

```json
{
  "token": "opaque-random-token",
  "token_type": "Bearer",
  "expires_in": 7200,
  "user": {"id":1,"name":"Sinh viên","email":"student@example.test"}
}
```

Sai thông tin trả 401 `invalid_credentials`. Năm lỗi trong 15 phút khóa identity 15 phút;
429 `login_throttled` kèm `Retry-After`. User tồn tại/không tồn tại dùng cùng response.

### User hiện tại và logout

```http
GET /api/v1/me
Authorization: Bearer <token>
```

```json
{"user":{"id":1,"name":"Sinh viên","email":"student@example.test"}}
```

```http
POST /api/v1/auth/logout
Authorization: Bearer <token>
```

Logout thành công trả 204. Token thiếu/hết hạn/đã revoke trả 401 `unauthorized` cùng
`WWW-Authenticate: Bearer`.

### Catalog

```http
GET /api/v1/products?q=Pebble&category=Thi%E1%BA%BFt%20b%E1%BB%8B
GET /api/v1/products/1
```

Danh sách trả 200:

```json
{
  "items": [
    {
      "id": 1,
      "name": "Bàn phím Pebble",
      "category": "Thiết bị",
      "illustration": "keyboard",
      "price": 890000,
      "stock": 24,
      "description": "Mô tả sản phẩm"
    }
  ]
}
```

Chi tiết trả `{"product": {...}}`; không tìm thấy trả 404 `not_found`. `q` tối đa 200,
`category` tối đa 40 ký tự. Hai endpoint catalog hiện là public.

## Phần nhóm server tiếp tục triển khai

Mọi endpoint dưới đây cần bearer token. Không nhận `user_id`, giá hoặc total từ client.

### Cart

```http
GET /api/v1/cart
```

```json
{
  "items": [
    {
      "product": {"id":1,"name":"Bàn phím Pebble","price":890000,"stock":24},
      "quantity": 2,
      "line_total": 1780000
    }
  ],
  "total": 1780000
}
```

```http
PUT /api/v1/cart/items/1
Content-Type: application/json

{"quantity":2}
```

`quantity` là integer 1–10 và không vượt stock; PUT đặt số lượng cuối cùng, không cộng dồn.
Thành công trả cart mới với 200. Product không tồn tại trả 404 `not_found`; vượt giới hạn
hoặc stock trả 409 `stock_unavailable`.

```http
DELETE /api/v1/cart/items/1
```

Thành công trả 204, kể cả item đã không còn trong cart để thao tác idempotent.

### Order

```http
POST /api/v1/orders
Authorization: Bearer <token>
Idempotency-Key: <UUID/string ngẫu nhiên 1–100 ký tự>
```

Server đọc cart, kiểm tra stock và tính toàn bộ giá trong một transaction. Lần đầu thành
công trả 201; gửi lại cùng key của cùng user trả cùng order với 200, không trừ stock lần hai.

```json
{
  "order": {
    "id": "opaque-order-id",
    "total": 1780000,
    "created_at": "2026-09-24T02:00:00+00:00",
    "items": [
      {"product_id":1,"name":"Bàn phím Pebble","price":890000,"quantity":2}
    ]
  }
}
```

Cart rỗng trả 409 `empty_cart`; stock thay đổi trả 409 `stock_unavailable`; key thiếu/sai
dạng trả 400 `invalid_idempotency_key`.

```http
GET /api/v1/orders/{order_id}
```

Chỉ chủ sở hữu được xem. Không tồn tại hoặc không thuộc user đều trả cùng 404 `not_found`.

## Status code chung

| Status | Ý nghĩa |
|---|---|
| 200 | GET/PUT thành công hoặc replay idempotent |
| 201 | Tạo account/order lần đầu |
| 204 | Logout/delete thành công, không body |
| 400 | JSON/field/query/idempotency key sai |
| 401 | Credential/token không hợp lệ |
| 404 | Resource không tồn tại hoặc không thuộc user |
| 409 | Xung đột email/cart/stock |
| 413 | Body vượt 16 KiB |
| 415 | Body bắt buộc nhưng không phải JSON |
| 429 | Login throttle |

## Điều kiện không được phá

- SQLite chỉ nằm trên server; desktop client không mở hoặc copy database.
- Query luôn dùng bound parameter; order total luôn tính từ dữ liệu server.
- Thao tác order/stock/cart phải transaction và idempotent.
- API token và browser cookie dùng purpose/table riêng, không thay thế lẫn nhau.
- Không tin `X-Forwarded-For` từ client trực tiếp. Khi demo LAN, log phải chứng minh IP
  transport của máy client hoặc peer Nginx theo topology đã cấu hình.
