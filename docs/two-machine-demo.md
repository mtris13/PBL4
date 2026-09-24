# Checklist demo hai máy

> Người mới bắt đầu: dùng [DEMO.md](DEMO.md) để chạy desktop và server từng bước.
> Checklist bên dưới dành cho đối chiếu cấu hình mạng.

Không điền IP giả vào source. Trước buổi demo, ghi nhận từ hai máy:

| Giá trị | Ví dụ | Người xác nhận |
|---|---|---|
| Server LAN IPv4 | `192.168.1.20` | Nhóm server/security |
| Server interface | `enp3s0` hoặc `wlan0` | Nhóm server/security |
| Client LAN IPv4 | `192.168.1.30` | Nhóm client |
| API port | `8080` mặc định | Cả hai nhóm |
| Base URL | `http://192.168.1.20:8080/api/v1` | Cả hai nhóm |

IP server phải ổn định trong buổi demo (DHCP reservation hoặc kiểm tra lại sau khi nối mạng).
Không dùng `0.0.0.0` trong config sinh bởi dự án.

## Trên máy server Arch

Xem địa chỉ/interface, sau đó thay `SERVER_IP` bằng RFC1918 IPv4 thật:

```bash
ip -br -4 address
.venv/bin/python -m deploy.arch.render --lan-address SERVER_IP
nginx -t -p "$PWD/runtime/arch/" -c "$PWD/runtime/arch/nginx.conf"
systemctl --user restart pbl4-shop pbl4-nginx pbl4-security
```

Review UFW rồi chỉ allow đúng client/interface/IP/port. Thay bốn placeholder trước khi chạy:

```bash
sudo ufw allow in on SERVER_INTERFACE from CLIENT_IP to SERVER_IP port 8080 proto tcp comment 'PBL4 desktop client'
sudo ufw status verbose
```

Không mở 8081 hoặc 8082: Waitress và Nginx origin vẫn chỉ bind loopback. Không dùng rule
`allow 8080` cho mọi nguồn nếu mục tiêu demo chỉ có một client.

Kiểm tra server local:

```bash
curl --noproxy '*' http://127.0.0.1:8080/api/v1/health
ss -ltn
```

## Trên máy client

Cấu hình desktop app bằng base URL, không sửa source/hard-code:

```text
http://SERVER_IP:8080/api/v1
```

Kiểm tra trước UI:

```bash
curl --noproxy '*' http://SERVER_IP:8080/api/v1/health
curl --noproxy '*' http://SERVER_IP:8080/api/v1/products
```

Nếu timeout: kiểm tra hai máy cùng mạng, IP có đổi không, server Nginx có listen exact IP,
UFW rule có đúng interface/client IP và AP có bật client isolation không. Không tắt UFW để
"sửa" demo.

## Bằng chứng cần lưu

- `ip -br -4 address` đã che các interface không liên quan nếu đưa vào báo cáo.
- `ss -ltn` chứng minh chỉ edge 8080 nghe LAN; backend/origin vẫn loopback.
- UFW numbered/status chứng minh chỉ client IP được allow.
- Client gọi health/catalog/login thành công.
- Access log cho request client và audit tương ứng, không chứa Authorization/password.
- Thử một peer khác hoặc xóa tạm allow rule để chứng minh deny, rồi khôi phục có kiểm soát.

HTTP LAN chỉ dùng account/password giả. Sau demo sơ bộ phải thêm TLS và xác thực certificate
server trước khi coi luồng credential đủ an toàn.

## Cleanup rule sau lab

Không dùng `ufw reset`. Xem numbered rules và xóa đúng rule đã tạo, hoặc dùng chính xác:

```bash
sudo ufw delete allow in on SERVER_INTERFACE from CLIENT_IP to SERVER_IP port 8080 proto tcp
```
