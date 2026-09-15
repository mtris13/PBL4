# Lộ trình theo từng chặng

Mục tiêu cuối: chạy trên Linux/AWS, website thương mại điện tử có đăng nhập, firewall
Linux và cơ chế phát hiện/phản ứng có bằng chứng thực nghiệm trong lab được phép.

| Chặng | Đầu ra | Điều kiện xong |
| --- | --- | --- |
| **1. Bản local sau proxy** | Website + SQLite, proxy append XFF, access log, watcher, dry-run, test và README | Đăng ký → đăng nhập → mua hàng mô phỏng; bốn detector nhận request HTTP local; không tin XFF giả |
| **2. Linux và vận hành security** | Nginx thật, app service, analyzer service, log redaction/rotation, checkpoint + flood/lease state dry-run, health-check policy, login throttling/session hardening; WAF response plan | Reboot/restart có hành vi rõ ràng, log thật đúng contract; cấu hình firewall được review và kiểm thử trong lab |
| **3. Hạ tầng AWS sau ALB** | VPC, subnet, SG, NACL, EC2, ALB, target group, health check và hướng dẫn từng bước | Website truy cập qua ALB, backend bị hạn chế truy cập trực tiếp, log xác định đúng IP client |
| **4. Enforcement và thực nghiệm** | WAF WebACL/IP sets, adapter, IAM tối thiểu, persistent TTL, retry/reconcile; controlled tests | Có bằng chứng block/unblock thật, không block ALB/admin; kiểm tra request hợp lệ và đo độ trễ |
| **5. Báo cáo và demo** | Sơ đồ, bảng số liệu, kịch bản demo, ảnh/log đã lọc, phân công, giới hạn, cleanup | Thành viên khác chạy được theo README và giải thích được các lớp phòng thủ |

## Bàn giao chặng 1

- `shop/`: Flask/Jinja + SQLite, 6 sản phẩm mẫu, search/category, auth, cart, order.
- `lab/`: launcher, proxy loopback, target access logger, demo có giới hạn.
- `security/scripts/watch.py`: follow file liên tục với dry-run.
- `tests/`: auth/data isolation/CSRF/XSS/SQLi/stock/idempotence, file following và HTTP proxy thật.
- Giữ `security/` độc lập; các CLI giai đoạn core vẫn chạy như trước.

Chưa gọi AWS, sửa firewall máy chủ, cài WSL hoặc cấu hình máy khác. Không có chứng
nhận hiệu quả production. Báo cáo kiểm thử nằm trong `docs/stage-1-verification.md`.

## Vai trò của bạn ở các chặng sau

Ở chặng 2 cần có Linux: WSL2/Ubuntu, VM hoặc máy Linux của nhóm. Người dùng đã xác nhận có Arch Linux dual boot, sudo và các package cần thiết;
chặng 2A dùng Arch, không cần cài WSL. Xem arch-stage-2a.md.
Ở chặng 3 bạn đăng nhập AWS và quyết định ngân sách/region; không gửi password,
access key hoặc secret qua chat. Chúng ta tạo tài nguyên theo từng bước có kiểm chứng,
không dựng toàn bộ rồi mới kiểm tra. Chuẩn bị teardown checklist cùng lúc với setup.

## Nguyên tắc báo cáo

Phân biệt *đã viết code*, *đã kiểm thử local*, *đã kiểm thử Linux* và *đã kiểm thử AWS*.
Chỉ điền số liệu/ảnh thực sự thu được. Với mô hình ALB, giải thích firewall Linux bảo
vệ host còn WAF phản ứng HTTP; không tuyên bố iptables chặn được client HTTP sau ALB
chỉ nhờ đọc XFF.
