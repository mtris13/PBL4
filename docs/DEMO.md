# DEMO NGÀY MAI — 1 MÁY CLIENT + 1 MÁY SERVER LINUX

Bạn là **server Linux**. Một thành viên là **client Windows hoặc Linux**.
Hai máy nối cùng Wi-Fi/LAN (có thể cùng hotspot điện thoại nếu cho phép thiết bị nói chuyện với nhau).
Không cần AWS, Docker hoặc mua tên miền. Máy client không cài Flask, không có database.

Bản demo nằm trên nhánh **codex/demo-client-server**, không phải main.
Chạy lệnh từng khối, đợi khối trước hoàn tất. Các lệnh server gõ trong Terminal Linux;
lệnh client Windows gõ trong PowerShell. Không gõ dấu `$` hay `>` ở đầu lệnh.

## A. Bạn làm trên máy server Linux

### 1. Cài phần mềm một lần

Trên **Arch Linux**:

```bash
sudo pacman -Syu --needed git python python-pip nginx ufw
```

Nếu máy là **Ubuntu 24.04+** thay bằng:

```bash
sudo apt update
sudo apt install git python3 python3-venv nginx ufw
```

Không chạy cả hai khối. Khi sudo hỏi mật khẩu, nhập mật khẩu đăng nhập Linux của bạn;
màn hình không hiện ký tự lúc gõ là bình thường. Server cần Python 3.12 trở lên.
Không cần bật Nginx hệ thống: script dùng cấu hình và service riêng của đồ án.

### 2. Lấy đúng code

**Máy chưa có thư mục PBL4:**

```bash
mkdir -p ~/projects
cd ~/projects
git clone --branch codex/demo-client-server https://github.com/mtris13/PBL4.git
cd PBL4
```

**Máy đã có PBL4:** mở Terminal tại thư mục chứa README.md, sau đó:

```bash
git status
git fetch origin
git switch codex/demo-client-server
git pull --ff-only origin codex/demo-client-server
```

Nếu Git báo có thay đổi cục bộ hoặc conflict, dừng và giữ nguyên; không dùng reset --hard.
Nếu nhánh local đã tồn tại, git switch vẫn dùng được. Hai máy phải cùng nhánh trên.
Để repo trong thư mục home Linux, không có dấu cách, không dùng ổ NTFS chung với Windows.
Không copy .venv hoặc runtime từ máy khác.

### 3. Tìm IP của bạn và khởi động server

```bash
ip -br -4 address
```

Tìm dòng của Wi-Fi/Ethernet đang UP, ví dụ `wlan0 UP 192.168.1.20/24`.
IP cần nhập là **192.168.1.20**, bỏ phần /24. Không lấy 127.0.0.1 hoặc IP Docker.

```bash
read -rp "Nhap IP LAN cua may server: " SERVER_IP
bash scripts/server.sh setup "$SERVER_IP"
```

Chạy script bằng user thường, **không thêm sudo trước bash**.
Script tự tạo .venv, cài dependency server, sinh Nginx config, cài user services,
bật Flask/Nginx/analyzer/log rotation và kiểm tra health. Database/secret cũ được giữ lại.
Đợi thấy:

```text
OK: Nginx -> Flask -> SQLite
SERVER READY. Client URL: http://192.168.1.20:8080
```

Gửi địa chỉ Client URL này cho thành viên client. IP trên là ví dụ; dùng IP script in ra.

### 4. Cho phép đúng máy client qua firewall

Nhờ thành viên Windows chạy `ipconfig` và gửi IPv4 của Wi-Fi/Ethernet.
Ví dụ IP client là 192.168.1.30. Trên Linux chạy:

```bash
read -rp "Nhap IP LAN cua may client: " CLIENT_IP
sudo ufw status verbose
sudo ufw allow in from "$CLIENT_IP" to "$SERVER_IP" port 8080 proto tcp comment 'PBL4 desktop demo'
sudo ufw enable
sudo systemctl enable --now ufw
sudo ufw status verbose
```

Thực hiện bước này tại bàn phím máy Linux. Nếu đang quản trị qua SSH, giữ rule SSH hiện
có trước khi bật UFW. Không chạy ufw reset và không mở cổng 8081/8082.
Rule trên cho phép đúng client; nếu máy vốn đã có rule allow rộng thì phải review riêng,
không tuyên bố firewall chỉ cho phép một client khi còn rule rộng.

### 5. Kiểm tra nhanh

```bash
bash scripts/server.sh status
```

Ba service shop/nginx/security phải active (running), timer active (waiting).
Giữ Linux đăng nhập, cắm sạc và tắt tự ngủ trong thời gian demo.
Chỉ đóng terminal không làm dừng services; đăng xuất Linux có thể dừng user services.

## B. Thành viên làm trên máy client Windows

### 1. Chuẩn bị một lần

Cài Git và Python 3.12+ nếu máy chưa có. Với Python, chọn **Add Python to PATH** và giữ
thành phần **Tcl/Tk and IDLE**. Mở lại PowerShell sau khi cài. Kiểm tra:

```powershell
git --version
py -3 --version
```

Client chỉ dùng thư viện Python đi kèm; **không cần pip install requirements-lock.txt**.

### 2. Lấy code

Máy chưa có PBL4:

```powershell
git clone --branch codex/demo-client-server https://github.com/mtris13/PBL4.git
cd PBL4
```

Máy đã có PBL4, mở PowerShell tại thư mục đó:

```powershell
git fetch origin
git switch codex/demo-client-server
git pull --ff-only origin codex/demo-client-server
```

### 3. Chạy ứng dụng

Nhấp đúp **run-client.cmd** trong thư mục PBL4, hoặc chạy:

```powershell
py -3 -m client
```

1. Nhập địa chỉ server cung cấp, ví dụ **http://192.168.1.20:8080**.
2. Bấm **Kết nối**. Thấy danh sách 6 sản phẩm là kết nối thành công.
3. Bấm **Tạo tài khoản**, nhập tên, email dạng student@example.test và mật khẩu tự chọn
   dài ít nhất 12 ký tự. Chỉ dùng dữ liệu giả cho demo.
4. Bấm **Đăng nhập** bằng tài khoản vừa tạo.
5. Chọn sản phẩm, chọn số lượng, bấm **Thêm / cập nhật giỏ**.
6. Tab **Giỏ hàng** hiển thị tổng tiền. Bấm **Đặt đơn mô phỏng** rồi xác nhận.
7. Tab **Đơn hàng của tôi** → **Tải lại đơn hàng** → chọn dòng → **Xem chi tiết**.
8. Bấm **Đăng xuất** khi kết thúc.

Số lượng là số cuối cùng muốn có trong giỏ (không cộng dồn mỗi lần bấm).
Giỏ/đơn giữ trên server qua lần đăng nhập sau. Danh sách đơn hiển thị tối đa 100 đơn gần nhất.
Token chỉ giữ trong RAM; địa chỉ server được nhớ tại .pbl4-client.json trong thư mục home.
Nếu mất mạng lúc đặt đơn, giữ ứng dụng mở, khôi phục mạng rồi bấm **Thử lại đơn vừa gửi**.
Client dùng lại đúng mã của lần trước để tránh tạo đơn trùng.

### Client Linux (thay cho Windows)

Trên Arch cài `sudo pacman -S --needed python tk git`.
Trên Ubuntu cài `sudo apt install python3 python3-tk git`.
Lấy cùng nhánh như phần server rồi:

```bash
bash run-client.sh
```

Không chạy script server trên máy client.

## C. Kịch bản trình bày với thầy — khoảng 5 phút

1. **Giải thích 30 giây:** “Máy này chạy desktop client. Máy Linux kia giữ API và SQLite.
   Hai máy giao tiếp HTTP qua Nginx; client không truy cập database.”
2. **Demo chức năng:** đăng ký/đăng nhập, tìm “Pebble”, thêm 2 sản phẩm, đặt đơn, mở chi tiết.
3. **Chứng minh lưu dữ liệu:** đăng xuất, đăng nhập lại, tải lại đơn hàng; đơn cũ vẫn còn.
4. **Trên server mở terminal thứ hai:**

```bash
cd ~/projects/PBL4
tail -n 5 -f runtime/arch/access.jsonl
```

   Nếu repo nằm nơi khác, thay đường dẫn cd. Cho client bấm Tìm kiếm hoặc Tải lại giỏ;
   log mới xuất hiện. remote_addr của origin là 127.0.0.2; IP client nằm ở XFF cuối chuỗi.
   Đây là topology hai lớp Nginx cùng host. Ctrl+C chỉ dừng xem log.
5. **Demo security tùy thời gian, trên server:**

```bash
.venv/bin/python -m lab.demo --config runtime/arch/demo.json
tail -n 12 runtime/arch/audit.jsonl
```

   Demo gửi 25 request cố định đến loopback, tìm dấu hiệu SQLi/XSS/path traversal/flood.
   Kết quả loopback bị suppressed_protected_address là đúng thiết kế. Nói rõ:
   **analyzer đã phát hiện và ghi audit; chưa tự động chặn IP thật**.
   Firewall UFW allow/deny là lớp riêng. Không gọi đây là đã chống được DDoS thực tế.

Sơ đồ đang chạy:

```text
Desktop client (máy thành viên)
   -> IP server:8080 / Nginx edge
   -> 127.0.0.1:8082 / Nginx origin
   -> 127.0.0.1:8081 / Flask + SQLite
                         |
Nginx access.jsonl -> analyzer -> audit.jsonl (dry-run)
```

## D. Những lần chạy tiếp theo

Server, tại thư mục PBL4:

```bash
git pull --ff-only origin codex/demo-client-server
bash scripts/server.sh start
```

Nếu IP Wi-Fi thay đổi, chạy lại setup với IP mới và cập nhật rule firewall/client URL.
Sau reboot phải đăng nhập Linux. Giữ hai máy cùng mạng.

Client: pull cùng nhánh rồi mở run-client.cmd. Không cần tạo tài khoản lại.
Database nằm ở runtime/arch/shop.sqlite3 trên server; không xóa runtime khi chuẩn bị demo.

Dừng demo:

```bash
bash scripts/server.sh stop
```

Xem `sudo ufw status numbered` và xóa đúng rule PBL4 nếu không dùng nữa;
không reset toàn bộ firewall. Script stop không xóa database, không vô hiệu hóa autostart;
muốn không tự chạy ở lần đăng nhập sau:

```bash
systemctl --user disable pbl4-shop pbl4-nginx pbl4-security pbl4-logrotate.timer
```

## E. Khi gặp lỗi

| Hiện tượng | Làm gì |
|---|---|
| Client không kết nối | Server chạy status; kiểm tra IP, cùng mạng, đúng client IP trong UFW; Wi-Fi trường có thể chặn các máy nói chuyện |
| 127.0.0.1 chạy được nhưng máy kia không được | Client phải dùng IP LAN server; kiểm tra listen LAN và UFW, không tắt firewall để chữa |
| Server báo cannot assign requested address | IP đã đổi hoặc lấy nhầm IP; xem ip -br -4 address rồi chạy setup lại |
| Address already in use | Dừng lab.run cũ bằng Ctrl+C; dùng ss -ltnp xem cổng 8080/8081/8082 bị chiếm |
| Login 429 | Sai 5 lần sẽ khóa 15 phút; đợi Retry-After hoặc dùng tài khoản demo khác |
| Thiếu tkinter trên Windows | Sửa/cài Python có Tcl/Tk; chọn đúng Python từ python.org |
| Thiếu tkinter trên Linux client | Cài tk (Arch) hoặc python3-tk (Ubuntu) |
| Failed to connect to bus | Chạy server bằng user đăng nhập desktop Linux, không sudo bash |
| API 404 khi mở giỏ/đơn | Server chưa ở nhánh demo hoặc chưa restart sau pull |
| Server service failed | Chạy bash scripts/server.sh logs, giữ nguyên thông báo lỗi để nhờ hỗ trợ |
| Lỗi pip do .venv Windows | Tạo venv mới trên Linux; không dùng venv copy từ Windows |

## F. Kiểm thử và giới hạn

```bash
.venv/bin/python -m unittest discover -v
.venv/bin/python -m pip check
```

Windows dùng .venv\Scripts\python.exe nếu chạy bộ test server.
Test tạo database tạm, có luồng client qua HTTP/proxy thật, transaction/ownership,
đơn đồng thời và mất response rồi retry. Linux-only rotation được skip trên Windows.
Test giao diện được skip nếu không có Tk/display.

HTTP LAN chỉ dành cho dữ liệu demo giả. TLS và enforcement tự động là phần tiếp theo.
Chưa có bằng chứng kiểm thử hai máy thật cho lần thay đổi này: cần làm A/B một lần
trước khi trình bày. Không copy kết quả test local thành kết quả LAN.
