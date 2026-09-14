# PBL4 — Security core, giai đoạn 1

Module Python **3.12+**, chạy độc lập bằng access log Nginx JSONL, không cần AWS,
website đang chạy hay dependency bên ngoài. Môi trường phát triển hiện có Python
3.14.7; cú pháp được giữ tương thích 3.12. Chưa kiểm thử runtime 3.12 trên máy này.

**Cập nhật chặng local:** core đã được chạy lại trên Python 3.12.14. Website và proxy
local hiện có ở README gốc. `python -m security.scripts.watch --input LOG --audit AUDIT`
đọc log liên tục ở chế độ dry-run; có thể truyền `--config-dir` và `--policy` (JSON đầy
đủ các nhóm địa chỉ). Watcher chưa có checkpoint bền vững, restart replay từ đầu;
rotation cơ bản có thể mất dòng chưa đọc. Không dùng để enforcement production.

**Mọi response đều là dry-run hoặc preview. Không có code thực thi firewall,
không gọi AWS, không gửi request tấn công.** Sample dùng địa chỉ IP dành cho tài liệu.

## Chạy nhanh

Chạy từ thư mục gốc `D:\SEM5\PBL4` (trên Linux: thư mục chứa `security/`):

```powershell
python -m security.scripts.analyze --input security/tests/sample_logs/mixed.jsonl
python -m security.scripts.analyze --input security/tests/sample_logs/mixed.jsonl --adapter iptables
python -m security.scripts.analyze --input security/tests/sample_logs/mixed.jsonl --adapter ufw
python -m unittest discover -s security/tests -t . -v
```

Lưu audit nếu cần:

```powershell
python -m security.scripts.analyze --input security/tests/sample_logs/mixed.jsonl > security/logging/demo-audit.jsonl
```

CLI nhận `--input`, `--config-dir`, `--adapter dry-run|ufw|iptables|aws-waf`.
Không có cờ execute. Exit code 0 nghĩa là đã đọc xong stream, kể cả khi có dòng lỗi;
xem `summary.invalid_lines` để biết log bị bỏ qua. Exit code 2 cho lỗi input/config.
Đường dẫn input không nằm trong mã detector. Config mặc định được tìm tương đối theo
package, không theo thư mục log hay tài nguyên AWS.

## Kiến trúc và thư mục

```text
File JSONL (scripts/analyze.py, đọc từng dòng có giới hạn)
  → Parser protocol / NginxJsonParser
  → Event chuẩn hóa
  → SQLi + XSS + PathTraversal + RequestFlood
  → Detection[] → RiskScorer → Decision
  → ResponseAdapter → ResponseRecord
  → audit JSONL trên stdout
```

- `analyzer/models`: dataclass Event, Detection, Decision.
- `analyzer/parsers`: interface parser và parser Nginx JSON.
- `analyzer/detectors`: signature cho request target và sliding window theo IP.
- `analyzer/scoring`: tổng score từng loại dấu hiệu trên một request.
- `response`: chính sách địa chỉ, lease tạm thời, dry-run và command preview.
- `logging`: serialize audit; không serialize Event.
- `config`: luật, threshold và các nhóm IP/CIDR bảo vệ.
- `tests/unit`, `tests/integration`, `tests/sample_logs`: kiểm thử offline.

`Engine(settings, adapter=None, parser=None)` mặc định dùng DryRunAdapter;
`process(line, line_number)` trả về list audit record. Muốn thêm ALB/WAF/application
log: triển khai `Parser.parse()` trả Event hoặc ném `ParseError` với mã lỗi cố định,
không đưa nội dung input vào thông báo. Detector chỉ trả Detection, không gọi adapter.

## Cấu hình

Các file `.yaml` hiện dùng **cú pháp JSON, là tập con của YAML 1.2** để đọc bằng
thư viện chuẩn. Khi chỉnh sửa phải giữ cú pháp JSON (không comment, không trailing
comma). Đây là lựa chọn giảm dependency cho giai đoạn 1, chưa phải loader YAML tổng quát.
Config này là config mẫu không chứa secret; không cần `.env`.

| File | Ý nghĩa |
| --- | --- |
| `detection-rules.yaml` | enabled, score, regex mỗi loại; decode URL/HTML tối đa 2 lượt mặc định |
| `thresholds.yaml` | alert ≥40, temporary_block ≥80, block 300 giây; flood ≥20 request trong 10 giây |
| `allowlist.yaml` | allowlist, trusted_proxies, alb_networks, admin_networks là IP/CIDR |

Một detector signature chỉ cộng điểm một lần trên mỗi request. Nhiều detector có thể
cùng khớp: SQLi 50 + XSS 50 → score 100 → temporary_block. Một dấu hiệu SQLi → alert.
Không cộng điểm SQLi/XSS xuyên nhiều request trong giai đoạn này; chỉ flood giữ state.
Detection có action gợi ý; Decision sau scoring mới quyết định response.

Loopback luôn được bảo vệ, kể cả khi config bỏ loopback. Link-local, multicast,
unspecified, limited broadcast và IPv4-mapped loopback cũng không được block.
Thêm IP quản trị và subnet ALB thực tế trước khi tích hợp. `alb_networks` chỉ bảo vệ
khỏi block; muốn tin header từ ALB phải khai báo CIDR đó trong `trusted_proxies` nữa.
Không dùng `0.0.0.0/0` hay `::/0` làm trusted proxy. Config là dữ liệu quản trị đáng tin;
không cho người dùng website chỉnh regex (regex tùy ý có thể gây chậm xử lý).

## Contract log dành cho backend/Nginx

Mỗi dòng là một JSON object UTF-8, tối đa 65,536 byte; mỗi text field tối đa 8,192 ký tự.
Field quá dài làm dòng bị bỏ qua, không âm thầm cắt payload rồi phân tích thiếu.

| Field đầu vào | Yêu cầu / Event tương ứng |
| --- | --- |
| `time_iso8601` | Bắt buộc, ISO 8601 có timezone; chuyển UTC thành `timestamp` |
| `remote_addr` | Bắt buộc, IP peer TCP thật → `peer_ip`, mặc định cũng là `source_ip` |
| `request_method` | Bắt buộc, chữ ASCII in hoa → `method` |
| `request_uri` | Bắt buộc, origin-form bắt đầu `/`, còn URL encoding; tách `path`, `query_string` |
| `status` | Bắt buộc, integer hoặc chuỗi số 100–599 → `status_code` |
| `http_user_agent` | Tùy chọn chuỗi, mặc định rỗng → `user_agent` |
| `request_id` | Tùy chọn chuỗi → `request_id`; chỉ ở Event, không xuất audit |
| `http_x_forwarded_for` | Tùy chọn; chỉ dùng nếu peer thuộc trusted_proxies |

`log_source` do parser/caller gán (mặc định `nginx_json`), không lấy từ header client.
Giữ timestamp **không giảm** trên một Engine: giai đoạn 1 xử lý một stream tuần tự.
Log sai thứ tự sinh `rejected_event`, không cập nhật flood/lease. Khi ghép nhiều nguồn,
cần sort/reorder trước hoặc dùng Engine riêng. Dòng JSON lỗi, field lỗi, timezone thiếu,
encoding lỗi hay vượt giới hạn đều sinh audit lỗi rồi tiếp tục dòng kế tiếp.

Ví dụ format trong `http {}` của Nginx (chưa áp dụng tự động):

```nginx
log_format security_json escape=json
  '{"time_iso8601":"$time_iso8601",'
  '"remote_addr":"$remote_addr",'
  '"request_method":"$request_method",'
  '"request_uri":"$request_uri",'
  '"status":$status,'
  '"http_user_agent":"$http_user_agent",'
  '"request_id":"$request_id",'
  '"http_x_forwarded_for":"$http_x_forwarded_for"}';
# Chọn access_log path phù hợp với server, rồi truyền path đó vào --input.
```

Nếu Nginx realip module đã sửa `$remote_addr`, cần xuất địa chỉ peer gốc phù hợp
(thường `$realip_remote_addr`) vào field `remote_addr` của contract này. Không dùng
IP đã được header client thay thế làm peer xác thực.
Tham khảo [Nginx log_format](https://nginx.org/en/docs/http/ngx_http_log_module.html#log_format).

Không đưa password/token vào URL. Format trên không ghi body, Cookie hay Authorization,
nhưng URL nguồn có thể chứa dữ liệu nhạy cảm nếu backend cho phép. Nhóm backend phải
ngăn dữ liệu đó đi vào URL hoặc redact tại nguồn. Core không ghi lại request target,
headers, user agent hoặc request ID vào audit; regex chỉ xem path/query trong bộ nhớ.
POST body không nằm trong contract và **không được kiểm tra** bởi module hiện tại.

## Flood, lease và idempotence

Flood là HTTP request flood theo từng IP, không phải nhận diện DDoS tổng thể. Cửa sổ
`(t - window, t]`, đạt threshold là khớp. Bộ nhớ tối đa `max_sources` nguồn và
`request_threshold` timestamps mỗi nguồn. Xóa nguồn cũ hết cửa sổ; khi đầy nguồn thì
loại nguồn ít hoạt động gần đây và xuất `capacity_warning`. Việc loại bỏ có thể làm
đếm thiếu. NAT chung có thể gây false positive; tune threshold bằng traffic lab.

Lease dùng thời gian event để replay sample có kết quả ổn định. Engine gọi `expire()`
trước mỗi event hợp lệ. Đề xuất lặp lại cùng IP → `already_planned`, không tạo thêm
lệnh và không gia hạn. Hết hạn → `would_unblock`; request sau đó có thể tạo lease mới.
EOF không tự nhảy thời gian: xem `summary.active_preview_leases`; consumer gọi
`adapter.expire(now)` với clock phù hợp nếu cần mô phỏng hết hạn khi không có request.
Không trộn wall clock với timestamp lịch sử khi replay.

State nằm trong RAM, mất khi restart. Lease và idempotence chỉ áp dụng trong một process,
chưa kiểm tra luật hệ điều hành đang có. Trước khi thêm executor thật phải có durable
store, timer độc lập, reconciliation sau crash/restart, giới hạn lease, ownership luật
và kiểm tra rule hiện hữu. Bản hiện tại không có scheduler hay daemon production.

## Contract response và AWS

Detection gồm `attack_type`, `score`, `source_ip`, `evidence` (mã signature),
`detector_name`, `recommended_action`, `block_duration_seconds`, `timestamp`.
Decision chứa score tổng, action, duration, timestamp, reasons và proxy metadata.
Response có outcome, expiry, command argv nếu có và **`executed: false`**.
Audit có các kind `detection`, `decision`, `response`, `parse_error`, `rejected_event`,
`capacity_warning`, `summary`. JSON escaping ngăn control character tạo dòng audit giả.

| Topology | Cách phản ứng phù hợp |
| --- | --- |
| Client → EC2 trực tiếp | Có thể preview UFW/iptables chặn source IP ở host |
| Client → ALB → EC2 | Dùng IP client đã xác thực cho scoring/WAF; firewall host thường chỉ thấy ALB |

Không tin XFF từ peer ngoài trusted proxy. Với peer tin cậy, parser duyệt chuỗi XFF
từ phải sang trái, bỏ qua proxy tin cậy, lấy hop đầu tiên không tin cậy. Header lỗi
ở peer tin cậy làm reject dòng. Chỉ hỗ trợ IP trần; XFF dạng IP:port hoặc `[IPv6]:port`
bị reject, nên nhóm AWS phải tắt preserve client port hoặc bổ sung parser có test.
Giới hạn mạng backend để chỉ ALB hợp lệ truy cập, đặt XFF ở chế độ **append**, không
dùng preserve làm cơ sở xác thực IP. Theo [tài liệu AWS ALB về XFF](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/x-forwarded-headers.html),
ALB hỗ trợ append/preserve/remove và tùy chọn client port.

UFW/iptables adapter trả `unsupported_proxy_topology_use_waf` cho request qua trusted
proxy. Không block địa chỉ ALB/proxy trong policy. Preview UFW dùng insert đầu luật;
iptables dùng INPUT position 1 và phân biệt IPv4/IPv6. Các argv chỉ để review, không
phải script triển khai: cần kiểm tra chain, traffic Docker/FORWARD, thứ tự rule và quản
lý connection khi thiết kế firewall Linux thực tế. Không copy command vào production.

`AwsWafAdapter` trả `not_implemented`, không giả lập thành công. Giai đoạn sau:

1. Nhóm AWS thống nhất region, WebACL scope, hai IP sets IPv4/IPv6, rule priority,
   managed rules và rate-based rules; cấu hình truyền vào adapter, không hard-code.
2. WAF adapter nhận cùng Decision; kiểm tra policy bảo vệ trước update IP set.
3. IAM tối thiểu; optimistic lock/token, retry có giới hạn; persistent lease và TTL worker
   gỡ IP hết hạn; reconcile nhiều worker/restart, audit success/failure thật.
4. Phối hợp ALB, AWS WAF, AWS Shield và rate limit Nginx/application cho tải lớn.

## Giới hạn và trách nhiệm backend

Regex/signature là heuristic cho lab, không phải biện pháp phòng chống tuyệt đối.
SQLi/XSS/path traversal có nhiều biến thể chưa bao phủ; encoding hơn số lượt cấu hình,
POST body, headers, context HTML/SQL cụ thể và traffic không được log có thể bị bỏ sót.
Nội dung hướng dẫn lập trình trong query cũng có thể khớp nhầm. Audit ghi *dấu hiệu*
chứ không chứng minh khai thác thành công. Phản ứng sau access log có độ trễ và không
ngăn được request đầu tiên. Flood phân tán, bot chậm và nghẽn băng thông cần lớp khác.

Backend vẫn phải dùng parameterized queries, output encoding/sanitization/CSP,
chuẩn hóa đường dẫn và allowlist truy cập file. Nhóm AWS cung cấp topology, subnet
proxy/ALB, IP quản trị, chế độ XFF, đường dẫn log và quyền đọc tối thiểu. Cần xác nhận
sample log đúng contract trước ghép hệ thống. Không cần framework website cụ thể.

## Kiểm thử

Unit/integration test bao gồm request lành tính và độc hại, SQLi/XSS, traversal double
encoding, flood boundary/isolation/capacity, scoring nhiều dấu hiệu, parser malformed,
XFF giả mạo, IP injection, allowlist/proxy/admin/IPv6, idempotence/expiry, audit redaction,
CLI recovery và kiểm tra adapter không gọi subprocess/os.system.

Sample `benign.jsonl`, `malicious.jsonl`, `flood.jsonl`, `mixed.jsonl` chỉ là dữ liệu,
không thực thi payload. Workspace ban đầu trống, chưa có lint/type-check configuration;
test dùng `unittest` thư viện chuẩn. Khi có CI, thêm matrix Python 3.12+ và kiểm thử
Nginx thật trong lab trước chuyển sang giai đoạn enforcement.
