# Feature Specification: XDP Firewall chống DDoS & so sánh hiệu năng với iptables/nftables

**Feature Branch**: `001-xdp-firewall`

**Created**: 2026-11-24

**Status**: Draft

**Input**: User description: "XDP firewall chống DDoS với đếm gói và so sánh hiệu năng với iptables/nftables. Người vận hành nạp chương trình XDP lên interface ngoài của fw-node (chế độ generic hoặc native), chặn IP/subnet nguồn (CIDR) và chặn port đích theo giao thức TCP/UDP, thêm/xóa rule lúc đang chạy không gián đoạn, xem thống kê pass/drop theo action và theo rule qua CLI và qua dashboard Grafana (exporter Prometheus). Lab docker-compose gồm client, attacker, fw-node (router+firewall), server (nginx + iperf3), prometheus, grafana; dựng bằng make up từ repo sạch. Benchmark: so sánh XDP native, XDP generic, iptables-legacy, iptables-nft (raw PREROUTING và filter FORWARD), nftables set, baseline: (1) CPU tiêu thụ khi drop ở tải flood cố định, (2) mở rộng theo số rule 10/100/1000/10000, (3) ảnh hưởng tới latency/throughput traffic hợp lệ khi bị flood; mỗi điểm ≥3 lần, xuất CSV và biểu đồ. Kịch bản demo ≤10 phút. Ngoài phạm vi: rate limit, LB L4, IPv6, lọc có trạng thái. Chỉ IPv4 ingress. Hạn 2026-11-27."

## User Scenarios & Testing *(mandatory)*

**Tác nhân:**
- **Người vận hành** — người quản trị firewall (sinh viên khi demo): nạp/gỡ firewall, quản lý rule, xem thống kê.
- **Người đánh giá** — giảng viên/người chấm: dựng lại lab từ repo, xem demo, đọc kết quả benchmark.
- **Client hợp lệ** và **Attacker** — các node mô phỏng trong lab.

### User Story 1 - Chặn traffic tấn công ngay tại điểm nhận gói (Priority: P1)

Người vận hành dựng lab, nạp firewall lên interface hướng ra mạng ngoài của nút firewall, rồi
thêm rule chặn địa chỉ nguồn của attacker (một IP hoặc cả subnet) và/hoặc chặn một port đích
theo giao thức. Traffic từ attacker bị loại bỏ ngay khi tới nút firewall, trong khi client hợp
lệ vẫn truy cập server bình thường. Rule có thể thêm/xóa khi firewall đang chạy mà không làm
gián đoạn traffic hợp lệ.

**Why this priority**: Đây là chức năng cốt lõi của đề tài "data plane lập trình được"; không có
nó thì không có gì để quan sát, đo hay demo.

**Independent Test**: Dựng lab, nạp firewall, chặn IP attacker; kiểm tra attacker không còn tới
được server còn client vẫn tải được trang web và ping được server.

**Acceptance Scenarios**:

1. **Given** lab đang chạy và firewall đã nạp nhưng chưa có rule, **When** client và attacker cùng
   gửi traffic tới server, **Then** cả hai đều tới được server.
2. **Given** firewall đã nạp, **When** người vận hành chặn IP của attacker (/32), **Then** mọi gói
   từ attacker bị loại bỏ tại nút firewall và client vẫn truy cập server bình thường.
3. **Given** firewall đã nạp, **When** người vận hành chặn subnet chứa attacker nhưng không chứa
   client, **Then** mọi IP trong subnet bị chặn, client không bị ảnh hưởng.
4. **Given** firewall đã nạp, **When** người vận hành chặn port UDP đích 9999, **Then** gói UDP tới
   port 9999 bị loại bỏ, còn TCP tới port 9999 và UDP tới port khác vẫn đi qua.
5. **Given** đang có rule chặn attacker, **When** người vận hành xóa rule đó lúc firewall đang chạy,
   **Then** attacker tới được server trở lại trong vòng 1 giây, không cần nạp lại firewall, và
   client không mất kết nối trong suốt quá trình.
6. **Given** firewall có thể gắn theo hai chế độ (generic và native), **When** người vận hành chọn
   một chế độ khi nạp, **Then** firewall chạy ở đúng chế độ đã chọn và người vận hành xác nhận
   được chế độ đang chạy.

---

### User Story 2 - Quan sát thống kê pass/drop theo thời gian thực (Priority: P2)

Người vận hành xem được số gói/byte được cho qua và bị loại bỏ — theo từng loại hành động và
theo từng rule — qua dòng lệnh và qua một dashboard đồ thị cập nhật liên tục. Khi bị flood,
dashboard cho thấy rõ lượng gói bị chặn tăng vọt.

**Why this priority**: Làm cho tác dụng của firewall nhìn thấy được — cần cho demo và cho việc
kiểm chứng benchmark; nhưng firewall vẫn có giá trị dù chưa có phần quan sát.

**Independent Test**: Gửi một số lượng gói đã biết từ attacker khi đang có rule chặn; kiểm tra bộ
đếm drop tăng đúng bằng số gói đã gửi, cả trên dòng lệnh và dashboard.

**Acceptance Scenarios**:

1. **Given** firewall đang chặn attacker, **When** attacker gửi đúng 1.000 gói, **Then** bộ đếm drop
   theo rule chặn IP tăng đúng 1.000 và bộ đếm pass không tính các gói này.
2. **Given** firewall đang chạy, **When** người vận hành yêu cầu liệt kê rule, **Then** hiện đủ mọi
   rule đang hiệu lực kèm số lần mỗi rule bị khớp.
3. **Given** lab đang chạy, **When** người vận hành mở dashboard, **Then** thấy đồ thị gói/giây
   được cho qua và bị loại bỏ, cập nhật với độ trễ không quá 5 giây, không cần cấu hình tay.

---

### User Story 3 - So sánh hiệu năng với giải pháp truyền thống (Priority: P3)

Người vận hành chạy bộ benchmark tự động so sánh firewall này với các giải pháp lọc gói truyền
thống của Linux trong cùng điều kiện, và nhận được bảng số liệu thô cùng biểu đồ để đưa vào báo cáo.

Các cấu hình được so sánh: firewall chế độ native, firewall chế độ generic, iptables-legacy và
iptables-nft (mỗi loại ở hai vị trí: bảng raw PREROUTING và bảng filter FORWARD), nftables dùng
set, và baseline không lọc.

Ba phép đo:
1. **Chi phí loại bỏ gói:** CPU tiêu thụ trên nút firewall khi loại bỏ một luồng flood có tốc độ cố định.
2. **Khả năng mở rộng theo số rule:** CPU tiêu thụ khi bảng rule có 10 / 100 / 1.000 / 10.000 rule,
   với rule khớp attacker nằm cuối danh sách.
3. **Ảnh hưởng tới traffic hợp lệ:** độ trễ và thông lượng của client khi đang có flood.

**Why this priority**: Đây là yêu cầu "so sánh với giải pháp truyền thống" của đề bài và là nội
dung chính của chương thực nghiệm; phụ thuộc vào US1 đã hoạt động.

**Independent Test**: Chạy bộ benchmark ở chế độ rút gọn (1 lần/điểm) và kiểm tra sinh ra đủ file
số liệu cho mọi cấu hình và biểu đồ tương ứng.

**Acceptance Scenarios**:

1. **Given** lab đang chạy, **When** người vận hành chạy bộ benchmark đầy đủ, **Then** mỗi tổ hợp
   (cấu hình × phép đo × mức số rule) được đo ít nhất 3 lần và kết quả ghi ra file số liệu thô.
2. **Given** đã có file số liệu thô, **When** người vận hành chạy lệnh vẽ biểu đồ, **Then** sinh ra
   biểu đồ cho cả 3 phép đo với trung bình và độ lệch chuẩn.
3. **Given** một lần đo vừa kết thúc, **When** lần đo kế tiếp bắt đầu, **Then** không còn rule hay
   chương trình lọc nào từ lần trước còn hiệu lực.
4. **Given** bộ benchmark chạy xong, **When** người đánh giá xem kết quả, **Then** có kèm thông tin
   môi trường đo (kernel, phiên bản công cụ, CPU, ghim CPU, tốc độ tải).

---

### User Story 4 - Dựng lại lab và trình diễn từ repo sạch (Priority: P4)

Người đánh giá (hoặc chính người vận hành trên máy khác) tải repo về, chạy một lệnh duy nhất để
dựng toàn bộ lab, rồi làm theo kịch bản demo viết sẵn để thấy toàn bộ câu chuyện: bình thường →
bị flood → bật firewall → hồi phục → so sánh với iptables, trong không quá 10 phút.

**Why this priority**: Đáp ứng yêu cầu "script cài đặt lặp lại được trên Git" và "video demo
≤ 10 phút"; gom kết quả của US1–US3 thành sản phẩm nộp.

**Independent Test**: Clone repo vào thư mục mới, chạy lệnh dựng lab, làm theo kịch bản demo
từ đầu đến cuối và bấm giờ.

**Acceptance Scenarios**:

1. **Given** một máy Linux/WSL2 có Docker và repo vừa clone, **When** chạy lệnh dựng lab, **Then**
   đủ 6 thành phần (client, attacker, fw-node, server, prometheus, grafana) chạy và dashboard có
   sẵn dữ liệu mà không cần thao tác tay.
2. **Given** lab đang chạy, **When** chạy lệnh dỡ lab, **Then** mọi container, mạng và chương trình
   lọc đã gắn đều bị gỡ sạch.
3. **Given** kịch bản demo viết sẵn, **When** người vận hành làm theo từng bước, **Then** toàn bộ
   kịch bản hoàn thành trong ≤ 10 phút và mỗi bước cho kết quả như kịch bản mô tả.

---

### Edge Cases

- Gói không phải IPv4 (ARP, IPv6) hoặc gói bị cắt cụt/hỏng header → phải được cho qua, không làm
  firewall lỗi; gói hỏng được đếm riêng.
- Gói IPv4 không phải TCP/UDP (ví dụ ICMP) → chỉ áp dụng rule chặn IP, không áp dụng rule chặn port.
- Gói IPv4 có phần options (header dài hơn 20 byte) → vẫn xác định đúng port đích.
- Hai rule CIDR lồng nhau (ví dụ /24 và /32 trong nó) → gói bị chặn nếu khớp bất kỳ rule nào; số
  lần khớp được tính cho rule có prefix dài nhất.
- Thêm rule đã tồn tại → báo trùng, không tạo bản ghi thứ hai; xóa rule không tồn tại → báo lỗi rõ
  ràng, mã thoát khác 0.
- CIDR không hợp lệ (ví dụ `10.0.0.300/24`, `/33`) hoặc port ngoài 1–65535 → từ chối với thông báo lỗi.
- Bảng rule đầy (vượt quá dung lượng tối đa) → từ chối thêm với thông báo lỗi, rule cũ vẫn hoạt động.
- Nạp firewall chế độ native trên interface không hỗ trợ → báo lỗi rõ ràng, gợi ý dùng chế độ generic.
- Nạp firewall khi interface đã có chương trình khác gắn sẵn → báo lỗi, không ghi đè ngầm.
- Gỡ firewall → interface trở lại chuyển gói bình thường ngay lập tức.

## Requirements *(mandatory)*

### Functional Requirements

**Lọc gói (data plane)**

- **FR-001**: Hệ thống PHẢI kiểm tra mọi gói IPv4 đi vào interface ngoài của nút firewall và quyết
  định cho qua hoặc loại bỏ trước khi gói đi vào ngăn xếp mạng thông thường.
- **FR-002**: Hệ thống PHẢI loại bỏ gói có địa chỉ nguồn khớp bất kỳ rule chặn IP/subnet nào
  (độ dài prefix 0–32).
- **FR-003**: Hệ thống PHẢI loại bỏ gói TCP/UDP có (giao thức, port đích) khớp bất kỳ rule chặn port nào.
- **FR-004**: Hệ thống PHẢI cho qua mọi gói không khớp rule nào, mọi gói không phải IPv4, và mọi gói
  không phân tích được header.
- **FR-005**: Hệ thống PHẢI hỗ trợ tối thiểu 10.000 rule chặn IP/subnet và 1.000 rule chặn port cùng lúc.

**Điều khiển (control plane)**

- **FR-006**: Người vận hành PHẢI nạp được firewall lên một interface chỉ định, chọn chế độ generic
  hoặc native, và gỡ được firewall khỏi interface.
- **FR-007**: Người vận hành PHẢI thêm/xóa được rule chặn IP/subnet và rule chặn port (theo giao thức
  TCP hoặc UDP) khi firewall đang chạy; rule mới PHẢI có hiệu lực trong vòng 1 giây mà không cần nạp
  lại firewall.
- **FR-008**: Người vận hành PHẢI liệt kê được toàn bộ rule đang hiệu lực.
- **FR-009**: Hệ thống PHẢI kiểm tra đầu vào (CIDR, giao thức, port) và từ chối giá trị không hợp lệ
  với thông báo lỗi rõ ràng và mã thoát khác 0.

**Quan sát**

- **FR-010**: Hệ thống PHẢI đếm số gói và số byte theo từng loại kết quả: cho qua, loại bỏ do rule IP,
  loại bỏ do rule port, gói không phân tích được.
- **FR-011**: Hệ thống PHẢI đếm số gói và số byte bị khớp theo từng rule.
- **FR-012**: Người vận hành PHẢI xem được các bộ đếm qua dòng lệnh.
- **FR-013**: Hệ thống PHẢI công bố các bộ đếm theo định dạng mà hệ thống giám sát thu thập được, và
  lab PHẢI có sẵn một dashboard hiển thị tốc độ gói cho qua/bị loại bỏ theo thời gian.

**Lab & tái lập**

- **FR-014**: Lab PHẢI gồm 6 thành phần: client, attacker, fw-node (định tuyến + lọc), server (dịch vụ
  web + điểm đo thông lượng), hệ thống thu thập số liệu, dashboard.
- **FR-015**: Lab PHẢI dựng được bằng một lệnh từ repo sạch và dỡ sạch được bằng một lệnh.
- **FR-016**: Traffic từ client và attacker tới server PHẢI đi qua fw-node.
- **FR-017**: Lab PHẢI tách tài nguyên CPU giữa nhóm sinh tải (client, attacker) và fw-node.
- **FR-018**: Mọi traffic tấn công PHẢI nằm trong mạng cô lập của lab, không ra ngoài máy chủ.

**Benchmark**

- **FR-019**: Bộ benchmark PHẢI so sánh 8 cấu hình: firewall native, firewall generic, iptables-legacy
  raw, iptables-legacy filter, iptables-nft raw, iptables-nft filter, nftables set, baseline.
- **FR-020**: Bộ benchmark PHẢI thực hiện 3 phép đo mô tả trong US3, với tải flood ở tốc độ cố định
  và cấu hình được.
- **FR-021**: Mỗi điểm đo PHẢI được lặp lại ≥ 3 lần; kết quả thô ghi ra file dạng bảng (mỗi dòng một lần đo).
- **FR-022**: Bộ benchmark PHẢI dọn sạch toàn bộ rule/chương trình lọc giữa các lần đo.
- **FR-023**: Hệ thống PHẢI sinh biểu đồ từ file kết quả thô bằng một lệnh, và ghi kèm thông tin môi
  trường đo.

**Demo & tài liệu**

- **FR-024**: Repo PHẢI có kịch bản demo từng bước, thực hiện được trong ≤ 10 phút.
- **FR-025**: Repo PHẢI có hướng dẫn cài đặt, dựng lab, chạy demo và chạy benchmark.

### Key Entities

- **Rule chặn IP**: một dải địa chỉ nguồn IPv4 (địa chỉ + độ dài prefix), mã rule, bộ đếm số lần khớp.
- **Rule chặn port**: một cặp (giao thức TCP/UDP, port đích), mã rule, bộ đếm số lần khớp.
- **Bộ đếm theo kết quả**: số gói và byte cho mỗi loại kết quả (pass, drop do IP, drop do port, lỗi phân tích).
- **Phiên gắn firewall**: interface, chế độ (generic/native), thời điểm gắn.
- **Cấu hình benchmark**: một trong 8 cấu hình ở FR-019.
- **Lần đo**: cấu hình, phép đo, số rule, tốc độ tải, số thứ tự lần lặp, các giá trị đo được
  (CPU %, gói bị loại bỏ/giây, độ trễ, thông lượng), thời điểm đo.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Khi có rule chặn attacker, 100% gói từ attacker bị loại bỏ và 0 gói từ client bị loại
  bỏ nhầm trong một lần thử 1.000 gói mỗi bên.
- **SC-002**: Thêm hoặc xóa một rule có hiệu lực trong ≤ 1 giây, và client không mất gói nào (ping
  liên tục 0% loss) trong lúc thay đổi rule.
- **SC-003**: Bộ đếm drop khớp chính xác (sai lệch 0) với số gói attacker đã gửi trong phép thử có
  số gói xác định.
- **SC-004**: Dashboard phản ánh thay đổi lưu lượng trong ≤ 5 giây.
- **SC-005**: Từ repo sạch, lab dựng xong và dashboard có dữ liệu trong ≤ 5 phút (không tính thời gian
  tải image lần đầu), không cần bước thao tác tay nào.
- **SC-006**: Bộ benchmark đầy đủ tạo ra số liệu cho 100% tổ hợp (8 cấu hình × 3 phép đo × các mức
  số rule) với ≥ 3 lần đo mỗi điểm, và hoàn thành trong ≤ 2 giờ.
- **SC-007**: Ở cùng tải flood, firewall chế độ native tiêu thụ CPU thấp hơn iptables-legacy filter
  FORWARD một cách có thể đo được (khác biệt lớn hơn độ lệch chuẩn của cả hai). Nếu kết quả thực tế
  không như kỳ vọng, kết quả PHẢI được báo cáo trung thực kèm phân tích nguyên nhân.
- **SC-008**: Ở phép đo mở rộng, CPU của firewall gần như không đổi (thay đổi ≤ 20%) khi số rule tăng
  từ 10 lên 10.000.
- **SC-009**: Kịch bản demo hoàn thành trong ≤ 10 phút từ lab đã dựng.

## Assumptions

- Môi trường chạy là WSL2 Ubuntu 24.04 (kernel 6.18, có BTF) trên một laptop 4 nhân/8 luồng; máy
  sinh tải và nút firewall dùng chung phần cứng, nên số liệu là **so sánh tương đối** giữa các cấu
  hình, không phải hiệu năng đường truyền thật.
- Các interface trong lab là cặp interface ảo; chế độ native được hỗ trợ trên loại interface này
  (đã kiểm chứng bằng smoke test ngày 2026-11-23).
- Firewall chỉ xử lý chiều vào (ingress), chỉ IPv4; IPv6, chiều ra, lọc có trạng thái, giới hạn tốc
  độ và cân bằng tải nằm ngoài phạm vi.
- Rule chặn port áp dụng cho port **đích**; không có rule chặn theo port nguồn.
- Rule không được lưu bền: khi gỡ firewall hoặc dỡ lab, rule bị xóa. Kịch bản demo và benchmark tự
  thêm rule cần thiết.
- Chỉ có một người vận hành; không cần xác thực/phân quyền cho các lệnh điều khiển (chạy với quyền
  quản trị trong lab).
- Tốc độ tải flood cố định được chọn sau một lần đo thử, ở mức baseline chưa làm bão hòa CPU của
  nút firewall.
- Dashboard và hệ thống thu thập số liệu chỉ mở trên localhost.
- Hạn hoàn thành 2026-11-27; theo constitution, MVP (US1–US2 và lab) được ưu tiên trước benchmark và demo.
