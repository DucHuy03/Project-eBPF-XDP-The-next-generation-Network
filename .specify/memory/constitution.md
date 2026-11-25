<!--
Sync Impact Report
- Version: 1.0.0 -> 1.0.1 (PATCH: chỉnh câu chữ, không đổi tinh thần nguyên tắc)
- Nguyên tắc sửa: I. "Data Plane trong kernel" — CO-RE/vmlinux.h chỉ bắt buộc khi truy cập
  struct nội bộ của kernel; chương trình chỉ đọc header gói dùng header UAPI.
- Lý do: specs/001-xdp-firewall/plan.md (Complexity Tracking), research.md R1.
- Người duyệt: sinh viên, 2026-11-25.
- Template cần cập nhật: không.
-->
# XDP Firewall Project Constitution

## Core Principles

### I. Data Plane trong kernel: C + libbpf, thân thiện verifier

- Chương trình XDP PHẢI viết bằng C, biên dịch bằng clang (`-target bpf`), dùng libbpf.
- Khi truy cập struct nội bộ của kernel PHẢI dùng CO-RE (`vmlinux.h` sinh từ BTF của kernel);
  chương trình chỉ đọc header gói (định dạng theo RFC) dùng header UAPI (`linux/*.h`).
- Mọi truy cập vào dữ liệu gói PHẢI kiểm tra biên với `data_end` trước khi đọc.
- KHÔNG dùng vòng lặp không giới hạn; mọi vòng lặp (nếu có) PHẢI có cận trên cố định.
- Gói không thuộc phạm vi xử lý (không phải IPv4, ARP, IPv6, gói hỏng) PHẢI trả về
  `XDP_PASS` — firewall không được làm hỏng traffic ngoài phạm vi.
- Bộ đếm PHẢI dùng map per-CPU để không có tranh chấp giữa các CPU.

**Lý do:** verifier từ chối chương trình không an toàn; code đơn giản, kiểm tra biên rõ ràng
vừa qua verifier dễ dàng vừa dễ giải thích khi bảo vệ.

### II. Control Plane: Go + cilium/ebpf, một binary duy nhất

- Phần user space PHẢI là một binary Go duy nhất (`xdpfw`) dùng `cilium/ebpf` (bpf2go),
  cung cấp: nạp/gỡ XDP (generic/native), quản lý rule, in thống kê, exporter Prometheus.
- Rule PHẢI thay đổi được lúc đang chạy bằng cách ghi vào BPF map — KHÔNG nạp lại chương trình.
- Lỗi PHẢI in ra stderr với thông báo rõ ràng và mã thoát khác 0.

**Lý do:** một binary dễ đóng gói vào container, dễ demo, ít thành phần cần giải thích.

### III. Lab tái lập được

- Toàn bộ lab PHẢI dựng được bằng `make up` từ một bản clone sạch trên Linux/WSL2 có Docker.
- Topology, cấu hình Prometheus/Grafana (datasource + dashboard) PHẢI được provision bằng
  file trong repo — KHÔNG cấu hình tay qua giao diện.
- Mọi phiên bản công cụ/image PHẢI được ghim cụ thể (không dùng tag `latest`).
- `make down` PHẢI dọn sạch container, mạng và chương trình XDP đã gắn.

**Lý do:** đề bài yêu cầu "script cài đặt lặp lại được lưu trên Git"; demo trên lớp không
được phụ thuộc vào trạng thái máy cá nhân.

### IV. Benchmark công bằng & tái lập được

- Mọi cấu hình so sánh (XDP native, XDP generic, iptables-legacy, iptables-nft, nftables set,
  baseline) PHẢI chạy trên cùng topology, cùng tải, cùng ghim CPU.
- Phép đo PHẢI dùng **tải cố định** và so sánh **CPU tiêu thụ** (vì máy sinh tải và máy bị
  đo dùng chung phần cứng), kèm số gói thực sự bị drop.
- Mỗi điểm đo PHẢI chạy ≥ 3 lần; báo cáo trung bình ± độ lệch chuẩn.
- Trạng thái PHẢI được dọn sạch giữa các lần chạy (rule iptables/nft, chương trình XDP).
- Số liệu thô (CSV) và script vẽ biểu đồ PHẢI được commit; biểu đồ PHẢI sinh lại được
  bằng `make plot`.
- Môi trường đo (kernel, phiên bản công cụ, CPU, cấu hình WSL) PHẢI được ghi lại cùng kết quả.

**Lý do:** so sánh với iptables là phần cốt lõi của đề tài; số liệu thiếu công bằng hoặc
không tái lập được sẽ làm mất giá trị toàn bộ báo cáo.

### V. Dễ giải thích & liêm chính học thuật (NON-NEGOTIABLE)

- Code PHẢI ngắn gọn, có comment giải thích *tại sao* ở các điểm không hiển nhiên
  (kiểm tra biên, lựa chọn kiểu map, thứ tự byte).
- Sinh viên PHẢI đọc hiểu và tự giải thích được mọi file trước khi đánh dấu một hạng mục là
  xong; Claude PHẢI giải thích khi được hỏi.
- Báo cáo PHẢI do sinh viên tự viết. AI KHÔNG viết nội dung văn bản báo cáo; AI chỉ được
  giải thích kiến thức, trả lời câu hỏi, cung cấp số liệu và hình từ thực nghiệm.
- Mọi kết quả báo cáo PHẢI trung thực: không chỉnh sửa số liệu, ghi rõ khi một phép đo
  thất bại hoặc chỉ thành công một phần.

**Lý do:** đề bài cấm dùng AI để sinh báo cáo và yêu cầu "hiểu kỹ source code".

### VI. Đơn giản & kỷ luật phạm vi

- Hạn nộp cố định: **2026-11-27**. MVP (chặn IP/CIDR, chặn port/giao thức, bộ đếm, CLI,
  exporter, lab, benchmark) PHẢI hoàn thành trước mọi tính năng mở rộng.
- Tính năng mở rộng (rate limit, load balancer L4, IPv6, VM Hyper-V) CHỈ được bắt đầu khi
  toàn bộ MVP đã chạy và đã được kiểm chứng.
- Không thêm thư viện, dịch vụ hay lớp trừu tượng nào không phục vụ trực tiếp cho demo
  hoặc benchmark (YAGNI).

**Lý do:** làm một mình trong 4 ngày; một MVP hoàn chỉnh có giá trị hơn nhiều tính năng dở dang.

## Ràng buộc kỹ thuật & an toàn lab

- **Nền tảng:** WSL2 Ubuntu 24.04, kernel 6.18 (BTF bật), Docker Engine + Compose plugin.
- **Công cụ:** clang 18, Go 1.22, libbpf 1.3, bpftool 7.5, iptables 1.8.10 (legacy & nft),
  nftables 1.0.9, trafgen/hping3/iperf3/mpstat, Python 3 (pandas, matplotlib).
- **Phạm vi giao thức:** IPv4 với TCP/UDP/ICMP; chỉ xử lý chiều vào (ingress).
- **An toàn:** mọi kịch bản tấn công (flood) PHẢI chạy trong mạng container cô lập của lab;
  KHÔNG gửi traffic tấn công ra ngoài máy, ra mạng LAN hay Internet.
- **Quyền:** container fw-node chạy privileged chỉ vì cần nạp BPF; không mở cổng nào của lab
  ra ngoài localhost ngoại trừ Grafana/Prometheus để xem dashboard.

## Quy trình phát triển & cổng chất lượng

- Luồng làm việc: Spec Kit (constitution → specify → plan → tasks → implement) → build →
  kiểm thử chức năng → benchmark → demo/báo cáo.
- Tiến độ theo dõi trong `CHECKLIST.md`. Một mục chỉ được đánh dấu xong khi có **bằng chứng**
  (lệnh đã chạy + kết quả); mục thành công một phần PHẢI ghi rõ.
- Cổng chất lượng trước khi coi một tính năng là xong:
  1. Chương trình BPF biên dịch không warning và qua verifier.
  2. `make test` xác nhận chặn đúng và không chặn nhầm traffic hợp lệ.
  3. Sinh viên đã đọc và tự giải thích được phần code liên quan.
- Commit nhỏ, thông điệp rõ ràng; không commit file build, file bí mật hay tài liệu môn học (PDF).

## Governance

- Constitution này có hiệu lực cao hơn mọi quy ước khác trong repo; spec, plan và tasks
  PHẢI tuân thủ và phải nêu rõ nếu có vi phạm cần chấp nhận (kèm lý do).
- Sửa đổi: do sinh viên quyết định, ghi lại trong Sync Impact Report và tăng version:
  MAJOR khi bỏ/định nghĩa lại nguyên tắc, MINOR khi thêm nguyên tắc/mục, PATCH khi chỉnh câu chữ.
- Rà soát tuân thủ: chạy `/speckit-analyze` sau khi sinh tasks và trước khi implement;
  kiểm tra lại nguyên tắc IV và V trước khi nộp bài.
- Hướng dẫn thực thi chi tiết nằm trong `PROJECT_OVERVIEW.md` và `CHECKLIST.md`.

**Version**: 1.0.1 | **Ratified**: 2026-11-23 | **Last Amended**: 2026-11-25
