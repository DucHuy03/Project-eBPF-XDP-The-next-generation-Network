# Checklist làm việc — Project giữa kỳ eBPF/XDP

**Đề tài:** #2 Data plane lập trình được — XDP Firewall chống DDoS + đếm gói, so sánh với iptables/nftables
**Hạn nộp:** Thứ Sáu 27/11/2026 — toàn bộ (code + báo cáo + video + slide)
**Môi trường:** WSL2 Ubuntu 24.04 (kernel 6.18) + Docker Engine + docker-compose
**Nhân lực:** 1 người + Claude (AI hỗ trợ code/lab/benchmark)

> Ký hiệu: **[🤖]** = Claude làm, bạn review & kiểm chứng · **[👤]** = bạn tự làm (bắt buộc, AI không được làm thay) · **[🤝]** = làm cùng nhau
> Đánh dấu `[x]` khi xong, commit file này lên Git để theo dõi.

---

## Ngày 0 — Thứ Hai 23/11: Chuẩn bị môi trường & kế hoạch

### Môi trường
- [x] [🤖] Tạo `.wslconfig` (`memory=8GB`, `processors=8`) rồi `wsl --shutdown`
- [x] [🤖] Cài Docker Engine trong WSL (không dùng Docker Desktop), kiểm tra `docker run hello-world`
- [x] [🤖] Cài toolchain: `clang llvm libbpf-dev linux-tools-common bpftool golang make`
- [x] [🤖] Cài công cụ mạng/đo: `iptables nftables iperf3 hping3 netsniff-ng (trafgen) sysstat (mpstat)`
- [x] [🤖] Smoke test: tạo cặp veth, nạp XDP `XDP_DROP` tối giản, xác nhận bằng `bpftool prog show` / `ip link`
- [x] [🤖] Thử cả 2 chế độ gắn: `xdpgeneric` và `xdpdrv` (native) trên veth

### Git & Spec Kit
- [x] [🤖] Tạo commit đầu tiên, đổi branch về `main`
- [ ] [👤] Tạo repo remote (GitHub/GitLab) và cho Claude biết URL
- [x] [🤝] `/speckit-constitution` — nguyên tắc dự án (bản gọn)
- [x] [🤝] `/speckit-specify` — spec tính năng XDP firewall
- [x] [🤖] `/speckit-plan` → `/speckit-tasks`

### Báo cáo (tự viết — không dùng AI để sinh văn bản)
- [ ] [👤] Chốt dàn ý báo cáo (xem cuối file)
- [ ] [👤] Viết chương 1: Giới thiệu, bối cảnh SDN/programmable data plane
- [ ] [👤] Viết chương 2: Kiến trúc eBPF (verifier, JIT, map, hook) và XDP (vị trí hook, các action)

---

## Ngày 1 — Thứ Ba 24/11: Code chính

### Chương trình XDP (C + libbpf) — [🤖]
- [x] Parse Ethernet → IPv4 → TCP/UDP/ICMP (có kiểm tra biên để qua verifier)
- [x] Map `LPM_TRIE`: chặn IP/subnet nguồn
- [x] Map `HASH`: chặn theo port đích + giao thức
- [x] Map `PERCPU_ARRAY`: đếm gói/byte theo action (PASS/DROP) và theo rule
- [x] Biên dịch không warning, qua verifier

### User space (Go + cilium/ebpf) — [🤖]
- [x] Loader: gắn/gỡ XDP lên interface, chọn chế độ generic/native
- [x] CLI: `block-ip`, `unblock-ip`, `block-port`, `list`, `stats`
- [x] Exporter Prometheus `/metrics` (đọc map counter)

### Lab — [🤖]
- [x] `docker-compose.yml`: `client`, `attacker`, `fw-node`, `server`, `prometheus`, `grafana`
- [x] Mạng: client/attacker → fw-node → server (định tuyến qua fw-node)
- [x] Ghim CPU (`cpuset`): attacker/client CPU 0–3, fw-node CPU 4–7
- [x] Server chạy web (nginx) + `iperf3 -s`
- [x] Dashboard Grafana: pps pass/drop, bytes, top rule bị hit (provision sẵn bằng file JSON)
- [ ] `make up` / `make down` chạy được từ repo sạch

### Kiểm tra cuối ngày
- [x] [🤖] Chặn được IP attacker, client vẫn truy cập bình thường
- [x] [🤖] Thêm/xóa rule khi đang chạy không cần nạp lại chương trình
- [x] [👤] Tự mở Grafana kiểm tra counter hiển thị đúng
- [ ] [👤] **Đọc và tự giải thích được toàn bộ code XDP + Go** (hỏi Claude chỗ chưa hiểu)

---

## Ngày 2 — Thứ Tư 25/11: Benchmark

### Script đo — [🤖]
- [x] Script cấu hình iptables tương đương (bảng `raw PREROUTING` và bảng `filter FORWARD`)
- [x] Script cấu hình nftables tương đương (dùng set)
- [x] Script sinh tải: UDP flood / SYN flood (`trafgen` hoặc `hping3`)
- [x] Script thu số liệu: pps drop, % CPU fw-node (`mpstat`), xuất CSV
- [ ] Mỗi phép đo chạy ≥ 3 lần, lấy trung bình + độ lệch

### Các phép đo — [🤖 chạy, 👤 kiểm tra kết quả]
- [ ] **Đo 1 — Chi phí drop:** XDP native vs XDP generic vs iptables raw vs iptables filter vs nftables set
- [ ] **Đo 2 — Mở rộng theo số rule:** 10 / 100 / 1.000 / 10.000 rule
- [ ] **Đo 3 — Ảnh hưởng tới traffic hợp lệ:** latency (ping) + throughput (iperf3) của client khi bị flood
- [ ] Vẽ biểu đồ (Python matplotlib) từ CSV, lưu vào `results/`
- [ ] Ghi lại cấu hình máy, kernel, phiên bản công cụ (để báo cáo tái lập được)

### Báo cáo
- [ ] [👤] Viết chương 3: Thiết kế & triển khai (kiến trúc hệ thống, map, luồng xử lý gói)
- [ ] [👤] Viết phần mô tả môi trường lab & phương pháp đo

---

## Ngày 3 — Thứ Năm 26/11: Demo, video, slide

### Demo
- [ ] [🤖] Viết `docs/demo-script.md` — kịch bản từng bước (≤ 10 phút):
  1. Hệ thống bình thường — client truy cập web
  2. Attacker flood — CPU tăng, client bị ảnh hưởng
  3. Bật XDP / thêm rule bằng CLI — drop tăng trên Grafana, client hồi phục
  4. So sánh nhanh cùng kịch bản với iptables
- [ ] [👤] Tự chạy thử demo ≥ 2 lần từ repo sạch
- [ ] [👤] Quay video demo (≤ 10 phút), kiểm tra tiếng & độ phân giải

### Báo cáo & slide
- [ ] [👤] Viết chương 4: Kết quả đo & phân tích biểu đồ
- [ ] [👤] Viết chương 5: Hạn chế + hướng phát triển
- [ ] [👤] Kết luận, tài liệu tham khảo
- [ ] [👤] Slide trình bày 15 phút (~12–15 slide)
- [ ] [🤝] Tập thuyết trình + luyện trả lời câu hỏi phản biện (Claude đóng vai giảng viên hỏi)

---

## Ngày 4 — Thứ Sáu 27/11: Rà soát & nộp

- [ ] [👤] Báo cáo ≤ 20 trang, định dạng chỉn chu, đánh số hình/bảng, trích dẫn đầy đủ
- [ ] [🤖] README repo: mục tiêu, kiến trúc, cách cài (`make up`), cách chạy demo, cách chạy benchmark
- [ ] [🤖] Clone repo ra thư mục mới và chạy lại từ đầu — mọi thứ hoạt động
- [ ] [👤] Video ≤ 10 phút đã upload, link truy cập được
- [ ] [👤] Nộp: báo cáo + link Git + link video + slide

---

## Đối chiếu yêu cầu đề bài

| Yêu cầu | Đáp ứng bởi | Xong |
|---|---|---|
| Trình bày kiến trúc, nguyên lý | Báo cáo chương 2–3 | [ ] |
| So sánh với giải pháp truyền thống | Benchmark vs iptables/nftables + chương 4 | [ ] |
| Triển khai VM/container, script lặp lại được trên Git | `docker-compose.yml` + `Makefile` | [ ] |
| Trình diễn ≥ 1 kịch bản | Kịch bản chống flood + video | [ ] |
| Nêu rõ hạn chế | Báo cáo chương 5 + slide | [ ] |
| Báo cáo ≤ 20 trang, tự viết | — | [ ] |
| Hiểu kỹ source code | Tự giải thích được mọi file | [ ] |
| Video ≤ 10 phút, trình bày 15 phút | — | [ ] |

## Dàn ý báo cáo (gợi ý — tự viết nội dung)

1. Giới thiệu
2. Cơ sở lý thuyết: eBPF, XDP, netfilter/iptables
3. Thiết kế & triển khai hệ thống
4. Thực nghiệm & đánh giá
5. Hạn chế & hướng phát triển
6. Kết luận · Tài liệu tham khảo

## Ngoài phạm vi (chỉ làm nếu dư thời gian)

- [ ] Rate limit theo IP nguồn (token bucket, map `LRU_HASH`)
- [ ] Load balancer L4
- [ ] Benchmark trên VM Hyper-V (XDP native trên `hv_netvsc`)
