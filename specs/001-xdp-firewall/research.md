# Research: XDP Firewall (001-xdp-firewall)

**Date**: 2026-11-24 · Các quyết định dưới đây đã được kiểm chứng trên máy thật khi có thể
(smoke test 2026-11-23, probe 2026-11-24).

## R1. Header cho chương trình BPF: UAPI headers thay vì `vmlinux.h`

- **Decision**: Dùng header UAPI chuẩn (`linux/bpf.h`, `linux/if_ether.h`, `linux/ip.h`,
  `linux/tcp.h`, `linux/udp.h`, `linux/in.h`) + `bpf/bpf_helpers.h`, `bpf/bpf_endian.h` của libbpf.
- **Rationale**: Firewall chỉ đọc header gói (định dạng cố định theo RFC), không đọc struct nội bộ
  của kernel → không cần CO-RE relocation. Bỏ `vmlinux.h` (~3 MB, sinh từ BTF của từng máy) giúp
  build trong container độc lập với kernel host và code dễ đọc hơn.
- **Alternatives**: `vmlinux.h` + CO-RE — cần khi truy cập `struct sk_buff`, task… — không cần ở đây.
- **Constitution**: lệch chữ của nguyên tắc I ("dùng CO-RE/vmlinux.h"), được biện minh ở mục
  Complexity Tracking của plan.md (đơn giản hơn, theo nguyên tắc VI).

## R2. Thư viện user space: `cilium/ebpf` v0.19.0 + Go 1.23

- **Decision**: `github.com/cilium/ebpf v0.19.0` (go.mod yêu cầu Go 1.23), dùng `bpf2go` để nhúng
  bytecode và sinh Go binding. Build trong image `golang:1.23.4-bookworm`.
- **Rationale**: Go trên WSL là 1.22.2 — không đủ cho các bản cilium/ebpf mới; build trong Docker
  giúp phiên bản cố định và không phụ thuộc máy host (nguyên tắc III). v0.19.0 đã ổn định nhiều
  tháng (bản mới nhất là v0.22.0).
- **Alternatives**: v0.17.3 (Go 1.22, chạy được trên host) — cũ hơn; libbpf-go/C loader — nhiều code hơn.

## R3. Exporter: `prometheus/client_golang`

- **Decision**: `github.com/prometheus/client_golang` (ghim phiên bản tương thích Go 1.23 khi
  `go mod tidy`), một `Collector` tự viết đọc map mỗi lần scrape.
- **Rationale**: Đọc map trực tiếp lúc scrape → không có goroutine nền, không có trạng thái trùng lặp.

## R4. Giữ firewall sống giữa các lần gọi CLI: pin vào bpffs

- **Decision**: `xdpfw load` gắn XDP bằng **bpf_link** và pin link + các map vào
  `/sys/fs/bpf/xdpfw/`. Các lệnh sau (`block-ip`, `stats`, `serve`…) mở map đã pin.
  `xdpfw unload` gỡ link và xóa thư mục pin.
- **Rationale**: Mỗi lệnh CLI là một tiến trình ngắn; không pin thì chương trình bị gỡ khi tiến trình
  thoát. bpf_link cũng chống ghi đè ngầm (edge case "interface đã có chương trình khác").
- **Kiểm chứng**: bpffs **chưa được mount** trên WSL (probe) → entrypoint của fw-node chạy
  `mount -t bpf bpf /sys/fs/bpf` nếu chưa có.

## R5. Topology Docker & cô lập

- **Decision**: 3 mạng bridge:
  - `net_ext` 10.10.1.0/24 (`internal: true`): client .10, attacker .66, fw-node .254
  - `net_int` 10.10.2.0/24 (`internal: true`): server .20, fw-node .254
  - `net_mgmt` 10.10.9.0/24: fw-node, prometheus, grafana (Grafana/Prometheus publish `127.0.0.1` only)
  Client/attacker thêm route `10.10.2.0/24 via 10.10.1.254`; server thêm route `10.10.1.0/24 via
  10.10.2.254`; fw-node bật `net.ipv4.ip_forward=1`. XDP gắn trên interface của fw-node thuộc
  `net_ext` (tìm theo IP 10.10.1.254, không giả định tên `eth0`).
- **Rationale**: `internal: true` bảo đảm traffic tấn công không ra ngoài (FR-018); mạng mgmt tách
  riêng để số liệu giám sát không đi qua đường đo.
- **Alternatives**: netns thuần bằng script — nhẹ hơn nhưng đề yêu cầu docker-compose/Ansible.

## R6. `br_netfilter` trên host làm nhiễu phép đo

- **Finding**: Probe cho thấy `br_netfilter` đã nạp và `net.bridge.bridge-nf-call-iptables = 1`
  (do Docker) → mọi frame đi qua bridge của Docker bị iptables **của host** xử lý thêm.
- **Decision**: Script benchmark đặt `bridge-nf-call-iptables=0` (và `ip6tables`, `arptables`) trong
  lúc đo, khôi phục sau đó, và ghi giá trị vào file môi trường đo. Demo không cần đổi.
- **Rationale**: Chi phí này cộng đều cho mọi cấu hình nhưng làm giảm độ tương phản; tắt đi để số
  liệu phản ánh đúng fw-node.

## R7. Đo CPU trên veth: chi phí nhận gói rơi vào CPU **bên gửi**

- **Finding** (phân tích đường đi trong kernel): trên veth, `veth_xmit` chuyển gói sang peer và việc
  xử lý nhận (backlog softirq, hoặc NAPI của veth khi có XDP native) được lập lịch trên **CPU đang
  gửi** — tức CPU của attacker, không phải CPU ghim cho fw-node. Ghim CPU fw-node (4–7) vì vậy không
  đủ để cô lập chi phí của firewall.
- **Decision** — dùng hai chỉ số bổ trợ nhau:
  1. **Thông lượng tối đa với 1 luồng gửi**: trafgen 1 luồng, ghim 1 CPU, không giới hạn tốc độ. Vì
     CPU gửi cũng làm luôn phần nhận, pps đạt được ≈ 1 / (chi phí gửi + chi phí nhận/lọc) → cấu hình
     lọc rẻ hơn cho pps cao hơn. Đây là chỉ số chính của Đo 1 và Đo 2.
  2. **CPU toàn hệ thống ở tải cố định**: trafgen giới hạn tốc độ (chọn sau đo thử, mức baseline
     chưa bão hòa), đo `%sys + %soft` cộng trên **tất cả** CPU bằng `mpstat`, trừ baseline idle.
     Không phụ thuộc gói được xử lý trên CPU nào.
  - Bổ sung cho XDP: bật `kernel.bpf_stats_enabled=1` và đọc `run_time_ns / run_cnt` của chương
    trình (ns/gói) bằng `bpftool prog show` — chi phí thuần của chương trình XDP.
- **Rationale**: Giữ phép so sánh công bằng (nguyên tắc IV) trên phần cứng dùng chung; cả hai chỉ
  số và lý do chọn được ghi trong báo cáo như một hạn chế của môi trường.
- **Alternatives**: pktgen kernel — module không chắc có trên kernel WSL; 2 VM riêng — ngoài phạm vi.
- **Rủi ro**: phải kiểm chứng bằng thực nghiệm sớm (ngày benchmark); nếu chỉ số 1 nhiễu, dùng
  chỉ số 2 làm chính.

## R8. Sinh tải

- **Decision**: `trafgen` (netsniff-ng) cho flood UDP 64 byte từ attacker, file cấu hình gói cố định
  (src 10.10.1.66 → dst 10.10.2.20:9999), tùy chọn giới hạn tốc độ; `hping3 --flood -S` chỉ dùng
  trong demo (SYN flood dễ nhìn). Traffic hợp lệ: `ping -i 0.2`, `iperf3 -c` (TCP, 10 s), `curl`.
- **Rationale**: trafgen dùng packet mmap, sinh tải cao nhất trong các công cụ có sẵn bằng apt.

## R9. Các cấu hình netfilter để so sánh

- **Decision**:
  - `ipt-legacy-raw` / `ipt-nft-raw`: `iptables[-legacy|-nft] -t raw -A PREROUTING -s <ip> -j DROP`
  - `ipt-legacy-filter` / `ipt-nft-filter`: `iptables[-legacy|-nft] -A FORWARD -s <ip> -j DROP`
  - `nft-set`: bảng `inet bench`, set `blk { type ipv4_addr; flags interval; }`, chain hook
    `prerouting priority raw`, rule `ip saddr @blk drop`
  - Đo 2 (mở rộng): N−1 rule IP ngẫu nhiên không khớp (ngoài 10.10.0.0/16) + rule khớp attacker ở **cuối**.
- **Rationale**: Tách được hai yếu tố: *vị trí hook* (raw vs filter vs XDP) và *cấu trúc tra cứu*
  (chuỗi tuyến tính của iptables vs set/LPM O(1)). Module `ip_tables`, `iptable_raw`,
  `iptable_filter`, `nf_tables` đã modprobe thành công trên WSL (probe); `make up` modprobe trước.
- **Ghi chú**: `iptables` mặc định của Ubuntu 24.04 là backend nf_tables → phải gọi rõ
  `iptables-legacy` / `iptables-nft`; luôn flush cả hai backend giữa các lần đo.

## R10. Kiểm thử

- **Decision**:
  1. **Unit test Go** (`go test`): parse CIDR/port, cấp phát rule id.
  2. **Test chương trình XDP không cần lab**: `BPF_PROG_TEST_RUN` qua `ebpf.Program.Run` với gói tự
     dựng (IPv4 có/không options, ARP, IPv6, gói cụt, TCP/UDP/ICMP) → kiểm tra action + bộ đếm.
     Chạy trong container builder privileged.
  3. **Functional test** (`make test`, bash): trên lab đang chạy — kịch bản theo acceptance scenarios
     US1/US2 (chặn IP, subnet, port, đổi rule khi ping liên tục, bộ đếm = 1.000).
- **Rationale**: (2) bao phủ các edge case khó tạo bằng traffic thật; (3) chứng minh SC-001..SC-003.

## R11. Phiên bản image (ghim theo nguyên tắc III)

| Image | Tag | Kiểm chứng |
|---|---|---|
| golang | `1.23.4-bookworm` | Docker Hub 200 |
| debian | `bookworm-slim` | Docker Hub 200 |
| prom/prometheus | `v2.53.0` | Docker Hub 200 |
| grafana/grafana-oss | `11.1.0` | Docker Hub 200 |

`bookworm-slim` là tag trượt theo bản vá Debian 12; chấp nhận được (chỉ cài gói apt). Digest cụ thể
sẽ được ghi vào file môi trường đo khi chạy benchmark.
