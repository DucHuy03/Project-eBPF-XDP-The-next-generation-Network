# XDP firewall chống DDoS — so sánh với iptables/nftables

Project giữa kỳ môn **Mạng thế hệ mới** (HUST SoICT), đề tài #2: eBPF/XDP.

Firewall chạy trong kernel ở hook XDP, chặn theo IP/subnet nguồn và theo port đích + giao thức, đếm gói
theo action và theo rule, đổi rule lúc đang chạy. Kèm lab docker-compose có dashboard Grafana và bộ
benchmark so sánh với iptables (legacy/nft, bảng raw/filter) và nftables set.

- Thiết kế tổng thể, luồng xử lý gói, phương pháp đo: [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md)
- Đặc tả, kế hoạch, quyết định kỹ thuật: [specs/001-xdp-firewall/](specs/001-xdp-firewall/)
  (`spec.md`, `plan.md`, `research.md`, `data-model.md`, `contracts/`)
- Kịch bản demo: [docs/demo-script.md](docs/demo-script.md)
- Kết quả đo: [results/20261124-200114/](results/20261124-200114/)

## Kiến trúc

```
  client   10.10.1.10 ─┐                                   ┌─ server 10.10.2.20 (nginx, iperf3)
                       ├─ net_ext ── fw-node ── net_int ───┘
  attacker 10.10.1.66 ─┘        XDP ▲  │ router + xdpfw
                                    │  net_mgmt ── prometheus :9090 ── grafana :3000
```

- `bpf/xdp_fw.c` — chương trình XDP: parse Ethernet/IPv4/TCP/UDP, tra LPM trie (IP/CIDR nguồn) và hash
  (proto + port đích), cộng bộ đếm per-CPU, trả `XDP_DROP`/`XDP_PASS`. Chỉ IPv4 ingress.
- `cmd/xdpfw` + `internal/fw` — CLI Go (cilium/ebpf): nạp/gỡ chương trình, ghi map rule, đọc bộ đếm.
  Map được pin trong bpffs nên rule đổi được mà không nạp lại chương trình.
- `internal/exporter` — `xdpfw serve`: endpoint Prometheus `/metrics` trên mạng quản trị.

## Yêu cầu

Đã kiểm thử trên: Windows 11 + **WSL2 Ubuntu 24.04**, kernel 6.18 (WSL), i5-10300H, 8 vCPU, 8 GB RAM.

- Linux hoặc WSL2, kernel ≥ 5.15 có BTF; quyền **root**.
- **Docker Engine + Compose plugin cài trong WSL** (không dùng Docker Desktop). Mọi lệnh `make`/`docker`
  phải chạy trong terminal Ubuntu (WSL): gõ `wsl` trong PowerShell, hoặc chọn profile "Ubuntu (WSL)" trong
  terminal VS Code. Gõ trong PowerShell sẽ báo không tìm thấy `docker`.
- `make`, `git`, `curl`; cho benchmark thêm `sysstat` (mpstat), `python3-pandas`, `python3-matplotlib`.
- Không cần cài clang/Go trên máy: chương trình BPF và CLI được build trong Docker (`lab/fw-node/Dockerfile`).
- `.wslconfig` nên có `processors=8` và `memory=8GB` (compose ghim attacker/client vào CPU 0–3,
  fw-node vào CPU 4–7).

## Chạy nhanh

```bash
sudo -i
cd <thư mục repo>        # ví dụ /mnt/d/...
make up                  # nạp module kernel, build image, dựng 6 container, chờ tới khi sẵn sàng
make ps                  # 6 service running
```

Grafana: <http://localhost:3000> (dashboard **XDP Firewall**, ẩn danh chỉ xem). Prometheus: <http://localhost:9090>.

```bash
alias fw='docker exec xdplab-fw-node-1 xdpfw'
fw load --iface $(docker exec xdplab-fw-node-1 cat /run/xdp_iface) --mode native   # hoặc generic
fw block-ip 10.10.1.66/32        # chặn attacker; cũng nhận subnet, ví dụ 10.10.1.64/26
fw block-port udp 9999           # chặn port đích theo giao thức
fw list                          # rule + số gói/byte khớp từng rule
fw stats                         # tổng theo action: pass, drop_ip, drop_port, parse_err
fw unblock-ip 10.10.1.66/32
fw unload
make down                        # gỡ XDP, xóa container và mạng
```

Đủ lệnh: `docker exec xdplab-fw-node-1 xdpfw help`.

**Lưu ý khi dùng WSL**: VM WSL tự tắt khi không còn terminal WSL nào mở, kéo theo cả lab. Giữ một
terminal Ubuntu mở, hoặc chạy `wsl -d Ubuntu -- sleep infinity` trong một cửa sổ riêng.

## Demo

`lab/demo.sh` gồm các lệnh: sinh flood (`flood`/`stop`), chuyển nhanh giữa 8 cấu hình lọc với N rule
(`use`), và in pps tới/bị drop cùng CPU mỗi giây (`watch`). Kịch bản 10 phút, từng bước có lệnh và kết quả
mong đợi: [docs/demo-script.md](docs/demo-script.md).

## Kiểm thử

```bash
make test-unit   # unit test Go: parse CIDR, port, giao thức
make test-bpf    # BPF_PROG_TEST_RUN: chạy chương trình XDP trên gói dựng sẵn (IPv4/IPv6/ARP/cụt/...)
make test        # functional test trên lab đang chạy: chặn IP, subnet, port, bộ đếm (cần jq)
```

## Benchmark

```bash
make bench QUICK=1   # 1 lần/điểm, ~30 phút, để kiểm tra pipeline
make bench           # 3 lần/điểm, 264 lần đo, ~2,5 giờ
make plot            # results/<run_id>/summary.csv + drop_cost.png, rule_scaling.png, legit_impact.png
```

So sánh 8 cấu hình: `baseline` (không lọc), `xdp-native`, `xdp-generic`, `ipt-legacy-raw`,
`ipt-legacy-filter`, `ipt-nft-raw`, `ipt-nft-filter`, `nft-set`. Ba phép đo:

1. **Chi phí drop**: pps tối đa với 1 luồng gửi và CPU toàn hệ thống ở tải cố định 200k pps.
2. **Mở rộng theo số rule**: 10 / 100 / 1 000 / 10 000 rule, rule khớp đặt cuối.
3. **Ảnh hưởng tới traffic hợp lệ**: ping (RTT p99) và iperf3 của client, khi có và không có flood.

Mỗi lần đo ghi một dòng vào `raw.csv` (định nghĩa cột: `specs/001-xdp-firewall/data-model.md` §2).
`env.txt` ghi kernel, CPU, phiên bản công cụ, sysctl, image ID để tái lập. Trong lúc đo không dùng lab vào
việc khác; cắm sạc và tắt chế độ sleep. Vì sao đo CPU toàn hệ thống thay vì CPU của fw-node: `research.md` R7.

## Cấu trúc repo

```
bpf/xdp_fw.c                 chương trình XDP
cmd/xdpfw/                   CLI
internal/fw/                 nạp/gỡ, rule, bộ đếm; fw_test.go = BPF_PROG_TEST_RUN
internal/parse/              parse CIDR/port/giao thức
internal/exporter/           Prometheus exporter
internal/bpfobj/             bpf2go: biên dịch bpf/xdp_fw.c và sinh binding Go
lab/                         docker-compose, Dockerfile, Prometheus, Grafana, wait-ready.sh, demo.sh
bench/                       run_bench.sh, configs.sh (8 cấu hình), env.sh, gen_ips.py, flood.trafgen, plot.py
tests/functional.sh          functional test trên lab
results/<run_id>/            raw.csv, summary.csv, env.txt, *.png
docs/demo-script.md          kịch bản demo
specs/001-xdp-firewall/      spec, plan, research, data-model, contracts, tasks
```

## Hạn chế

Của XDP:
- Chỉ xử lý chiều vào; chiều ra cần TC-BPF.
- Không có conntrack sẵn, nên không lọc có trạng thái; project này cũng không làm rate limit hay IPv6.
- Verifier giới hạn độ phức tạp chương trình (vòng lặp, stack 512 byte); gỡ lỗi khó hơn iptables.
- Chế độ native cần driver hỗ trợ; LPM trie không phải O(1): chi phí mỗi gói tăng từ khoảng 70 lên
  150 ns khi số rule tăng từ 10 lên 10 000.

Của môi trường đo:
- **veth ảo trên WSL2.** Gói tới fw-node đã là skb do bên gửi cấp phát, nên lợi thế chính của XDP (drop
  trước khi cấp phát skb) không xuất hiện: với 1 rule, iptables bảng raw tốn CPU ngang hoặc ít hơn XDP.
- **XDP native trên veth tắt GRO/TSO**: throughput TCP hợp lệ giảm từ khoảng 30 xuống khoảng 3,5 Gbit/s
  ngay cả khi không có flood.
- Bên gửi và bên nhận dùng chung một máy; phần xử lý nhận chạy trên CPU bên gửi. Số liệu chỉ có giá trị
  **so sánh tương đối** giữa các cấu hình, không phải hiệu năng trên NIC thật.
- Bản đo đầy đủ mất khoảng 2,5 giờ, vượt mục tiêu ≤ 2 giờ của SC-006.
- `br_netfilter` phải tắt (`bridge-nf-call-iptables=0`) sau khi Docker tạo mạng, nếu không iptables của
  host chặn gói giữa hai mạng internal; `make up` và benchmark tự làm việc này (research R6).
