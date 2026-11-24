# Implementation Plan: XDP Firewall chống DDoS & so sánh hiệu năng với iptables/nftables

**Branch**: `001-xdp-firewall` | **Date**: 2026-11-24 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/001-xdp-firewall/spec.md`

## Summary

Xây dựng firewall lọc gói IPv4 ingress tại hook XDP: chặn IP/subnet nguồn (LPM trie) và chặn
port đích theo TCP/UDP (hash), đếm gói/byte theo kết quả và theo rule (map per-CPU). Một binary Go
(`xdpfw`) nạp/gỡ chương trình (generic/native, pin vào bpffs), quản lý rule lúc đang chạy và xuất
metric Prometheus. Lab docker-compose 6 service (client, attacker, fw-node, server, prometheus,
grafana) dựng bằng `make up`. Bộ benchmark bash + Python so sánh 8 cấu hình × 3 phép đo, dùng
**pps tối đa với 1 luồng gửi** và **CPU toàn hệ thống ở tải cố định** vì trên veth chi phí nhận gói
rơi vào CPU bên gửi (research R7).

## Technical Context

**Language/Version**: C (BPF, clang 14+ `-target bpf`), Go 1.23 (build trong `golang:1.23.4-bookworm`),
Bash, Python 3 (pandas, matplotlib)

**Primary Dependencies**: libbpf headers (`bpf_helpers.h`, `bpf_endian.h`), `github.com/cilium/ebpf`
v0.19.0 (+ `bpf2go`), `github.com/prometheus/client_golang`; Docker Engine + Compose; trafgen,
hping3, iperf3, iptables (legacy + nft), nftables, mpstat; Prometheus v2.53.0, Grafana OSS 11.1.0

**Storage**: BPF maps pin tại `/sys/fs/bpf/xdpfw/` (không lưu bền); kết quả benchmark là file CSV/PNG trong `results/`

**Testing**: `go test` (unit), `BPF_PROG_TEST_RUN` qua `ebpf.Program.Run` (test chương trình XDP
không cần lab), `tests/functional.sh` (functional trên lab, `make test`)

**Target Platform**: Linux kernel ≥ 5.15 có BTF; môi trường chính WSL2 Ubuntu 24.04, kernel 6.18

**Project Type**: CLI + daemon exporter + lab hạ tầng (docker-compose) + bộ script benchmark

**Performance Goals**: Rule có hiệu lực ≤ 1 s; dashboard trễ ≤ 5 s; CPU/pps của XDP gần như không
đổi (≤ 20%) khi số rule 10 → 10.000; XDP native rẻ hơn iptables filter đo được (SC-007/008)

**Constraints**: Chỉ IPv4 ingress; verifier (không vòng lặp không giới hạn, stack ≤ 512 B); một
laptop 4C/8T, WSL 8 GB RAM; máy sinh tải và firewall dùng chung CPU; hạn 2026-11-27

**Scale/Scope**: ≤ 16.384 rule IP + 1.024 rule port; 6 container; benchmark ≤ 2 giờ;
ước lượng ~250 dòng C, ~800 dòng Go, ~500 dòng bash/Python

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Nguyên tắc | Đánh giá (trước research) | Sau thiết kế (Phase 1) |
|---|---|---|
| **I. Data plane C + libbpf, thân thiện verifier** | ✅ C + libbpf helpers; kiểm tra biên mọi lần đọc; không vòng lặp; gói ngoài phạm vi → `XDP_PASS`; counter per-CPU. ⚠️ Không dùng `vmlinux.h`/CO-RE — xem Complexity Tracking | ✅ data-model §1 dùng PERCPU_ARRAY cho bộ đếm; `PARSE_ERR` → PASS |
| **II. Control plane Go + cilium/ebpf, một binary** | ✅ `xdpfw` duy nhất: load/unload/rule/stats/serve; rule ghi map, không reload | ✅ contracts/cli.md: mã thoát, stderr |
| **III. Lab tái lập được** | ✅ `make up`/`make down`; Prometheus/Grafana provision bằng file; image ghim tag | ✅ research R5, R11 |
| **IV. Benchmark công bằng** | ✅ 8 cấu hình cùng topology/tải; ≥ 3 lần; dọn sạch giữa lần; CSV + `make plot`; `env.txt` | ✅ Bổ sung R6 (tắt `br_netfilter`) và R7 (chỉ số đo phù hợp veth) — làm phép đo **công bằng hơn**, đúng tinh thần nguyên tắc |
| **V. Dễ giải thích & liêm chính** | ✅ Code nhỏ, comment "tại sao"; tasks có bước "sinh viên đọc hiểu"; AI không viết báo cáo | ✅ |
| **VI. Đơn giản & kỷ luật phạm vi** | ✅ MVP = US1 + US2 + lab; US3/US4 sau; không rate limit/LB/IPv6; CLI dùng `flag` chuẩn, không framework | ✅ |
| **An toàn lab** | ✅ `net_ext`/`net_int` là mạng `internal`; Grafana/Prometheus chỉ bind 127.0.0.1 | ✅ |

**Kết quả gate**: ĐẠT (1 sai lệch có biện minh).

## Project Structure

### Documentation (this feature)

```text
specs/001-xdp-firewall/
├── plan.md              # This file
├── research.md          # Phase 0 — R1..R11
├── data-model.md        # Phase 1 — BPF maps, CSV schema
├── quickstart.md        # Phase 1 — hướng dẫn chạy & kiểm chứng
├── contracts/
│   ├── cli.md           # Lệnh xdpfw, mã thoát, JSON
│   └── metrics.md       # Metric Prometheus + panel Grafana
├── checklists/requirements.md
└── tasks.md             # Phase 2 (/speckit-tasks)
```

### Source Code (repository root)

```text
bpf/
└── xdp_fw.c                  # Chương trình XDP: parse → LPM → port hash → counters

cmd/xdpfw/
└── main.go                   # Điểm vào CLI, phân lệnh bằng flag chuẩn

internal/
├── bpfobj/                   # Sinh bởi bpf2go (gen.go + *_bpfel.go/.o không commit)
│   └── gen.go
├── fw/                       # Nạp/gỡ, pin, mở map đã pin, đọc/ghi rule & counter
│   ├── loader.go
│   ├── rules.go
│   ├── stats.go
│   └── fw_test.go            # BPF_PROG_TEST_RUN (cần root)
├── parse/                    # Parse & validate CIDR/port/proto (thuần Go)
│   ├── parse.go
│   └── parse_test.go
└── exporter/
    └── exporter.go           # prometheus.Collector đọc map khi scrape

lab/
├── docker-compose.yml        # 6 service, 3 mạng, cpuset
├── fw-node/
│   ├── Dockerfile            # multi-stage: build (golang+clang) → runtime (debian + xdpfw + iptables + nft + bpftool)
│   └── entrypoint.sh         # mount bpffs, ip_forward, xdpfw serve
├── node/
│   ├── Dockerfile            # image chung client/attacker/server: iproute2, ping, curl, iperf3, hping3, trafgen, nginx
│   └── entrypoint.sh         # đặt route qua fw-node theo vai trò
├── prometheus/prometheus.yml
└── grafana/
    ├── provisioning/{datasources,dashboards}/*.yml
    └── dashboards/xdp-firewall.json

bench/
├── run_bench.sh              # điều phối 3 phép đo × 8 cấu hình × N lần → raw.csv
├── configs.sh                # apply/clear từng cấu hình (xdp, iptables-legacy/nft, nft-set)
├── gen_ips.py                # sinh N IP ngẫu nhiên không khớp
├── flood.trafgen             # mẫu gói UDP 64 B
├── env.sh                    # ghi env.txt
└── plot.py                   # raw.csv → summary.csv + PNG

tests/
└── functional.sh             # acceptance US1/US2 trên lab

docs/
└── demo-script.md            # kịch bản demo ≤ 10 phút

go.mod, go.sum, Makefile, README.md
results/                      # đầu ra benchmark (CSV/PNG commit; tmp/ bỏ qua)
```

**Structure Decision**: Một project Go đơn (module gốc repo) + thư mục `bpf/` cho mã kernel,
`lab/` cho hạ tầng, `bench/` cho đo đạc. Không chia nhiều module — phù hợp nguyên tắc VI.
Toàn bộ build diễn ra trong Docker (stage builder) để không phụ thuộc toolchain host;
`make test-bpf` chạy `go test` trong container builder privileged.

## Thiết kế chính (tóm tắt)

**Luồng XDP** (`bpf/xdp_fw.c`): `eth` (kiểm tra biên) → không phải IPv4 ⇒ PASS → `iphdr` (biên,
`ihl ≥ 5`, biên theo `ihl*4`) hỏng ⇒ PARSE_ERR + PASS → tra `blocked_src` (LPM) ⇒ DROP_IP + `rule_hits`
→ nếu TCP/UDP: đọc `dport` (biên) → tra `blocked_port` ⇒ DROP_PORT + `rule_hits` → PASS. Gói là
fragment không phải đầu (`frag_off & 0x1FFF ≠ 0`) không có header L4 → bỏ qua bước port.

**Control plane**: `fw.Load(iface, mode)` → `link.AttachXDP` với `XDPGenericMode`/`XDPDriverMode`
→ pin link + 4 map → ghi `meta.json`. Mọi lệnh khác `ebpf.LoadPinnedMap`. Exporter mở map mỗi lần
scrape (hỗ trợ unload/load lại khi `serve` đang chạy).

**Lab**: xem research R5; `cpuset` client/attacker `0-3`, fw-node `4-7` (giữ theo FR-017 dù R7 cho
thấy không cô lập hoàn toàn trên veth — được ghi trong báo cáo).

**Benchmark**: research R6–R9; mỗi lần đo: `clear_all` → `apply <config> <rules>` → khởi động trafgen
(30 s, bỏ 5 s đầu) → song song `mpstat` + đọc counter → ghi 1 dòng CSV → `clear_all`.

## Rủi ro & phương án

| Rủi ro | Phương án |
|---|---|
| Native XDP trong container trên interface Docker không gắn được | Đã chạy được trong netns (smoke test); nếu lỗi → chỉ dùng generic, ghi vào hạn chế |
| Chỉ số pps 1 luồng nhiễu lớn | Dùng CPU ở tải cố định làm chỉ số chính (R7) |
| trafgen không chạy trong container (cần `CAP_NET_RAW`, mmap) | attacker `cap_add: NET_ADMIN, NET_RAW`; dự phòng `hping3 --flood` |
| Không đủ thời gian cho Đo 3 | Đo 3 chỉ chạy 4 cấu hình chính (baseline, xdp-native, ipt-legacy-filter, nft-set) |

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| Nguyên tắc I ghi "dùng CO-RE (`vmlinux.h`)"; plan dùng **UAPI headers** | Chương trình chỉ đọc header gói theo RFC, không truy cập struct kernel nên CO-RE không mang lại gì; UAPI headers nhỏ, đọc được, build trong container không cần BTF của host | `vmlinux.h` (~3 MB, sinh theo từng kernel) làm build phụ thuộc máy host và khó giải thích hơn — trái nguyên tắc III và VI. Đề xuất sửa constitution (PATCH) thành "CO-RE khi truy cập struct kernel" |
