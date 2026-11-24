---

description: "Task list for 001-xdp-firewall"
---

# Tasks: XDP Firewall chống DDoS & so sánh hiệu năng với iptables/nftables

**Input**: Design documents from `specs/001-xdp-firewall/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/cli.md, contracts/metrics.md, quickstart.md

**Tests**: Có — plan.md/research R10 và quickstart.md yêu cầu `make test-bpf` (BPF_PROG_TEST_RUN), `go test` và `make test` (functional trên lab).

**Organization**: Theo user story của spec.md (US1 P1 → US4 P4).

## Format: `[ID] [P?] [Story] Description`

- **[P]**: chạy song song được (khác file, không phụ thuộc task chưa xong)
- **[Story]**: US1–US4
- Đường dẫn theo cấu trúc trong plan.md (module Go ở gốc repo, `bpf/`, `lab/`, `bench/`, `tests/`)

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Khởi tạo cấu trúc repo và hệ thống build

- [X] T001 Tạo cây thư mục theo plan.md: `bpf/`, `cmd/xdpfw/`, `internal/{bpfobj,fw,parse,exporter}/`, `lab/{fw-node,node,prometheus,grafana/provisioning/datasources,grafana/provisioning/dashboards,grafana/dashboards}/`, `bench/`, `tests/`, `docs/`, `results/`
- [X] T002 Khởi tạo module Go `go.mod` (module `xdpfw`, `go 1.23`) với `github.com/cilium/ebpf v0.19.0` và `github.com/prometheus/client_golang` (bản tương thích Go 1.23), tạo `go.sum` bằng `go mod tidy` chạy trong image `golang:1.23.4-bookworm` (research R2, R3)
- [X] T003 Viết `lab/fw-node/Dockerfile` multi-stage: stage `builder` từ `golang:1.23.4-bookworm` + `clang llvm libbpf-dev` chạy `go generate ./... && go build -o /out/xdpfw ./cmd/xdpfw`; stage `runtime` từ `debian:bookworm-slim` + `iproute2 iptables nftables bpftool iputils-ping curl tcpdump` và copy `xdpfw` (research R11)
- [X] T004 Viết `Makefile` với các target: `build` (docker build), `prereq` (modprobe `ip_tables iptable_raw iptable_filter nf_tables br_netfilter`), `up`, `down`, `shell-fw`, `test-bpf`, `test`, `bench`, `plot`, `clean` (quickstart.md)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Chương trình XDP, loader và lab cơ bản — mọi user story đều cần

**⚠️ CRITICAL**: Không bắt đầu user story trước khi xong phase này

- [X] T005 Viết `bpf/xdp_fw.c`: khai báo 4 map theo data-model.md — `blocked_src` (data-model.md §1.1 `blocked_src.key`, `blocked_src.value`, `blocked_src.max_entries`, cờ `BPF_F_NO_PREALLOC`), `blocked_port` (§1.2 `blocked_port.key` gồm `proto`/`pad`/`dport`, `blocked_port.value`, `blocked_port.max_entries`), `stats` (§1.3 `stats.key` 0–3, `counter`), `rule_hits` (§1.4 `rule_hits.max_entries`); dùng UAPI headers (research R1)
- [X] T006 Trong `bpf/xdp_fw.c` cài đặt hàm `xdp_fw`: parse Ethernet → IPv4 (kiểm tra biên `data_end`, `ihl ≥ 5`, biên theo `ihl*4`) → tra `blocked_src` → nếu TCP/UDP và không phải fragment sau → đọc `dport` (biên) → tra `blocked_port` → cập nhật `stats`/`rule_hits` → trả action; gói không phải IPv4 → PASS, IPv4 hỏng → `PARSE_ERR` + PASS (plan.md "Luồng XDP", spec Edge Cases); comment giải thích "tại sao" ở mỗi kiểm tra biên (constitution V)
- [X] T007 Viết `internal/bpfobj/gen.go` với chỉ thị `//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel XdpFw ../../bpf/xdp_fw.c -- -O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu`; xác nhận biên dịch không warning (constitution — cổng chất lượng 1)
- [X] T008 [P] Viết `internal/parse/parse.go`: `ParseCIDR` (không có `/` ⇒ /32, prefixlen 0–32, chuẩn hóa bit host và trả cờ cảnh báo — data-model.md §1.1 validation), `ParseProto` (tcp→6, udp→17), `ParsePort` (1–65535 — data-model.md §1.2 validation)
- [X] T009 [P] Viết `internal/parse/parse_test.go`: bảng test cho CIDR hợp lệ/không hợp lệ (`10.0.0.300/24`, `/33`, thiếu `/`, bit host ≠ 0), proto, port biên 0/1/65535/65536
- [X] T010 Viết `internal/fw/loader.go`: `Load(iface, mode)` — tìm ifindex, nạp object bpf2go, `link.AttachXDP` với `XDPGenericMode`/`XDPDriverMode`, mount-check `/sys/fs/bpf`, pin link + 4 map vào `/sys/fs/bpf/xdpfw/`, ghi `meta.json` (data-model.md §1.6 `interface`, `mode`, `attached_at`, `link`); `Unload()` gỡ link và xóa thư mục pin; `Open()` mở map đã pin (`ebpf.LoadPinnedMap`); lỗi "đã gắn" khi thư mục pin tồn tại, gợi ý `--mode generic` khi native thất bại (research R4, contracts/cli.md mã thoát 3/4)
- [X] T011 Viết `cmd/xdpfw/main.go`: phân lệnh bằng `flag` chuẩn, cài đặt `load`, `unload`, `status`, `version`; in lỗi `xdpfw: <lệnh>: <mô tả>` ra stderr với mã thoát theo contracts/cli.md
- [X] T012 [P] Viết `lab/node/Dockerfile` (debian:bookworm-slim + `iproute2 iputils-ping curl iperf3 hping3 netsniff-ng nginx procps`) và `lab/node/entrypoint.sh` (theo biến `ROLE`: client/attacker thêm route `10.10.2.0/24 via 10.10.1.254`; server thêm route `10.10.1.0/24 via 10.10.2.254`, chạy `nginx` + `iperf3 -s -D`; rồi `sleep infinity`) (research R5)
- [X] T013 [P] Viết `lab/fw-node/entrypoint.sh`: mount bpffs nếu chưa có, `sysctl net.ipv4.ip_forward=1`, xuất biến `XDP_IFACE` = interface có IP 10.10.1.254, chạy `xdpfw serve --listen :9100` ở foreground (research R4, R5)
- [X] T014 Viết `lab/docker-compose.yml` phần lõi: mạng `net_ext` 10.10.1.0/24 và `net_int` 10.10.2.0/24 (`internal: true`), `net_mgmt` 10.10.9.0/24; service `client` (.10), `attacker` (.66), `server` (10.10.2.20), `fw-node` (.254 trên ext/int, privileged, `cpuset: "4-7"`); client/attacker `cpuset: "0-3"`, `cap_add: [NET_ADMIN, NET_RAW]` (research R5, FR-014, FR-016–FR-018)
- [X] T015 Kiểm chứng nền tảng: `make up`, vào fw-node chạy `xdpfw load --iface $XDP_IFACE --mode native` rồi `bpftool net show` (kỳ vọng `driver`), lặp lại với `generic`, `xdpfw unload`; client `curl 10.10.2.20` thành công qua fw-node

**Checkpoint**: Firewall nạp/gỡ được trong lab ở cả hai chế độ; traffic client→server đi qua fw-node

---

## Phase 3: User Story 1 - Chặn traffic tấn công (Priority: P1) 🎯 MVP

**Goal**: Chặn IP/subnet nguồn và port đích theo giao thức, thay đổi rule lúc đang chạy

**Independent Test**: Chặn IP attacker → attacker không tới server, client vẫn `curl`/`ping` được (spec US1)

### Tests for User Story 1

- [X] T016 [P] [US1] Viết `internal/fw/fw_test.go` (build tag `bpftest`, cần root): dùng `ebpf.Program.Run` (BPF_PROG_TEST_RUN) với gói tự dựng — IPv4 UDP/TCP/ICMP, IPv4 có options (ihl=6), fragment sau, ARP, IPv6, gói cụt sau Ethernet, cụt giữa IP header; nạp rule /32, /24 lồng /32, port udp/9999; kiểm tra action trả về (research R10, spec Edge Cases)
- [X] T017 [P] [US1] Viết `tests/functional.sh` phần US1: helper `assert_ok`/`assert_fail`; kịch bản acceptance 1–6 của US1 (không rule → cả hai tới được; block /32; block /24 chứa attacker không chứa client; block udp/9999 nhưng tcp/9999 và udp/khác vẫn qua; unblock khi `ping -i 0.2` liên tục từ client → 0% loss và attacker thông lại ≤ 1 s; `status` đúng mode) (SC-001, SC-002)

### Implementation for User Story 1

- [X] T018 [US1] Viết `internal/fw/rules.go`: `AddIP`/`DelIP` trên `blocked_src` (key theo data-model.md §1.1 `blocked_src.key`, network byte order), `AddPort`/`DelPort` trên `blocked_port` (key theo §1.2 `blocked_port.key`, `pad` = 0), cấp phát `rule_id` nhỏ nhất chưa dùng trong dải tương ứng (data-model.md §1.5), xóa rule ⇒ đặt lại `rule_hits[id]` về 0 (§1.4), lỗi trùng/không tồn tại (mã 4) và đầy (mã 5) (contracts/cli.md)
- [X] T019 [US1] Trong `internal/fw/rules.go` thêm `List()` trả rule IP + port (đọc cả `rule_hits` cộng dồn per-CPU) và `Flush()` xóa mọi rule + đặt lại counter
- [X] T020 [US1] Mở rộng `cmd/xdpfw/main.go`: lệnh `block-ip`, `unblock-ip`, `block-port`, `unblock-port`, `list` (bảng + `--json`), `flush`; cảnh báo chuẩn hóa CIDR ra stderr với mã 0 (contracts/cli.md)
- [X] T021 [US1] Thêm target `test-bpf` vào `Makefile`: chạy `go test -tags bpftest ./internal/...` trong container builder `--privileged`; chạy và sửa tới khi PASS
- [X] T022 [US1] Thêm target `test` vào `Makefile` gọi `tests/functional.sh`; chạy trên lab và sửa tới khi mọi kịch bản US1 PASS
- [ ] T023 [US1] Sinh viên đọc hiểu `bpf/xdp_fw.c`, `internal/fw/loader.go`, `internal/fw/rules.go` và tự giải thích luồng xử lý gói + cách rule đi từ CLI vào map (constitution V — cổng chất lượng 3)

**Checkpoint**: US1 hoạt động độc lập — MVP có thể demo bằng CLI

---

## Phase 4: User Story 2 - Quan sát thống kê pass/drop (Priority: P2)

**Goal**: Bộ đếm theo kết quả và theo rule qua CLI, exporter Prometheus và dashboard Grafana

**Independent Test**: Attacker gửi đúng 1.000 gói khi đang bị chặn → `drop_ip` tăng đúng 1.000 trên CLI và Grafana (spec US2)

### Tests for User Story 2

- [X] T024 [P] [US2] Mở rộng `internal/fw/fw_test.go`: sau N lần `Program.Run`, đọc `stats` (data-model.md §1.3 `stats.key`) và `rule_hits` (§1.4) cộng dồn per-CPU — kiểm tra đúng số gói/byte cho PASS, DROP_IP, DROP_PORT, PARSE_ERR
- [X] T025 [P] [US2] Mở rộng `tests/functional.sh` phần US2: chặn attacker, `ping -c 1000 -i 0.002` → `xdpfw stats --json` `drop_ip` tăng đúng 1000 và `pass` không tăng tương ứng; `xdpfw list` có rule với `packets` = 1000; `curl fw-node:9100/metrics` chứa `xdpfw_packets_total{action="drop_ip"}` (SC-003)

### Implementation for User Story 2

- [X] T026 [US2] Viết `internal/fw/stats.go`: `ReadStats()` cộng dồn per-CPU `stats` (data-model.md §1.3 `counter.packets`, `counter.bytes`) cho 4 action
- [X] T027 [US2] Mở rộng `cmd/xdpfw/main.go`: lệnh `stats` (bảng + `--json` theo contracts/cli.md)
- [X] T028 [US2] Viết `internal/exporter/exporter.go`: `prometheus.Collector` mở map đã pin mỗi lần `Collect`, xuất đúng các metric trong contracts/metrics.md (`xdpfw_up`, `xdpfw_packets_total`, `xdpfw_bytes_total`, `xdpfw_rule_packets_total`, `xdpfw_rule_bytes_total`, `xdpfw_rules`, `xdpfw_info`); khi chưa nạp chỉ xuất `xdpfw_up 0`
- [X] T029 [US2] Mở rộng `cmd/xdpfw/main.go`: lệnh `serve --listen` dùng `promhttp.HandlerFor` với registry riêng
- [ ] T030 [P] [US2] Viết `lab/prometheus/prometheus.yml`: `scrape_interval: 1s`, job `xdpfw` target `fw-node:9100` qua `net_mgmt` (contracts/metrics.md)
- [ ] T031 [P] [US2] Viết `lab/grafana/provisioning/datasources/prometheus.yml`, `lab/grafana/provisioning/dashboards/dashboards.yml` và `lab/grafana/dashboards/xdp-firewall.json` với 4 panel trong contracts/metrics.md, refresh 1 s, truy cập ẩn danh chỉ xem
- [ ] T032 [US2] Thêm service `prometheus` (`prom/prometheus:v2.53.0`) và `grafana` (`grafana/grafana-oss:11.1.0`) vào `lab/docker-compose.yml`, publish `127.0.0.1:9090` và `127.0.0.1:3000`, mount file provisioning (FR-013, research R11)
- [ ] T033 [US2] Chạy `make test-bpf` + `make test`; mở Grafana kiểm tra đường `drop_ip` phản ánh flood trong ≤ 5 s (SC-004)
- [ ] T034 [US2] Sinh viên đọc hiểu `internal/fw/stats.go`, `internal/exporter/exporter.go` và cách Grafana truy vấn `rate()` (constitution V)

**Checkpoint**: US1 + US2 hoạt động — đủ cho phần demo chính

---

## Phase 5: User Story 3 - Benchmark so sánh (Priority: P3)

**Goal**: 8 cấu hình × 3 phép đo, ≥ 3 lần/điểm, CSV + biểu đồ + thông tin môi trường

**Independent Test**: `make bench QUICK=1` sinh `raw.csv` đủ mọi tổ hợp và `make plot` sinh biểu đồ (spec US3)

### Implementation for User Story 3

- [ ] T035 [P] [US3] Viết `bench/gen_ips.py`: sinh N địa chỉ IPv4 ngẫu nhiên (seed cố định) nằm ngoài 10.10.0.0/16, in mỗi dòng một IP (research R9)
- [ ] T036 [P] [US3] Viết `bench/flood.trafgen`: gói UDP 64 B, src MAC/IP attacker 10.10.1.66 → dst 10.10.2.20:9999, MAC đích là MAC của fw-node (điền lúc chạy) (research R8)
- [ ] T037 [P] [US3] Viết `bench/env.sh`: ghi `results/<run_id>/env.txt` gồm kernel, phiên bản clang/Go/bpftool/iptables/nft/trafgen, CPU, `nproc`, `.wslconfig`, `bridge-nf-call-iptables`, image digest, tham số tải (data-model.md §2.2)
- [ ] T038 [US3] Viết `bench/configs.sh`: hàm `clear_all` (xdpfw unload, `iptables-legacy`/`iptables-nft` flush bảng raw+filter, `nft flush ruleset`) và `apply <config> <rules>` cho 8 giá trị của data-model.md §2.1 `config`, rule khớp attacker đặt **cuối** (research R9, FR-022)
- [ ] T039 [US3] Viết `bench/run_bench.sh`: tắt `bridge-nf-call-*` trong lúc đo và khôi phục khi thoát (trap) (research R6); bật `kernel.bpf_stats_enabled=1`; vòng lặp `experiment` × `config` × `rules` × `rep` (data-model.md §2.1 `experiment`, `rules`, `rep`); mỗi lần: `clear_all` → `apply` → trafgen (`load_mode` `max` 1 luồng ghim 1 CPU, hoặc `fixed` với `offered_pps`) 30 s bỏ 5 s đầu, song song `mpstat -P ALL 1` và đọc counter → ghi 1 dòng vào `raw.csv` đúng thứ tự cột data-model.md §2.1 → `clear_all`; biến `QUICK=1` ⇒ 1 lần/điểm, 10 s (research R7, FR-019–FR-021)
- [ ] T040 [US3] Trong `bench/run_bench.sh` cài đặt Đo 3 `legit_impact`: client chạy `ping -i 0.2` (tính `rtt_avg_ms`, `rtt_p99_ms`) và `iperf3 -t 10` (`legit_mbps`) trong lúc flood cố định (data-model.md §2.1 `rtt_avg_ms`, `rtt_p99_ms`, `legit_mbps`)
- [ ] T041 [P] [US3] Viết `bench/plot.py`: đọc `raw.csv` → `summary.csv` (mean, std, n theo `experiment`/`config`/`rules` — data-model.md §2.3) + 3 biểu đồ PNG: cột nhóm `drop_cost`, đường log-x `rule_scaling`, cột + error bar `legit_impact`
- [ ] T042 [US3] Thêm target `bench` (truyền `QUICK`) và `plot` vào `Makefile`; chạy `make bench QUICK=1` để chọn `offered_pps` cố định (mức baseline chưa bão hòa) và kiểm tra pipeline
- [ ] T043 [US3] Chạy `make bench` đầy đủ (≥ 3 lần/điểm) và `make plot`; commit `results/<run_id>/{raw.csv,summary.csv,env.txt,*.png}` (SC-006; ghi trung thực nếu SC-007/SC-008 không đạt — constitution V)
- [ ] T044 [US3] Sinh viên đọc hiểu `bench/run_bench.sh`, `bench/configs.sh` và giải thích được vì sao đo pps 1 luồng + CPU toàn hệ thống (research R7) (constitution V)

**Checkpoint**: Có đủ số liệu và biểu đồ cho chương thực nghiệm

---

## Phase 6: User Story 4 - Dựng lại lab & demo từ repo sạch (Priority: P4)

**Goal**: Một lệnh dựng lab trên máy sạch; kịch bản demo ≤ 10 phút

**Independent Test**: Clone repo sang thư mục mới → `make up` → làm theo `docs/demo-script.md`, bấm giờ (spec US4)

### Implementation for User Story 4

- [ ] T045 [US4] Hoàn thiện `make up`/`make down` trong `Makefile`: `up` = `prereq` + `build` + `docker compose up -d` + chờ healthcheck; `down` = `xdpfw unload` (bỏ qua lỗi) + `docker compose down -v` (FR-015)
- [ ] T046 [P] [US4] Viết `docs/demo-script.md`: 7 bước theo PROJECT_OVERVIEW.md mục 7 với lệnh copy-paste, kết quả mong đợi, thời lượng mỗi bước (FR-024)
- [ ] T047 [P] [US4] Viết `README.md`: mục tiêu, kiến trúc (link PROJECT_OVERVIEW.md), yêu cầu, `make up`, demo, test, benchmark, cấu trúc repo, hạn chế (FR-025)
- [ ] T048 [US4] Kiểm chứng từ repo sạch: `git clone` sang thư mục tạm, `make up`, kiểm tra 6 service chạy và dashboard có dữ liệu ≤ 5 phút, chạy hết demo-script và bấm giờ ≤ 10 phút, `make down` sạch (SC-005, SC-009)

**Checkpoint**: Mọi user story hoàn thành

---

## Phase 7: Polish & Cross-Cutting Concerns

- [ ] T049 [P] Rà comment trong `bpf/xdp_fw.c` và `internal/**/*.go`: mỗi điểm không hiển nhiên có giải thích "tại sao" (constitution V)
- [ ] T050 [P] Chạy `go vet ./...` và `gofmt -l .` trong container builder; sửa mọi cảnh báo
- [ ] T051 Chạy lại toàn bộ quickstart.md (mục 1–7) và cập nhật `CHECKLIST.md` với bằng chứng
- [ ] T052 Đề xuất sửa constitution PATCH cho nguyên tắc I ("CO-RE khi truy cập struct kernel") theo Complexity Tracking của plan.md, chờ sinh viên duyệt

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)** → **Foundational (Phase 2)** → các user story
- **US1 (P1)**: sau Phase 2 — không phụ thuộc story khác
- **US2 (P2)**: sau Phase 2; dùng `rules.go` của US1 để tạo rule khi test (T025) — kiểm thử độc lập được bằng cách thêm rule qua CLI
- **US3 (P3)**: cần US1 (chặn) để có cấu hình XDP; số đo đọc counter của US2 khi có, nếu không thì đọc trực tiếp map
- **US4 (P4)**: gom US1–US3; T046/T047 viết song song được
- **Polish**: sau các story mong muốn

### Within Each User Story

- Test viết trước, xác nhận FAIL, rồi cài đặt
- `internal/fw/*` trước `cmd/xdpfw/main.go`
- Task "sinh viên đọc hiểu" là điều kiện để đánh dấu story hoàn thành

### Parallel Opportunities

- Phase 2: T008, T009, T012, T013 song song (khác file) trong khi viết T005–T007
- US1: T016 ‖ T017
- US2: T024 ‖ T025; T030 ‖ T031
- US3: T035 ‖ T036 ‖ T037 ‖ T041
- US4: T046 ‖ T047

---

## Parallel Example: User Story 1

```bash
Task: "Viết internal/fw/fw_test.go (BPF_PROG_TEST_RUN) cho các loại gói"
Task: "Viết tests/functional.sh phần US1"
```

## Parallel Example: User Story 3

```bash
Task: "Viết bench/gen_ips.py"
Task: "Viết bench/flood.trafgen"
Task: "Viết bench/env.sh"
Task: "Viết bench/plot.py"
```

---

## Implementation Strategy

### MVP First (User Story 1)

1. Phase 1 + Phase 2 (T001–T015) — **T3 24/11 sáng**
2. Phase 3 US1 (T016–T023) — **T3 24/11 chiều** → DỪNG, kiểm chứng, demo bằng CLI

### Incremental Delivery (theo CHECKLIST.md)

1. US2 (T024–T034) — **T3 24/11 tối** → có dashboard
2. US3 (T035–T044) — **T4 25/11** → có số liệu + biểu đồ
3. US4 (T045–T048) + Polish — **T5 26/11 sáng** → sẵn sàng quay video

### Cắt giảm nếu trễ (constitution VI)

- Đo 3 chỉ chạy 4 cấu hình (baseline, xdp-native, ipt-legacy-filter, nft-set) — plan.md "Rủi ro"
- Bỏ T052 (chỉ là đề xuất)

---

## Notes

- Commit sau mỗi task hoặc nhóm task logic; cập nhật `CHECKLIST.md` kèm bằng chứng
- Mọi lệnh BPF/Docker chạy trong WSL Ubuntu (user root)
- Không viết nội dung báo cáo — chỉ code, script, tài liệu kỹ thuật (constitution V)
