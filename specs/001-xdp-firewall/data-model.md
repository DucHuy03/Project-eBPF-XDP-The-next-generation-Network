# Data Model: XDP Firewall (001-xdp-firewall)

Hai lớp dữ liệu: **BPF maps** (trạng thái chia sẻ giữa kernel và user space) và **file kết quả
benchmark**. Không có cơ sở dữ liệu; rule không lưu bền (spec — Assumptions).

## 1. BPF maps (pin tại `/sys/fs/bpf/xdpfw/`)

### 1.1 `blocked_src` — rule chặn IP/subnet nguồn

| Thuộc tính | Giá trị |
|---|---|
| Kiểu | `BPF_MAP_TYPE_LPM_TRIE` (cờ `BPF_F_NO_PREALLOC` — bắt buộc với LPM) |
| Key | `struct lpm_v4_key { __u32 prefixlen; __u32 addr; }` — `addr` theo network byte order |
| Value | `__u32 rule_id` (0 … 16383) |
| max_entries | 16384 (≥ 10.000 theo FR-005) |

- **Validation** (user space): prefixlen 0–32; bit host phải bằng 0 sau khi chuẩn hóa
  (`10.0.0.5/24` → lưu `10.0.0.0/24`, báo cho người dùng); trùng key → lỗi "rule đã tồn tại".
- **Tra cứu**: LPM trả về prefix **dài nhất** khớp → số lần khớp được tính cho rule cụ thể nhất (edge case CIDR lồng nhau).

### 1.2 `blocked_port` — rule chặn port đích theo giao thức

| Thuộc tính | Giá trị |
|---|---|
| Kiểu | `BPF_MAP_TYPE_HASH` |
| Key | `struct port_key { __u8 proto; __u8 pad; __u16 dport; }` — `proto` ∈ {6 TCP, 17 UDP}; `dport` network byte order; `pad` = 0 |
| Value | `__u32 rule_id` (16384 … 17407) |
| max_entries | 1024 (≥ 1.000 theo FR-005) |

- **Validation**: proto ∈ {tcp, udp}; port 1–65535; trùng key → lỗi.

### 1.3 `stats` — bộ đếm theo kết quả

| Thuộc tính | Giá trị |
|---|---|
| Kiểu | `BPF_MAP_TYPE_PERCPU_ARRAY` |
| Key | `__u32` chỉ số kết quả: `0 PASS`, `1 DROP_IP`, `2 DROP_PORT`, `3 PARSE_ERR` |
| Value | `struct counter { __u64 packets; __u64 bytes; }` (mỗi CPU một bản) |
| max_entries | 4 |

- `PARSE_ERR` = gói IPv4 bị cụt/hỏng header → vẫn `XDP_PASS` (FR-004). Gói không phải IPv4 được
  tính vào `PASS`.
- User space cộng dồn qua mọi CPU khi đọc.

### 1.4 `rule_hits` — bộ đếm theo rule

| Thuộc tính | Giá trị |
|---|---|
| Kiểu | `BPF_MAP_TYPE_PERCPU_ARRAY` |
| Key | `__u32 rule_id` |
| Value | `struct counter` |
| max_entries | 17408 (= 16384 IP + 1024 port) |

- Khi xóa rule, user space **đặt lại về 0** bộ đếm của `rule_id` đó để id được tái sử dụng sạch.

### 1.5 Cấp phát `rule_id`

- Hai dải tách biệt: IP `[0, 16384)`, port `[16384, 17408)`.
- `block-*` quét map tương ứng, lấy **id nhỏ nhất chưa dùng** → không cần file trạng thái riêng.
- Dải đầy → lỗi "bảng rule đầy" (edge case), rule cũ không bị ảnh hưởng.

### 1.6 Phiên gắn firewall

| Trường | Nguồn |
|---|---|
| interface | tên + ifindex, lưu trong `/sys/fs/bpf/xdpfw/meta.json` |
| mode | `generic` \| `native` |
| attached_at | thời điểm RFC 3339 |
| link | bpf_link pin tại `/sys/fs/bpf/xdpfw/link` |

**Trạng thái**:

```
(không gắn) --load--> (đã gắn: generic|native) --unload--> (không gắn)
     ^                         |
     └──── load lần 2 khi đã gắn → lỗi "đã gắn", không ghi đè
```

## 2. Kết quả benchmark

### 2.1 File thô `results/<run_id>/raw.csv` — mỗi dòng một lần đo

| Cột | Kiểu | Ý nghĩa |
|---|---|---|
| `run_id` | string | `YYYYMMDD-HHMMSS` của cả đợt |
| `experiment` | enum | `drop_cost` \| `rule_scaling` \| `legit_impact` |
| `config` | enum | `baseline`, `xdp-native`, `xdp-generic`, `ipt-legacy-raw`, `ipt-legacy-filter`, `ipt-nft-raw`, `ipt-nft-filter`, `nft-set` |
| `rules` | int | số rule đã cài (1 cho Đo 1/3; 10/100/1000/10000 cho Đo 2) |
| `load_mode` | enum | `max` (không giới hạn, 1 luồng) \| `fixed` \| `none` (Đo 3: không flood — mốc tách chi phí của chính bộ lọc khỏi tác động của flood) |
| `offered_pps` | int | tốc độ tải đặt (0 nếu `max`/`none`; mặc định 200 000 — baseline chưa bão hòa ở mức này) |
| `rep` | int | lần lặp 1…N |
| `sent_pps` | float | pps tới interface ngoài của fw-node (`rx_packets`), đọc **cùng một lần exec** với bộ đếm drop để tỉ lệ drop/sent không lệch do trễ `docker exec` |
| `dropped_pps` | float | pps bị loại bỏ đo tại firewall (bộ đếm XDP hoặc iptables/nft) |
| `cpu_busy_pct` | float | `%sys + %irq + %soft` cộng trên mọi CPU (0–800), `mpstat` trên host |
| `xdp_ns_per_pkt` | float | từ bpf_stats (trống nếu không phải XDP) |
| `rtt_avg_ms`, `rtt_p99_ms` | float | Đo 3: ping của client |
| `legit_mbps` | float | Đo 3: iperf3 của client |
| `duration_s` | float | thời lượng đo thực tế giữa hai lần đọc bộ đếm |

### 2.2 File môi trường `results/<run_id>/env.txt`

Kernel, phiên bản clang/Go/bpftool/iptables/nft/trafgen, model CPU, `nproc`, nội dung `.wslconfig`,
giá trị `bridge-nf-call-iptables` lúc đo, image digest, tham số tải.

### 2.3 Tổng hợp `results/<run_id>/summary.csv` và biểu đồ `results/<run_id>/*.png`

Nhóm theo (`experiment`, `config`, `rules`) → `mean`, `std`, `n` cho mỗi chỉ số; sinh bằng `make plot`.
