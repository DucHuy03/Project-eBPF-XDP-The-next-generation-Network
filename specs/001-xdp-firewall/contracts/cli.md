# Contract: `xdpfw` CLI

Binary duy nhất, chạy trong container `fw-node` với quyền root. Mọi lệnh trừ `load`/`version`
yêu cầu firewall đã được nạp (map đã pin), nếu không → lỗi mã 3.

## Lệnh

| Lệnh | Tham số | Kết quả thành công (stdout) |
|---|---|---|
| `xdpfw load` | `--iface <name>` (bắt buộc) · `--mode generic\|native` (mặc định `native`) | `loaded on <iface> (ifindex N) mode=<mode> prog_id=<id>` |
| `xdpfw unload` | — | `unloaded from <iface>` |
| `xdpfw status` | — | interface, mode, prog_id, thời điểm gắn, số rule IP/port |
| `xdpfw block-ip <CIDR>` | `10.10.1.66` hoặc `10.10.1.0/24` (không có `/` ⇒ `/32`) | `added ip rule id=<n> <cidr>` |
| `xdpfw unblock-ip <CIDR>` | như trên | `removed ip rule id=<n> <cidr>` |
| `xdpfw block-port <tcp\|udp> <port>` | port 1–65535 | `added port rule id=<n> <proto>/<port>` |
| `xdpfw unblock-port <tcp\|udp> <port>` | | `removed port rule id=<n> <proto>/<port>` |
| `xdpfw list` | `--json` (tùy chọn) | Bảng: `ID  TYPE  MATCH  PACKETS  BYTES` |
| `xdpfw stats` | `--json` (tùy chọn) | Bảng: `ACTION  PACKETS  BYTES` cho `pass`, `drop_ip`, `drop_port`, `parse_err` |
| `xdpfw flush` | — | Xóa mọi rule, đặt lại mọi bộ đếm |
| `xdpfw serve` | `--listen <addr>` (mặc định `:9100`) | Chạy exporter (mục metrics.md); chạy được cả khi chưa nạp firewall |
| `xdpfw version` | — | phiên bản + commit |

## Mã thoát

| Mã | Ý nghĩa |
|---|---|
| 0 | Thành công |
| 1 | Lỗi chung / lỗi hệ thống (kernel từ chối, verifier, quyền) |
| 2 | Tham số không hợp lệ (CIDR/port/proto/mode sai, thiếu `--iface`) |
| 3 | Firewall chưa được nạp |
| 4 | Xung đột: rule đã tồn tại, rule không tồn tại, interface đã có chương trình XDP |
| 5 | Bảng rule đầy |

Mọi thông báo lỗi in ra **stderr**, dạng `xdpfw: <lệnh>: <mô tả>` (+ gợi ý nếu có, ví dụ
`native mode not supported on <iface>; try --mode generic`).

## Định dạng `--json`

```json
// xdpfw stats --json
{"pass":{"packets":0,"bytes":0},"drop_ip":{"packets":0,"bytes":0},
 "drop_port":{"packets":0,"bytes":0},"parse_err":{"packets":0,"bytes":0}}

// xdpfw list --json
[{"id":0,"type":"ip","match":"10.10.1.66/32","packets":0,"bytes":0},
 {"id":16384,"type":"port","match":"udp/9999","packets":0,"bytes":0}]
```

## Hành vi đảm bảo

- `block-*`/`unblock-*` chỉ ghi map; **không** nạp lại chương trình; có hiệu lực với gói tiếp theo.
- `block-ip 10.0.0.5/24` → chuẩn hóa thành `10.0.0.0/24` và in cảnh báo ra stderr (mã 0).
- `unload` xóa toàn bộ pin; interface chuyển gói bình thường ngay sau đó.
