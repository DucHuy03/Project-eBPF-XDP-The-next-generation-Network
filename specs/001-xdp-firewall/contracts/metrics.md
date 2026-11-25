# Contract: Prometheus metrics (`xdpfw serve`)

Endpoint `GET http://<fw-node mgmt IP>:9100/metrics`, định dạng text exposition của Prometheus.
Giá trị đọc trực tiếp từ BPF map tại thời điểm scrape (cộng dồn mọi CPU).

| Metric | Kiểu | Label | Ý nghĩa |
|---|---|---|---|
| `xdpfw_up` | gauge | — | 1 nếu firewall đang nạp (map đã pin), 0 nếu không |
| `xdpfw_packets_total` | counter | `action` ∈ {`pass`,`drop_ip`,`drop_port`,`parse_err`} | Số gói theo kết quả |
| `xdpfw_bytes_total` | counter | `action` | Số byte theo kết quả |
| `xdpfw_rule_packets_total` | counter | `id`, `type` ∈ {`ip`,`port`}, `match` | Số gói khớp mỗi rule |
| `xdpfw_rule_bytes_total` | counter | `id`, `type`, `match` | Số byte khớp mỗi rule |
| `xdpfw_rules` | gauge | `type` | Số rule đang hiệu lực |
| `xdpfw_info` | gauge (=1) | `iface`, `mode`, `prog_id` | Thông tin phiên gắn |

- Khi `xdpfw_up == 0`, chỉ xuất `xdpfw_up` (không xuất counter cũ).
- Counter đặt lại về 0 khi `unload`/`load` lại hoặc `flush` — Prometheus `rate()` xử lý reset.
- Prometheus scrape mỗi **1 s** (đáp ứng SC-004 ≤ 5 s).

## Dashboard Grafana (provision sẵn)

| Panel | Truy vấn |
|---|---|
| Packets/s theo action | `sum by (action) (rate(xdpfw_packets_total[5s]))` |
| Bytes/s theo action | `sum by (action) (rate(xdpfw_bytes_total[5s]))` |
| Top rule bị khớp | `topk(10, rate(xdpfw_rule_packets_total[5s]))` |
| Trạng thái | `xdpfw_up`, `xdpfw_info`, `xdpfw_rules` |
