# Quickstart & Validation: XDP Firewall (001-xdp-firewall)

Hướng dẫn chạy và kiểm chứng end-to-end. Chi tiết lệnh: [contracts/cli.md](contracts/cli.md);
metric: [contracts/metrics.md](contracts/metrics.md); dữ liệu: [data-model.md](data-model.md).

## 0. Yêu cầu

- Linux hoặc WSL2 (kernel ≥ 5.15, có BTF), quyền root/sudo, Docker Engine + Compose plugin, `make`.
- Trên WSL2: đã cấu hình như Ngày 0 trong `CHECKLIST.md`.

## 1. Dựng lab (US4 — SC-005)

```bash
make up          # modprobe module cần thiết, build image, docker compose up -d
docker compose -f lab/docker-compose.yml ps   # kỳ vọng: 6 service "running"
```

Mở Grafana `http://localhost:3000` (dashboard "XDP Firewall" có sẵn, đăng nhập ẩn danh chỉ xem).

## 2. Chặn tấn công (US1 — SC-001, SC-002)

```bash
make shell-fw                                   # vào fw-node
xdpfw load --iface <if-ext> --mode native       # <if-ext>: interface có IP 10.10.1.254
xdpfw status                                    # kỳ vọng: mode=native
xdpfw block-ip 10.10.1.66
xdpfw block-port udp 9999
xdpfw list
```

Kỳ vọng:
- `docker exec attacker ping -c 3 10.10.2.20` → 100% loss.
- `docker exec client curl -s 10.10.2.20` → trả về trang web; `ping` → 0% loss.
- `xdpfw unblock-ip 10.10.1.66` → attacker ping được lại trong ≤ 1 s.

## 3. Quan sát (US2 — SC-003, SC-004)

```bash
xdpfw stats                        # ghi nhớ drop_ip
docker exec attacker ping -c 1000 -i 0.002 -q 10.10.2.20
xdpfw stats                        # drop_ip tăng đúng 1000
curl -s localhost:9100/metrics | grep xdpfw_packets_total    # từ trong mạng mgmt / qua Prometheus
```

Grafana: đường `drop_ip` tăng trong ≤ 5 s.

## 4. Kiểm thử tự động

```bash
make test-bpf    # BPF_PROG_TEST_RUN: gói IPv4/IPv6/ARP/cụt/options/ICMP → action + bộ đếm đúng
make test        # functional test trên lab đang chạy (US1 + US2 acceptance scenarios)
```

Kỳ vọng: mọi test `PASS`, mã thoát 0.

## 5. Benchmark (US3 — SC-006..SC-008)

```bash
make bench QUICK=1    # 1 lần/điểm, kiểm tra pipeline (~10 phút)
make bench            # đầy đủ ≥ 3 lần/điểm (≤ 2 giờ)
make plot             # results/<run_id>/summary.csv + *.png
```

Kỳ vọng: `raw.csv` có dòng cho mọi tổ hợp (8 cấu hình × 3 phép đo × mức rule); `env.txt` ghi môi trường.

## 6. Demo (US4 — SC-009)

Làm theo `docs/demo-script.md`, bấm giờ: ≤ 10 phút.

## 7. Dỡ lab

```bash
make down        # gỡ XDP, xóa container + mạng
```
