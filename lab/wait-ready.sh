#!/usr/bin/env bash
# Chờ lab sẵn sàng sau `docker compose up -d` (gọi từ `make up`, FR-015 / SC-005).
# Sẵn sàng = client tải được web của server qua fw-node, Prometheus scrape được exporter
# của fw-node, và Grafana trả lời /api/health. Hết TIMEOUT giây thì báo lỗi.
# KHỐI B9 (lab) — docs/ARCHITECTURE.md §4. Kiểm cả 3 đường: client→fw-node→server,
# Prometheus→B7, trình duyệt→Grafana.
set -uo pipefail

TIMEOUT=${TIMEOUT:-180}
start=$(date +%s)

web_ok()  { docker exec xdplab-client-1 curl -sf -m 2 http://10.10.2.20/ >/dev/null 2>&1; }
prom_ok() { curl -sf -m 2 'http://127.0.0.1:9090/api/v1/query?query=up%7Bjob%3D%22xdpfw%22%7D' 2>/dev/null \
              | grep -q '"value":\[[0-9.]*,"1"\]'; }
graf_ok() { curl -sf -m 2 http://127.0.0.1:3000/api/health 2>/dev/null | grep -q '"database": *"ok"'; }

for name in web prom graf; do
	until ${name}_ok; do
		if [ $(( $(date +%s) - start )) -ge "$TIMEOUT" ]; then
			echo "wait-ready: '$name' chưa sẵn sàng sau ${TIMEOUT}s — xem: make logs" >&2
			exit 1
		fi
		sleep 1
	done
done
echo "lab ready sau $(( $(date +%s) - start ))s: web ok, prometheus scrape ok, grafana ok"
echo "  Grafana:    http://localhost:3000   (dashboard 'XDP Firewall', không cần đăng nhập)"
echo "  Prometheus: http://localhost:9090"
