#!/bin/sh
# Node trong lab. ROLE=client|attacker|server.
# Mạng ext/int là mạng "internal" (không ra Internet), nên mỗi node chỉ cần một
# route tới mạng bên kia qua fw-node (.254).
set -eu

case "${ROLE:-}" in
  client|attacker)
    ip route replace 10.10.2.0/24 via 10.10.1.254
    ;;
  server)
    ip route replace 10.10.1.0/24 via 10.10.2.254
    echo "<h1>XDP lab server</h1>" > /var/www/html/index.html
    nginx                      # web :80 (tự chạy nền)
    iperf3 -s -D               # điểm đo thông lượng :5201
    ;;
  *)
    echo "ROLE must be client, attacker or server" >&2; exit 1
    ;;
esac

echo "node ready: role=$ROLE"
exec sleep infinity
