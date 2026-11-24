#!/usr/bin/env bash
# Functional test trên lab đang chạy (`make up` trước). Kiểm tra acceptance
# scenarios của US1 (chặn) và US2 (bộ đếm) trong spec.md.
# Chạy: make test        (cần root trong WSL/Linux, cần jq)
set -uo pipefail

FW=xdplab-fw-node-1
CLIENT=xdplab-client-1
ATTACKER=xdplab-attacker-1
SERVER_IP=10.10.2.20
ATTACKER_IP=10.10.1.66
MODE=${MODE:-native}

pass=0; fail=0
ok()   { echo "  PASS  $*"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail+1)); }
check(){ local desc=$1; shift; if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi; }
check_not(){ local desc=$1; shift; if "$@" >/dev/null 2>&1; then bad "$desc"; else ok "$desc"; fi; }

fw()       { docker exec "$FW" xdpfw "$@"; }
reach()    { docker exec "$1" ping -c 2 -W 1 -q "$SERVER_IP"; }     # 2 gói, đủ 1 gói về là thành công
web()      { docker exec "$CLIENT" curl -sf -m 3 "http://$SERVER_IP/"; }
stat_of()  { fw stats --json | jq -r ".${1}.packets"; }
udp_to()   { docker exec "$1" hping3 -2 -p "$2" -c "$3" -i u20000 -q "$SERVER_IP" >/dev/null 2>&1; }
tcp_to()   { docker exec "$1" hping3 -S -p "$2" -c "$3" -i u20000 -q "$SERVER_IP" >/dev/null 2>&1; }

docker inspect -f '{{.State.Running}}' "$FW" 2>/dev/null | grep -q true || { echo "lab is not running (make up)"; exit 2; }
IFACE=$(docker exec "$FW" cat /run/xdp_iface)

fw unload >/dev/null 2>&1
trap 'fw unload >/dev/null 2>&1' EXIT

echo "== US1-1: không có rule — mọi node tới được server"
fw load --iface "$IFACE" --mode "$MODE" >/dev/null || { echo "load failed"; exit 1; }
check "client tới được server"   reach "$CLIENT"
check "attacker tới được server" reach "$ATTACKER"
check "client tải được trang web" web

echo "== US1-6: chạy đúng chế độ đã chọn ($MODE)"
check "status báo mode=$MODE" sh -c "docker exec $FW xdpfw status | grep -q 'mode: *$MODE'"
want=$([ "$MODE" = native ] && echo driver || echo generic)
check "kernel báo XDP $want" sh -c "docker exec $FW bpftool net show dev $IFACE | grep -q '$want id'"

echo "== US1-2: chặn IP attacker /32"
fw block-ip "$ATTACKER_IP" >/dev/null
check_not "attacker bị chặn"            reach "$ATTACKER"
check     "client vẫn tới được server"  reach "$CLIENT"
check     "client vẫn tải được web"     web
fw unblock-ip "$ATTACKER_IP" >/dev/null

echo "== US1-3: chặn subnet 10.10.1.64/26 (chứa .66, không chứa .10)"
fw block-ip 10.10.1.64/26 >/dev/null
check_not "attacker trong subnet bị chặn" reach "$ATTACKER"
check     "client ngoài subnet không bị ảnh hưởng" reach "$CLIENT"
fw unblock-ip 10.10.1.64/26 >/dev/null

echo "== US1-4: chặn udp/9999 — tcp/9999 và udp/khác vẫn qua"
fw block-port udp 9999 >/dev/null
d0=$(stat_of drop_port); p0=$(stat_of pass)
udp_to "$CLIENT" 9999 20
d1=$(stat_of drop_port)
check "20 gói udp/9999 bị drop (drop_port +$((d1-d0)))" test $((d1-d0)) -eq 20
tcp_to "$CLIENT" 9999 20; udp_to "$CLIENT" 9998 20
d2=$(stat_of drop_port); p2=$(stat_of pass)
check "tcp/9999 và udp/9998 không bị drop (drop_port +$((d2-d1)))" test $((d2-d1)) -eq 0
check "40 gói đó được PASS (pass +$((p2-p0)) >= 40)" test $((p2-p0)) -ge 40
fw unblock-port udp 9999 >/dev/null

echo "== US1-5: đổi rule khi đang chạy — client không mất gói, attacker thông lại ≤ 1 s"
docker exec "$CLIENT" sh -c "ping -i 0.2 -c 25 -q $SERVER_IP > /tmp/live.txt 2>&1" &
ping_pid=$!
sleep 1
fw block-ip "$ATTACKER_IP" >/dev/null
check_not "attacker bị chặn khi rule vừa thêm" docker exec "$ATTACKER" ping -c 1 -W 1 -q "$SERVER_IP"
t0=$(date +%s%N)
fw unblock-ip "$ATTACKER_IP" >/dev/null
check "attacker thông lại ngay sau unblock" docker exec "$ATTACKER" ping -c 1 -W 1 -q "$SERVER_IP"
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
check "thời gian từ unblock tới khi ping được: ${ms} ms (≤ 1000)" test "$ms" -le 1000
wait "$ping_pid"
loss=$(docker exec "$CLIENT" grep -oE '[0-9.]+% packet loss' /tmp/live.txt)
check "ping liên tục của client: $loss" sh -c "echo '$loss' | grep -q '^0% packet loss'"

echo "== US2-1: bộ đếm khớp chính xác 1000 gói"
fw flush >/dev/null
fw block-ip "$ATTACKER_IP" >/dev/null
p0=$(stat_of pass)
docker exec "$ATTACKER" ping -c 1000 -i 0.002 -W 1 -q "$SERVER_IP" >/dev/null 2>&1
d=$(stat_of drop_ip); p1=$(stat_of pass)
check "drop_ip = $d (đúng 1000)" test "$d" -eq 1000
check "pass không tính gói attacker (pass +$((p1-p0)) < 50)" test $((p1-p0)) -lt 50

echo "== US2-2: list hiện rule kèm số lần khớp"
hits=$(fw list --json | jq -r ".[] | select(.match==\"$ATTACKER_IP/32\") | .packets")
check "rule $ATTACKER_IP/32 có packets = $hits" test "$hits" = 1000

echo "== US2-3: exporter xuất counter"
metrics=$(docker exec "$FW" curl -s 10.10.9.254:9100/metrics)
check "xdpfw_up 1"            sh -c "echo '$metrics' | grep -q '^xdpfw_up 1'"
check "drop_ip = 1000 trên /metrics" sh -c "echo '$metrics' | grep -q '^xdpfw_packets_total{action=\"drop_ip\"} 1000$'"

echo "== Kiểm tra đầu vào sai (mã thoát theo contract)"
code() { docker exec "$FW" xdpfw "$@" >/dev/null 2>&1; echo $?; }
check "CIDR sai -> 2"         test "$(code block-ip 10.0.0.300/24)" = 2
check "port sai -> 2"         test "$(code block-port udp 70000)" = 2
check "rule trùng -> 4"       test "$(code block-ip $ATTACKER_IP)" = 4
check "xóa rule không có -> 4" test "$(code unblock-port tcp 1)" = 4

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
