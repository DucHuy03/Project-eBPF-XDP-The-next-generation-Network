#!/usr/bin/env bash
# Trợ giúp cho kịch bản demo (docs/demo-script.md). Dùng lại đúng các hàm cấu hình của
# benchmark (bench/configs.sh) để số liệu trong demo khớp cách đo trong báo cáo.
#
#   lab/demo.sh flood [pps]          attacker bắn UDP 64 B tới server (mặc định 200000 pps; 0 = tối đa)
#   lab/demo.sh stop                 dừng flood
#   lab/demo.sh use <config> [N]     gỡ mọi bộ lọc rồi cài <config> với N rule (rule khớp attacker ở cuối)
#   lab/demo.sh watch [giây]         mỗi giây: pps tới fw-node, pps bị drop, CPU toàn hệ thống
#   lab/demo.sh clear                gỡ mọi bộ lọc (XDP, iptables, nft)
#
# <config>: baseline xdp-native xdp-generic ipt-legacy-raw ipt-legacy-filter ipt-nft-raw ipt-nft-filter nft-set
# Chạy từ thư mục gốc repo, với root trong WSL/Linux, khi lab đang chạy (make up).
# KHỐI B11 (demo) — docs/ARCHITECTURE.md §4. Dùng chung configs.sh với B10.
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=../bench/configs.sh
source bench/configs.sh

AT=xdplab-attacker-1
ATTACKER_IP=10.10.1.66
STATE=/tmp/xdplab-demo.cfg   # cấu hình đang dùng, để `watch` biết đọc bộ đếm nào
FLOOD=/tmp/xdplab-demo.flood # pps của flood đang chạy (rỗng = không flood)
NCPU=$(nproc)

# Cấu hình đang dùng. XDP nạp tay bằng `xdpfw load` (bước 3 của demo) cũng được nhận ra.
current() {
	local mode s
	mode=$(fwx xdpfw status 2>/dev/null | awk -F': *' '$1 ~ /mode/{print $2; exit}')
	if [ -n "$mode" ]; then echo "xdp-$mode"; return; fi
	s=$(cat "$STATE" 2>/dev/null || echo baseline)
	case $s in xdp-*) echo baseline ;; *) echo "$s" ;; esac
}

cmd_flood() {
	local pps=${1:-200000} iface mac b=""
	iface=$(fw_iface); mac=$(fwx cat "/sys/class/net/$iface/address")
	sed "s/@FW_MAC@/$mac/" bench/flood.trafgen | docker exec -i "$AT" sh -c 'cat > /tmp/flood.cfg'
	docker exec "$AT" pkill -x trafgen >/dev/null 2>&1 && sleep 0.5
	[ "$pps" -gt 0 ] && b="-b ${pps}pps"
	docker exec -d "$AT" sh -c "exec trafgen -i /tmp/flood.cfg -o eth0 -P 1 $b >/tmp/tg.log 2>&1"
	echo "$pps" >"$FLOOD"
	echo "flood: attacker $ATTACKER_IP -> 10.10.2.20 udp/9999, $([ "$pps" -gt 0 ] && echo "$pps pps" || echo 'tối đa')"
}

cmd_stop() { docker exec "$AT" pkill -INT -x trafgen >/dev/null 2>&1; rm -f "$FLOOD"; echo "flood: đã dừng"; }

cmd_use() {
	local cfg=${1:?thiếu <config>} n=${2:-1} f
	f=$(mktemp)
	{ [ "$n" -gt 1 ] && python3 bench/gen_ips.py $((n - 1)); echo "$ATTACKER_IP"; } >"$f"
	clear_all
	# br_netfilter=0 như lúc benchmark, để iptables không xử lý thêm frame trên bridge (research R6)
	sysctl -qw net.bridge.bridge-nf-call-iptables=0 net.bridge.bridge-nf-call-ip6tables=0
	apply "$cfg" "$f" || { rm -f "$f"; echo "cài $cfg thất bại" >&2; exit 1; }
	rm -f "$f"
	echo "$cfg" >"$STATE"
	# trafgen không giữ đúng tốc độ -b khi chi phí phía nhận đổi giữa chừng => khởi động lại
	# flood sau mỗi lần đổi cấu hình, giống benchmark (mỗi lần đo một tiến trình trafgen mới).
	[ -s "$FLOOD" ] && cmd_flood "$(cat "$FLOOD")" >/dev/null
	echo "đang dùng: $cfg với $n rule (rule khớp attacker đặt cuối)"
}

cmd_clear() { clear_all; echo baseline >"$STATE"; echo "đã gỡ mọi bộ lọc"; }

cmd_watch() {
	local secs=${1:-10} cfg iface a b cpu i
	cfg=$(current); iface=$(fw_iface)
	printf '%-18s %12s %12s %10s\n' "config" "tới fw (pps)" "drop (pps)" "CPU /$((NCPU * 100))"
	for ((i = 0; i < secs; i++)); do
		a=$(fw_counters "$cfg" "$iface")
		cpu=$(LC_ALL=C mpstat 1 1 | awk -v n="$NCPU" '/^Average/{printf "%.0f", ($5+$7+$8)*n}')
		b=$(fw_counters "$cfg" "$iface")
		# a, b = "<ns> <rx_packets> <drop>"; tính tốc độ theo đồng hồ bên trong container
		echo "$a $b" | awk -v c="$cfg" -v cpu="$cpu" '{dt=($4-$1)/1e9;
			printf "%-18s %12.0f %12.0f %10s\n", c, ($5-$2)/dt, ($6-$3)/dt, cpu}'
	done
}

case ${1:-} in
flood) shift; cmd_flood "$@" ;;
stop)  cmd_stop ;;
use)   shift; cmd_use "$@" ;;
watch) shift; cmd_watch "$@" ;;
clear) cmd_clear ;;
*) sed -n '2,13p' "$0"; exit 2 ;;
esac
