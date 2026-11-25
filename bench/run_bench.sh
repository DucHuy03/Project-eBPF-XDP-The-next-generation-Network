#!/usr/bin/env bash
# Benchmark XDP firewall vs iptables/nftables (spec US3, research R6–R9, data-model.md §2).
#
#   make bench            # đầy đủ: 3 lần/điểm, đo 25 s sau 5 s khởi động
#   make bench QUICK=1    # thử nhanh: 1 lần/điểm, đo 10 s
#
# Biến môi trường ghi đè: REPS, DUR, WARMUP, RATE (pps tải cố định), EXPERIMENTS, CONFIGS_ONLY.
#
# Mỗi lần đo: clear_all -> apply <config> -> flood -> bỏ WARMUP giây -> đo DUR giây -> clear_all.
# Chỉ số (research R7 — trên veth, phần nhận gói chạy trên CPU của bên GỬI):
#   * load_mode=max   : trafgen 1 luồng không giới hạn => sent_pps cao hơn = lọc rẻ hơn
#   * load_mode=fixed : trafgen RATE pps => cpu_busy_pct (%sys+%irq+%soft cộng mọi CPU, 0–800)
#   * XDP thêm xdp_ns_per_pkt từ bpf_stats (chi phí thuần của chương trình)
#
# KHỐI B10 (benchmark) — docs/ARCHITECTURE.md §4. Đọc theo thứ tự: measure() -> plan() -> vòng lặp cuối.
set -uo pipefail
cd "$(dirname "$0")/.."

FW=xdplab-fw-node-1
AT=xdplab-attacker-1
CL=xdplab-client-1
SERVER_IP=10.10.2.20
ATTACKER_IP=10.10.1.66
source bench/configs.sh
source bench/env.sh

QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1
if [ $QUICK = 1 ]; then REPS=${REPS:-1}; DUR=${DUR:-10}; else REPS=${REPS:-3}; DUR=${DUR:-25}; fi
WARMUP=${WARMUP:-5}
RATE=${RATE:-200000}
EXPERIMENTS=${EXPERIMENTS:-"drop_cost rule_scaling legit_impact"}
RULE_COUNTS=(10 100 1000 10000)
read -r -a CFGS <<<"${CONFIGS_ONLY:-${CONFIGS[*]}}"
NCPU=$(nproc)

RUN_ID=$(date +%Y%m%d-%H%M%S)
OUT=results/$RUN_ID
TMP=results/tmp/$RUN_ID
mkdir -p "$OUT" "$TMP"
RAW=$OUT/raw.csv
echo "run_id,experiment,config,rules,load_mode,offered_pps,rep,sent_pps,dropped_pps,cpu_busy_pct,xdp_ns_per_pkt,rtt_avg_ms,rtt_p99_ms,legit_mbps,duration_s" >"$RAW"

log() { echo "[$(date +%H:%M:%S)] $*" >&2; }

# ---------- Chuẩn bị ----------
[ "$(id -u)" = 0 ] || { echo "cần chạy bằng root (sysctl, bpftool)" >&2; exit 2; }
docker inspect -f '{{.State.Running}}' "$FW" 2>/dev/null | grep -q true || { echo "lab chưa chạy (make up)" >&2; exit 2; }

# R6: tắt br_netfilter trong lúc đo, khôi phục khi thoát. Bật bpf_stats để đo ns/gói của XDP.
declare -A SAVED
for s in net.bridge.bridge-nf-call-iptables net.bridge.bridge-nf-call-ip6tables \
	net.bridge.bridge-nf-call-arptables kernel.bpf_stats_enabled; do
	SAVED[$s]=$(sysctl -n "$s" 2>/dev/null)
done
restore() {
	docker exec "$AT" pkill -INT -x trafgen >/dev/null 2>&1
	clear_all
	for s in "${!SAVED[@]}"; do [ -n "${SAVED[$s]}" ] && sysctl -qw "$s=${SAVED[$s]}"; done
	log "đã dọn rule và khôi phục sysctl"
}
trap restore EXIT
trap 'exit 130' INT TERM
sysctl -qw net.bridge.bridge-nf-call-iptables=0 net.bridge.bridge-nf-call-ip6tables=0 \
	net.bridge.bridge-nf-call-arptables=0 kernel.bpf_stats_enabled=1

# File cấu hình gói cho trafgen: MAC đích = MAC interface ngoài của fw-node.
IFACE=$(fw_iface)
FW_MAC=$(fwx cat "/sys/class/net/$IFACE/address")
sed "s/@FW_MAC@/$FW_MAC/" bench/flood.trafgen | docker exec -i "$AT" sh -c 'cat > /tmp/flood.cfg'

# Danh sách rule: N-1 IP không khớp (seed cố định) + IP attacker ở CUỐI (R9, trường hợp xấu nhất
# cho chuỗi tuyến tính của iptables).
for n in 1 "${RULE_COUNTS[@]}"; do
	{ [ "$n" -gt 1 ] && python3 bench/gen_ips.py $((n - 1)); echo "$ATTACKER_IP"; } >"$TMP/rules_$n.txt"
done

clear_all
write_env "$OUT/env.txt" "REPS=$REPS DUR=${DUR}s WARMUP=${WARMUP}s RATE=${RATE}pps QUICK=$QUICK frame=64B udp 1 flow"
# CPU nền khi không có tải (để trừ khi phân tích)
echo "idle_cpu_busy:   $(LC_ALL=C mpstat 1 5 | awk -v n="$NCPU" '/^Average/{printf "%.2f", ($5+$7+$8)*n}') (/$((NCPU * 100)), 5 s, không tải)" >>"$OUT/env.txt"

# ---------- Tải ----------
flood_start() { # $1 = pps (0 = không giới hạn)
	local b=""
	[ "$1" -gt 0 ] && b="-b ${1}pps"
	docker exec -d "$AT" sh -c "exec trafgen -i /tmp/flood.cfg -o eth0 -P 1 $b >/tmp/tg.log 2>&1"
}
flood_stop() {
	docker exec "$AT" pkill -INT -x trafgen >/dev/null 2>&1
	local i
	for i in 1 2 3 4 5 6 7 8 9 10; do
		docker exec "$AT" pgrep -x trafgen >/dev/null || return 0
		sleep 0.3
	done
	docker exec "$AT" pkill -KILL -x trafgen >/dev/null 2>&1
}

# Ảnh chụp bộ đếm: "<ns> <rx_packets fw> <drop_count> <xdp run_time_ns> <xdp run_cnt>"
# sent_pps = gói tới interface ngoài của fw-node. Đọc cùng một lần exec với bộ đếm drop, timestamp
# lấy bên trong container: đọc riêng ở attacker thì trễ `docker exec` (50–150 ms, dao động) làm
# lệch tỉ lệ drop/sent vài % ở tải cố định.
snapshot() { # $1 config, $2 xdp prog id (có thể rỗng)
	local x="0 0"
	[ -n "$2" ] && x=$(bpftool prog show id "$2" -j | jq -r '"\(.run_time_ns // 0) \(.run_cnt // 0)"')
	echo "$(fw_counters "$1" "$IFACE") $x"
}

cpu_of() { awk -v n="$NCPU" '/^Average/{printf "%.2f", ($5+$7+$8)*n}' "$1"; }

# Traffic hợp lệ của client (Đo 3): ping rồi iperf3, mỗi phần $1 giây. In "avg p99 mbps".
legit_traffic() {
	local t=$1 pings mbps
	pings=$(docker exec "$CL" ping -i 0.2 -c $((t * 5)) -W 1 "$SERVER_IP" 2>/dev/null |
		grep -oE 'time=[0-9.]+' | cut -d= -f2 | sort -n)
	mbps=$(docker exec "$CL" iperf3 -c "$SERVER_IP" -t "$t" -J 2>/dev/null |
		jq -r '(.end.sum_received.bits_per_second // empty) / 1e6 | . * 100 | round / 100' 2>/dev/null)
	if [ -n "$pings" ]; then
		echo "$pings" | awk -v m="${mbps}" '{a[NR]=$1; s+=$1}
			END{i=int(NR*0.99); if (i<NR*0.99) i++; if (i<1) i=1;
			    printf "%.3f %.3f %s\n", s/NR, a[i], m}'
	else
		echo "NA NA ${mbps:-NA}"
	fi
}

# ---------- Một lần đo ----------
# measure <experiment> <config> <rules> <load_mode max|fixed|none> <rep>
measure() {
	local exp=$1 cfg=$2 n=$3 mode=$4 rep=$5 rate=0 pid="" a b
	[ "$mode" = fixed ] && rate=$RATE
	clear_all
	if ! apply "$cfg" "$TMP/rules_$n.txt"; then
		log "FAIL apply $cfg n=$n — bỏ qua"; clear_all; return 1
	fi
	[[ $cfg == xdp-* ]] && pid=$(xdp_prog_id)
	[ "$mode" != none ] && flood_start "$rate"
	sleep "$WARMUP"

	local rtt_avg="" rtt_p99="" mbps="" lt
	a=$(snapshot "$cfg" "$pid")
	if [ "$exp" = legit_impact ]; then
		lt=$(( (DUR + 1) / 2 ))
		LC_ALL=C mpstat 1 $((2 * lt)) >"$TMP/mpstat" &
		read -r rtt_avg rtt_p99 mbps < <(legit_traffic "$lt")
		wait
		[ "$rtt_avg" = NA ] && rtt_avg="" && rtt_p99=""   # mất hết gói ping
		[ "$mbps" = NA ] && mbps=""                       # iperf3 không kết nối được
	else
		LC_ALL=C mpstat 1 "$DUR" >"$TMP/mpstat"
	fi
	b=$(snapshot "$cfg" "$pid")
	[ "$mode" != none ] && flood_stop
	clear_all

	# shellcheck disable=SC2086
	set -- $a $b   # $1..$5 = lần A, $6..$10 = lần B
	local secs sent drop ns=""
	secs=$(awk -v x="$1" -v y="$6" 'BEGIN{printf "%.2f", (y-x)/1e9}')
	sent=$(awk -v x="$2" -v y="$7" -v s="$secs" 'BEGIN{printf "%.0f", (y-x)/s}')
	drop=$(awk -v x="$3" -v y="$8" -v s="$secs" 'BEGIN{printf "%.0f", (y-x)/s}')
	[ -n "$pid" ] && ns=$(awk -v t0="$4" -v t1="$9" -v c0="$5" -v c1="${10}" \
		'BEGIN{ if (c1>c0) printf "%.1f", (t1-t0)/(c1-c0) }')
	local cpu; cpu=$(cpu_of "$TMP/mpstat")

	if [ "$mode" != none ] && [ "$sent" -lt 1000 ]; then
		log "WARN $cfg: trafgen gần như không gửi gói (sent=$sent pps) — xem /tmp/tg.log trong attacker"
	fi
	echo "$RUN_ID,$exp,$cfg,$n,$mode,$rate,$rep,$sent,$drop,$cpu,$ns,$rtt_avg,$rtt_p99,$mbps,$secs" >>"$RAW"
	log "$exp $cfg rules=$n $mode rep=$rep: sent=${sent}pps drop=${drop}pps cpu=$cpu ns/pkt=${ns:--} rtt=${rtt_avg:--}/${rtt_p99:--}ms tput=${mbps:--}Mbps"
}

# ---------- Ma trận đo ----------
# Lặp `rep` ở ngoài cùng để độ trôi theo thời gian (nhiệt, nền) chia đều cho mọi cấu hình.
plan() {
	local rep exp cfg n mode
	for rep in $(seq 1 "$REPS"); do
		for exp in $EXPERIMENTS; do
			for cfg in "${CFGS[@]}"; do
				case $exp in
				drop_cost)
					for mode in max fixed; do echo "$exp $cfg 1 $mode $rep"; done ;;
				rule_scaling)
					[ "$cfg" = baseline ] && continue
					for n in "${RULE_COUNTS[@]}"; do
						for mode in max fixed; do echo "$exp $cfg $n $mode $rep"; done
					done ;;
				legit_impact)
					# none = không flood: tách chi phí của chính bộ lọc (vd. XDP trên veth làm mất
					# GRO/TSO) khỏi tác động của flood.
					for mode in none fixed; do echo "$exp $cfg 1 $mode $rep"; done ;;
				esac
			done
		done
	done
}

mapfile -t STEPS < <(plan)
total=${#STEPS[@]}
log "run_id=$RUN_ID: $total lần đo, mỗi lần ~$((WARMUP + DUR + 5)) s => ~$((total * (WARMUP + DUR + 5) / 60)) phút"
i=0
for s in "${STEPS[@]}"; do
	i=$((i + 1))
	log "($i/$total)"
	# shellcheck disable=SC2086
	measure $s
done

log "xong: $RAW ($(($(wc -l <"$RAW") - 1)) dòng). Vẽ biểu đồ: make plot"
