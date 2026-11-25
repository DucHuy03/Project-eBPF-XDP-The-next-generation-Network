# shellcheck shell=bash
# Bật/tắt 8 cấu hình lọc trên fw-node cho benchmark (research R9, data-model.md §2.1 `config`).
# File này được `source` bởi run_bench.sh; mọi lệnh chạy trong container fw-node qua docker exec.
# KHỐI B10 (benchmark) — docs/ARCHITECTURE.md §4. Thư viện dùng chung cho B10 và B11 (demo).
#
#   clear_all                     gỡ mọi chương trình/rule lọc (FR-022)
#   apply <config> <rules_file>   cài rule; rules_file: mỗi dòng 1 IP, IP attacker ở DÒNG CUỐI
#   drop_count <config>           tổng số gói đã bị cấu hình đó drop (đọc bộ đếm của chính nó)

FW=${FW:-xdplab-fw-node-1}
CONFIGS=(baseline xdp-native xdp-generic ipt-legacy-raw ipt-legacy-filter ipt-nft-raw ipt-nft-filter nft-set)

fwx() { docker exec -i "$FW" "$@"; }
fw_iface() { fwx cat /run/xdp_iface; }

clear_all() {
	fwx xdpfw unload >/dev/null 2>&1
	local b
	for b in legacy nft; do
		# Chỉ flush bảng raw và filter. KHÔNG đụng bảng nat: Docker cài rule DNS nội bộ ở đó.
		fwx iptables-$b -t raw -F >/dev/null 2>&1
		fwx iptables-$b -t filter -F >/dev/null 2>&1
	done
	# Chỉ xóa bảng của benchmark, không `nft flush ruleset` (cũng sẽ xóa rule DNS của Docker).
	fwx nft delete table inet bench >/dev/null 2>&1
	return 0
}

# Sinh input cho iptables-restore: mọi IP thành rule DROP, giữ nguyên thứ tự (khớp ở cuối).
_ipt_restore_input() { # $1 table, $2 chain, $3 rules_file
	echo "*$1"
	sed '/^$/d; s|.*|-A '"$2"' -s &/32 -j DROP|' "$3"
	echo "COMMIT"
}

apply() { # $1 config, $2 rules_file
	local cfg=$1 rules=$2
	case $cfg in
	baseline) ;;
	xdp-native | xdp-generic)
		fwx xdpfw load --iface "$(fw_iface)" --mode "${cfg#xdp-}" >/dev/null || return 1
		fwx sh -c 'cat > /tmp/rules.txt' <"$rules"
		fwx xdpfw block-ip --file /tmp/rules.txt >/dev/null || return 1
		;;
	ipt-legacy-raw)    _ipt_restore_input raw PREROUTING "$rules" | fwx iptables-legacy-restore --noflush ;;
	ipt-legacy-filter) _ipt_restore_input filter FORWARD "$rules" | fwx iptables-legacy-restore --noflush ;;
	ipt-nft-raw)       _ipt_restore_input raw PREROUTING "$rules" | fwx iptables-nft-restore --noflush ;;
	ipt-nft-filter)    _ipt_restore_input filter FORWARD "$rules" | fwx iptables-nft-restore --noflush ;;
	nft-set)
		{
			echo "table inet bench {"
			echo "  set blk { type ipv4_addr; flags interval;"
			echo "    elements = { $(sed '/^$/d' "$rules" | paste -sd, -) }"
			echo "  }"
			echo "  chain pre { type filter hook prerouting priority raw; policy accept;"
			echo "    ip saddr @blk counter drop"
			echo "  }"
			echo "}"
		} | fwx nft -f -
		;;
	*) echo "unknown config: $cfg" >&2; return 2 ;;
	esac
}

# Lệnh shell (chạy BÊN TRONG fw-node) in ra tổng số gói cấu hình đó đã drop.
drop_cmd() { # $1 config
	local ipt='| awk '"'"'$3=="DROP"{s+=$1} END{print s+0}'"'"
	case $1 in
	baseline) echo 'echo 0' ;;
	xdp-*) echo "xdpfw stats | awk '\$1==\"drop_ip\"{print \$2}'" ;;
	ipt-legacy-raw)    echo "iptables-legacy -t raw -nvxL PREROUTING 2>/dev/null $ipt" ;;
	ipt-legacy-filter) echo "iptables-legacy -nvxL FORWARD 2>/dev/null $ipt" ;;
	ipt-nft-raw)       echo "iptables-nft -t raw -nvxL PREROUTING 2>/dev/null $ipt" ;;
	ipt-nft-filter)    echo "iptables-nft -nvxL FORWARD 2>/dev/null $ipt" ;;
	nft-set) echo "nft list chain inet bench pre | grep -oE 'packets [0-9]+' | awk '{s+=\$2} END{print s+0}'" ;;
	esac
}

# Một lần exec duy nhất vào fw-node: "<ns> <rx_packets của iface ngoài> <drop_count>".
# Gói tới firewall và gói bị drop được đọc cùng thời điểm => tỉ lệ không lệch do trễ docker exec.
fw_counters() { # $1 config, $2 iface
	fwx sh -c "date +%s%N; cat /sys/class/net/$2/statistics/rx_packets; $(drop_cmd "$1")" | paste -sd' '
}

# id chương trình XDP đang gắn (rỗng nếu không phải XDP) — để đọc bpf_stats.
xdp_prog_id() { fwx xdpfw status 2>/dev/null | awk -F': *' '/prog_id/{print $2}'; }
