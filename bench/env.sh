# shellcheck shell=bash
# Ghi lại môi trường đo vào results/<run_id>/env.txt (data-model.md §2.2, nguyên tắc III/IV).
# Được `source` bởi run_bench.sh. Dùng: write_env <file> "<tham số tải>"

write_env() { # $1 file, $2 params string
	local f=$1 params=$2 img
	{
		echo "# Môi trường benchmark xdpfw"
		echo "date:            $(date -Is)"
		echo "git_commit:      $(git rev-parse --short HEAD 2>/dev/null)$(git diff --quiet 2>/dev/null || echo '-dirty')"
		echo "kernel:          $(uname -r)"
		echo "cpu_model:       $(LC_ALL=C lscpu | sed -n 's/^Model name: *//p')"
		echo "nproc:           $(nproc)"
		echo "mem_total:       $(awk '/MemTotal/{printf "%.1f GiB", $2/1048576}' /proc/meminfo)"
		echo "clang:           $(clang --version 2>/dev/null | head -1)"
		echo "go(build image): golang:1.23.4-bookworm"
		echo "bpftool:         $(bpftool version 2>/dev/null | head -1)"
		echo "iptables-legacy: $(docker exec "$FW" iptables-legacy -V)"
		echo "iptables-nft:    $(docker exec "$FW" iptables-nft -V)"
		echo "nft:             $(docker exec "$FW" nft -v)"
		echo "trafgen:         $(docker exec "$AT" trafgen -v 2>&1 | head -1)"
		echo "docker:          $(docker version --format '{{.Server.Version}}')"
		for s in net.bridge.bridge-nf-call-iptables net.bridge.bridge-nf-call-ip6tables \
			net.bridge.bridge-nf-call-arptables kernel.bpf_stats_enabled net.core.netdev_max_backlog; do
			printf '%-38s %s\n' "$s:" "$(sysctl -n "$s" 2>/dev/null)"
		done
		echo "fw_iface:        $(fw_iface) mac=$FW_MAC"
		echo "cpuset:          attacker/client 0-3, fw-node 4-7"
		echo "images:"
		for img in xdplab/fw-node:latest xdplab/node:latest; do
			echo "  $img $(docker image inspect -f '{{.Id}}' "$img" 2>/dev/null)"
		done
		echo "params:          $params"
		echo "wslconfig:"
		# .wslconfig của Windows (giới hạn RAM/CPU của VM WSL) nếu đọc được
		cat /mnt/c/Users/*/.wslconfig 2>/dev/null | sed 's/^/  /'
	} >"$f"
}
