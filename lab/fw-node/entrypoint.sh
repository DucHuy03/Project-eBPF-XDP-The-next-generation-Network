#!/bin/sh
# fw-node: router giữa net_ext (10.10.1.0/24) và net_int (10.10.2.0/24) + firewall XDP.
set -eu

# bpffs cần cho việc pin map/link (xdpfw cũng tự mount nếu thiếu).
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

# Bật định tuyến IPv4 để chuyển gói client/attacker -> server.
sysctl -qw net.ipv4.ip_forward=1

# Tên interface do Docker đặt (eth0, eth1, ...) không cố định thứ tự,
# nên tìm interface theo IP. Ghi ra file để các script khác dùng: $(cat /run/xdp_iface)
ifname_of() { ip -o -4 addr show | awk -v ip="$1" '$4 ~ "^"ip"/" {print $2; exit}'; }
EXT_IF=$(ifname_of 10.10.1.254)
INT_IF=$(ifname_of 10.10.2.254)
echo "$EXT_IF" > /run/xdp_iface
echo "fw-node: ext=$EXT_IF int=$INT_IF (XDP attaches to ext)"

# Exporter chỉ lắng nghe trên mạng quản trị, không lộ ra mạng ext/int.
exec xdpfw serve --listen 10.10.9.254:9100
