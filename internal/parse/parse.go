// Package parse kiểm tra và chuẩn hóa tham số người dùng nhập (CIDR, giao thức, port)
// trước khi ghi vào BPF map. Không phụ thuộc kernel nên test được bằng `go test` thường.
package parse

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Giao thức theo số hiệu trong IP header (IPPROTO_TCP=6, IPPROTO_UDP=17).
const (
	ProtoTCP uint8 = 6
	ProtoUDP uint8 = 17
)

// CIDR là một dải IPv4 đã chuẩn hóa (bit host = 0).
type CIDR struct {
	Prefix     netip.Prefix
	Normalized bool // true nếu người dùng nhập có bit host ≠ 0 và đã bị làm tròn
}

// ParseCIDR nhận "a.b.c.d" (coi là /32) hoặc "a.b.c.d/n" với n trong 0..32.
// Ví dụ "10.0.0.5/24" được chuẩn hóa thành "10.0.0.0/24" và Normalized=true.
func ParseCIDR(s string) (CIDR, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		s += "/32"
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return CIDR{}, fmt.Errorf("invalid CIDR %q", s)
	}
	if !p.Addr().Is4() {
		return CIDR{}, fmt.Errorf("only IPv4 is supported: %q", s)
	}
	masked := p.Masked()
	return CIDR{Prefix: masked, Normalized: masked != p}, nil
}

// ParseProto chuyển "tcp"/"udp" thành số hiệu giao thức.
func ParseProto(s string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tcp":
		return ProtoTCP, nil
	case "udp":
		return ProtoUDP, nil
	}
	return 0, fmt.Errorf("invalid protocol %q (want tcp or udp)", s)
}

// ProtoName là chiều ngược của ParseProto, dùng khi in kết quả.
func ProtoName(p uint8) string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	}
	return strconv.Itoa(int(p))
}

// ParsePort nhận port đích trong khoảng 1..65535.
func ParsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q (want 1-65535)", s)
	}
	return uint16(n), nil
}
