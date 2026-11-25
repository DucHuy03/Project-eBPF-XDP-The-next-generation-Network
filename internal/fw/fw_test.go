//go:build bpftest

// Test chương trình XDP thật trong kernel bằng BPF_PROG_TEST_RUN: dựng gói bằng tay,
// đưa vào chương trình, kiểm tra action trả về và bộ đếm. Không cần lab hay interface.
// Cần root (CAP_BPF/CAP_SYS_ADMIN): chạy bằng `make test-bpf`.
//
// KHỐI B12 (kiểm thử, tầng chương trình BPF) — docs/ARCHITECTURE.md §4. Kiểm B1 + B2 + B4.
package fw

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"

	"xdpfw/internal/bpfobj"
)

// Giá trị enum xdp_action trong linux/bpf.h.
const (
	xdpDrop = 1
	xdpPass = 2
)

// newTestFW nạp một bản chương trình + map mới (không pin, không gắn interface).
func newTestFW(t *testing.T) (*Firewall, *ebpf.Program) {
	t.Helper()
	var objs bpfobj.XdpFwObjects
	if err := bpfobj.LoadXdpFwObjects(&objs, nil); err != nil {
		t.Fatalf("load objects: %v", err)
	}
	t.Cleanup(func() { objs.Close() })
	return &Firewall{Src: objs.BlockedSrc, Port: objs.BlockedPort, Stats: objs.Stats, Hits: objs.RuleHits},
		objs.XdpFw
}

// ---- Dựng gói ----

type pktOpt struct {
	src, dst string
	proto    uint8  // 6 TCP, 17 UDP, 1 ICMP
	dport    uint16 // TCP/UDP
	ihl      int    // 0 => 5 (không options)
	fragOff  uint16 // offset fragment (đơn vị 8 byte)
}

func eth(etherType uint16) []byte {
	b := make([]byte, 14)
	copy(b[0:6], []byte{0x02, 0, 0, 0, 0, 0x01})  // MAC đích
	copy(b[6:12], []byte{0x02, 0, 0, 0, 0, 0x02}) // MAC nguồn
	binary.BigEndian.PutUint16(b[12:], etherType)
	return b
}

func ipv4Packet(o pktOpt) []byte {
	ihl := o.ihl
	if ihl == 0 {
		ihl = 5
	}
	var l4 []byte
	switch o.proto {
	case 6: // TCP header 20 byte, dport ở offset 2
		l4 = make([]byte, 20)
		binary.BigEndian.PutUint16(l4[0:], 40000)
		binary.BigEndian.PutUint16(l4[2:], o.dport)
		l4[12] = 5 << 4
	case 17: // UDP header 8 byte
		l4 = make([]byte, 8)
		binary.BigEndian.PutUint16(l4[0:], 40000)
		binary.BigEndian.PutUint16(l4[2:], o.dport)
		binary.BigEndian.PutUint16(l4[4:], 8)
	default: // ICMP echo 8 byte
		l4 = []byte{8, 0, 0, 0, 0, 1, 0, 1}
	}
	ip := make([]byte, ihl*4)
	ip[0] = 0x40 | byte(ihl)
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)+len(l4)))
	binary.BigEndian.PutUint16(ip[6:], o.fragOff&0x1FFF)
	ip[8] = 64
	ip[9] = o.proto
	s, d := netip.MustParseAddr(o.src).As4(), netip.MustParseAddr(o.dst).As4()
	copy(ip[12:16], s[:])
	copy(ip[16:20], d[:])
	for i := 20; i < len(ip); i++ {
		ip[i] = 1 // IP option NOP
	}
	pkt := append(eth(0x0800), ip...)
	return append(pkt, l4...)
}

func run(t *testing.T, prog *ebpf.Program, pkt []byte) uint32 {
	t.Helper()
	ret, err := prog.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog.Run: %v", err)
	}
	return ret
}

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

const (
	client   = "10.10.1.10"
	attacker = "10.10.1.66"
	server   = "10.10.2.20"
)

// ---- US1: quyết định PASS/DROP ----

func TestNoRulesPassesEverything(t *testing.T) {
	f, prog := newTestFW(t)
	for _, p := range []uint8{1, 6, 17} {
		if got := run(t, prog, ipv4Packet(pktOpt{src: attacker, dst: server, proto: p, dport: 80})); got != xdpPass {
			t.Errorf("proto %d: got %d, want PASS", p, got)
		}
	}
	st, _ := f.ReadStats()
	if st[StatPass].Packets != 3 {
		t.Errorf("pass counter = %d, want 3", st[StatPass].Packets)
	}
}

func TestBlockSingleIP(t *testing.T) {
	f, prog := newTestFW(t)
	if _, err := f.AddIPs([]netip.Prefix{mustPrefix(attacker + "/32")}); err != nil {
		t.Fatal(err)
	}
	if got := run(t, prog, ipv4Packet(pktOpt{src: attacker, dst: server, proto: 17, dport: 53})); got != xdpDrop {
		t.Errorf("attacker UDP: got %d, want DROP", got)
	}
	if got := run(t, prog, ipv4Packet(pktOpt{src: attacker, dst: server, proto: 1})); got != xdpDrop {
		t.Errorf("attacker ICMP: got %d, want DROP (IP rule applies to all protocols)", got)
	}
	if got := run(t, prog, ipv4Packet(pktOpt{src: client, dst: server, proto: 6, dport: 80})); got != xdpPass {
		t.Errorf("client TCP: got %d, want PASS", got)
	}
}

func TestBlockSubnetAndLongestPrefix(t *testing.T) {
	f, prog := newTestFW(t)
	// /26 = 10.10.1.64-127: chứa attacker (.66), không chứa client (.10).
	ids, err := f.AddIPs([]netip.Prefix{mustPrefix("10.10.1.64/26"), mustPrefix(attacker + "/32")})
	if err != nil {
		t.Fatal(err)
	}
	subnetID, hostID := ids[0], ids[1]

	run(t, prog, ipv4Packet(pktOpt{src: attacker, dst: server, proto: 17, dport: 1}))     // khớp /32
	run(t, prog, ipv4Packet(pktOpt{src: "10.10.1.70", dst: server, proto: 17, dport: 1})) // chỉ khớp /26
	if got := run(t, prog, ipv4Packet(pktOpt{src: client, dst: server, proto: 17, dport: 1})); got != xdpPass {
		t.Errorf("client outside subnet: got %d, want PASS", got)
	}

	rules, _ := f.List()
	hits := map[uint32]uint64{}
	for _, r := range rules {
		hits[r.ID] = r.Packets
	}
	if hits[hostID] != 1 || hits[subnetID] != 1 {
		t.Errorf("rule hits: /32=%d /26=%d, want 1 and 1 (longest prefix wins)", hits[hostID], hits[subnetID])
	}
}

func TestBlockPortByProtocol(t *testing.T) {
	f, prog := newTestFW(t)
	if _, err := f.AddPort(17, 9999); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		o    pktOpt
		want uint32
	}{
		{"udp/9999", pktOpt{src: client, dst: server, proto: 17, dport: 9999}, xdpDrop},
		{"tcp/9999", pktOpt{src: client, dst: server, proto: 6, dport: 9999}, xdpPass},
		{"udp/80", pktOpt{src: client, dst: server, proto: 17, dport: 80}, xdpPass},
		{"udp/9999 with IP options", pktOpt{src: client, dst: server, proto: 17, dport: 9999, ihl: 7}, xdpDrop},
		{"udp/9999 non-first fragment", pktOpt{src: client, dst: server, proto: 17, dport: 9999, fragOff: 10}, xdpPass},
		{"icmp", pktOpt{src: client, dst: server, proto: 1}, xdpPass},
	}
	for _, c := range cases {
		if got := run(t, prog, ipv4Packet(c.o)); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestNonIPv4AndMalformed(t *testing.T) {
	f, prog := newTestFW(t)
	// Chặn mọi IPv4 để chắc chắn PASS dưới đây không phải do "không khớp rule".
	if _, err := f.AddIPs([]netip.Prefix{mustPrefix("0.0.0.0/0")}); err != nil {
		t.Fatal(err)
	}
	arp := append(eth(0x0806), make([]byte, 28)...)
	ipv6 := append(eth(0x86DD), make([]byte, 40)...)
	ethOnly := eth(0x0800) // IPv4 nhưng cụt ngay sau Ethernet
	badIHL := ipv4Packet(pktOpt{src: attacker, dst: server, proto: 17, dport: 1})
	badIHL[14] = 0x44 // ihl = 4 < 5
	shortTCP := ipv4Packet(pktOpt{src: attacker, dst: server, proto: 6, dport: 1})[:14+20+4]

	for name, pkt := range map[string][]byte{"arp": arp, "ipv6": ipv6} {
		if got := run(t, prog, pkt); got != xdpPass {
			t.Errorf("%s: got %d, want PASS", name, got)
		}
	}
	for name, pkt := range map[string][]byte{"eth-only": ethOnly, "ihl<5": badIHL} {
		if got := run(t, prog, pkt); got != xdpPass {
			t.Errorf("%s: got %d, want PASS", name, got)
		}
	}
	// TCP header cụt: IP rule 0.0.0.0/0 khớp trước khi đọc L4 => DROP.
	if got := run(t, prog, shortTCP); got != xdpDrop {
		t.Errorf("truncated TCP from blocked src: got %d, want DROP", got)
	}

	st, _ := f.ReadStats()
	if st[StatParseErr].Packets != 2 {
		t.Errorf("parse_err = %d, want 2", st[StatParseErr].Packets)
	}
	if st[StatPass].Packets != 2 {
		t.Errorf("pass = %d, want 2 (arp + ipv6)", st[StatPass].Packets)
	}
}

func TestTruncatedL4IsParseError(t *testing.T) {
	f, prog := newTestFW(t)
	if _, err := f.AddPort(6, 80); err != nil {
		t.Fatal(err)
	}
	shortTCP := ipv4Packet(pktOpt{src: client, dst: server, proto: 6, dport: 80})[:14+20+4]
	if got := run(t, prog, shortTCP); got != xdpPass {
		t.Errorf("truncated TCP: got %d, want PASS", got)
	}
	st, _ := f.ReadStats()
	if st[StatParseErr].Packets != 1 {
		t.Errorf("parse_err = %d, want 1", st[StatParseErr].Packets)
	}
}

// ---- US1: quản lý rule (control plane trên map thật) ----

func TestRuleLifecycle(t *testing.T) {
	f, prog := newTestFW(t)
	p := mustPrefix(attacker + "/32")

	ids, err := f.AddIPs([]netip.Prefix{p})
	if err != nil || ids[0] != 0 {
		t.Fatalf("first ip rule: ids=%v err=%v, want id 0", ids, err)
	}
	if _, err := f.AddIPs([]netip.Prefix{p}); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate ip: err=%v, want ErrExists", err)
	}
	run(t, prog, ipv4Packet(pktOpt{src: attacker, dst: server, proto: 17, dport: 1}))

	if _, err := f.DelIP(p); err != nil {
		t.Fatal(err)
	}
	if _, err := f.DelIP(p); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete missing: err=%v, want ErrNotFound", err)
	}
	if got := run(t, prog, ipv4Packet(pktOpt{src: attacker, dst: server, proto: 17, dport: 1})); got != xdpPass {
		t.Errorf("after unblock: got %d, want PASS", got)
	}
	// id 0 được tái sử dụng và bộ đếm đã về 0.
	ids, _ = f.AddIPs([]netip.Prefix{mustPrefix("192.0.2.0/24")})
	rules, _ := f.List()
	if ids[0] != 0 || rules[0].Packets != 0 {
		t.Errorf("reused id=%d packets=%d, want id 0 with 0 packets", ids[0], rules[0].Packets)
	}

	id, err := f.AddPort(17, 9999)
	if err != nil || id != portIDBase {
		t.Fatalf("first port rule: id=%d err=%v, want %d", id, err, portIDBase)
	}
	if _, err := f.AddPort(17, 9999); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate port: err=%v, want ErrExists", err)
	}
	if _, err := f.DelPort(6, 9999); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete missing port: err=%v, want ErrNotFound", err)
	}

	if err := f.Flush(); err != nil {
		t.Fatal(err)
	}
	if rules, _ := f.List(); len(rules) != 0 {
		t.Errorf("after flush: %d rules, want 0", len(rules))
	}
}

func TestRuleTableFull(t *testing.T) {
	f, _ := newTestFW(t)
	prefixes := make([]netip.Prefix, ipIDMax+1)
	for i := range prefixes {
		a := [4]byte{100, byte(i >> 16), byte(i >> 8), byte(i)}
		prefixes[i] = netip.PrefixFrom(netip.AddrFrom4(a), 32)
	}
	ids, err := f.AddIPs(prefixes)
	if !errors.Is(err, ErrFull) {
		t.Fatalf("err=%v, want ErrFull", err)
	}
	if len(ids) != ipIDMax {
		t.Errorf("added %d rules before full, want %d", len(ids), ipIDMax)
	}
}

// ---- US2: bộ đếm (T024) ----

func TestCountersMatchTraffic(t *testing.T) {
	f, prog := newTestFW(t)
	f.AddIPs([]netip.Prefix{mustPrefix(attacker + "/32")})
	f.AddPort(17, 9999)

	drop := ipv4Packet(pktOpt{src: attacker, dst: server, proto: 17, dport: 53})
	dropPort := ipv4Packet(pktOpt{src: client, dst: server, proto: 17, dport: 9999})
	pass := ipv4Packet(pktOpt{src: client, dst: server, proto: 6, dport: 80})
	for i := 0; i < 1000; i++ {
		run(t, prog, drop)
	}
	for i := 0; i < 7; i++ {
		run(t, prog, dropPort)
	}
	for i := 0; i < 5; i++ {
		run(t, prog, pass)
	}

	st, err := f.ReadStats()
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint32]Counter{
		StatDropIP:   {1000, uint64(1000 * len(drop))},
		StatDropPort: {7, uint64(7 * len(dropPort))},
		StatPass:     {5, uint64(5 * len(pass))},
	}
	for idx, w := range want {
		if st[idx] != w {
			t.Errorf("%s = %+v, want %+v", StatNames[idx], st[idx], w)
		}
	}
	rules, _ := f.List()
	for _, r := range rules {
		wantPk := map[string]uint64{"ip": 1000, "port": 7}[r.Type]
		if r.Packets != wantPk {
			t.Errorf("rule %s packets=%d, want %d", r.Match, r.Packets, wantPk)
		}
	}
}
