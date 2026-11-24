package fw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"xdpfw/internal/bpfobj"
	"xdpfw/internal/parse"
)

// Dải rule_id (data-model.md §1.5): IP [0,16384), port [16384,17408).
// Phải khớp MAX_IP_RULES / MAX_PORT_RULES trong bpf/xdp_fw.c.
const (
	ipIDBase   = 0
	ipIDMax    = 16384
	portIDBase = 16384
	portIDMax  = 16384 + 1024
)

// Rule là một dòng trong `xdpfw list`.
type Rule struct {
	ID      uint32 `json:"id"`
	Type    string `json:"type"` // "ip" | "port"
	Match   string `json:"match"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// ---- Chuyển đổi key Go <-> byte trong map ----
//
// Kernel so sánh key theo từng byte. Địa chỉ IP và port trong gói ở dạng
// network byte order (big-endian), và chương trình XDP dùng nguyên giá trị đó
// làm key. Vì vậy ở user space ta phải đặt đúng các byte đó vào trường uint32/
// uint16 — NativeEndian.Uint32(ip[:]) cho ra số nguyên mà khi ghi xuống bộ nhớ
// (theo thứ tự byte của CPU) sẽ đúng là a.b.c.d.

func ipKey(p netip.Prefix) bpfobj.XdpFwLpmV4Key {
	a := p.Addr().As4()
	return bpfobj.XdpFwLpmV4Key{Prefixlen: uint32(p.Bits()), Addr: binary.NativeEndian.Uint32(a[:])}
}

func keyPrefix(k bpfobj.XdpFwLpmV4Key) netip.Prefix {
	var a [4]byte
	binary.NativeEndian.PutUint32(a[:], k.Addr)
	return netip.PrefixFrom(netip.AddrFrom4(a), int(k.Prefixlen))
}

func portKey(proto uint8, port uint16) bpfobj.XdpFwPortKey {
	be := [2]byte{byte(port >> 8), byte(port)} // network byte order
	return bpfobj.XdpFwPortKey{Proto: proto, Pad: 0, Dport: binary.NativeEndian.Uint16(be[:])}
}

func keyPort(k bpfobj.XdpFwPortKey) uint16 {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], k.Dport)
	return uint16(b[0])<<8 | uint16(b[1])
}

// ---- Rule chặn IP/subnet ----

// AddIPs thêm nhiều rule IP một lần (dùng cho `block-ip` và `block-ip --file`).
// Quét map một lần để biết id đã dùng, rồi cấp id nhỏ nhất còn trống cho mỗi rule —
// tránh O(n²) khi nạp 10.000 rule cho benchmark.
func (f *Firewall) AddIPs(prefixes []netip.Prefix) ([]uint32, error) {
	used, err := usedIDs[bpfobj.XdpFwLpmV4Key](f.Src)
	if err != nil {
		return nil, err
	}
	alloc := newAllocator(used, ipIDBase, ipIDMax)
	ids := make([]uint32, 0, len(prefixes))
	for _, p := range prefixes {
		id, ok := alloc.next()
		if !ok {
			return ids, ErrFull
		}
		k := ipKey(p)
		// UpdateNoExist: kernel báo lỗi nếu prefix y hệt đã có (không ghi đè).
		if err := f.Src.Update(&k, &id, ebpf.UpdateNoExist); err != nil {
			if errors.Is(err, ebpf.ErrKeyExist) {
				return ids, fmt.Errorf("%w: %s", ErrExists, p)
			}
			if errors.Is(err, unix.E2BIG) { // kernel trả E2BIG khi map đầy
				return ids, ErrFull
			}
			return ids, err
		}
		alloc.take(id)
		ids = append(ids, id)
	}
	return ids, nil
}

// DelIP xóa rule có đúng prefix p và đặt lại bộ đếm của rule đó.
func (f *Firewall) DelIP(p netip.Prefix) (uint32, error) {
	// Lookup trên LPM trie là "khớp prefix dài nhất", không phải khớp chính xác,
	// nên phải duyệt để tìm đúng key trước khi xóa.
	want := ipKey(p)
	var k bpfobj.XdpFwLpmV4Key
	var id uint32
	it := f.Src.Iterate()
	for it.Next(&k, &id) {
		if k == want {
			if err := f.Src.Delete(&k); err != nil {
				return 0, err
			}
			return id, f.resetHits(id)
		}
	}
	if err := it.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("%w: %s", ErrNotFound, p)
}

// ---- Rule chặn port ----

// AddPort thêm rule chặn (proto, port đích).
func (f *Firewall) AddPort(proto uint8, port uint16) (uint32, error) {
	used, err := usedIDs[bpfobj.XdpFwPortKey](f.Port)
	if err != nil {
		return 0, err
	}
	id, ok := newAllocator(used, portIDBase, portIDMax).next()
	if !ok {
		return 0, ErrFull
	}
	k := portKey(proto, port)
	if err := f.Port.Update(&k, &id, ebpf.UpdateNoExist); err != nil {
		if errors.Is(err, ebpf.ErrKeyExist) {
			return 0, fmt.Errorf("%w: %s/%d", ErrExists, parse.ProtoName(proto), port)
		}
		if errors.Is(err, unix.E2BIG) { // kernel trả E2BIG khi map đầy
			return 0, ErrFull
		}
		return 0, err
	}
	return id, nil
}

// DelPort xóa rule (proto, port) và đặt lại bộ đếm của rule đó.
func (f *Firewall) DelPort(proto uint8, port uint16) (uint32, error) {
	k := portKey(proto, port)
	var id uint32
	if err := f.Port.Lookup(&k, &id); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, fmt.Errorf("%w: %s/%d", ErrNotFound, parse.ProtoName(proto), port)
		}
		return 0, err
	}
	if err := f.Port.Delete(&k); err != nil {
		return 0, err
	}
	return id, f.resetHits(id)
}

// ---- Liệt kê / xóa hết ----

// List trả mọi rule kèm số gói/byte đã khớp, sắp theo id.
func (f *Firewall) List() ([]Rule, error) {
	var rules []Rule

	var k4 bpfobj.XdpFwLpmV4Key
	var id uint32
	it := f.Src.Iterate()
	for it.Next(&k4, &id) {
		rules = append(rules, Rule{ID: id, Type: "ip", Match: keyPrefix(k4).String()})
	}
	if err := it.Err(); err != nil {
		return nil, err
	}

	var kp bpfobj.XdpFwPortKey
	it = f.Port.Iterate()
	for it.Next(&kp, &id) {
		rules = append(rules, Rule{ID: id, Type: "port",
			Match: fmt.Sprintf("%s/%d", parse.ProtoName(kp.Proto), keyPort(kp))})
	}
	if err := it.Err(); err != nil {
		return nil, err
	}

	for i := range rules {
		c, err := sumPerCPU(f.Hits, rules[i].ID)
		if err != nil {
			return nil, err
		}
		rules[i].Packets, rules[i].Bytes = c.Packets, c.Bytes
	}
	sort.Slice(rules, func(a, b int) bool { return rules[a].ID < rules[b].ID })
	return rules, nil
}

// Flush xóa mọi rule và đặt lại mọi bộ đếm.
func (f *Firewall) Flush() error {
	var k4s []bpfobj.XdpFwLpmV4Key
	var k4 bpfobj.XdpFwLpmV4Key
	var id uint32
	var ids []uint32
	it := f.Src.Iterate()
	for it.Next(&k4, &id) {
		k4s = append(k4s, k4)
		ids = append(ids, id)
	}
	if err := it.Err(); err != nil {
		return err
	}
	for i := range k4s {
		if err := f.Src.Delete(&k4s[i]); err != nil {
			return err
		}
	}

	var kps []bpfobj.XdpFwPortKey
	var kp bpfobj.XdpFwPortKey
	it = f.Port.Iterate()
	for it.Next(&kp, &id) {
		kps = append(kps, kp)
		ids = append(ids, id)
	}
	if err := it.Err(); err != nil {
		return err
	}
	for i := range kps {
		if err := f.Port.Delete(&kps[i]); err != nil {
			return err
		}
	}

	for _, id := range ids {
		if err := f.resetHits(id); err != nil {
			return err
		}
	}
	for i := uint32(0); i < StatCount; i++ {
		if err := zeroPerCPU(f.Stats, i); err != nil {
			return err
		}
	}
	return nil
}

// ---- Tiện ích ----

// usedIDs duyệt một map rule (kiểu key K) và trả tập rule_id đang dùng.
func usedIDs[K any](m *ebpf.Map) (map[uint32]bool, error) {
	used := map[uint32]bool{}
	var k K
	var id uint32
	it := m.Iterate()
	for it.Next(&k, &id) {
		used[id] = true
	}
	return used, it.Err()
}

// allocator cấp id nhỏ nhất chưa dùng trong [base, max).
type allocator struct {
	used      map[uint32]bool
	cur, max  uint32
}

func newAllocator(used map[uint32]bool, base, max uint32) *allocator {
	return &allocator{used: used, cur: base, max: max}
}

func (a *allocator) next() (uint32, bool) {
	for ; a.cur < a.max; a.cur++ {
		if !a.used[a.cur] {
			return a.cur, true
		}
	}
	return 0, false
}

func (a *allocator) take(id uint32) { a.used[id] = true }

func (f *Firewall) resetHits(id uint32) error { return zeroPerCPU(f.Hits, id) }
