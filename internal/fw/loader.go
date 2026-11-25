// Package fw là control plane của firewall: nạp/gỡ chương trình XDP, đọc/ghi
// rule và bộ đếm trong BPF map.
//
// Mỗi lệnh CLI là một tiến trình ngắn. Để firewall vẫn chạy sau khi tiến trình
// thoát, `Load` "pin" (ghim) link XDP và các map vào bpffs tại PinDir. Các lệnh
// sau mở lại map từ đó. `Unload` gỡ link và xóa thư mục pin.
//
// KHỐI B4 (control plane) — docs/ARCHITECTURE.md §4. Gồm 3 file:
//   - loader.go: vòng đời chương trình (nạp, gắn, pin, gỡ, mở lại map)
//   - rules.go:  thêm/xóa/liệt kê rule trong blocked_src, blocked_port
//   - stats.go:  đọc/xóa bộ đếm per-CPU trong stats, rule_hits
//
// Gọi bởi B6 (CLI) và B7 (exporter); nói chuyện với B2 (map) qua syscall bpf().
package fw

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"xdpfw/internal/bpfobj"
)

// PinDir là nơi ghim link và map trong bpffs.
const PinDir = "/sys/fs/bpf/xdpfw"

// MetaDir chứa meta.json. Không đặt trong PinDir được vì bpffs chỉ chứa
// object BPF đã pin, không cho tạo file thường.
const MetaDir = "/run/xdpfw"

// Tên file pin của từng map/link (trùng tên map trong bpf/xdp_fw.c cho dễ tra).
const (
	pinLink   = "link"
	pinSrc    = "blocked_src"
	pinPort   = "blocked_port"
	pinStats  = "stats"
	pinHits   = "rule_hits"
	metaFile  = "meta.json"
	bpffsType = 0xcafe4a11 // magic number của bpffs (BPF_FS_MAGIC)
)

// Lỗi có ý nghĩa riêng — cmd/xdpfw ánh xạ sang mã thoát (contracts/cli.md).
var (
	ErrNotLoaded     = errors.New("firewall is not loaded (run: xdpfw load --iface <if>)")
	ErrAlreadyLoaded = errors.New("firewall is already loaded (run: xdpfw unload first)")
	ErrExists        = errors.New("rule already exists")
	ErrNotFound      = errors.New("rule does not exist")
	ErrFull          = errors.New("rule table is full")
	ErrConflict      = errors.New("interface already has an XDP program attached")
)

// Meta mô tả phiên gắn firewall hiện tại (data-model.md §1.6).
type Meta struct {
	Iface      string    `json:"iface"`
	Ifindex    int       `json:"ifindex"`
	Mode       string    `json:"mode"`
	ProgID     uint32    `json:"prog_id"`
	AttachedAt time.Time `json:"attached_at"`
}

// Firewall giữ các map đã mở từ pin.
type Firewall struct {
	Src, Port, Stats, Hits *ebpf.Map
	Meta                   Meta
}

// Load nạp chương trình XDP lên iface ở chế độ "generic" hoặc "native".
func Load(iface, mode string) (*Meta, error) {
	var flags link.XDPAttachFlags
	switch mode {
	case "generic":
		flags = link.XDPGenericMode
	case "native":
		flags = link.XDPDriverMode
	default:
		return nil, fmt.Errorf("invalid mode %q (want generic or native)", mode)
	}

	if _, err := os.Stat(PinDir); err == nil {
		return nil, ErrAlreadyLoaded
	}
	if err := ensureBpffs(); err != nil {
		return nil, err
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}

	// Nạp bytecode vào kernel: verifier kiểm tra, JIT biên dịch sang mã máy.
	var objs bpfobj.XdpFwObjects
	if err := bpfobj.LoadXdpFwObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects (verifier): %w", err)
	}
	defer objs.Close() // an toàn: sau khi pin, kernel giữ tham chiếu riêng

	// Gắn bằng bpf_link: kernel từ chối nếu interface đã có chương trình XDP khác,
	// nên không bao giờ ghi đè ngầm.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFw,
		Interface: ifi.Index,
		Flags:     flags,
	})
	if err != nil {
		switch {
		case errors.Is(err, unix.EBUSY), errors.Is(err, unix.EEXIST):
			return nil, fmt.Errorf("%w (%s)", ErrConflict, iface)
		case mode == "native":
			return nil, fmt.Errorf("native mode not supported on %s; try --mode generic: %w", iface, err)
		}
		return nil, fmt.Errorf("attach XDP to %s: %w", iface, err)
	}
	defer l.Close()

	if err := os.MkdirAll(PinDir, 0o700); err != nil {
		return nil, err
	}
	pins := []struct {
		name string
		pin  func(string) error
	}{
		{pinSrc, objs.BlockedSrc.Pin},
		{pinPort, objs.BlockedPort.Pin},
		{pinStats, objs.Stats.Pin},
		{pinHits, objs.RuleHits.Pin},
		{pinLink, l.Pin},
	}
	for _, p := range pins {
		if err := p.pin(filepath.Join(PinDir, p.name)); err != nil {
			_ = os.RemoveAll(PinDir)
			return nil, fmt.Errorf("pin %s: %w", p.name, err)
		}
	}

	info, err := objs.XdpFw.Info()
	if err != nil {
		return nil, err
	}
	progID, _ := info.ID()
	meta := &Meta{
		Iface:      iface,
		Ifindex:    ifi.Index,
		Mode:       mode,
		ProgID:     uint32(progID),
		AttachedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := writeMeta(meta); err != nil {
		return nil, err
	}
	return meta, nil
}

// Unload gỡ chương trình XDP và xóa mọi pin (rule và bộ đếm mất theo).
func Unload() (*Meta, error) {
	if _, err := os.Stat(PinDir); err != nil {
		return nil, ErrNotLoaded
	}
	meta, _ := readMeta()

	// Bỏ pin rồi đóng link: khi không còn tham chiếu nào, kernel tự gỡ XDP
	// khỏi interface. Nếu interface đã biến mất thì link không còn — bỏ qua lỗi.
	if l, err := link.LoadPinnedLink(filepath.Join(PinDir, pinLink), nil); err == nil {
		_ = l.Unpin()
		_ = l.Close()
	}
	_ = os.RemoveAll(MetaDir)
	if err := os.RemoveAll(PinDir); err != nil {
		return meta, fmt.Errorf("remove %s: %w", PinDir, err)
	}
	return meta, nil
}

// Open mở các map đã pin. Gọi Close khi dùng xong.
func Open() (*Firewall, error) {
	if _, err := os.Stat(PinDir); err != nil {
		return nil, ErrNotLoaded
	}
	f := &Firewall{}
	maps := []struct {
		name string
		dst  **ebpf.Map
	}{
		{pinSrc, &f.Src}, {pinPort, &f.Port}, {pinStats, &f.Stats}, {pinHits, &f.Hits},
	}
	for _, m := range maps {
		mp, err := ebpf.LoadPinnedMap(filepath.Join(PinDir, m.name), nil)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("open pinned map %s: %w", m.name, err)
		}
		*m.dst = mp
	}
	if meta, err := readMeta(); err == nil {
		f.Meta = *meta
	}
	return f, nil
}

// Close đóng file descriptor của các map (không ảnh hưởng firewall đang chạy).
func (f *Firewall) Close() {
	for _, m := range []*ebpf.Map{f.Src, f.Port, f.Stats, f.Hits} {
		if m != nil {
			m.Close()
		}
	}
}

// ensureBpffs mount bpffs tại /sys/fs/bpf nếu chưa có (WSL mặc định chưa mount).
func ensureBpffs() error {
	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &st); err == nil && uint32(st.Type) == bpffsType {
		return nil
	}
	if err := os.MkdirAll("/sys/fs/bpf", 0o755); err != nil {
		return err
	}
	if err := unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, ""); err != nil {
		return fmt.Errorf("mount bpffs at /sys/fs/bpf: %w", err)
	}
	return nil
}

// writeMeta / readMeta lưu Meta ra MetaDir/meta.json: mỗi lệnh xdpfw là một
// tiến trình riêng, nên `status` cần nơi lưu iface/mode/thời điểm gắn của lần `load` trước.
func writeMeta(m *Meta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(MetaDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(MetaDir, metaFile), b, 0o600)
}

func readMeta() (*Meta, error) {
	b, err := os.ReadFile(filepath.Join(MetaDir, metaFile))
	if err != nil {
		return nil, err
	}
	var m Meta
	return &m, json.Unmarshal(b, &m)
}
