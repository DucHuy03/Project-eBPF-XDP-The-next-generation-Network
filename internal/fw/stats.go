package fw

import (
	"github.com/cilium/ebpf"

	"xdpfw/internal/bpfobj"
)

// Chỉ số trong map stats — phải khớp enum stat_idx trong bpf/xdp_fw.c.
const (
	StatPass uint32 = iota
	StatDropIP
	StatDropPort
	StatParseErr
	StatCount
)

// StatNames là tên action dùng trong CLI và metric (contracts/cli.md, metrics.md).
var StatNames = [StatCount]string{"pass", "drop_ip", "drop_port", "parse_err"}

// Counter là tổng số gói/byte (đã cộng mọi CPU).
type Counter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// ReadStats đọc 4 bộ đếm theo kết quả, cộng dồn qua mọi CPU.
func (f *Firewall) ReadStats() ([StatCount]Counter, error) {
	var out [StatCount]Counter
	for i := uint32(0); i < StatCount; i++ {
		c, err := sumPerCPU(f.Stats, i)
		if err != nil {
			return out, err
		}
		out[i] = c
	}
	return out, nil
}

// sumPerCPU đọc một phần tử của map per-CPU. Kernel trả về một mảng gồm một giá
// trị cho mỗi CPU; tổng thực sự là tổng của mảng đó.
func sumPerCPU(m *ebpf.Map, key uint32) (Counter, error) {
	var perCPU []bpfobj.XdpFwCounter
	if err := m.Lookup(&key, &perCPU); err != nil {
		return Counter{}, err
	}
	var c Counter
	for _, v := range perCPU {
		c.Packets += v.Packets
		c.Bytes += v.Bytes
	}
	return c, nil
}

// zeroPerCPU đặt phần tử key về 0 trên mọi CPU.
func zeroPerCPU(m *ebpf.Map, key uint32) error {
	zeros := make([]bpfobj.XdpFwCounter, ebpf.MustPossibleCPU())
	return m.Update(&key, zeros, ebpf.UpdateAny)
}
