// Package exporter xuất bộ đếm của firewall theo định dạng Prometheus
// (contracts/metrics.md).
//
// Thiết kế: không có goroutine nền, không cache. Mỗi lần Prometheus scrape,
// Collect mở các map đã pin, đọc giá trị hiện tại rồi đóng lại. Nhờ vậy exporter
// vẫn đúng khi firewall bị unload/load lại trong lúc `xdpfw serve` đang chạy.
package exporter

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"xdpfw/internal/fw"
)

var (
	descUp = prometheus.NewDesc("xdpfw_up",
		"1 if the XDP firewall is loaded, 0 otherwise.", nil, nil)
	descPackets = prometheus.NewDesc("xdpfw_packets_total",
		"Packets processed by the XDP firewall, by action.", []string{"action"}, nil)
	descBytes = prometheus.NewDesc("xdpfw_bytes_total",
		"Bytes processed by the XDP firewall, by action.", []string{"action"}, nil)
	descRulePackets = prometheus.NewDesc("xdpfw_rule_packets_total",
		"Packets matched per rule.", []string{"id", "type", "match"}, nil)
	descRuleBytes = prometheus.NewDesc("xdpfw_rule_bytes_total",
		"Bytes matched per rule.", []string{"id", "type", "match"}, nil)
	descRules = prometheus.NewDesc("xdpfw_rules",
		"Number of active rules, by type.", []string{"type"}, nil)
	descInfo = prometheus.NewDesc("xdpfw_info",
		"Attachment info (always 1).", []string{"iface", "mode", "prog_id"}, nil)
)

// Collector cài đặt prometheus.Collector.
type Collector struct{}

// Describe gửi mô tả của mọi metric.
func (Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{descUp, descPackets, descBytes,
		descRulePackets, descRuleBytes, descRules, descInfo} {
		ch <- d
	}
}

// Collect đọc map và gửi giá trị. Khi firewall chưa nạp chỉ gửi xdpfw_up 0.
func (Collector) Collect(ch chan<- prometheus.Metric) {
	f, err := fw.Open()
	if err != nil {
		ch <- prometheus.MustNewConstMetric(descUp, prometheus.GaugeValue, 0)
		return
	}
	defer f.Close()
	ch <- prometheus.MustNewConstMetric(descUp, prometheus.GaugeValue, 1)
	ch <- prometheus.MustNewConstMetric(descInfo, prometheus.GaugeValue, 1,
		f.Meta.Iface, f.Meta.Mode, strconv.FormatUint(uint64(f.Meta.ProgID), 10))

	if st, err := f.ReadStats(); err == nil {
		for i, c := range st {
			ch <- prometheus.MustNewConstMetric(descPackets, prometheus.CounterValue,
				float64(c.Packets), fw.StatNames[i])
			ch <- prometheus.MustNewConstMetric(descBytes, prometheus.CounterValue,
				float64(c.Bytes), fw.StatNames[i])
		}
	}

	rules, err := f.List()
	if err != nil {
		return
	}
	count := map[string]int{"ip": 0, "port": 0}
	for _, r := range rules {
		count[r.Type]++
		id := strconv.FormatUint(uint64(r.ID), 10)
		ch <- prometheus.MustNewConstMetric(descRulePackets, prometheus.CounterValue,
			float64(r.Packets), id, r.Type, r.Match)
		ch <- prometheus.MustNewConstMetric(descRuleBytes, prometheus.CounterValue,
			float64(r.Bytes), id, r.Type, r.Match)
	}
	for t, n := range count {
		ch <- prometheus.MustNewConstMetric(descRules, prometheus.GaugeValue, float64(n), t)
	}
}
