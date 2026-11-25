package parse

// KHỐI B12 (kiểm thử, tầng unit) — docs/ARCHITECTURE.md §4. Kiểm B5 không cần kernel.

import "testing"

func TestParseCIDR(t *testing.T) {
	cases := []struct {
		in         string
		want       string
		normalized bool
		wantErr    bool
	}{
		{"10.10.1.66", "10.10.1.66/32", false, false},
		{"10.10.1.0/24", "10.10.1.0/24", false, false},
		{"10.0.0.5/24", "10.0.0.0/24", true, false},
		{"0.0.0.0/0", "0.0.0.0/0", false, false},
		{" 192.168.1.1/32 ", "192.168.1.1/32", false, false},
		{"10.0.0.300/24", "", false, true},
		{"10.0.0.0/33", "", false, true},
		{"10.0.0.0/-1", "", false, true},
		{"abc", "", false, true},
		{"", "", false, true},
		{"2001:db8::1/64", "", false, true},
	}
	for _, c := range cases {
		got, err := ParseCIDR(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseCIDR(%q): expected error, got %v", c.in, got.Prefix)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseCIDR(%q): unexpected error %v", c.in, err)
			continue
		}
		if got.Prefix.String() != c.want || got.Normalized != c.normalized {
			t.Errorf("ParseCIDR(%q) = %v normalized=%v, want %v normalized=%v",
				c.in, got.Prefix, got.Normalized, c.want, c.normalized)
		}
	}
}

func TestParseProto(t *testing.T) {
	for in, want := range map[string]uint8{"tcp": 6, "UDP": 17, " udp ": 17} {
		if got, err := ParseProto(in); err != nil || got != want {
			t.Errorf("ParseProto(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"icmp", "", "6"} {
		if _, err := ParseProto(in); err == nil {
			t.Errorf("ParseProto(%q): expected error", in)
		}
	}
	if ProtoName(6) != "tcp" || ProtoName(17) != "udp" {
		t.Error("ProtoName mismatch")
	}
}

func TestParsePort(t *testing.T) {
	for in, want := range map[string]uint16{"1": 1, "80": 80, "65535": 65535} {
		if got, err := ParsePort(in); err != nil || got != want {
			t.Errorf("ParsePort(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"0", "65536", "-1", "http", ""} {
		if _, err := ParsePort(in); err == nil {
			t.Errorf("ParsePort(%q): expected error", in)
		}
	}
}
