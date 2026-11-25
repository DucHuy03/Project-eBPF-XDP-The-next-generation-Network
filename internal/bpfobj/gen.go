// Package bpfobj chứa chương trình XDP đã biên dịch, nhúng vào binary Go.
//
// KHỐI B3 (build & binding) — docs/ARCHITECTURE.md §4. Cầu nối lúc build giữa B1 (C)
// và B4 (Go): bytecode + struct Go khớp từng byte với struct C của map.
//
// `go generate ./...` gọi bpf2go: biên dịch bpf/xdp_fw.c bằng clang thành
// bytecode BPF (xdpfw_bpfel.o) và sinh xdpfw_bpfel.go với các kiểu Go tương
// ứng struct/map trong C (XdpFwObjects, XdpFwCounter, XdpFwLpmV4Key, ...).
// Hai file sinh ra không được commit (xem .gitignore) — luôn build lại từ C.
package bpfobj

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -type counter -type lpm_v4_key -type port_key XdpFw ../../bpf/xdp_fw.c -- -O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu
