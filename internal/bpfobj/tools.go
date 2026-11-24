//go:build tools

// tools.go ghi nhận bpf2go là dependency lúc build để `go mod tidy` giữ nó
// trong go.mod/go.sum (bpf2go chỉ được gọi qua //go:generate).
package bpfobj

import _ "github.com/cilium/ebpf/cmd/bpf2go"
