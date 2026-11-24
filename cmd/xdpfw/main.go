// Command xdpfw là CLI điều khiển XDP firewall (contracts/cli.md).
//
//	xdpfw load --iface <if> [--mode native|generic]
//	xdpfw unload | status | version
//	xdpfw block-ip <CIDR> | block-ip --file <path> | unblock-ip <CIDR>
//	xdpfw block-port <tcp|udp> <port> | unblock-port <tcp|udp> <port>
//	xdpfw list [--json] | stats [--json] | flush
//	xdpfw serve [--listen :9100]
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"xdpfw/internal/exporter"
	"xdpfw/internal/fw"
	"xdpfw/internal/parse"
)

// version được gán lúc build: -ldflags "-X main.version=..."
var version = "dev"

// Mã thoát theo contracts/cli.md.
const (
	exitOK       = 0
	exitError    = 1
	exitUsage    = 2
	exitNotLoad  = 3
	exitConflict = 4
	exitFull     = 5
)

// usageError đánh dấu lỗi do người dùng nhập sai tham số (mã thoát 2).
type usageError struct{ error }

func usagef(format string, a ...any) error { return usageError{fmt.Errorf(format, a...)} }

type command struct {
	run  func(args []string) error
	help string
}

var commands map[string]command

func init() {
	commands = map[string]command{
		"load":         {cmdLoad, "load --iface <if> [--mode native|generic]"},
		"unload":       {cmdUnload, "unload"},
		"status":       {cmdStatus, "status"},
		"block-ip":     {cmdBlockIP, "block-ip <CIDR> | block-ip --file <path>"},
		"unblock-ip":   {cmdUnblockIP, "unblock-ip <CIDR>"},
		"block-port":   {cmdBlockPort, "block-port <tcp|udp> <port>"},
		"unblock-port": {cmdUnblockPort, "unblock-port <tcp|udp> <port>"},
		"list":         {cmdList, "list [--json]"},
		"stats":        {cmdStats, "stats [--json]"},
		"flush":        {cmdFlush, "flush"},
		"serve":        {cmdServe, "serve [--listen :9100]"},
		"version":      {func([]string) error { fmt.Println("xdpfw", version); return nil }, "version"},
	}
}

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		printUsage()
		os.Exit(exitUsage)
	}
	name := os.Args[1]
	cmd, ok := commands[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "xdpfw: unknown command %q\n", name)
		printUsage()
		os.Exit(exitUsage)
	}
	if err := cmd.run(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "xdpfw: %s: %v\n", name, err)
		os.Exit(exitCode(err))
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage: xdpfw <command> [args]\n\ncommands:")
	for _, n := range []string{"load", "unload", "status", "block-ip", "unblock-ip",
		"block-port", "unblock-port", "list", "stats", "flush", "serve", "version"} {
		fmt.Fprintln(os.Stderr, "  xdpfw", commands[n].help)
	}
}

// exitCode ánh xạ lỗi sang mã thoát.
func exitCode(err error) int {
	var ue usageError
	switch {
	case errors.As(err, &ue):
		return exitUsage
	case errors.Is(err, fw.ErrNotLoaded):
		return exitNotLoad
	case errors.Is(err, fw.ErrAlreadyLoaded), errors.Is(err, fw.ErrExists),
		errors.Is(err, fw.ErrNotFound), errors.Is(err, fw.ErrConflict):
		return exitConflict
	case errors.Is(err, fw.ErrFull):
		return exitFull
	}
	return exitError
}

// newFlags tạo FlagSet in lỗi theo kiểu của xdpfw thay vì thoát luôn.
func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return usageError{err}
	}
	return nil
}

// withFW mở map đã pin, chạy fn rồi đóng.
func withFW(fn func(f *fw.Firewall) error) error {
	f, err := fw.Open()
	if err != nil {
		return err
	}
	defer f.Close()
	return fn(f)
}

// ---- load / unload / status ----

func cmdLoad(args []string) error {
	fs := newFlags("load")
	iface := fs.String("iface", "", "interface to attach to (required)")
	mode := fs.String("mode", "native", "attach mode: native or generic")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *iface == "" {
		return usagef("--iface is required")
	}
	if *mode != "native" && *mode != "generic" {
		return usagef("invalid --mode %q (want native or generic)", *mode)
	}
	m, err := fw.Load(*iface, *mode)
	if err != nil {
		return err
	}
	fmt.Printf("loaded on %s (ifindex %d) mode=%s prog_id=%d\n", m.Iface, m.Ifindex, m.Mode, m.ProgID)
	return nil
}

func cmdUnload(args []string) error {
	m, err := fw.Unload()
	if err != nil {
		return err
	}
	iface := "?"
	if m != nil {
		iface = m.Iface
	}
	fmt.Printf("unloaded from %s\n", iface)
	return nil
}

func cmdStatus(args []string) error {
	return withFW(func(f *fw.Firewall) error {
		rules, err := f.List()
		if err != nil {
			return err
		}
		nIP, nPort := 0, 0
		for _, r := range rules {
			if r.Type == "ip" {
				nIP++
			} else {
				nPort++
			}
		}
		m := f.Meta
		fmt.Printf("iface:       %s (ifindex %d)\nmode:        %s\nprog_id:     %d\nattached_at: %s\nrules:       %d ip, %d port\n",
			m.Iface, m.Ifindex, m.Mode, m.ProgID, m.AttachedAt.Format("2006-01-02T15:04:05Z07:00"), nIP, nPort)
		return nil
	})
}

// ---- rule IP ----

func cmdBlockIP(args []string) error {
	fs := newFlags("block-ip")
	file := fs.String("file", "", "read one CIDR per line from file (bulk load)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	var inputs []string
	switch {
	case *file != "" && fs.NArg() == 0:
		lines, err := readLines(*file)
		if err != nil {
			return err
		}
		inputs = lines
	case *file == "" && fs.NArg() == 1:
		inputs = []string{fs.Arg(0)}
	default:
		return usagef("usage: %s", commands["block-ip"].help)
	}

	prefixes := make([]netip.Prefix, 0, len(inputs))
	for _, in := range inputs {
		c, err := parse.ParseCIDR(in)
		if err != nil {
			return usageError{err}
		}
		if c.Normalized {
			fmt.Fprintf(os.Stderr, "xdpfw: block-ip: warning: %s normalized to %s\n", in, c.Prefix)
		}
		prefixes = append(prefixes, c.Prefix)
	}

	return withFW(func(f *fw.Firewall) error {
		ids, err := f.AddIPs(prefixes)
		if *file != "" {
			fmt.Printf("added %d ip rules from %s\n", len(ids), *file)
		} else if len(ids) == 1 {
			fmt.Printf("added ip rule id=%d %s\n", ids[0], prefixes[0])
		}
		return err
	})
}

func cmdUnblockIP(args []string) error {
	if len(args) != 1 {
		return usagef("usage: %s", commands["unblock-ip"].help)
	}
	c, err := parse.ParseCIDR(args[0])
	if err != nil {
		return usageError{err}
	}
	return withFW(func(f *fw.Firewall) error {
		id, err := f.DelIP(c.Prefix)
		if err != nil {
			return err
		}
		fmt.Printf("removed ip rule id=%d %s\n", id, c.Prefix)
		return nil
	})
}

// ---- rule port ----

func parseProtoPort(name string, args []string) (uint8, uint16, error) {
	if len(args) != 2 {
		return 0, 0, usagef("usage: %s", commands[name].help)
	}
	proto, err := parse.ParseProto(args[0])
	if err != nil {
		return 0, 0, usageError{err}
	}
	port, err := parse.ParsePort(args[1])
	if err != nil {
		return 0, 0, usageError{err}
	}
	return proto, port, nil
}

func cmdBlockPort(args []string) error {
	proto, port, err := parseProtoPort("block-port", args)
	if err != nil {
		return err
	}
	return withFW(func(f *fw.Firewall) error {
		id, err := f.AddPort(proto, port)
		if err != nil {
			return err
		}
		fmt.Printf("added port rule id=%d %s/%d\n", id, parse.ProtoName(proto), port)
		return nil
	})
}

func cmdUnblockPort(args []string) error {
	proto, port, err := parseProtoPort("unblock-port", args)
	if err != nil {
		return err
	}
	return withFW(func(f *fw.Firewall) error {
		id, err := f.DelPort(proto, port)
		if err != nil {
			return err
		}
		fmt.Printf("removed port rule id=%d %s/%d\n", id, parse.ProtoName(proto), port)
		return nil
	})
}

// ---- list / stats / flush ----

func cmdList(args []string) error {
	fs := newFlags("list")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	return withFW(func(f *fw.Firewall) error {
		rules, err := f.List()
		if err != nil {
			return err
		}
		if *asJSON {
			if rules == nil {
				rules = []fw.Rule{}
			}
			return json.NewEncoder(os.Stdout).Encode(rules)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tTYPE\tMATCH\tPACKETS\tBYTES")
		for _, r := range rules {
			fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%d\n", r.ID, r.Type, r.Match, r.Packets, r.Bytes)
		}
		return w.Flush()
	})
}

func cmdStats(args []string) error {
	fs := newFlags("stats")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	return withFW(func(f *fw.Firewall) error {
		st, err := f.ReadStats()
		if err != nil {
			return err
		}
		if *asJSON {
			out := map[string]fw.Counter{}
			for i, c := range st {
				out[fw.StatNames[i]] = c
			}
			return json.NewEncoder(os.Stdout).Encode(out)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ACTION\tPACKETS\tBYTES")
		for i, c := range st {
			fmt.Fprintf(w, "%s\t%d\t%d\n", fw.StatNames[i], c.Packets, c.Bytes)
		}
		return w.Flush()
	})
}

func cmdFlush(args []string) error {
	return withFW(func(f *fw.Firewall) error {
		if err := f.Flush(); err != nil {
			return err
		}
		fmt.Println("flushed all rules and counters")
		return nil
	})
}

// ---- serve ----

func cmdServe(args []string) error {
	fs := newFlags("serve")
	listen := fs.String("listen", ":9100", "address for /metrics")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	// Registry riêng: chỉ có metric của xdpfw, không kèm metric runtime của Go.
	reg := prometheus.NewRegistry()
	reg.MustRegister(exporter.Collector{})
	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	fmt.Fprintf(os.Stderr, "xdpfw: serving metrics on %s/metrics\n", *listen)
	return http.ListenAndServe(*listen, nil)
}

// readLines đọc file, bỏ dòng trống và dòng bắt đầu bằng '#'.
func readLines(path string) ([]string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var out []string
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}
