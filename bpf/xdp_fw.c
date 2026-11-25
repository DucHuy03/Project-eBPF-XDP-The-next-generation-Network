// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_fw.c — XDP firewall: chặn IP/subnet nguồn và port đích (TCP/UDP), đếm gói.
 *
 * Luồng xử lý một gói:
 *   Ethernet -> (không phải IPv4? PASS) -> IPv4 header (hỏng? PARSE_ERR + PASS)
 *   -> tra blocked_src (LPM)  : khớp => DROP_IP
 *   -> nếu TCP/UDP: tra blocked_port (hash) : khớp => DROP_PORT
 *   -> PASS
 *
 * Nguyên tắc: gói nào firewall không hiểu thì cho qua (XDP_PASS) để kernel xử lý,
 * firewall không bao giờ được làm hỏng traffic ngoài phạm vi (ARP, IPv6, ...).
 *
 * Chỉ dùng header UAPI (định dạng gói theo RFC), không cần vmlinux.h/CO-RE vì
 * chương trình không đọc struct nội bộ nào của kernel (xem research.md R1).
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ---- Kích thước bảng (data-model.md §1) ---- */
#define MAX_IP_RULES   16384
#define MAX_PORT_RULES 1024
#define MAX_RULES      (MAX_IP_RULES + MAX_PORT_RULES)

/* Chỉ số trong map stats (data-model.md §1.3) */
enum stat_idx {
	STAT_PASS      = 0,
	STAT_DROP_IP   = 1,
	STAT_DROP_PORT = 2,
	STAT_PARSE_ERR = 3,
	STAT_MAX       = 4,
};

/* Bộ đếm gói/byte. Map per-CPU => mỗi CPU một bản, cộng không cần khóa. */
struct counter {
	__u64 packets;
	__u64 bytes;
};

/* Key cho LPM trie: BẮT BUỘC bắt đầu bằng prefixlen (u32), sau đó là dữ liệu.
 * addr giữ nguyên network byte order như trong IP header => không cần đổi byte. */
struct lpm_v4_key {
	__u32 prefixlen;
	__u32 addr;
};

/* Key cho rule chặn port. pad = 0 để 4 byte của key luôn xác định
 * (hash map so sánh toàn bộ byte của key). dport giữ network byte order. */
struct port_key {
	__u8  proto;
	__u8  pad;
	__u16 dport;
};

/* blocked_src: địa chỉ/subnet nguồn -> rule_id. LPM tự trả về prefix dài nhất khớp.
 * LPM trie bắt buộc cờ BPF_F_NO_PREALLOC. */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_IP_RULES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_v4_key);
	__type(value, __u32);
} blocked_src SEC(".maps");

/* blocked_port: (proto, dport) -> rule_id. Tra cứu O(1). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PORT_RULES);
	__type(key, struct port_key);
	__type(value, __u32);
} blocked_port SEC(".maps");

/* stats: bộ đếm theo kết quả xử lý. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, struct counter);
} stats SEC(".maps");

/* rule_hits: bộ đếm theo rule_id (IP: 0..16383, port: 16384..17407). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_RULES);
	__type(key, __u32);
	__type(value, struct counter);
} rule_hits SEC(".maps");

/* Cộng 1 gói + len byte vào phần tử idx của một map counter.
 * __always_inline: tránh gọi hàm BPF (đơn giản cho verifier). */
static __always_inline void count(void *map, __u32 idx, __u64 len)
{
	struct counter *c = bpf_map_lookup_elem(map, &idx);

	/* Verifier bắt buộc kiểm tra NULL dù idx luôn hợp lệ. */
	if (c) {
		c->packets++;
		c->bytes += len;
	}
}

/* Ghi nhận kết quả và trả về action tương ứng. */
static __always_inline int verdict(enum stat_idx s, __u64 len, int action)
{
	count(&stats, s, len);
	return action;
}

SEC("xdp")
int xdp_fw(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 len      = data_end - data;

	/* 1. Ethernet header. Mọi lần đọc dữ liệu gói phải chứng minh cho verifier
	 *    rằng không đọc vượt data_end, nếu không chương trình bị từ chối. */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return verdict(STAT_PARSE_ERR, len, XDP_PASS);

	/* Không phải IPv4 (ARP, IPv6, VLAN, ...) => ngoài phạm vi, cho qua. */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return verdict(STAT_PASS, len, XDP_PASS);

	/* 2. IPv4 header: đọc phần cố định 20 byte trước. */
	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return verdict(STAT_PARSE_ERR, len, XDP_PASS);

	/* ihl tính theo đơn vị 4 byte; < 5 là header hỏng. Header có thể dài hơn
	 * 20 byte (IP options) nên vị trí L4 = iph + ihl*4, không phải iph + 20. */
	__u32 ihl_bytes = iph->ihl * 4;
	if (iph->ihl < 5 || (void *)iph + ihl_bytes > data_end)
		return verdict(STAT_PARSE_ERR, len, XDP_PASS);

	/* 3. Rule chặn IP/subnet nguồn: LPM trả về prefix dài nhất khớp.
	 *    Kiểm tra TRƯỚC giao thức và fragment: IP bị chặn thì chặn mọi gói của nó
	 *    (ICMP, fragment, ...), không chỉ TCP/UDP. */
	struct lpm_v4_key k4 = { .prefixlen = 32, .addr = iph->saddr };
	__u32 *rule_id = bpf_map_lookup_elem(&blocked_src, &k4);
	if (rule_id) {
		count(&rule_hits, *rule_id, len);
		return verdict(STAT_DROP_IP, len, XDP_DROP);
	}

	/* 4. Rule chặn port: chỉ TCP/UDP có port. */
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return verdict(STAT_PASS, len, XDP_PASS);

	/* Fragment thứ 2 trở đi không chứa header L4 => không có port để so. */
	if (iph->frag_off & bpf_htons(0x1FFF))
		return verdict(STAT_PASS, len, XDP_PASS);

	void *l4 = (void *)iph + ihl_bytes;
	struct port_key kp = { .proto = iph->protocol, .pad = 0 };

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return verdict(STAT_PARSE_ERR, len, XDP_PASS);
		kp.dport = tcp->dest;
	} else {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return verdict(STAT_PARSE_ERR, len, XDP_PASS);
		kp.dport = udp->dest;
	}

	rule_id = bpf_map_lookup_elem(&blocked_port, &kp);
	if (rule_id) {
		count(&rule_hits, *rule_id, len);
		return verdict(STAT_DROP_PORT, len, XDP_DROP);
	}

	return verdict(STAT_PASS, len, XDP_PASS);
}

char LICENSE[] SEC("license") = "GPL";
