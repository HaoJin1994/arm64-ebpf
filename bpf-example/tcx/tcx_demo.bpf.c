// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef TCX_NEXT
#define TCX_NEXT -1
#endif

#ifndef TCX_PASS
#define TCX_PASS 0
#endif

char LICENSE[] SEC("license") = "GPL";

__u64 stats_hits;
__u64 classifier_hits;
__u32 last_len;
__u16 last_protocol;
__u32 last_ifindex;

#define OUR_PORT 12345


static __always_inline int is_our_packet(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct udphdr *udph;

	if ((void *)(eth + 1) > data_end)
		return 0;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return 0;

	iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return 0;
	if (iph->protocol != IPPROTO_UDP)
		return 0;

	udph = (void *)(iph + 1);
	if ((void *)(udph + 1) > data_end)
		return 0;

	return udph->dest == bpf_htons(OUR_PORT);
}

SEC("tcx/ingress")
int tcx_stats(struct __sk_buff *skb)
{
	if (!is_our_packet(skb))
		return TCX_NEXT;
	stats_hits++;
	last_len = skb->len;
	last_protocol = bpf_ntohs(skb->protocol);
	last_ifindex = skb->ifindex;
	return TCX_NEXT;
}

SEC("tcx/ingress")
int tcx_classifier(struct __sk_buff *skb)
{
	if (!is_our_packet(skb))
		return TCX_PASS;
	classifier_hits++;
	return TCX_PASS;
}