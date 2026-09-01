// SPDX-License-Identifier: GPL-2.0
#if 0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "tcp_status.h"

#define AF_INET 2
#define TCP_ESTABLISHED 1

char LICENSE[] SEC("license") = "GPL";

const volatile __u32 target_addr;
const volatile __u16 target_port;
const volatile __u8 target_state;

struct tcp_status_stats stats;

static const char *tcp_state_to_string(__u8 state)
{
    switch (state) {
    case TCP_ESTABLISHED:  return "ESTABLISHED";
    case TCP_SYN_SENT:     return "SYN_SENT";
    case TCP_SYN_RECV:     return "SYN_RECV";
    case TCP_FIN_WAIT1:    return "FIN_WAIT1";
    case TCP_FIN_WAIT2:    return "FIN_WAIT2";
    case TCP_TIME_WAIT:    return "TIME_WAIT";
    case TCP_CLOSE:        return "CLOSE";
    case TCP_CLOSE_WAIT:   return "CLOSE_WAIT";
    case TCP_LAST_ACK:     return "LAST_ACK";
    case TCP_LISTEN:       return "LISTEN";
    case TCP_CLOSING:      return "CLOSING";
    case TCP_NEW_SYN_RECV: return "NEW_SYN_RECV";
    default:               return "UNKNOWN";
    }
}

SEC("iter/tcp")
int tcp_link_status(struct bpf_iter__tcp *ctx)
{
	struct sock_common *sk = ctx->sk_common;
	struct seq_file *seq = ctx->meta->seq;

	__u32 dst_addr;
	__u32 src_addr;
	__u16 dst_port;
	__u16 src_port;
	__u16 family;
	__u8 state;

	int err;

	if (!sk)
		return 0;

	family = BPF_CORE_READ(sk, skc_family);
	state = BPF_CORE_READ(sk, skc_state);

	dst_addr = BPF_CORE_READ(sk, skc_daddr);
	src_addr = BPF_CORE_READ(sk, skc_rcv_saddr);
	dst_port = BPF_CORE_READ(sk, skc_dport);
	src_port = BPF_CORE_READ(sk, skc_num);

	if (target_addr && dst_addr != target_addr && src_addr != target_addr)
		return 0;
	if (target_port && dst_port != target_port && src_port != target_port)
		return 0;
	if(target_state && target_state != state)
		return 0;

	
	if (stats.scanned == 0) {
		BPF_SEQ_PRINTF(seq, "%-8s %-22s %-22s %-12s\n",
			       "Proto", "Local Address", "Foreign Address", "State");
	}
	{
		char src_str[22] = {};
		char dst_str[22] = {};

		BPF_SNPRINTF(src_str, sizeof(src_str), "%pI4:%-5u", &src_addr, src_port);
		BPF_SNPRINTF(dst_str, sizeof(dst_str), "%pI4:%-5u", &dst_addr, dst_port);
		BPF_SEQ_PRINTF(seq, "%-8s %-22s %-22s %-12s\n",
			       "tcp", src_str, dst_str,
			       tcp_state_to_string(state));
	}
                   
    stats.scanned++;

	return 0;
}
#else
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "tcp_status.h"

#define AF_INET 2
#define TCP_ESTABLISHED 1

char LICENSE[] SEC("license") = "GPL";

const volatile __u32 target_addr;
const volatile __u16 target_port;
const volatile __u8 target_state;

struct tcp_status_stats stats;

SEC("iter/tcp")
int tcp_link_status(struct bpf_iter__tcp *ctx)
{
    struct sock_common *sk = ctx->sk_common;
    struct seq_file *seq = ctx->meta->seq;

    __u32 dst_addr, src_addr;
    __u16 dst_port, src_port;
    __u16 family;
    __u8 state;

    if (!sk)
        return 0;

    family = BPF_CORE_READ(sk, skc_family);
    state = BPF_CORE_READ(sk, skc_state);

    if (family != AF_INET)
        return 0;

    dst_addr = BPF_CORE_READ(sk, skc_daddr);
    src_addr = BPF_CORE_READ(sk, skc_rcv_saddr);
    dst_port = BPF_CORE_READ(sk, skc_dport);
    src_port = BPF_CORE_READ(sk, skc_num);

    if (target_addr && dst_addr != target_addr && src_addr != target_addr)
        return 0;
    if (target_port && dst_port != target_port && src_port != target_port)
        return 0;
    if (target_state && target_state != state)
        return 0;

    if (stats.scanned == 0) {
        BPF_SEQ_PRINTF(seq, "Proto Local Address           Foreign Address          State\n");
        BPF_SEQ_PRINTF(seq, "----- ----------------------- ----------------------- ------------\n");
    }

  
    BPF_SEQ_PRINTF(seq, "tcp   ");
    BPF_SEQ_PRINTF(seq, "%pI4:%-5u", &src_addr, src_port);
    BPF_SEQ_PRINTF(seq, "     ");
    BPF_SEQ_PRINTF(seq, "%pI4:%-5u", &dst_addr, dst_port);
    BPF_SEQ_PRINTF(seq, "     ");
    
    
    switch (state) {
    case TCP_ESTABLISHED:  BPF_SEQ_PRINTF(seq, "ESTABLISHED"); break;
    case TCP_SYN_SENT:     BPF_SEQ_PRINTF(seq, "SYN_SENT   "); break;
    case TCP_SYN_RECV:     BPF_SEQ_PRINTF(seq, "SYN_RECV   "); break;
    case TCP_FIN_WAIT1:    BPF_SEQ_PRINTF(seq, "FIN_WAIT1  "); break;
    case TCP_FIN_WAIT2:    BPF_SEQ_PRINTF(seq, "FIN_WAIT2  "); break;
    case TCP_TIME_WAIT:    BPF_SEQ_PRINTF(seq, "TIME_WAIT  "); break;
    case TCP_CLOSE:        BPF_SEQ_PRINTF(seq, "CLOSE      "); break;
    case TCP_CLOSE_WAIT:   BPF_SEQ_PRINTF(seq, "CLOSE_WAIT "); break;
    case TCP_LAST_ACK:     BPF_SEQ_PRINTF(seq, "LAST_ACK   "); break;
    case TCP_LISTEN:       BPF_SEQ_PRINTF(seq, "LISTEN     "); break;
    case TCP_CLOSING:      BPF_SEQ_PRINTF(seq, "CLOSING    "); break;
    case TCP_NEW_SYN_RECV: BPF_SEQ_PRINTF(seq, "NEW_SYN_RECV"); break;
    default:               BPF_SEQ_PRINTF(seq, "UNKNOWN    "); break;
    }
    BPF_SEQ_PRINTF(seq, "\n");
                   
    stats.scanned++;

    return 0;
}
#endif