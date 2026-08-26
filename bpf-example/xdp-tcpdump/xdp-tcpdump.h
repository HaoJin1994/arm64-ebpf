#ifndef XDP_TCPDUMP_H_
#define XDP_TCPDUMP_H_



#define MAX_TCP_HEADER_BYTES 60
#define MAX_PAYLOAD_BYTES 1460

#define MAX_ARENA_EVENTS 256
#define ARENA_PAGES      128

struct tcp_event {
    unsigned int header_len;
    unsigned int payload_len;
    unsigned char header[MAX_TCP_HEADER_BYTES];
    unsigned char payload[MAX_PAYLOAD_BYTES];
};

struct arena_layout {
    struct bpf_spin_lock lock;
    __u32 write_index;
    __u32 _pad;
    struct tcp_event events[MAX_ARENA_EVENTS];
};

#endif /* XDP_TCPDUMP_H_ */