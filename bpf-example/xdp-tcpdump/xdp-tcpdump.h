#ifndef XDP_TCPDUMP_H_
#define XDP_TCPDUMP_H_

<<<<<<< HEAD


#define MAX_TCP_HEADER_BYTES 60
#define MAX_PAYLOAD_BYTES 1460

#define MAX_ARENA_EVENTS 256
#define ARENA_PAGES      128

=======
#define MAX_TCP_HEADER_BYTES 60
#define MAX_PAYLOAD_BYTES 1460
>>>>>>> 7f430aa7880f7203df002f612b93ea09303bd062
struct tcp_event {
    unsigned int header_len;
    unsigned int payload_len;
    unsigned char header[MAX_TCP_HEADER_BYTES];
    unsigned char payload[MAX_PAYLOAD_BYTES];
};

<<<<<<< HEAD
struct arena_layout {
    struct bpf_spin_lock lock;
    __u32 write_index;
    __u32 _pad;
    struct tcp_event events[MAX_ARENA_EVENTS];
};

#endif /* XDP_TCPDUMP_H_ */
=======
#endif /* XDP_TCPDUMP_H_ */
>>>>>>> 7f430aa7880f7203df002f612b93ea09303bd062
