#ifndef XDP_TCPDUMP_H_
#define XDP_TCPDUMP_H_

#define MAX_TCP_HEADER_BYTES 60
#define MAX_PAYLOAD_BYTES 1460
struct tcp_event {
    unsigned int header_len;
    unsigned int payload_len;
    unsigned char header[MAX_TCP_HEADER_BYTES];
    unsigned char payload[MAX_PAYLOAD_BYTES];
};

#endif /* XDP_TCPDUMP_H_ */
