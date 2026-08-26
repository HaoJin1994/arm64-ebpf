#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
<<<<<<< HEAD
#include <sys/mman.h>
=======
>>>>>>> 7f430aa7880f7203df002f612b93ea09303bd062
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

<<<<<<< HEAD
#include "xdp-tcpdump.skel.h"
#include "xdp-tcpdump.h"

static void print_event(struct tcp_event *event)
{
    if (event->header_len < 20 || event->header_len > MAX_TCP_HEADER_BYTES) {
        fprintf(stderr, "Invalid TCP header length: %u\n", event->header_len);
        return;
    }

=======
#include "xdp-tcpdump.skel.h"  // Generated skeleton header
#include "xdp-tcpdump.h"

// Callback function to handle events from the ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    if (data_sz < sizeof(struct tcp_event)) {
        fprintf(stderr, "Received incomplete TCP event\n");
        return 0;
    }

    struct tcp_event *event = data;
    if (event->header_len < 20 || event->header_len > MAX_TCP_HEADER_BYTES) {
        fprintf(stderr, "Invalid TCP header length: %u\n", event->header_len);
        return 0;
    }

    // Parse the raw TCP header bytes
>>>>>>> 7f430aa7880f7203df002f612b93ea09303bd062
    struct tcphdr {
        uint16_t source;
        uint16_t dest;
        uint32_t seq;
        uint32_t ack_seq;
        uint16_t res1:4,
                 doff:4,
                 fin:1,
                 syn:1,
                 rst:1,
                 psh:1,
                 ack:1,
                 urg:1,
                 ece:1,
                 cwr:1;
        uint16_t window;
        uint16_t check;
        uint16_t urg_ptr;
<<<<<<< HEAD
=======
        // Options and padding may follow
>>>>>>> 7f430aa7880f7203df002f612b93ea09303bd062
    } __attribute__((packed));

    struct tcphdr *tcp = (struct tcphdr *)event->header;

<<<<<<< HEAD
=======
    // Convert fields from network byte order to host byte order
>>>>>>> 7f430aa7880f7203df002f612b93ea09303bd062
    uint16_t source_port = ntohs(tcp->source);
    uint16_t dest_port = ntohs(tcp->dest);
    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack_seq = ntohl(tcp->ack_seq);
    uint16_t window = ntohs(tcp->window);

<<<<<<< HEAD
=======
    // Extract flags
>>>>>>> 7f430aa7880f7203df002f612b93ea09303bd062
    uint8_t flags = 0;
    flags |= (tcp->fin) ? 0x01 : 0x00;
    flags |= (tcp->syn) ? 0x02 : 0x00;
    flags |= (tcp->rst) ? 0x04 : 0x00;
    flags |= (tcp->psh) ? 0x08 : 0x00;
    flags |= (tcp->ack) ? 0x10 : 0x00;
    flags |= (tcp->urg) ? 0x20 : 0x00;
    flags |= (tcp->ece) ? 0x40 : 0x00;
    flags |= (tcp->cwr) ? 0x80 : 0x00;

    printf("Captured TCP Header:\n");
    printf("  Source Port: %u\n", source_port);
    printf("  Destination Port: %u\n", dest_port);
    printf("  Sequence Number: %u\n", seq);
    printf("  Acknowledgment Number: %u\n", ack_seq);
    printf("  Data Offset: %u\n", tcp->doff);
    printf("  Flags: 0x%02x\n", flags);
    printf("  Window Size: %u\n", window);
    printf("\n");

    printf("Payload:\n");
<<<<<<< HEAD
    for (int i = 0; i < event->payload_len; i++) {
        printf("%02x ", event->payload[i]);
    }
    printf("\n");
=======
    for(int i = 0; i < event->payload_len; i++){
        printf("%02x ", event->payload[i]);
    }
    printf("\n");
    return 0;
>>>>>>> 7f430aa7880f7203df002f612b93ea09303bd062
}

int main(int argc, char **argv)
{
    struct xdp_tcpdump_bpf *skel;
<<<<<<< HEAD
    struct arena_layout *layout = NULL;
    int ifindex;
    int err;
    __u32 last_idx = 0;
=======
    struct ring_buffer *rb = NULL;
    int ifindex;
    int err;
>>>>>>> 7f430aa7880f7203df002f612b93ea09303bd062

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
    {
        fprintf(stderr, "Invalid interface name %s\n", ifname);
        return 1;
    }

<<<<<<< HEAD
=======
    /* Open and load BPF application */
>>>>>>> 7f430aa7880f7203df002f612b93ea09303bd062
    skel = xdp_tcpdump_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

<<<<<<< HEAD
=======
    /* Load & verify BPF programs */
>>>>>>> 7f430aa7880f7203df002f612b93ea09303bd062
    err = xdp_tcpdump_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

<<<<<<< HEAD
=======
    /* Attach XDP program */
>>>>>>> 7f430aa7880f7203df002f612b93ea09303bd062
    err = xdp_tcpdump_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

<<<<<<< HEAD
=======
    /* Attach the XDP program to the specified interface */
>>>>>>> 7f430aa7880f7203df002f612b93ea09303bd062
    skel->links.xdp_pass = bpf_program__attach_xdp(skel->progs.xdp_pass, ifindex);
    if (!skel->links.xdp_pass)
    {
        err = -errno;
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("Successfully attached XDP program to interface %s\n", ifname);

<<<<<<< HEAD
    /* mmap the arena map into userspace */
    int arena_fd = bpf_map__fd(skel->maps.arena);
    size_t arena_sz = ARENA_PAGES * 4096;
    layout = mmap(NULL, arena_sz, PROT_READ | PROT_WRITE, MAP_SHARED, arena_fd, 0);
    if (layout == MAP_FAILED)
    {
        fprintf(stderr, "Failed to mmap arena: %s\n", strerror(errno));
        err = -errno;
        goto cleanup;
    }

    printf("Start polling arena (mmap'd shared memory)\n");

    /* Poll the arena write_index for new events */
    while (1)
    {
        __u32 cur_idx = __atomic_load_n(&layout->write_index, __ATOMIC_ACQUIRE);

        while (last_idx < cur_idx)
        {
            __u32 slot = last_idx % MAX_ARENA_EVENTS;
            struct tcp_event *event = &layout->events[slot];

            if (event->header_len >= 20 && event->header_len <= MAX_TCP_HEADER_BYTES)
                print_event(event);

            last_idx++;
        }

        usleep(10000);
    }

cleanup:
    if (layout && layout != MAP_FAILED)
        munmap(layout, arena_sz);
    xdp_tcpdump_bpf__destroy(skel);
    return -err;
}
=======
    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb)
    {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("Start polling ring buffer\n");

    /* Poll the ring buffer */
    while (1)
    {
        err = ring_buffer__poll(rb, -1);
        if (err == -EINTR)
            continue;
        if (err < 0)
        {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    xdp_tcpdump_bpf__destroy(skel);
    return -err;
}
>>>>>>> 7f430aa7880f7203df002f612b93ea09303bd062
