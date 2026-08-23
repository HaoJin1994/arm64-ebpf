#include <argp.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>

#include "bpf_contrack.skel.h"
#include "bpf_redirect.skel.h"

#define MAP_PIN_PATH "/sys/fs/bpf/sockops_map"

static bool exiting = false;

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void sig_handler(int signum)
{
    exiting = true;
    printf("Received signal %d\n", signum);
}

int main(int argc, char **argv)
{
    int cgroup_fd, map_fd, prog_fd;
    struct bpf_contrack_bpf *contrack = NULL;
    struct bpf_redirect_bpf *redirect = NULL;
    struct bpf_link *sockops_link = NULL;

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* 1. 打开 cgroup fd */
    cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
    if (cgroup_fd < 0) {
        perror("open cgroup");
        return 1;
    }

    /* 2. 加载 sockops 程序（负责填充 sockhash map） */
    contrack = bpf_contrack_bpf__open_and_load();
    if (!contrack) {
        fprintf(stderr, "Failed to load contrack\n");
        goto cleanup;
    }

    /* 3. 将 sockops 附加到 cgroup */
    sockops_link = bpf_program__attach_cgroup(
        contrack->progs.bpf_sockops_handler, cgroup_fd);
    if (!sockops_link) {
        fprintf(stderr, "Failed to attach sockops\n");
        goto cleanup;
    }

    /* 4. Pin map 以便 sk_msg 程序复用 */
    map_fd = bpf_map__fd(contrack->maps.sock_ops_map);
    bpf_map__pin(contrack->maps.sock_ops_map, MAP_PIN_PATH);

    /* 5. 加载 sk_msg 程序，但复用已 pin 的 map */
    redirect = bpf_redirect_bpf__open();
    if (!redirect) {
        fprintf(stderr, "Failed to open redirect\n");
        goto cleanup;
    }
    bpf_map__reuse_fd(redirect->maps.sock_ops_map, map_fd);
    if (bpf_redirect_bpf__load(redirect)) {
        fprintf(stderr, "Failed to load redirect\n");
        goto cleanup;
    }

    /* 6. 将 sk_msg 附加到 sockhash map */
    prog_fd = bpf_program__fd(redirect->progs.bpf_redir);
    if (bpf_prog_attach(prog_fd, map_fd, BPF_SK_MSG_VERDICT, 0)) {
        fprintf(stderr, "Failed to attach sk_msg\n");
        goto cleanup;
    }

    printf("BPF programs loaded and attached. Ctrl+C to exit.\n");

    while (!exiting)
        sleep(1);

cleanup:
    bpf_prog_detach2(prog_fd, map_fd, BPF_SK_MSG_VERDICT);
    bpf_link__destroy(sockops_link);
    bpf_redirect_bpf__destroy(redirect);
    bpf_contrack_bpf__destroy(contrack);
    bpf_map__unpin(contrack->maps.sock_ops_map, MAP_PIN_PATH);
    close(cgroup_fd);
    return 0;
}