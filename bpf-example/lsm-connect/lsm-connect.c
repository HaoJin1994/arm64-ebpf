#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <argp.h>
#include <arpa/inet.h>

#include "lsm-connect.skel.h"

static struct env
{
    __u32 ipaddr;
    bool verbose;
} env = {
    .ipaddr = 0,
    .verbose = true,
};

const struct argp_option opts[] = {
    {"help", 'h', 0, 0, " Print help"},
    {"verbose", 'v', 0, 0, " Print verbose output"},
    {"ipaddr", 'i', "IPADDR", 0, " IP address to filter"},
    {0, 0, 0, 0, 0},
};
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        return 0;
    case 'i':
        env.ipaddr = inet_addr(arg);
        return 0;
    case 'v':
        env.verbose = true;
        return 0;
    default:
        return ARGP_ERR_UNKNOWN;
    }
}
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}
static bool exiting = false;
static void sig_handler(int sig)
{
    exiting = true;
}
int main(int argc, char *argv[])
{
    printf("lsm-connect\n");
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
    };
    struct lsm_connect_bpf *skel = NULL;
    int err;
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err){
        fprintf(stderr, "argp_parse failed: %d\n", err);
        return err;
    }
    
    libbpf_set_print(libbpf_print_fn);

    skel = lsm_connect_bpf__open_opts(&open_opts);
    if (!skel)
    {
        fprintf(stderr, "lsm_connect_bpf__open_opts failed\n");
        return -1;
    }
    skel->rodata->blockme = env.ipaddr;
    printf("ipaddr: %s\n", inet_ntoa((struct in_addr){env.ipaddr}));

    err = lsm_connect_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "lsm_connect_bpf__load failed: %d\n", err);
        return -1;
    }
    err = lsm_connect_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "lsm_connect_bpf__attach failed: %d\n", err);
        return -1;
    }
    signal(SIGINT, sig_handler);
    while (1){
        sleep(1);

        if (exiting)
            break;
    }

    lsm_connect_bpf__detach(skel);
    lsm_connect_bpf__destroy(skel);

    return 0;
}