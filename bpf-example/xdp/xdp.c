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

#include "xdp.skel.h"

static struct env
{
    bool verbose;
    int ifindex;
} env = {
    .verbose = true,
};

const struct argp_option opts[] = {
    {"help", 'h', 0, 0, " Print help"},
    {"verbose", 'v', 0, 0, " Print verbose output"},
    {"dev",'d',"ETH",0,"Device name"},
    {0, 0, 0, 0, 0},
};
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        return 0;
    case 'v':
        env.verbose = true;
        return 0;
    case 'd':
        env.ifindex = if_nametoindex(arg);
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
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
    };
    struct xdp_bpf *skel = NULL;
    int err;
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err){
        fprintf(stderr, "argp_parse failed: %d\n", err);
        return err;
    }
    
    libbpf_set_print(libbpf_print_fn);

    skel = xdp_bpf__open_opts(&open_opts);
    if (!skel)
    {
        fprintf(stderr, "tc_bpf__open_opts failed\n");
        return -1;
    }
    
    err = xdp_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "tc_bpf__load failed: %d\n", err);
        return -1;
    }
   
    skel->links.xdp_pass = bpf_program__attach_xdp(skel->progs.xdp_pass, env.ifindex);
    if (skel->links.xdp_pass < 0)
    {
        fprintf(stderr, "Failed to attach XDP: %d\n", err);
        goto cleanup;
    }
    
    signal(SIGINT, sig_handler);
    while (1){
        sleep(1);

        if (exiting)
            break;
    }

    bpf_link__destroy(skel->links.xdp_pass);
cleanup:
    xdp_bpf__destroy(skel);

    return 0;
}