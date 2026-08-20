#include <stdio.h>
#include <ctype.h>
#include <argp.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include "usdt.skel.h"
#include "usdt.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG )
        return 0;
    return vfprintf(stderr, format, args);
}

static bool exiting = false;
static void sig_handler(int sig)
{
    exiting = true;
}
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct usdt_data *e = data;
    printf("pid: %llu, tid: %llu, arg1: %llu, arg2: %llu, ret: %llu\n", e->pid, e->tid, e->arg1, e->arg2, e->ret);

    return 0;
}

int main(char *argv[], int argc){
    
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    libbpf_set_print(libbpf_print_fn);
    struct usdt_bpf *skel;
    int err;
    struct ring_buffer *rb = NULL;

    skel= usdt_bpf__open_opts(&open_opts);
    if (!skel)
    {
        fprintf(stderr, "usdt_bpf__open_opts failed\n");
        return -1;
    }
    err = usdt_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "usdt_bpf__load failed: %d\n", err);
        return -1;
    }
   skel->links.start = bpf_program__attach_usdt(skel->progs.start,-1,"/home/jin/test_usdt", \
            "test_usdt","add_start",NULL);
    if (!skel->links.start)
    {
        fprintf(stderr, "bpf_program__attach_usdt failed\n");
        return -1;
    }
    skel->links.end = bpf_program__attach_usdt(skel->progs.end,-1,"/home/jin/test_usdt", \
            "test_usdt","add_end",NULL);
    if (!skel->links.end)
    {
        fprintf(stderr, "bpf_program__attach_usdt failed\n");
        return -1;
    }


    err = usdt_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "usdt_bpf__attach failed: %d\n", err);
        return -1;
    }
    signal(SIGINT, sig_handler);
    
    rb =ring_buffer__new(bpf_map__fd(skel->maps.ringbuf),handle_event,NULL,NULL);
    if (!rb)
    {
        fprintf(stderr, "ring_buffer__new failed\n");
        return -1;
    }

    while(1){
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
        if (exiting)
            break;

    }

}

