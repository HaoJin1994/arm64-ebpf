// /home/jin/arm64_lib/bpf-example/profile_flame/profile_flame.c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
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

#include "bpftrace.skel.h"
#include "bpftrace.h"
#include "blazesym_api.h"

int parse_cpu_mask_str(const char *s, bool **mask, int *mask_sz)
{
    int err = 0, n, len, start, end = -1;
    bool *tmp;

    *mask = NULL;
    *mask_sz = 0;

    /* Each sub string separated by ',' has format \d+-\d+ or \d+ */
    while (*s)
    {
        if (*s == ',' || *s == '\n')
        {
            s++;
            continue;
        }
        n = sscanf(s, "%d%n-%d%n", &start, &len, &end, &len);
        if (n <= 0 || n > 2)
        {
            printf("Failed to get CPU range %s: %d\n", s, n);
            err = -EINVAL;
            goto cleanup;
        }
        else if (n == 1)
        {
            end = start;
        }
        if (start < 0 || start > end)
        {
            printf("Invalid CPU range [%d,%d] in %s\n",
                   start, end, s);
            err = -EINVAL;
            goto cleanup;
        }
        tmp = realloc(*mask, end + 1);
        if (!tmp)
        {
            err = -ENOMEM;
            goto cleanup;
        }
        *mask = tmp;
        memset(tmp + *mask_sz, 0, start - *mask_sz);
        memset(tmp + start, 1, end - start + 1);
        *mask_sz = end + 1;
        s += len;
    }
    if (!*mask_sz)
    {
        printf("Empty CPU range\n");
        return -EINVAL;
    }
    return 0;
cleanup:
    free(*mask);
    *mask = NULL;
    return err;
}

int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz)
{
    int fd, err = 0, len;
    char buf[128];

    fd = open(fcpu, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        err = -errno;
        printf("Failed to open cpu mask file %s: %d\n", fcpu, err);
        return err;
    }
    len = read(fd, buf, sizeof(buf));
    close(fd);
    if (len <= 0)
    {
        err = len ? -errno : -EINVAL;
        printf("Failed to read cpu mask from %s: %d\n", fcpu, err);
        return err;
    }
    if (len >= sizeof(buf))
    {
        printf("CPU mask is too big in file %s\n", fcpu);
        return -E2BIG;
    }
    buf[len] = '\0';

    return parse_cpu_mask_str(buf, mask, mask_sz);
}

static volatile sig_atomic_t g_exiting = 0;

static void sig_handler(int sig)
{
    g_exiting = 1;
}

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

static void get_comm(int pid, char *comm, size_t size)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *fp = fopen(path, "r");
    if (!fp)
    {
        snprintf(comm, size, "unknown");
        return;
    }
    if (!fgets(comm, size, fp))
        snprintf(comm, size, "unknown");
    fclose(fp);
    size_t len = strlen(comm);
    if (len > 0 && comm[len - 1] == '\n')
        comm[len - 1] = '\0';
}

static void print_folded(sym_info_t *frames, int depth, __u64 count)
{
    for (int i = depth - 1; i >= 0; i--)
    {
        if (i < depth - 1)
            printf(";");
        if (frames[i].name[0])
            printf("%s", frames[i].name);
        else if (frames[i].module[0])
        {
            const char *base = strrchr(frames[i].module, '/');
            if (base)
                base++;
            else
                base = frames[i].module;
            printf("%s+0x%lx", base, frames[i].module_offset);
        }
        else
            printf("[0x%lx]", frames[i].addr);
    }
    printf(" %llu\n", (unsigned long long)count);
}

static void dump_bpftrace_graph(struct bpftrace_bpf *skel, int pid, const char *comm, uint64_t load_base)
{
    int counts_fd = bpf_map__fd(skel->maps.counts);
    int ustack_fd = bpf_map__fd(skel->maps.ustackmap);
    int kstack_fd = bpf_map__fd(skel->maps.kstackmap);

    struct key_t key = {}, prev_key;
    __u64 uips[MAX_STACK_DEPTH];
    __u64 kips[MAX_STACK_DEPTH];
    __u64 count;
    int total = 0;

    if (bpf_map_get_next_key(counts_fd, NULL, &key) != 0) // 获取第一个key
    {
        fprintf(stderr, "No samples collected\n");
        return;
    }

    do
    {
        if (bpf_map_lookup_elem(counts_fd, &key, &count) != 0)
            goto next;

        memset(uips, 0, sizeof(uips));
        int udepth = 0;
        if (key.ustackid != (__u32)-1)
        {
            if (bpf_map_lookup_elem(ustack_fd, &key.ustackid, uips) == 0)
            {
                while (udepth < MAX_STACK_DEPTH && uips[udepth] != 0) // 获取用户栈深度
                    udepth++;
            }
        }

        memset(kips, 0, sizeof(kips));
        int kdepth = 0;
        if (key.kstackid != (__u32)-1)
        {
            if (bpf_map_lookup_elem(kstack_fd, &key.kstackid, kips) == 0)
            {
                while (kdepth < MAX_STACK_DEPTH && kips[kdepth] != 0)
                    kdepth++;
            }
        }

        if (udepth > 0)
        {
            sym_info_t uframes[udepth];
            int n = resolve_symbols(pid, comm, load_base, uips, udepth, uframes);
            if (n > 0)
                print_folded(uframes, n, count);
        }

        if (kdepth > 0)
        {
            sym_info_t kframes[kdepth];
            int n = resolve_kernel_symbols(kips, kdepth, kframes);
            if (n > 0)
                print_folded(kframes, n, count);
        }

        total += count;

    next:
        prev_key = key;
    } while (bpf_map_get_next_key(counts_fd, &prev_key, &key) == 0);

    fprintf(stderr, "Total samples: %d\n", total);
}

static void show_help(const char *progname)
{
    printf("Usage: %s -p <pid> [-f <frequency>] [-h]\n", progname);
    printf("  -p <pid>       Target PID to profile\n");
    printf("  -f <freq>      Sampling frequency (default: 99)\n");
    printf("  -h             Show help\n");
    printf("\nOutput: folded stack format for flamegraph.pl\n");
}

int main(int argc, char *const argv[])
{
    const char *online_cpus_file = "/sys/devices/system/cpu/online";
    int freq = 99, pid = -1, cpu;
    struct bpftrace_bpf *skel = NULL;
    struct perf_event_attr attr;
    struct bpf_link **links = NULL;
    int num_cpus, num_online_cpus;
    int *pefds = NULL, pefd;
    int argp, i, err = 0;
    bool *online_mask = NULL;

    while ((argp = getopt(argc, argv, "hf:p:")) != -1)
    {
        switch (argp)
        {
        case 'f':
            freq = atoi(optarg);
            if (freq < 1)
                freq = 1;
            break;
        case 'p':
            pid = atoi(optarg);
            break;
        case 'h':
        default:
            show_help(argv[0]);
            return 1;
        }
    }

    if (pid < 1)
    {
        fprintf(stderr, "Error: PID required (-p <pid>)\n");
        show_help(argv[0]);
        return 1;
    }

    char comm[64];
    get_comm(pid, comm, sizeof(comm));

    fprintf(stderr, "Profiling PID=%d comm=%s freq=%d load_base=0x%x\n",
            pid, comm, freq, 0);
    fprintf(stderr, "Press Ctrl-C to stop and dump flame graph data\n");

    err = parse_cpu_mask_file(online_cpus_file, &online_mask, &num_online_cpus);
    if (err)
    {
        fprintf(stderr, "Fail to get online CPU numbers: %d\n", err);
        goto cleanup;
    }

    num_cpus = libbpf_num_possible_cpus();
    if (num_cpus <= 0)
    {
        fprintf(stderr, "Fail to get the number of processors\n");
        err = -1;
        goto cleanup;
    }

    skel = bpftrace_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Fail to open BPF skeleton\n");
        err = -1;
        goto cleanup;
    }

    skel->rodata->target_tgid = (__u64)pid;

    err = bpftrace_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Fail to load BPF skeleton\n");
        err = -1;
        goto cleanup;
    }

    pefds = malloc(num_cpus * sizeof(int));
    for (i = 0; i < num_cpus; i++)
        pefds[i] = -1;

    links = calloc(num_cpus, sizeof(struct bpf_link *));

    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE; // PERF_TYPE_HARDWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_CPU_CLOCK; // PERF_COUNT_HW_CPU_CYCLES;
    attr.sample_freq = freq;
    attr.freq = 1;

    for (cpu = 0; cpu < num_cpus; cpu++)
    {
        if (cpu >= num_online_cpus || !online_mask[cpu])
            continue;

        pefd = perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
        if (pefd < 0)
        {
            fprintf(stderr, "Fail to set up performance monitor on CPU %d\n", cpu);
            err = -1;
            goto cleanup;
        }
        pefds[cpu] = pefd;

        links[cpu] = bpf_program__attach_perf_event(skel->progs.bpftrace, pefd);
        if (!links[cpu])
        {
            err = -1;
            goto cleanup;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!g_exiting)
        sleep(1);

    fprintf(stderr, "\nDumping flame graph data...\n");
    dump_bpftrace_graph(skel, pid, comm, 0);

cleanup:
    if (links)
    {
        for (cpu = 0; cpu < num_cpus; cpu++)
            bpf_link__destroy(links[cpu]);
        free(links);
    }
    if (pefds)
    {
        for (i = 0; i < num_cpus; i++)
        {
            if (pefds[i] >= 0)
                close(pefds[i]);
        }
        free(pefds);
    }
    bpftrace_bpf__destroy(skel);
    free(online_mask);
    return -err;
}