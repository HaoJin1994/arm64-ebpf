#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcprtt.h"
#include "tcprtt.skel.h"

static struct env
{
    bool verbose;
    bool targ_laddr_hist;
    bool targ_raddr_hist;
    bool targ_show_ext;
    __u16 targ_sport;
    __u16 targ_dport;
    __u32 targ_saddr;
    __u32 targ_daddr;
    bool targ_ms;
    time_t interval;
} env = {
    .interval = 1,
};
static bool exiting = false;
enum
{
    TARGET_LADDR_HIST = 256,
    TARGET_RADDR_HIST,
    TARGET_SHOW_EXT,
    TARGET_SPORT,
    TARGET_DPORT,
    TARGET_SADDR,
    TARGET_DADDR,
    TARGET_MS
};
static const struct argp_option opts[] = {
    {"targ_laddr_hist", TARGET_LADDR_HIST, 0, 0, "Set value of  \'bool\' variable targ_laddr_hist"},
    {"targ_raddr_hist", TARGET_RADDR_HIST, 0, 0, "Set value of  \'bool\' variable targ_raddr_hist"},
    {"targ_show_ext", TARGET_SHOW_EXT, 0, 0, "Set value of  \'bool\' variable targ_show_ext"},
    {"targ_sport", TARGET_SPORT, "SPORT", 0, "Set value of  \'__u16\' variable targ_sport"},
    {"targ_dport", TARGET_DPORT, "DPORT", 0, "Set value of  \'__u16\' variable targ_dport"},
    {"targ_saddr", TARGET_SADDR, "SADDR", 0, "Set value of  \'__u32\' variable targ_saddr"},
    {"targ_daddr", TARGET_DADDR, "DADDR", 0, "Set value of  \'__u32\' variable targ_daddr"},
    {"targ_ms", TARGET_MS, "MS", 0, "Set value of  \'bool\' variable targ_ms"},
    {"verbose", 'v', 0, 0, "Whether to show libbpf debug information"},
    {"help", 'h', 0, 0, " Print help"},
    {"version", 'V', 0, 0, "Print version"},
    {0, 0, 0, 0, 0},
};
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    static int pos_args;
    switch (key)
    {
    case 'v':
        env.verbose = true;
        break;
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    case TARGET_LADDR_HIST:
        env.targ_laddr_hist = true;
        break;
    case TARGET_RADDR_HIST:
        env.targ_raddr_hist = true;
        break;
    case TARGET_SHOW_EXT:
        env.targ_show_ext = true;
        break;
    case TARGET_SPORT:
        env.targ_sport = atoi(arg);
        printf("targ_sport: %u\n", env.targ_sport);
        break;
    case TARGET_DPORT:
        env.targ_dport = atoi(arg);
        break;
    case TARGET_SADDR:
        env.targ_saddr = inet_addr(arg);
        break;
    case TARGET_DADDR:
        env.targ_daddr = inet_addr(arg);
        break;
    case TARGET_MS:
        env.targ_ms = true;
        break;
    default:
        break;
    }
    return 0;
}
const char argp_program_doc[] = {
    "tcprtt - TCP RTT histogram"
    "Usage:\n"
    "tcprtt [options]\n"
    "options:\n"
    "  -v, --verbose  Whether to show libbpf debug information\n"
    "  -h, --help     Print help\n"
    "  -V, --version  Print version\n"
    "  --targ_laddr_hist  Set value of  \'bool\' variable targ_laddr_hist\n"
    "  --targ_raddr_hist  Set value of  \'bool\' variable targ_raddr_hist\n"
    "  --targ_show_ext  Set value of  \'bool\' variable targ_show_ext\n"
    "  --targ_sport  Set value of  \'__u16\' variable targ_sport\n"
    "  --targ_dport  Set value of  \'__u16\' variable targ_dport\n"
    "  --targ_saddr  Set value of  \'__u32\' variable targ_saddr\n"
    "  --targ_daddr  Set value of  \'__u32\' variable targ_daddr\n"
    "  --targ_ms  Set value of  \'bool\' variable targ_ms\n"};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
    exiting = true;
}

static void print_stars(unsigned int val, unsigned int val_max, int stars_max)
{
    int stars = val_max ? (int)((unsigned long long)val * stars_max / val_max) : 0;
    for (int i = 0; i < stars; i++)
        printf("*");
    for (int i = stars; i < stars_max; i++)
        printf(" ");
}

void print_hist(__u32 key, struct hist *hists)
{
    int idx_max = -1, width, stars, i;
    unsigned int val_max = 0;

    for (i = 0; i < MAX_SLOTS; i++)
    {
        if (hists->slots[i] > 0)
            idx_max = i;
        if (hists->slots[i] > val_max)
            val_max = hists->slots[i];
    }

    if (idx_max < 0)
        return;

    printf("key: %u, latency: %llu, cnt: %llu\n", key, hists->latency, hists->cnt);

    width = idx_max <= 32 ? 10 : 20;
    stars = idx_max <= 32 ? 40 : 20;

    printf("%*s%-*s : count    distribution\n",
           idx_max <= 32 ? 5 : 15, "",
           idx_max <= 32 ? 19 : 29, "usecs");

    for (i = 0; i <= idx_max; i++)
    {
        unsigned long long low = (1ULL << (i + 1)) >> 1;
        unsigned long long high = (1ULL << (i + 1)) - 1;
        if (low == high)
            low -= 1;
        printf("%*lld -> %-*lld : %-8u |", width, low, width, high, hists->slots[i]);
        print_stars(hists->slots[i], val_max, stars);
        printf("|\n");
    }
}

int main(int argc, char *argv[])
{
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };
    struct tcprtt_bpf *skel = NULL;
    int err;
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;
    libbpf_set_print(libbpf_print_fn);

    skel = tcprtt_bpf__open_opts(&open_opts);
    if (!skel)
    {
        fprintf(stderr, "tcprtt_bpf__open_opts failed\n");
        return -1;
    }

    skel->rodata->targ_laddr_hist = env.targ_laddr_hist;
    skel->rodata->targ_raddr_hist = env.targ_raddr_hist;
    skel->rodata->targ_show_ext = env.targ_show_ext;
    skel->rodata->targ_sport = env.targ_sport;
    skel->rodata->targ_dport = env.targ_dport;
    skel->rodata->targ_saddr = env.targ_saddr;
    skel->rodata->targ_daddr = env.targ_daddr;
    skel->rodata->targ_ms = env.targ_ms;

    err = tcprtt_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "tcprtt_bpf__load failed: %d\n", err);
        return -1;
    }

    err = tcprtt_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "tcprtt_bpf__attach failed: %d\n", err);
        return -1;
    }
    signal(SIGINT, sig_handler);
    struct hist hists;
    memset(&hists, 0, sizeof(hists));

    int fd = bpf_map__fd(skel->maps.hists);
    if (fd < 0)
    {
        fprintf(stderr, "bpf_map__fd failed: %d\n", fd);
        return -1;
    }

    while (1)
    {
        sleep(env.interval);

        __u32 total, lookup_key = -1, next_key;

        while (!bpf_map_get_next_key(fd, &lookup_key, &next_key))
        {
            err = bpf_map_lookup_elem(fd, &next_key, &hists);
            if (err)
            {
                fprintf(stderr, "bpf_map_lookup_elem failed: %d\n", err);
                continue;
            }
            bpf_map_delete_elem(fd, &next_key);
            lookup_key = next_key;
            print_hist(next_key, &hists);
        }
        if (exiting)
            break;
    }
    return 0;
}