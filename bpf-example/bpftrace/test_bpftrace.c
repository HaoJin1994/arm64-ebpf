// /home/jin/arm64_lib/bpf-example/bpftrace/test_profile.c
// gcc -g -O2 -o test_profile test_profile.c -lpthread -lm

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <math.h>
#include <unistd.h>
#include <time.h>

/* ============================================================
 * 调用链 A: 计算密集型 — 快速排序 + 斐波那契
 * ============================================================ */

static void swap(int *a, int *b)
{
    int t = *a;
    *a = *b;
    *b = t;
}

static int partition(int arr[], int low, int high)
{
    int pivot = arr[high];
    int i = low - 1;
    for (int j = low; j < high; j++)
    {
        if (arr[j] < pivot)
        {
            i++;
            swap(&arr[i], &arr[j]);
        }
    }
    swap(&arr[i + 1], &arr[high]);
    return i + 1;
}

static void quick_sort(int arr[], int low, int high)
{
    if (low < high)
    {
        int pi = partition(arr, low, high);
        quick_sort(arr, low, pi - 1);
        quick_sort(arr, pi + 1, high);
    }
}

static long fib(int n)
{
    if (n <= 1)
        return n;
    return fib(n - 1) + fib(n - 2);
}

static void compute_heavy_workload(int n)
{
    int *arr = malloc(n * sizeof(int));
    if (!arr)
        return;

    for (int i = 0; i < n; i++)
        arr[i] = rand() % 10000;

    quick_sort(arr, 0, n - 1);

    long f = fib(35); /* 递归计算，消耗 CPU */
    volatile long sink = f;
    (void)sink;

    free(arr);
}

static void chain_a_worker(int iterations)
{
    for (int i = 0; i < iterations; i++)
        compute_heavy_workload(5000);
}

/* ============================================================
 * 调用链 B: 数学计算 — 三角函数 + 矩阵乘法
 * ============================================================ */

static void trig_crunch(int n)
{
    double sum = 0.0;
    for (int i = 0; i < n; i++)
    {
        double x = (double)i * 0.001;
        sum += sin(x) * cos(x) + tan(x) * 0.001;
        sum += sqrt(x + 1.0) * log(x + 2.0);
    }
    volatile double sink = sum;
    (void)sink;
}

static void matrix_mult(int size)
{
    double **a = malloc(size * sizeof(double *));
    double **b = malloc(size * sizeof(double *));
    double **c = malloc(size * sizeof(double *));
    for (int i = 0; i < size; i++)
    {
        a[i] = malloc(size * sizeof(double));
        b[i] = malloc(size * sizeof(double));
        c[i] = calloc(size, sizeof(double));
    }
    for (int i = 0; i < size; i++)
        for (int j = 0; j < size; j++)
        {
            a[i][j] = (double)(rand() % 100) / 10.0;
            b[i][j] = (double)(rand() % 100) / 10.0;
        }
    for (int i = 0; i < size; i++)
        for (int j = 0; j < size; j++)
            for (int k = 0; k < size; k++)
                c[i][j] += a[i][k] * b[k][j];
    volatile double sink = c[size / 2][size / 2];
    (void)sink;
    for (int i = 0; i < size; i++)
    {
        free(a[i]);
        free(b[i]);
        free(c[i]);
    }
    free(a);
    free(b);
    free(c);
}

static void chain_b_worker(int iterations)
{
    for (int i = 0; i < iterations; i++)
    {
        trig_crunch(50000);
        matrix_mult(120);
    }
}

/* ============================================================
 * 调用链 C: 字符串处理 — 哈希 + 查找
 * ============================================================ */

typedef struct node
{
    char *key;
    int val;
    struct node *next;
} node_t;

#define HASH_SIZE 4096
static node_t *hash_table[HASH_SIZE];

static unsigned int hash_str(const char *s)
{
    unsigned int h = 5381;
    while (*s)
        h = ((h << 5) + h) + (unsigned char)(*s++);
    return h % HASH_SIZE;
}

static void hash_insert(const char *key, int val)
{
    unsigned int idx = hash_str(key);
    node_t *n = malloc(sizeof(node_t));
    n->key = strdup(key);
    n->val = val;
    n->next = hash_table[idx];
    hash_table[idx] = n;
}

static int hash_lookup(const char *key)
{
    unsigned int idx = hash_str(key);
    for (node_t *n = hash_table[idx]; n; n = n->next)
        if (strcmp(n->key, key) == 0)
            return n->val;
    return -1;
}

static void build_strings(int count)
{
    char buf[32];
    for (int i = 0; i < count; i++)
    {
        snprintf(buf, sizeof(buf), "key_%08d", i);
        hash_insert(buf, i * 7);
    }
}

static void lookup_strings(int count)
{
    char buf[32];
    volatile int sum = 0;
    for (int i = 0; i < count; i++)
    {
        snprintf(buf, sizeof(buf), "key_%08d", rand() % count);
        sum += hash_lookup(buf);
    }
    (void)sum;
}

static void chain_c_worker(int iterations)
{
    for (int i = 0; i < iterations; i++)
    {
        build_strings(4000);
        lookup_strings(8000);
    }
}

/* ============================================================
 * 调用链 D: 内存密集型 — 大量分配/释放 + 模式匹配
 * ============================================================ */

static int naive_pattern_match(const char *text, const char *pattern)
{
    int n = strlen(text), m = strlen(pattern);
    int count = 0;
    for (int i = 0; i <= n - m; i++)
    {
        int j;
        for (j = 0; j < m; j++)
            if (text[i + j] != pattern[j])
                break;
        if (j == m)
            count++;
    }
    return count;
}

static void alloc_stress(int mb)
{
    size_t sz = (size_t)mb * 1024 * 1024;
    char *buf = malloc(sz);
    if (!buf)
        return;
    memset(buf, 0xAB, sz);
    /* 模拟碎片化：分配很多小块 */
    void **ptrs = malloc(10000 * sizeof(void *));
    for (int i = 0; i < 10000; i++)
        ptrs[i] = malloc(64);
    for (int i = 0; i < 10000; i++)
        free(ptrs[i]);
    free(ptrs);
    free(buf);
}

static void chain_d_worker(int iterations)
{
    for (int i = 0; i < iterations; i++)
    {
        alloc_stress(8);
        const char *text =
            "Lorem ipsum dolor sit amet consectetur adipiscing elit "
            "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua "
            "ut enim ad minim veniam quis nostrud exercitation ullamco laboris";
        naive_pattern_match(text, "dolor");
        naive_pattern_match(text, "consectetur");
        naive_pattern_match(text, "incididunt");
    }
}

/* ============================================================
 * 线程入口
 * ============================================================ */

static void *thread_a(void *arg)
{
    (void)arg;
    while (1)
        chain_a_worker(1);
    return NULL;
}

static void *thread_b(void *arg)
{
    (void)arg;
    while (1)
        chain_b_worker(1);
    return NULL;
}

static void *thread_c(void *arg)
{
    (void)arg;
    while (1)
        chain_c_worker(1);
    return NULL;
}

static void *thread_d(void *arg)
{
    (void)arg;
    while (1)
        chain_d_worker(3);
    return NULL;
}

int main(void)
{
    srand(time(NULL));

    pthread_t ta, tb, tc, td;
    pthread_create(&ta, NULL, thread_a, NULL);
    pthread_create(&tb, NULL, thread_b, NULL);
    pthread_create(&tc, NULL, thread_c, NULL);
    pthread_create(&td, NULL, thread_d, NULL);

    printf("test_profile started (pid=%d), 4 worker threads\n", getpid());
    printf("Call chains:\n");
    printf("  A: chain_a_worker -> compute_heavy_workload -> quick_sort/partition/swap + fib\n");
    printf("  B: chain_b_worker -> trig_crunch + matrix_mult\n");
    printf("  C: chain_c_worker -> build_strings/hash_insert + lookup_strings/hash_lookup/strcmp\n");
    printf("  D: chain_d_worker -> alloc_stress/memset + naive_pattern_match\n");
    printf("Press Ctrl-C to stop\n");

    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    pthread_join(tc, NULL);
    pthread_join(td, NULL);
    return 0;
}