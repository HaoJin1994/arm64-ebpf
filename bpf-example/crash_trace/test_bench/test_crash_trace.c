// crash_mt.c
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

void *worker_a(void *arg) {
    sleep(1);
    int *p = (int*)0xDEAD;   // ← 线程 A SIGSEGV
    
    *p = 42;
    return NULL;
}

void *worker_b(void *arg) {
    for (int i = 0; i < 5; i++) {
        printf("[worker_b] running...\n");
        sleep(1);
    }
    return NULL;
}

int main() {
    pthread_t ta, tb;
    pthread_create(&ta, NULL, worker_a, NULL);
    pthread_create(&tb, NULL, worker_b, NULL);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);
    return 0;
}