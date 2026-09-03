#! /bin/bash

PROJECT_ROOT=/home/ubuntu/work/ebpf/arm64-ebpf


make \
    ARCH=arm64 \
    CROSS_COMPILE=aarch64-linux-gnu- \
    CC=aarch64-linux-gnu-gcc \
    LD=aarch64-linux-gnu-ld \
    AR=aarch64-linux-gnu-ar \
    NO_PKG_CONFIG=1 \
    EXTRA_LDFLAGS="-L${PROJECT_ROOT}/elfutils-0.191/release/lib -lelf -L${PROJECT_ROOT}/zlib-1.3.2/release/lib -lz"

make install_headers PREFIX=${PROJECT_ROOT}/libbpf_v1_7/install    
