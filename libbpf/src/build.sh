#! /bin/bash
make clean

make \
    ARCH=arm64 \
    CROSS_COMPILE=aarch64-linux-gnu- \
    CC=aarch64-linux-gnu-gcc \
    LD=aarch64-linux-gnu-ld \
    AR=aarch64-linux-gnu-ar \
    NO_PKG_CONFIG=1 \
    EXTRA_LDFLAGS="-L/home/jin/arm64_lib/elfutils-0.191/release/lib -lelf -L/home/jin/arm64_lib/zlib-1.3.2/release/lib -lz"
