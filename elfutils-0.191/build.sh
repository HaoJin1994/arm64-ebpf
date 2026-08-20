#! /bin/bash

cd ~/arm64_lib/elfutils-0.191

# 1. 清除可能干扰的环境变量
unset CFLAGS LDFLAGS LIBS

# 2. 设置 zlib 的安装路径（请确认这个路径下真的有 lib/libz.a）
ZLIB_DIR=/home/jin/arm64_lib/zlib-1.3.2/release

# 3. 执行配置，最关键的是通过 LDFLAGS 指定库路径，通过 LIBS 指定要链接的库
./configure --host=aarch64-linux-gnu \
            --prefix=/home/jin/arm64_lib/elfutils-0.191/release \
            --with-zlib=$ZLIB_DIR \
	    --disable-debuginfod \
	    --disable-libdebuginfod \
            LDFLAGS="-L$ZLIB_DIR/lib" \
            LIBS="-lz"
