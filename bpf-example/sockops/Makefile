TARGET = sockops_exp
ARCH = arm64
CROSS_COMPILE = aarch64-linux-gnu-
CC = ${CROSS_COMPILE}gcc
LD = ${CROSS_COMPILE}ld
AR = ${CROSS_COMPILE}ar

BPF_C = $(wildcard *.bpf.c)
BPF_OBJ = $(BPF_C:.c=.o)

USER_C = ${TARGET:=.c}
USER_SKELS = $(BPF_OBJ:.bpf.o=.skel.h)

COMMON_H = #${TARGET:=.h}

LIBBPF_LIB = /home/jin/arm64_lib/lib
ELFUTILS_LIB = /home/jin/arm64_lib/lib
ZLIB_LIB = /home/jin/arm64_lib/lib

LDFLAGS = -L$(LIBBPF_LIB) -lbpf \
	  -L$(ELFUTILS_LIB) -lelf \
	  -L$(ZLIB_LIB) -lz \
	  -lpthread -ldl  	\
	  -Wl,-rpath,$(LIBBPF_LIB) 

INCLUDE = -I/home/jin/arm64_lib/libbpf/install/include \
	  -I./

all: $(TARGET) $(BPF_OBJ)
.PHONY: all

$(TARGET): $(USER_C) $(USER_SKELS) $(COMMON_H) 
	${CC} -Wall -g -o $(TARGET) $(USER_C) \
		$(INCLUDE) \
		$(LDFLAGS)

$(BPF_OBJ): %.o: %.c vmlinux.h $(COMMON_H)
	clang \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -D __TARGET_ARCH_$(ARCH) \
	    -Wall \
	    -I/home/jin/arm64_lib/libbpf/install/include \
	    -I/usr/aarch64-linux-gnu/include \
	    -O2 -g -o $@ -c $<
	llvm-strip -g $@

$(USER_SKELS): %.skel.h: %.bpf.o
	bpftool gen skeleton $< > $@

vmlinux.h:
	bpftool btf dump file /home/jin/arm64_lib/vmlinux format c > vmlinux.h

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(USER_SKELS) $(HELPER_OBJ)

.PHONY: all clean
