TARGET = biopattern
ARCH = arm64
CROSS_COMPILE = aarch64-linux-gnu-
CC = ${CROSS_COMPILE}gcc
LD = ${CROSS_COMPILE}ld
AR = ${CROSS_COMPILE}ar

BPF_TARGET = ${TARGET:=.bpf}
BPF_C = ${BPF_TARGET:=.c}
BPF_OBJ = ${BPF_TARGET:=.o}

HELPER_C = trace_helpers.c
HELPER_OBJ = trace_helpers.o

USER_C = ${TARGET:=.c}
USER_SKEL = ${TARGET:=.skel.h}

COMMON_H = ${TARGET:=.h}

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

$(TARGET): $(USER_C) $(USER_SKEL) $(COMMON_H) $(HELPER_OBJ)
	${CC} -Wall -g -o $(TARGET) $(USER_C) $(HELPER_OBJ) \
		$(INCLUDE) \
		$(LDFLAGS)

$(BPF_OBJ): %.o: $(BPF_C) vmlinux.h $(COMMON_H)
	clang \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -D __TARGET_ARCH_$(ARCH) \
	    -Wall \
	    -I/home/jin/arm64_lib/libbpf/install/include \
	    -I/usr/aarch64-linux-gnu/include \
	    -O2 -g -o $@ -c $<
	llvm-strip -g $@

$(HELPER_OBJ): $(HELPER_C) trace_helpers.h
	${CC} -Wall -g -c -o $@ $< $(INCLUDE)

$(USER_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

vmlinux.h:
	bpftool btf dump file /home/jin/arm64_lib/vmlinux format c > vmlinux.h

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(USER_SKEL) $(HELPER_OBJ)

.PHONY: all clean