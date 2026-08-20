TARGET = bpftrace
ARCH = arm64
CROSS_COMPILE = aarch64-linux-gnu-
CC = ${CROSS_COMPILE}gcc

BPF_TARGET = ${TARGET:=.bpf}
BPF_C = ${BPF_TARGET:=.c}
BPF_OBJ = ${BPF_TARGET:=.o}

USER_C = ${TARGET:=.c}
USER_SKEL = ${TARGET:=.skel.h}

COMMON_H = ${TARGET:=.h}

BLAZESYM_LIB = /home/jin/arm64_lib/lib
BLAZESYM_API_LIB = /home/jin/arm64_lib/bpf-example/blazesym_src/
LIBBPF_LIB = /home/jin/arm64_lib/lib
ELFUTILS_LIB = /home/jin/arm64_lib/lib
ZLIB_LIB = /home/jin/arm64_lib/lib

BLAZESYM_INCLUDE = /home/jin/arm64_lib/blazesym/capi/include 
BLAZESYM_API_INCLUDE = /home/jin/arm64_lib/bpf-example/blazesym_src/
LIBBPF_INCLUDE = /home/jin/arm64_lib/libbpf/install/include

LDFLAGS = -L$(BLAZESYM_API_LIB) -lblazesym_api \
		-L$(BLAZESYM_LIB) -lblazesym_c \
		-L$(LIBBPF_LIB) -lbpf \
		-L$(ELFUTILS_LIB) -lelf \
		-L$(ZLIB_LIB) -lz \
		-lpthread -ldl \
		-Wl,-rpath,$(BLAZESYM_LIB)

INCLUDE = -I$(LIBBPF_INCLUDE) \
		 -I$(BLAZESYM_INCLUDE) \
		 -I$(BLAZESYM_API_INCLUDE) 

all: $(TARGET) $(BPF_OBJ)
.PHONY: all

$(TARGET): $(USER_C) $(USER_SKEL) $(COMMON_H)
	${CC} -Wall -o $(TARGET) $(USER_C) \
		$(INCLUDE) \
		$(LDFLAGS)

$(BPF_OBJ): %.o: $(BPF_C) vmlinux.h $(COMMON_H)
	clang \
	    -target bpf \
	    -D __BPF_TRACING__ \
        -D __TARGET_ARCH_$(ARCH) \
	    -Wall \
	    -I$(LIBBPF_INCLUDE) \
	    -O2 -g -o $@ -c $<
	llvm-strip -g $@

$(USER_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

vmlinux.h:
	ln -sf ../profile/vmlinux.h vmlinux.h

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(USER_SKEL) vmlinux.h

.PHONY: all clean