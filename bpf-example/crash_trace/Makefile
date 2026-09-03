TARGET = crash_trace
ARCH = arm64
CROSS_COMPILE = aarch64-linux-gnu-
CC = ${CROSS_COMPILE}gcc
LD = ${CROSS_COMPILE}ld
AR = ${CROSS_COMPILE}ar

BPF_TARGET = ${TARGET:=.bpf}
BPF_C = ${BPF_TARGET:=.c}
BPF_OBJ = ${BPF_TARGET:=.o}

USER_C = ${TARGET:=.c}
USER_SKEL = ${TARGET:=.skel.h}

COMMON_H = ${TARGET:=.h}

PROJECT_DIR = $(shell pwd)
EBPF_DIR = $(PROJECT_DIR)/../../


LIBBPF_LIB = $(EBPF_DIR)/libbpf_v1_7/src
ELFUTILS_LIB = $(EBPF_DIR)/lib
ZLIB_LIB = $(EBPF_DIR)/lib

BLAZESYM_LIB =  $(EBPF_DIR)/lib
BLAZESYM_API_LIB =  $(EBPF_DIR)/bpf-example/blazesym_src/


BLAZESYM_INCLUDE = $(EBPF_DIR)/blazesym/capi/include 
BLAZESYM_API_INCLUDE = $(EBPF_DIR)/bpf-example/blazesym_src/
LIBBPF_INCLUDE = $(EBPF_DIR)/libbpf/install/include


LDFLAGS = -L$(BLAZESYM_API_LIB) -lblazesym_api \
		-L$(BLAZESYM_LIB) -lblazesym_c \
		-L$(LIBBPF_LIB) -lbpf \
		-L$(ELFUTILS_LIB) -lelf \
		-L$(ZLIB_LIB) -lz \
		-lpthread -ldl \
		-Wl,-rpath,$(BLAZESYM_LIB) \

INCLUDE = -I$(BLAZESYM_INCLUDE) \
		 -I$(BLAZESYM_API_INCLUDE) \
		 -I$(LIBBPF_INCLUDE)	

all: $(TARGET) $(BPF_OBJ)
.PHONY: all

$(TARGET): $(USER_C) $(USER_SKEL)  $(COMMON_H)
	${CC} -Wall -o $(TARGET) $(USER_C) \
		$(INCLUDE) \
		$(LDFLAGS)

$(BPF_OBJ): %.o: $(BPF_C) vmlinux.h  $(COMMON_H)
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
	bpftool btf dump file $(EBPF_DIR)/vmlinux format c > vmlinux.h

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(USER_SKEL)

.PHONY: all clean