obj-m += bpf_memcpy_kfunc.o

KDIR := /home/jin/imx8m_image/linux-imx-lf-6.18.y
ARCH := arm64
CROSS_COMPILE := aarch64-linux-gnu-

all: kernel_module bpf_prog

kernel_module:
	make -C $(KDIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) M=$(PWD) modules

bpf_prog:
	clang -O2 -g -target bpf -c memcpy_test.bpf.c -o memcpy_test.bpf.o

clean:
	make -C $(KDIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) M=$(PWD) clean
	rm -f memcpy_test.bpf.o

.PHONY: all kernel_module bpf_prog clean