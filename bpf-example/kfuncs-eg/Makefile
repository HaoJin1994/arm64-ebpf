obj-m += bpf_memcpy_kfunc.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	clang -O2 -g -target bpf -c memcpy_test.bpf.c -o memcpy_test.bpf.o

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f memcpy_test.bpf.o