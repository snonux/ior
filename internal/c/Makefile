export LIBBPFGO = $(CURDIR)/../../../libbpfgo
export CC = clang

all: bpfbuild

.PHONY: bpfbuild
bpfbuild:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	$(CC) -g -O2 -Wall -fpie -target bpf -D__TARGET_ARCH_amd64 -I$(LIBBPFGO)/output -c ioriotng.bpf.c -o ioriotng.bpf.o

.PHONY: clean
clean:
	find . -name \*.o -delete
	find . -name vmlinux.h -delete
