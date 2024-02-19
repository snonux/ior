export LIBBPFGO = $(CURDIR)/../../../libbpfgo
export CC = clang

ioriotng.bpf.o: ioriotng.bpf.c vmlinux.h
	$(CC) -g -O2 -Wall -fpie -target bpf -D__TARGET_ARCH_amd64 \
		-I$(LIBBPFGO)/output -c ioriotng.bpf.c -o ioriotng.bpf.o

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: clean
clean:
	find . -name \*.o -delete
	find . -name vmlinux.h -delete
