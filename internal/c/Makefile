export LIBBPFGO = $(CURDIR)/../../../libbpfgo
export CC = clang

SOURCES := $(wildcard *.bpf.c)
TARGETS := $(SOURCES:.bpf.c=.bpf.o)

all: $(TARGETS)
	# Only required when linking multiple .o into a single .o (not doing that atm)
	# bpftool gen object ioriotng.bpf.o $(TARGETS)

%.bpf.o: %.bpf.c vmlinux.h
	$(CC) -g -O2 -Wall -fpie -target bpf -D__TARGET_ARCH_amd64 \
		-I$(LIBBPFGO)/output -c $< -o $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: clean
clean:
	find . -name \*.o -delete
	find . -name vmlinux.h -delete
