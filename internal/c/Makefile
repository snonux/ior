export LIBBPFGO = $(CURDIR)/../../../libbpfgo
export CC = clang

SOURCES := $(wildcard *.bpf.c)
TARGETS := $(SOURCES:.bpf.c=.bpf.o)

all: $(TARGETS)

redo: clean all

%.bpf.o: %.bpf.c vmlinux.h
	$(CC) -g -O2 -Wall -fpie -target bpf -D__TARGET_ARCH_amd64 \
		-I$(LIBBPFGO)/output -c $< -o $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: clean
clean:
	find . -name \*.o -delete
	find . -name vmlinux.h -delete

.PHONY: generate
generate: generate_tracepoints

.PHONY: generate_tracepoints
generate_tracepoints:
	sudo sh -c 'cat /sys/kernel/tracing/events/syscalls/sys_{enter,exit}_*/format' \
		| raku generate_tracepoints.raku > ./generated_tracepoints.c

.PHONY: generate_tracepoints_stdout
generate_tracepoints_stdout:
	sudo sh -c 'cat /sys/kernel/tracing/events/syscalls/sys_{enter,exit}_*/format' \
		| raku generate_tracepoints.raku
