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
	sudo sh -c 'sudo find /sys/kernel/tracing/events/syscalls -maxdepth 2 -mindepth 2 -name format' \
		| sort -t_ -k3 | sudo xargs cat \
		| raku generate_tracepoints_c.raku > ./generated_tracepoints.c
	grep '^/// ' ./generated_tracepoints.c | sort | sed 's|/// ||' > ./generated_tracepoints_result.txt.new
	diff -u ./generated_tracepoints_result.txt ./generated_tracepoints_result.txt.new
	cp ./generated_tracepoints_result.txt.new ./generated_tracepoints_result.txt
	
.PHONY: generate_tracepoints_force
generate_tracepoints_force:
	sudo sh -c 'sudo find /sys/kernel/tracing/events/syscalls -maxdepth 2 -mindepth 2 -name format' \
		| sort -t_ -k3 | sudo xargs cat \
		| raku generate_tracepoints_c.raku > ./generated_tracepoints.c
	grep '^/// ' ./generated_tracepoints.c | sort | sed 's|/// ||' > ./generated_tracepoints_result.txt.new
	sh -c 'diff -u ./generated_tracepoints_result.txt ./generated_tracepoints_result.txt.new; exit 0'
	cp ./generated_tracepoints_result.txt.new ./generated_tracepoints_result.txt
	
.PHONY: generate_tracepoints_stdout
generate_tracepoints_stdout:
	sudo sh -c 'sudo find /sys/kernel/tracing/events/syscalls -maxdepth 2 -mindepth 2 -name format' \
		| sort -t_ -k3 | sudo xargs cat \
		| raku generate_tracepoints_c.raku
