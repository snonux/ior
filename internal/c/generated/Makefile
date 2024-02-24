all: generate

generate: tracepoints

.PHONY: tracepoints
tracepoints:
	sudo sh -c 'cat /sys/kernel/tracing/events/syscalls/sys_{enter,exit}_*/format' \
		| raku tracepoints.raku > ./tracepoints.c

