all: generate

generate: types tracepoints

.PHONY: types
types:
	cat ../c/types.h | raku nqc.raku > types/types.go

.PHONY: tracepoints
tracepoints:
	cat ../c/tracepoints/*.c | raku tracepoints.raku > tracepoints/tracepoints.go
