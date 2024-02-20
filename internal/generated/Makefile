all: generate

generate: types tracepoints

.PHONY: types
types:
	cat ../c/types.h | raku nqc.raku | tee types/types.go

.PHONY: tracepoints
tracepoints:
	raku tracepoints.raku > tracepoint_list.go
