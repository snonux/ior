all: generate

generate: tracepoints types

.PHONY: generate_tracepoints
tracepoints:
	cat ../c/generated_tracepoints.c \
		| raku tracepoints.raku \
		| goimports | gofmt \
		> tracepoints/tracepoints.go

.PHONY: types
types:
	( cat ../c/types.h; grep -h '^#define' ../c/generated_tracepoints.c ) \
		| raku nqc.raku \
		| goimports | gofmt \
		> types/types.go
