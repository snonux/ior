all: generate

generate: tracepoints types

.PHONY: tracepoints
tracepoints:
	cat ../c/*/*.c \
		| raku tracepoints.raku \
		| goimports | gofmt \
		| tee tracepoints/tracepoints.go

.PHONY: types
types:
	( cat ../c/types.h; grep -h '^#define' ../c/*/*.c ) \
		| raku nqc.raku \
		| goimports | gofmt \
		| tee types/types.go
