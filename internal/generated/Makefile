all: generate

generate: tracepoints types

.PHONY: tracepoints
tracepoints:
	cat ../c/tracepoints/*.c \
		| raku tracepoints.raku \
		| goimports | gofmt \
		| tee tracepoints/tracepoints.go

.PHONY: types
types:
	cat ../c/types.h \
		| raku nqc.raku \
		| goimports | gofmt \
		| tee types/types.go
