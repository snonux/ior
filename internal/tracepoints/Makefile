generate: generate_tracepoints

.PHONY: generate_tracepoints
generate_tracepoints:
	cat ../c/generated_tracepoints.c \
		| raku generate_tracepoints_go.raku \
		| goimports | gofmt \
		> ./generated_tracepoints.go
