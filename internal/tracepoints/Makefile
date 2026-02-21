generate: generate_tracepoints

.PHONY: generate_tracepoints
generate_tracepoints:
	cat ../c/generated_tracepoints.c \
		| go run ../../cmd/generate tracepoints-go \
		| goimports | gofmt \
		> ./generated_tracepoints.go
