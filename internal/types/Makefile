generate: generate_types

.PHONY: generate_types
generate_types:
	( cat ../c/types.h; grep -h '^#define' ../c/generated_tracepoints.c ) \
		| raku generate_types_go.raku \
		| goimports | gofmt \
		> ./generated_types.go

.PHONY: generate_types_stdout
generate_types_stdout:
	( cat ../c/types.h; grep -h '^#define' ../c/generated_tracepoints.c ) \
		| raku generate_types_go.raku
