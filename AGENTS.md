# AGENTS.md

This file provides guidance to AI coding assistants working with the I/O Riot NG (ior) codebase.

## Build/Test Commands

**Prerequisites**: Ensure libbpfgo is cloned at `../libbpfgo` relative to this repository.

```bash
make all          # Build everything (BPF objects and Go binary)  
make test         # Run all tests
make test_with_name TEST_NAME=TestEventloop  # Run specific test
go test ./internal/event -v                  # Run tests for specific package
make generate     # Generate code (required after modifying tracepoint definitions)
make bench        # Run benchmarks
make clean        # Clean build artifacts
```

## Code Generation

**Run `make generate` before building when tracepoint definitions change!**

Three Raku scripts generate code from Linux kernel tracepoint data:

```bash
make generate                    # Generate all code (C and Go)
make -C internal/c generate      # Generate C tracepoint handlers from /sys/kernel/tracing
make -C internal/types generate  # Generate Go types from C structs 
make -C internal/tracepoints generate  # Generate Go tracepoint list
```

Generated files (do not edit manually):
- `internal/c/generated_tracepoints.c` - BPF C handlers for syscall tracepoints
- `internal/types/generated_types.go` - Go structs matching C structs + type mappings
- `internal/tracepoints/generated_tracepoints.go` - List of available syscall tracepoints

## Architecture

- **Entry point**: `cmd/ior/main.go` - Linux-only BPF-based I/O syscall tracer
- **Core packages**: `/internal/event/` (BPF event handling), `/internal/flamegraph/` (FlameGraph generation), `/internal/c/` (BPF programs)  
- **Output**: Compressed zstd files, collapsed stack format compatible with Inferno FlameGraphs

## Code Style

- Standard Go conventions with static linking (`-ldflags '-w -extldflags "-static"'`)
- Keep functions under 50 lines, refactor larger code to `/internal/` packages  
- Use generated types from `/internal/types/generated_types.go` for kernel-userspace communication
- BPF C code in `/internal/c/ior.bpf.c` should be minimal for verification
- Import style: `"ior/internal/packagename"` for internal packages
- Error handling: Return errors, don't panic except for setup validation
