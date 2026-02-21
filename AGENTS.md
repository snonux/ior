# AGENTS.md

This file provides guidance to AI coding assistants working with the I/O Riot NG (ior) codebase.

## Build/Test Commands

**Prerequisites**: Ensure libbpfgo is cloned at `../libbpfgo` relative to this repository.

```bash
mage all          # Build everything (BPF objects and Go binary)
mage test         # Run all tests
TEST_NAME=TestEventloop mage testWithName  # Run specific test
go test ./internal -v                      # Run tests for internal package
mage generate     # Generate code (required after modifying tracepoint definitions)
mage bench        # Run benchmarks
mage clean        # Clean build artifacts
```

## Code Generation

**Run `mage generate` before building when tracepoint definitions change!**

A Mage target generates code from Linux kernel tracepoint data:

```bash
mage generate              # Generate all code (C and Go)
mage generateTracepointsC  # Generate C tracepoint handlers from /sys/kernel/tracing
mage generateTypesGo       # Generate Go types from C structs
mage generateTracepointsGo # Generate Go tracepoint list
```

Generated files (do not edit manually):
- `internal/c/generated_tracepoints.c` - BPF C handlers for syscall tracepoints
- `internal/types/generated_types.go` - Go structs matching C structs + type mappings
- `internal/tracepoints/generated_tracepoints.go` - List of available syscall tracepoints

Generator source code:
- `internal/generate/` - Parser, classifier, and code generation logic

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
