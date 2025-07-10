# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

I/O Riot NG (ior) is a Linux system performance monitoring tool that traces synchronous I/O syscalls using BPF technology. It analyzes syscall execution time and generates FlameGraphs for performance visualization.

## Build Commands

**Prerequisites**: Ensure libbpfgo is cloned at `../libbpfgo` relative to this repository.

```bash
# Generate code (required after modifying tracepoint definitions)
make generate

# Build everything (BPF objects and Go binary)
make all

# Build only BPF objects
make bpfbuild

# Build only Go binary
make gobuild

# Build with race detector
make gobuild_race

# Clean build artifacts
make clean

# Deep clean (includes output files)
make mrproper

# Full rebuild (clean, generate, test, build)
make world
```

## Testing Commands

```bash
# Run all tests
make test

# Run specific test
make test_with_name TEST_NAME=TestEventloop

# Run benchmarks
make bench

# Run Go tests directly
go test ./internal/event -v
go test ./internal/flamegraph -v
```

## Architecture Overview

### Core Components

1. **BPF Programs** (`/internal/c/`)
   - Kernel-side code that attaches to syscall tracepoints
   - Collects timing data with minimal overhead
   - Communicates with userspace via perf events

2. **Event Processing** (`/internal/event/`)
   - Handles BPF events from kernel
   - Manages event loop and data collection
   - Key struct: `IorEvent` containing syscall timing data

3. **FlameGraph Generation** (`/internal/flamegraph/`)
   - Converts raw events into collapsed stack format
   - Compatible with Inferno FlameGraph tools
   - Handles aggregation and sorting of stack traces

4. **Code Generation**
   - Tracepoint definitions are generated from `/proc/kallsyms`
   - Uses Raku scripts to generate both Go and C code
   - Ensures consistency between kernel and userspace structures

### Key Design Patterns

- **Static Linking**: Binary is statically compiled for portability
- **Platform-Specific**: Linux-only, enforced at compile time
- **Output Compression**: Uses zstd for efficient storage
- **Modular Structure**: Clear separation between BPF, event handling, and visualization

## Development Guidelines

### Adding New Syscall Tracepoints

1. Modify the tracepoint generation scripts in `/internal/tracepoints/`
2. Run `make generate` to regenerate code
3. Update BPF programs in `/internal/c/` if needed
4. Test with `make test` before building

### Working with BPF Code

- BPF C code is in `/internal/c/ior.bpf.c`
- Keep BPF programs minimal for verification
- Use perf events for kernel-userspace communication
- Test on different kernel versions for compatibility

### Code Style

- Follow standard Go conventions
- Keep functions under 50 lines (refactor into smaller functions)
- For larger files, move code to appropriate packages under `/internal/`
- Update comments to reflect code changes