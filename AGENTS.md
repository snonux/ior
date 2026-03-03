# AGENTS.md

This file provides guidance to AI coding assistants working with the I/O Riot NG (ior) codebase.

## Build/Test Commands

**Prerequisites**: Ensure libbpfgo is cloned at `../libbpfgo` relative to this repository.
If builds/tests fail with missing libbpf headers (for example `bpf/bpf.h` not found), run `mage world` first. It bootstraps generation/dependencies and is the preferred first troubleshooting step before retrying `mage test` or `go test`.

```bash
mage all          # Build everything (BPF objects and Go binary)
mage test         # Run all tests
TEST_NAME=TestEventloop mage testWithName  # Run specific test
go test ./internal -v                      # Run tests for internal package
mage integrationTest                       # Build + run integration tests (default parallelism is capped)
INTEGRATION_PARALLEL=1 mage integrationTest  # Force serial integration tests
mage generate     # Generate code (required after modifying tracepoint definitions)
mage bench        # Run benchmarks
mage prReview     # Run PR review baseline: world + benchProf
mage clean        # Clean build artifacts
mage world        # Clean + generate + test + build (recommended reset path)
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
- **Output**: Compressed `.ior.zst` trace data and native SVG flamegraphs (served via embedded web server in `-ior` mode)
- **TUI package**: `/internal/tui/` contains top-level Bubble Tea orchestration (`tui.go`), shared key map (`keys.go`), and styles (`styles.go`).
- **Dashboard tabs**: `/internal/tui/dashboard/` contains tab renderers (overview/syscalls/files/processes/latency/gaps) and tab framework model.
- **Export modal**: `/internal/tui/export/model.go` implements the centered modal used for CSV export flow in TUI mode.

## TUI Behavior

- **Default mode** is TUI (`-plain` disables TUI and prints CSV rows to stdout).
- **TUI trace flow** ingests events into the in-memory stats engine; it does **not** continuously write trace rows to disk.
- **File output in TUI** is explicit export only (`e`), writing `ior-snapshot-<timestamp>.csv` in the current directory.
- **Export toggle flag**: `-tuiExport=true|false` (default `true`) enables or disables TUI snapshot file export at runtime.
- **Tab navigation** supports `tab/shift+tab`, numeric keys `1..6`, and directional keys `left/right` and `h/l`.
- **When export is disabled**, export key hints are hidden from dashboard help and `e` does not open export modal.

## Code Style

- Standard Go conventions with static linking (`-ldflags '-w -extldflags "-static"'`)
- Keep functions under 50 lines, refactor larger code to `/internal/` packages  
- Use generated types from `/internal/types/generated_types.go` for kernel-userspace communication
- BPF C code in `/internal/c/ior.bpf.c` should be minimal for verification
- Import style: `"ior/internal/packagename"` for internal packages
- Error handling: Return errors, don't panic except for setup validation
