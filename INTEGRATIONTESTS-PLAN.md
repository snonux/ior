# Integration Tests Plan

> Individual implementation tasks are tracked in **Taskwarrior** (`task project:ior +integrationtests`).

## Overview

End-to-end integration tests that verify ior correctly captures real I/O syscalls from a
known workload process via BPF tracepoints. A standalone Go binary performs deterministic
I/O operations, ior traces it by PID, and the test harness asserts the captured `.ior.zst`
output matches expectations.

## Architecture

```
  ┌─────────────────────────────────────────────────────────┐
  │              Go Test Harness (*_test.go)                │
  │                                                         │
  │  1. Start ioworkload --scenario=X                       │
  │  2. Read PID from workload's stdout (line 1)            │
  │  3. Start ior -pid=PID -flamegraph -duration=N          │
  │  4. Workload sleeps 2s, then performs I/O, exits        │
  │  5. ior finishes, produces .ior.zst                     │
  │  6. Parse .ior.zst → assert expected events present     │
  └─────────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
  ┌──────────────┐             ┌──────────────────┐
  │  ioworkload  │             │       ior        │
  │  (separate   │             │  (BPF tracing    │
  │   binary)    │             │   -pid=WORKLOAD) │
  │              │             │                  │
  │  prints PID  │             │  writes .ior.zst │
  │  sleeps 2s   │             └──────────────────┘
  │  does I/O    │
  │  exits       │
  └──────────────┘
```

## Directory Layout

```
integrationtests/
├── cmd/
│   └── ioworkload/
│       └── main.go              # Standalone I/O workload binary
├── harness.go                   # Test orchestration (start ior + workload, collect output)
├── parse.go                     # Parse .ior.zst into assertable TestResult
├── expectations.go              # ExpectedEvent type & assertion helpers
├── open_test.go                 # open, openat, creat, open_by_handle_at
├── readwrite_test.go            # read, write, pread64, pwrite64, readv, writev
├── close_test.go                # close, close_range
├── dup_test.go                  # dup, dup2, dup3
├── fcntl_test.go                # fcntl (F_DUPFD, F_SETFL, F_DUPFD_CLOEXEC)
├── rename_test.go               # rename, renameat, renameat2
├── link_test.go                 # link, linkat, symlink, symlinkat, readlink
├── unlink_test.go               # unlink, unlinkat, rmdir
├── dir_test.go                  # mkdir, mkdirat, chdir, getdents
├── stat_test.go                 # stat, fstat, lstat, statx, access, faccessat
├── sync_test.go                 # fsync, fdatasync, sync, sync_file_range
├── truncate_test.go             # truncate, ftruncate
├── iouring_test.go              # io_uring_setup, io_uring_enter, io_uring_register
└── README.md
```

## Components

### 1. I/O Workload Binary (`cmd/ioworkload/main.go`)

A standalone Go binary that:
- Accepts `--scenario=<name>` flag (e.g. `open-basic`, `dup-dup3-cloexec`)
- Prints its PID to stdout on line 1
- Sleeps 2 seconds (gives harness time to start ior with PID filter)
- Performs deterministic, known I/O operations in a temp directory
- Cleans up and exits with code 0

### 2. Test Harness (`harness.go`)

```go
type TestHarness struct {
    IorBinary      string // path to built ior binary
    WorkloadBinary string // path to built ioworkload binary
    BpfObject      string // path to ior.bpf.o
    OutputDir      string // temp dir for .ior.zst output
}

func (h *TestHarness) Run(scenario string, duration int) (*TestResult, error)
```

`Run()` sequence:
1. Start `ioworkload --scenario=<name>`
2. Read PID from workload stdout (line 1)
3. Start `ior -pid=<PID> -flamegraph -name=<scenario> -duration=<N>`
4. Workload's 2s sleep expires, it performs I/O, then exits
5. ior finishes (duration expires or SIGTERM), writes `.ior.zst`
6. Parse `.ior.zst` into `TestResult`

Requires root/CAP_BPF. Tests skip with `t.Skip("requires root for BPF")` if not root.

### 3. Parser (`parse.go`)

Reuses existing `flamegraph.newIorDataFromFile()` and `iorData.iter()` to deserialize
`.ior.zst` into an assertable `TestResult` struct containing all captured events.

### 4. Assertions (`expectations.go`)

```go
type ExpectedEvent struct {
    PathContains string // substring match on file path
    Tracepoint   string // e.g. "sys_enter_openat"
    Comm         string // e.g. "ioworkload"
    MinCount     uint64 // minimum occurrences
}

func AssertEventsPresent(t *testing.T, result *TestResult, expected []ExpectedEvent)
func AssertNoUnexpectedComm(t *testing.T, result *TestResult, expectedComm string)
```

### 5. Test Files (per syscall family)

Each `*_test.go` defines scenarios and expectations for its syscall family. Example:

```go
// open_test.go
func TestOpenBasic(t *testing.T)          { runScenario(t, "open-basic", ...) }
func TestOpenCreat(t *testing.T)          { runScenario(t, "open-creat", ...) }
func TestOpenByHandleAt(t *testing.T)     { runScenario(t, "open-by-handle-at", ...) }
```

### 6. Mage Target (`Magefile.go`)

```go
func IntegrationTest() error {
    mg.SerialDeps(All)
    // build ioworkload
    // sudo go test ./integrationtests/... -v -failfast -count=1
}
```

## Key Design Decisions

- **Separate binary**: syscalls come from a real process with a distinct PID, matching production
- **`.ior.zst` as verification format**: reuses existing serialization, avoids parsing noisy stdout
- **`-pid` filter**: isolates workload I/O from system noise
- **2s sleep**: simple timing-based coordination, no synchronization pipes needed
- **One `*_test.go` per syscall family**: scales to many scenarios without monolithic test files
- **Standard `go test`**: no custom runner; `t.Skip` for non-root environments
