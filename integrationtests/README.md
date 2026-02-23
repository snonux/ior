# Integration Tests

End-to-end integration tests for ior. A standalone I/O workload binary performs
deterministic syscalls, ior traces the workload by PID via BPF, and the test
harness asserts the captured `.ior.zst` output matches expectations.

## Prerequisites

- Built `ior` binary and `ior.bpf.o` (`mage all`)
- Root privileges or `CAP_BPF` (required for BPF tracepoint attachment)

## Running

```bash
mage integrationTest
```

This builds everything (ior, ioworkload) and runs the test suite with `sudo`.

Tests automatically skip with `t.Skip` when not running as root.

To opt into parallel scenario execution:

```bash
mage integrationTestParallel
```

Tune parallelism by setting `INTEGRATION_PARALLEL` (default `8`), for example:

```bash
INTEGRATION_PARALLEL=4 mage integrationTestParallel
```

## Structure

- `cmd/ioworkload/` — Standalone binary performing known I/O patterns
- `harness.go` — Test orchestration (start ior + workload, collect output)
- `parse.go` — Parse `.ior.zst` into assertable `TestResult`
- `expectations.go` — `ExpectedEvent` type and assertion helpers
- `*_test.go` — One file per syscall family

See `../INTEGRATIONTESTS-PLAN.md` for the full design.
