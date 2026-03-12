# Integration Tests

End-to-end integration tests for ior. A standalone I/O workload binary performs
deterministic syscalls, ior traces the workload by PID via BPF, and the test
harness asserts the captured `.ior.zst` output matches expectations.

## Prerequisites

- Built `ior` binary (`mage all`)
- Root privileges or `CAP_BPF` (required for BPF tracepoint attachment)
- Local `libbpfgo` checkout pinned to `v0.9.2-libbpf-1.5.1` and rebuilt with
  `git -C ../libbpfgo submodule update --init --recursive && make -C ../libbpfgo libbpfgo-static`

The binary embeds its default BPF object. Set `IOR_BPF_OBJECT=/path/to/ior.bpf.o`
only when you explicitly want to override the embedded object during testing.
The harness runs `ior` in the legacy compatibility mode that writes aggregated
`.ior.zst` output via `-flamegraph -name <scenario>`; this is kept specifically
for integration coverage and rollback validation.

## Running

```bash
env GOTOOLCHAIN=auto mage integrationTest
```

This builds everything (ior, ioworkload) and runs integration tests in parallel.
Default parallelism is `NumCPU * 2` (minimum `1`).

Validated upgrade checks:

```bash
env GOTOOLCHAIN=auto mage world
env GOTOOLCHAIN=auto mage integrationTest
```

Tests automatically skip with `t.Skip` when not running as root.

To run serially (useful for debugging/flaky triage):

```bash
env GOTOOLCHAIN=auto INTEGRATION_PARALLEL=1 mage integrationTest
```

Tune parallelism by setting `INTEGRATION_PARALLEL`, for example:

```bash
env GOTOOLCHAIN=auto INTEGRATION_PARALLEL=4 mage integrationTest
```

If the suite fails before tracing starts, check for these common causes:

- The local `libbpfgo` checkout is not pinned to `v0.9.2-libbpf-1.5.1` or was
  rebuilt without `git submodule update --init --recursive`.
- `ior` was not rebuilt after pulling the compatibility fix for `-flamegraph`
  / `-name`.
- The run is missing root privileges, in which case the suite will skip or fail
  before BPF attach.

## Structure

- `cmd/ioworkload/` — Standalone binary performing known I/O patterns
- `harness.go` — Test orchestration (start ior + workload, collect output)
- `parse.go` — Parse `.ior.zst` into assertable `TestResult`
- `expectations.go` — `ExpectedEvent` type and assertion helpers
- `*_test.go` — One file per syscall family

See `../INTEGRATIONTESTS-PLAN.md` for the full design.
