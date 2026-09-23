# Integration tests

The `ioworkload` binary makes known syscalls while `ior` traces its PID. Tests check either
the aggregated `.ior.zst` recording or exact rows in Parquet. Descriptor flags belong in the
aggregated assertions; return values, errors and other per-event fields belong in Parquet.

## Requirements

- A Linux host that permits BPF tracepoint attachment, with root or an appropriate sudo rule for `integrationtests.test`.
- `libbpfgo` at `../libbpfgo` (or `LIBBPFGO`), pinned to `v0.9.2-libbpf-1.5.1` and rebuilt with its submodules. See [AGENTS.md](../AGENTS.md).
- A kernel with the tracepoints needed by the scenario. Tests probe for newer syscalls and explain skips.

`ior` embeds its normal BPF object. Set `IOR_BPF_OBJECT` only when testing another object,
including an older release.

## Run

```sh
mage integrationTest
```

This builds `ior`, `ioworkload` and `integrationtests.test`, then runs the suite with
`-test.failfast`. Parallelism defaults to `runtime.NumCPU()` and can be set with
`INTEGRATION_PARALLEL=2`. For serial execution, use `mage integrationTestSerial`.

To collect a verdict for every test after one fails, run the compiled binary without
`-test.failfast`.
[The Fedora handoff](../docs/fedora-gate-handoff.md#5-privileged-integration-suite) has the
command, output filter and skip criteria. The test binary runs from `integrationtests/` so
it can find `../ior` and `../ioworkload`.

The four `*xattrat` tests and some mount and io_uring expectations need newer or less
restricted kernels. The probes in `kernel_support_test.go` check tracefs and
`io_uring_setup`; they do not infer support from a kernel version.
`TestMountFsManagementSyscalls` can pass while logging individual expectations it could not
check, so read its verbose output.

## Files

- `harness.go` starts `ior` and the workload and collects output.
- `parse.go` reads `.ior.zst` recordings into `TestResult`.
- `expectations.go` defines the aggregated event assertions.
- `*_test.go` files cover syscall families and Parquet row semantics.

The suite does not force `close(2)` to return `EINTR` or `EIO`; those outcomes depend on
timing and delayed I/O errors. Unit tests cover descriptor eviction for those returns. Live
tests cover successful and `EBADF` closes.
