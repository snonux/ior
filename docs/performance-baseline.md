# Performance baselines

`scripts/perf-baseline.sh` records userspace benchmarks and static BPF metrics in `perf/`.
Commit both files with a performance change so the next comparison has a known starting
point.

## Record and compare

```sh
scripts/perf-baseline.sh record before-change
# edit the code
scripts/perf-baseline.sh record after-change
scripts/perf-baseline.sh compare before-change after-change-dirty
```

The script adds `-dirty` when the tree differs from `HEAD` outside `perf/`. That is
expected for an after measurement taken before the code commit. It records the measured
commit, tree state, kernel, CPU, clocksource, Go version and load average in the benchmark
header. The tree fingerprint includes untracked, non-ignored files; it uses a temporary Git
index and does not stage your work.

A recording writes `perf/bench-<label>.txt` and `perf/static-<label>.txt`. Existing files
are protected unless `PERF_FORCE=1` is set. An interrupted run writes neither final file.
Labels cannot contain slashes or `..`.

The default run takes several minutes: eight samples per benchmark at one second each. Set
`PERF_COUNT` and `PERF_BENCHTIME` when you need a quicker comparison, and record the same
settings on both sides. `PERF_BENCH` narrows the benchmark expression; `LIBBPFGO` selects
the local static libbpfgo checkout. Run on an otherwise idle host.

`compare` uses `benchstat`; install it with
`go install golang.org/x/perf/cmd/benchstat@latest` if needed. Read the result in this
order:

1. Check `allocs/op` and `B/op` against the raw samples. Pooled allocations and pipeline runs vary slightly. A change smaller than the sample spread is weak evidence.
2. Treat `sec/op` as a timing signal only when the before and after runs used the same host and benchstat reports a difference. Three samples, as used for task 89, are too few for its usual significance test.
3. Check static metrics for BPF changes. They do not depend on host load.

Do not compare timings across different hosts or trust a load-polluted recording just
because benchstat prints a percentage. Re-record the before commit on the measurement host
when necessary.

## What the files measure

The benchmark file covers the event pipeline mixes, decode and pairing stages, exit
handlers, fd tracker, comm cache, event pool, stream rows, stats and Parquet writing.
Scaling, TUI and flamegraph benchmarks have separate Mage targets.

The static file reports:

| Metric | Meaning |
|---|---|
| `struct_size` | Natural C size of each event struct in `internal/c/types.h` |
| `pair_bytes` | Enter plus exit ring-buffer reservation for representative syscalls |
| `clock_reads` | `bpf_ktime_get_boot_ns` calls along a traced syscall path |
| `memset_sites` | Full-buffer `__builtin_memset` sites in generated handlers |

These are source-derived sizes and counts, not kernel throughput measurements. They do not
include ring-buffer header overhead.

## Current payload split

Task 89 changed the ring-buffer layout at commit `0e4ebbe`. Compare
`perf/static-task89-before.txt` with `perf/static-task89-after-dirty.txt`:

| Metric | Before | After |
|---|---:|---:|
| `fd_event` | 48 B | 32 B |
| `two_fd_event` | 568 B | 48 B |
| `eventfd_event` | 312 B | 48 B |
| `read` pair | 88 B | 72 B |
| `close_range` pair | 608 B | 88 B |
| `eventfd2` pair | 624 B | 96 B |
| `memfd_create` pair | 624 B | 360 B |

Rare requested sizes and names moved to `fd_size_event`, `two_fd_names_event` and
`eventfd_name_event`. The 32-byte fd record includes C alignment; its Go fields alone
occupy 28 bytes. The after benchmark uses lean fd fixtures. Pipeline allocations stayed
essentially flat in the three-sample run; its timings did not establish a significant
change.

The earlier `1266ffe` baseline is a historical reference, not the current wire layout. Its
static file records 110 full-buffer memset sites and four clock reads per syscall; later BPF
tasks removed those costs.

## Older noisy recordings

- `bench-1a7f74b.txt`: the host was busy. Component timings spread by as much as 118%; the five pipeline mixes spread by 3.6–22%. Static metrics and allocation counts remain useful.
- `bench-03249c1.txt`: load rose sharply during recording. Many untouched component benchmarks appeared slower; an interleaved rerun found no code regression. Its static metrics and stable allocation rows remain useful.
- `bench-4d2d76f.txt`: also noisy, especially deserialization timings and `WriterThroughput` bytes per operation.

Each file has a `# note:` header with the measured conditions. For timing comparisons
against those commits, record a fresh before baseline on the same host as the after run.
