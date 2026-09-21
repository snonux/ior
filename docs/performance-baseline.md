# Performance baselines

`scripts/perf-baseline.sh` records the performance of a commit into `perf/` and
compares two recordings. The recordings are committed, so a performance change
is always judged against the exact numbers that motivated it, not against a
re-run on a machine in a different mood.

## What a baseline contains

| File | Content |
|---|---|
| `perf/bench-<label>.txt` | Raw `go test -bench -benchmem` output in benchstat format, preceded by `#` lines with commit, date, kernel, CPU, clocksource, Go version, sample settings and load average. |
| `perf/static-<label>.txt` | Deterministic metrics of the BPF side, computed from the source tree. |

The benchmark set is focused on the event hot path: the end-to-end pipeline
mixes (`BenchmarkPipeline{ReadHeavy,WriteHeavy,MetadataHeavy,DiverseAllTypes,HeadlessParquetCapture}`),
the per-stage components they are made of (decode, pairing, the exit handlers,
fd tracker, comm cache, event pools) and the downstream row, stats and parquet
stages. The scaling, TUI and flamegraph benchmarks stay with `mage benchCompare`
and `mage benchFlameCmp`; they take much longer and do not move with the hot
path.

The static metrics exist because nothing in userspace can benchmark the BPF
programs, and measuring them in the kernel (`bpf_stats`, `bpftool prog profile`)
needs root. They need neither and never vary between runs:

- `struct_size`: size of every event struct in `internal/c/types.h`.
- `pair_bytes`: ring-buffer bytes reserved for one enter/exit pair of
  representative syscalls (`read`, `close`, `openat`, `newfstatat`, `renameat2`,
  `close_range`, `eventfd2`, `memfd_create`, `mmap`, `epoll_wait`, `futex`).
- `clock_reads`: `bpf_ktime_get_boot_ns` calls on the path of one traced
  syscall, counting the handler body and the inlined enter/exit hook.
- `memset_sites`: full-buffer `__builtin_memset` sites across the generated
  handlers, by buffer.

## Recording

```shell
scripts/perf-baseline.sh record              # label = short commit hash (+ "-dirty")
scripts/perf-baseline.sh record my-label     # explicit label
PERF_COUNT=10 scripts/perf-baseline.sh record
```

A label must start with a letter or digit and may contain only letters,
digits and `.` `_` `+` `-` (no `/`, no `..`, not empty); anything else is
refused before any work starts.

If the tree differs from `HEAD` outside `perf/` (tracked edits or deletions, or
non-ignored untracked files — `.gitignore`, `.git/info/exclude` and the global
`core.excludesFile` all count — since `go test` compiles a new uncommitted
`.go` file just the same), the recording measures code that no commit
contains. The label then always gets a `-dirty` suffix, explicit labels
included, and the header's `commit:` line ends in `+uncommitted changes`.
Conversely, an explicit label ending in `-dirty` on a clean tree is refused.
Commit first and record from a clean tree.

The check stages the whole tree outside `perf/` into a throwaway index
(`git read-tree HEAD`, `git add -A`, `git write-tree`) and compares the
resulting tree id with `HEAD^{tree}`, so the real index, diff settings such as
`diff.external` or `GIT_EXTERNAL_DIFF`, and symlink targets play no part. An
untracked nested git repository counts as dirty, but edits inside it are not
tracked; a file git cannot read (e.g. mode `000`) aborts the recording with
"cannot fingerprint the tree". The loose blobs `git add` writes are
unreferenced and pruned by `git gc`; the throwaway index lives in a temporary
directory under `$TMPDIR` (default `/tmp`) that is removed on exit.

An existing `perf/bench-<label>.txt` or `perf/static-<label>.txt` is never
overwritten silently: the script refuses before any benchmark runs unless
`PERF_FORCE=1` is set (right after the dirty check, which decides the final
label). Both files are written to temporary files in `perf/`
and renamed into place only after the run produced benchmark results and no
package failed, so a failed, empty or interrupted (Ctrl-C) recording leaves
nothing behind and can simply be rerun with the same label. Stray temporary
files (`perf/.bench-*`, `perf/.static-*`, e.g. after `kill -9`) are ignored by
git and safe to delete. If `HEAD` or the tree outside `perf/` (the same tree
id as above) changed between the start and the end of the run, the recording
is discarded with "tree changed during recording; nothing written",
since the header would describe a different tree than the one measured. The
written files get the usual mode (`0666` minus the umask, e.g. `0644`).

Every baseline names the commit it measured, so `HEAD` must resolve: on an
unborn branch or a broken checkout the script fails whatever the label —
commit first. A git error while checking whether the tree is clean also aborts
the recording rather than being taken for a dirty tree.

Settings come from the environment: `PERF_COUNT` (samples per benchmark, default
8), `PERF_BENCHTIME` (default `1s`), `PERF_BENCH` (benchmark regexp, default the
focused set), `LIBBPFGO` (default `../libbpfgo`) and `PERF_FORCE` (`1`
overwrites an existing baseline of the same label). A full recording takes
roughly ten minutes.

Record on an idle machine. The header stores the load average at the start so a
noisy recording can be recognised later. On the RHEL 9 development VM the
clocksource is `hpet`, which makes every goroutine park and wake expensive and
the `ns/op` numbers jittery; allocation counts are exact regardless.

## Comparing

```shell
scripts/perf-baseline.sh compare 1266ffe <new-label>
```

This runs `benchstat` on the two benchmark files and prints the static metrics
that changed. `benchstat` is installed with
`go install golang.org/x/perf/cmd/benchstat@latest`.

Read the result in this order:

1. **`allocs/op` and `B/op`.** They are deterministic. Any change is real.
2. **`sec/op`.** Trust a delta only when benchstat reports it as significant
   (it prints `~` otherwise) and both recordings come from the same host.
3. **Static metrics.** A BPF change that claims to shrink records or remove
   helper calls must show up here; a userspace change must leave them alone.

Recordings from different machines are not comparable in `sec/op`. Record the
"before" again on the machine that measures the "after" if it has changed.

## Workflow for a performance task

1. Make sure a baseline exists for the commit you branch from; record one if not.
2. Make the change. Functionality must not change: same rows, fields, ordering,
   filter semantics and statistics.
3. Commit, then `scripts/perf-baseline.sh record`.
4. `scripts/perf-baseline.sh compare <before> <after>` and paste the relevant
   lines into the commit message or the task annotation.
5. Commit the new `perf/` files together with the change, so the next task has
   its own "before".

## Reference baseline

`1266ffe` is the reference for the performance review of 2026-09-21 (tasks
tagged `+performance` in `ask`). Its static metrics at a glance:

| Metric | Value |
|---|---|
| `fd_event` | 48 B |
| `ret_event` | 40 B |
| `path_event` | 312 B |
| `name_event` | 560 B |
| `eventfd_event` | 312 B |
| `two_fd_event` | 568 B |
| `read` / `close` pair on the wire | 88 B |
| `close_range` pair | 608 B |
| `eventfd2` pair | 624 B |
| clock reads per traced syscall | 4 (2 on enter, 2 on exit) |
| full-buffer memset sites | 110 across 731 handlers |
