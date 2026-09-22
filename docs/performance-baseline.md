# Performance baselines

`scripts/perf-baseline.sh` records the performance of a commit into `perf/` and
compares two recordings. The recordings are committed, so a performance change
is always judged against the exact numbers that motivated it, not against a
re-run on a machine in a different mood.

## What a baseline contains

| File | Content |
|---|---|
| `perf/bench-<label>.txt` | Raw `go test -bench -benchmem` output in benchstat format, preceded by `#` lines with commit, date, kernel, CPU, clocksource, Go version, sample settings and load average, plus a `# note:` line added later if the recording turned out noisy. |
| `perf/static-<label>.txt` | Deterministic metrics of the BPF side, computed from the source tree. |

The benchmark set is focused on the event hot path: the end-to-end pipeline
mixes (`BenchmarkPipeline{ReadHeavy,WriteHeavy,MetadataHeavy,DiverseAllTypes,HeadlessParquetCapture}`),
the per-stage components they are made of (decode, pairing, the exit handlers,
fd tracker, comm cache, the event pool) and the downstream row, stats and parquet
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
  handlers, by buffer. Zero since task 79: string fields are terminated
  (`ev->FIELD[0] = 0` on the NULL and failed-read paths) instead of zeroed.

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
`perf-baseline.*` directory inside the git directory (never in the worktree,
whatever `$TMPDIR` is) that is removed on exit.

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
the `ns/op` numbers jittery. `allocs/op` and `B/op` are far steadier but not
exact for every row; see [Comparing](#comparing).

## Comparing

```shell
scripts/perf-baseline.sh compare 1266ffe <new-label>
```

This runs `benchstat` on the two benchmark files and prints the static metrics
that changed. `benchstat` is installed with
`go install golang.org/x/perf/cmd/benchstat@latest`.

Read the result in this order:

1. **`allocs/op` and `B/op`.** Rows whose raw samples are all equal within
   each of the two recordings (e.g. every `Deserialize*` row and `allocs/op`
   of the component benchmarks) are exact: any change there is real. Check
   the raw samples, not the benchstat table: benchstat prints the footnote
   "all samples are equal" only when both files hold the same single value,
   i.e. for an unchanged exact row. A changed exact row shows `± 0%` on both
   sides with no footnote, just like a varying row that rounds to `± 0%`.
   A row equal in only one recording is not exact
   (`SyscallAccumulatorSnapshot` `B/op` is 1056 in every `4d2d76f` sample but
   1056-1057 in `03249c1`, same code). Pooled and allocation-heavy rows are
   not: within one recording component `B/op` varies by a few percent, up
   to about 10% (samples in `03249c1`: `HandleNullExit` 94-103,
   `EventPoolGetPut` 95-105, `HandleDup3Exit` 159-164; in `4d2d76f`:
   `HandleFcntlExit` 140-150), and `allocs/op` of the pipeline mixes by
   under 0.1%
   (`PipelineHeadlessParquetCapture` 9135-9140 across both). Both also drift
   between recordings of the same code, so a delta beyond the sample spread
   can still be noise. Between `4d2d76f` and `03249c1`, which differ only in
   `sendPair` (which allocates nothing), benchstat calls these deltas
   significant (the complete list): `B/op` of `HandleDup3Exit` -3.31%
   (samples 165-168 vs 159-164), `HandleFcntlExit` -2.38%, `HandleOpenExit`
   -1.08% (506-510 vs 502-505), `HandleNameExit` -0.32%, `TracepointEntered`
   +0.72%, `PipelineMetadataHeavy` +0.01%, `PipelineThreadScaling`
   +0.03-0.04% and `PipelineHeadlessParquetCapture` -7.43% (timing-dependent,
   see below); `allocs/op` of `PipelineMetadataHeavy` +0.00%,
   `PipelineThreadScaling` +0.00-0.01% (e.g. `threads_10` about +4,
   `threads_1000` about +6 allocations per op, by median) and
   `PipelineHeadlessParquetCapture` -0.02%. For rows whose samples vary, count
   an `allocs/op` or `B/op` change as real only when it is larger than the
   row's sample spread (min to max of the raw samples) in both recordings
   **and** larger than a drift floor: about 4%
   for component `B/op`, about 0.1% for pipeline `allocs/op` and `B/op`.
   For a change near the floor, confirm it with a before/after re-run in the
   same session. `B/op` of `PipelineHeadlessParquetCapture`
   depends on timing and spreads up to 13% within a recording, more than the
   floor; trust it only with caution. `B/op` of
   `WriterThroughput` is not trustworthy at all: its samples ranged 961-2247
   (`4d2d76f`) and 719-3224 (`03249c1`), benchstat ±36% and ±64%.
2. **`sec/op`.** Trust a delta only when benchstat reports it as significant
   (it prints `~` otherwise) and both recordings come from the same host.
3. **Static metrics.** A BPF change that claims to shrink records or remove
   helper calls must show up here; a userspace change must leave them alone.

Recordings from different machines are not comparable in `sec/op`. Record the
"before" again on the machine that measures the "after" if it has changed.
Some committed recordings are load-polluted; check
[Known-noisy recordings](#known-noisy-recordings) and any `# note:` header line
before trusting a `sec/op` delta against them.

## Workflow for a performance task

1. Make sure a baseline exists for the commit you branch from; record one if not.
   If the newest committed baseline is listed under
   [Known-noisy recordings](#known-noisy-recordings) (or carries a `# note:`
   header), record a fresh "before" at your branch point instead. If that
   commit already has a baseline, use a distinct label
   (`scripts/perf-baseline.sh record <hash>-rerun`) or set `PERF_FORCE=1` to
   overwrite it. `sec/op` deltas are best between a "before" and "after"
   recorded in the same session.
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

## Known-noisy recordings

Each file below also carries a `# note:` header line saying the same.

`perf/bench-1a7f74b.txt` (the final code of task 79) was recorded on a host
that was not idle (load average 0.95 1-min, but 3.21 / 3.63 over 5 and 15
minutes at the start). Its `sec/op` is unusable for the component rows, whose
samples spread by up to 118% within the recording (`HandleOpenExit`
898-1955 ns, `DeserializeRetEvent` 325-707 ns, `TracepointEntered`
4507-7466 ns); the five pipeline mixes spread 11-22%, so only a large delta
means anything there. The static metrics and `allocs/op` are valid, and `B/op`
follows the usual rules above. Task 79 changed only BPF C and the generated
`String()` method, neither of which any benchmark executes, so no `sec/op`
change was expected from it in the first place.

`perf/bench-03249c1.txt` (the final code of task 39) has load-polluted
`sec/op`: the load average was 0.82 at the start and rose to about 8.66
during the run, and many benchmarks of components task 39 never touched came
out up to 92% slower than in `perf/bench-4d2d76f.txt`, while an interleaved
re-run showed no code regression. Outside tests, 03249c1 differs from 4d2d76f
only in `sendPair`, whose pair send no longer blocks (a `select` with
`default`). Between the two recordings, `sec/op` of the four mixes
`PipelineReadHeavy`, `PipelineWriteHeavy`, `PipelineMetadataHeavy` and
`PipelineDiverseAllTypes` matches (benchstat `~`); the load-affected rows
include `PipelineHeadlessParquetCapture` (+66.3% `sec/op`, -7.4% `B/op`),
`PipelineThreadScaling` (+54..86% for 10 threads and up), the exit handlers,
fd tracker, comm cache, the event pool and the downstream stages
(`WriterThroughput` +58.1%, `RecorderQueueHandoff` +60.4%,
`SyscallAccumulatorSnapshot` +65.6%, `streamrow` `New` +22.3%).

`perf/bench-4d2d76f.txt` is noisy too (load 2.19 at the start): 03249c1's
`Deserialize*` rows are 5-49% faster than 4d2d76f's (all but
`DeserializeRetEvent`, which is `~`), i.e. 4d2d76f's are up to 96% slower,
with 4d2d76f spreads up to ±38%.

What to trust in these two files:

| Rows | 4d2d76f | 03249c1 |
|---|---|---|
| static metrics | yes | yes |
| `allocs/op` and `B/op` (except the two rows below) | exact rows (all samples equal in both files): yes, any delta; varying rows: yes, for deltas beyond both the per-row sample spread (component `B/op` up to ~7%, pipeline `allocs/op` under 0.1%) and the drift floor (component `B/op` ~4%, pipeline `allocs/op` and `B/op` ~0.1%) | yes, same rule (component `B/op` spread up to ~10%) |
| `B/op` of `PipelineHeadlessParquetCapture` | with caution (samples spread 7%) | with caution (samples spread 13%) |
| `B/op` of `WriterThroughput` | no (±36%) | no (±64%) |
| `sec/op` of the four mixes above | yes (the reference for task 39's final code) | no |
| `sec/op` of the component rows (`RawHandlerLookup`, `Tracepoint*`, `Handle*Exit`, `FdTrackerGetSet`, `CommResolverCachedHit`, `EventPoolGetPut`) and downstream stages (`WriterThroughput`, `RecorderQueueHandoff`, `SyscallAccumulatorSnapshot`, `New`) | with caution: spreads ±1-8% except `TracepointExited` (±22%, not usable); recorded at load 2.19, so count only deltas well beyond the spread | no (up to 92% slower, spreads up to ±41%) |
| `sec/op` of `Deserialize*`, `PipelineHeadlessParquetCapture` and `PipelineThreadScaling` rows | no | no |

A performance task branching from task 39's code should record a fresh
"before" rather than compare against either file.
