# Output files and recordings

Details behind the output modes listed in the [README](../README.md#save-output). The
[tutorial](./tutorial/tutorial.md#recording-for-offline-analysis) shows them in use.

## TUI CSV export

`e` writes the current filtered stream to `ior-stream-<timestamp>.csv`. It always snapshots
the live ring, even while the stream is paused (its modal says so). On the paused Stream tab
`x`/`X` write the frozen paused rows instead.

## Headless runs

Headless `-flamegraph` and `-parquet` check that their output can be written before tracing starts, so a mistyped directory fails immediately rather than after the run. If the working directory's filesystem rejects `:` (vfat, exFAT, some SMB shares), the `.ior.zst` timestamp uses `-` instead (`15-04-05`); if it rejects other characters of the `-name` (`? * " < > |`, non-ASCII text or raw non-UTF-8 bytes, which some `iocharset`/`utf8only`/case-folded filesystems refuse), `ior` refuses to start and says so.

A headless run scoped with `-pid N` (`-plain`, `-flamegraph`, `-parquet`) ends when process N exits, like `strace -p`: ior prints `Traced process N exited, stopping the trace`, then shuts down normally (statistics, recording published, exit status 0) instead of idling until `-duration` and possibly tracing whatever process is handed the recycled pid. It notices the exit from the kernel's process-exit event and, as a fallback that also covers a target dying while ior is still attaching its probes, by checking every 500 ms that the process is still the original one (a reused pid counts as exited). Children the target forked keep running untraced, since ior does not follow forks. The TUI keeps its session open after its target exits.

A headless run scoped with `-tid T` ends when thread T exits, even while the rest of its process runs on: ior prints `Traced thread T exited, stopping the trace` and shuts down the same way. For the main thread (`-tid` equal to the pid) that is when the main thread itself exits (for example `pthread_exit` in `main`), not when its last sibling does. One exception: when another thread of the process calls `execve`, the kernel gives the main thread's id to the new program, which ior keeps tracing under `-tid T` until it exits. A non-main thread T that calls `execve` continues under the process id, which `-tid T` no longer matches, so that run ends. With both `-pid P -tid T` the run follows the thread; the 500 ms fallback check covers the thread too (a reused thread id counts as exited).

## CSV schemas

The TUI keeps its statistics in memory until you export or start a recording.
`-tuiExport=false` disables CSV export shortcuts; it does not disable `R` recording. The
plain CSV schema is deliberately small:
`durationToPrevNs,durationNs,comm,pid.tid,name,ret,file`. Use TUI CSV export or Parquet for
timestamps, byte counts and other per-event fields. A row without a file shows the display
placeholder `N:file` in the `file` column of `-plain` output; TUI CSV export, Parquet and the
`.ior.zst` record store an empty file for it instead. `.ior.zst` recordings made before this
change still hold `N:file` as a real path frame (no format version bump; the format is unchanged).

## File names and overwriting

Files are written to a temporary `ior-<random>.tmp` file and renamed into place when
complete. Names ior generates itself (`ior-stream-<timestamp>.csv`,
`ior-recording-<timestamp>.parquet`, and the
`<host>-<name>-<timestamp>.ior.zst` flamegraph record) are only accurate to the second and are
never overwritten: if the name is taken, ior writes `<name>-1.<ext>` (then `-2`, ...) and
prints or shows the path it really used (a very long name is shortened to fit the 255-byte
file name limit). A file name you choose yourself (`-parquet trace.parquet`, or a name typed
into a TUI export/recording prompt) is replaced if it exists, keeping that file's permissions
(and, when ior may set it, owner); a symlink at that name is replaced, not written through.
The TUI treats a name as generated only when it matches the generated pattern exactly
(zero-padded date and time, right extension); a hand-typed near miss such as
`ior-stream-20260930-90500.csv` or a missing `.csv`/`.parquet` counts as your own name and is
replaced. A typed name may carry a directory (`/tmp/x.csv`, `out/x.csv`, `../x.csv`): the stream
export honours it as typed, relative to the current directory unless absolute, and the Stream
tab shows the path it wrote. ior does not create missing directories. An empty name, a
name that denotes a directory (`out/`, `out/.`), a name over 255 bytes, a NUL byte, or a missing
or unwritable directory is refused with the reason shown in the `X` prompt, which stays open
with your text and cursor so you can fix it. The name is cleaned as text, not through symlinks:
`link/../x.csv` means `x.csv` next to `link`, even when `link` points elsewhere. A killed ior can leave an
orphaned `ior-*.tmp` behind; `mage mrproper` removes `*.tmp`.

## Sampling

With an explicit sampling rate, a raw-mode run (`-plain`, `-flamegraph`, `-parquet`) writes only a
sample of the sampled syscalls. It says so on stderr at startup, reports their exact totals
(rows written plus the invocations the kernel only counted) in the end-of-run statistics, and
marks the files: Parquet footer keys `ior.sampling` and `ior.sampling.totals` (see
`docs/parquet-querying.md`), and the `.ior.zst` header (format version 2; unsampled recordings
keep version 1).
`ior collapsed` reports the sampling details on stderr. Totals are reported as unavailable
under a filter the kernel counters cannot apply (`-comm`, `-path`, ...). If the kernel's ring
buffer dropped events (`ring buffer drops: N` in the statistics), records still buffered at
stop could not be decoded (`records discarded at stop: N`) or the stop left records in the
ring (`records left in the kernel ring buffer at stop: N`), the lost rows are in neither
count, so the totals are labelled `at least` (Parquet: `"lower_bound":true`) instead of exact.
Records are left in the ring when ior lagged behind the kernel at the stop, and also when a
busy trace that had kept up is stopped (`-duration`, Ctrl-C) while its tasks produce faster
than ior takes records out of the ring: the records produced during the stop itself are not
decoded, and the line counts them.
They are labelled the same way when the kernel skipped probe runs (`probe runs skipped by the
kernel: N`, see [Known limitations](./troubleshooting.md#known-limitations)): a skipped run of a traced task is in neither count, and
since that counter covers every task on the host ior cannot tell whether one was.
A family rate (`-syscall-sampling-families FS=10`) is reported once as `FS=10`, with lines and
totals only for the syscalls that were invoked; syscalls whose probes are not attached are not
reported.
TUI `R` recordings are marked the same way whenever a sampled syscall's probe is attached:
`futex*` and `clock_gettime` are aggregate-only in the TUI, so once their probes are attached
(`-trace-families FS,IPC,Time` or the probes modal; the default attaches the FS family only,
so a default recording is unmarked) they have no rows, and `ior.sampling.totals` holds their
exact counts for that recording alone (see `docs/parquet-querying.md`).

## Native `.ior.zst` recordings

`-flamegraph` writes an aggregated native record, not an SVG. To render it with external
FlameGraph tools, run `ior collapsed <file>.ior.zst | flamegraph.pl > flame.svg`.
Records whose selected `-fields` are all empty (for example an empty file name with
`-fields path`) are counted under a `[unknown]` frame so the total weight is preserved (the
event count with the default `-count count`, otherwise the sum of that counter); zero-weight
records are omitted.

The recording is bounded in memory: it keeps about 2^19 (524288) distinct
(path, comm, pid, tid, flags) records, plus a cap/8 headroom for pid/tid-folded records
and a handful of `[other]` records, which an ordinary trace never reaches but a
fork-heavy system-wide run can. Past that, events of new pid/tid combinations are folded
into a pid 0/tid 0 record of the same path and comm, and, if the path/comm population
churns as well, into `[other]` records. Counts, durations and bytes stay exact; only the
detail of the folded events is lost, which the default collapsed fields (`comm,tracepoint,path`)
barely notice for pid/tid churn. ior warns on stderr when the limit is first hit and
prints the number of folded events after `Wrote <file>`. `-flamegraph-max-keys N` sets the
limit (1 to 16777216, default 524288); each record costs about 250 bytes of memory, so the
default needs ~130 MB and the maximum ~4 GB, plus 1/8 headroom on top. Writing the file at the
end streams the records into it in small batches and adds only ~1-2 MB, however many there are.
Raise it when the warning appears and the pid/tid detail matters; lower it on a
memory-constrained host.

A recording stores tracepoint names (`enter_openat`), not the build-specific numeric IDs, so
it stays readable across ior releases and is translated to the reading build's IDs. A
recording that names a tracepoint the reading build does not know is refused, as is one
written before recordings carried names (no format header): its numbers cannot be mapped
reliably, so re-record it instead of trusting a silently wrong syscall name.

## Terminal escaping

Traced comm names and paths come from other users and may contain terminal escape
sequences. When `-plain` or `ior collapsed` writes to a terminal, control characters
(ESC, BEL, C1, line breaks), invalid UTF-8 bytes and invisible, bidi format or blank-rendering space characters (no-break space,
ideographic space, Braille blank, ...) are shown in Go escape notation such as `\x1b` or `\u202e`; the CSV stays valid.
Backslashes are not doubled, so this display is for reading only. When stdout is piped or
redirected, both commands write the exact traced bytes for machine consumers, with one
exception: `ior collapsed` always writes a line feed or carriage return inside a frame as
`\x0a` or `\x0d`, because the collapsed format is one `frame;frame count` stack per line and
a raw line break in a traced path would forge an extra weighted stack. A `;` in a traced
name splits it into frames exactly as the TUI flamegraph does.

That terminal check is `-escape=auto`, the default. It cannot see a terminal at the end
of a pipe, so `ior -plain | grep`, `| tee` or `| less -R` (and `ior collapsed ... | less -R`)
still show raw bytes. Use `-escape=always` for such pipelines, or `-escape=never` to keep
raw bytes on a terminal. Both `-plain` and `ior collapsed` accept the flag, and any other
value is an error.
