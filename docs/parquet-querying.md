# Query Parquet recordings with ClickHouse

Press `R` in the TUI to record rows while tracing, or run
`sudo ./ior -parquet trace.parquet` for headless output. The TUI recorder follows the active
global filter. Headless `-parquet` is a raw output mode and does not run the TUI.

The examples use `clickhouse local` from the `clickhouse/clickhouse-server` Docker image.
Mount the directory containing the recording read-only:

```sh
recording_dir=$(pwd)
recording_file=trace.parquet
docker run --rm -v "$recording_dir:/data:ro" clickhouse/clickhouse-server:latest \
  clickhouse local -q "SELECT count(*) FROM file('/data/$recording_file', Parquet)"
```

Use an absolute `recording_dir` if the file is elsewhere. The file schema comes from
[`internal/parquet/schema.go`](../internal/parquet/schema.go):

| Column | Type | Meaning |
|---|---|---|
| `seq` | UInt64 | Event sequence number |
| `time_ns` | UInt64 | Timestamp in nanoseconds since boot |
| `gap_ns` | UInt64 | Gap since the previous traced syscall on the same thread |
| `latency_ns` | UInt64 | Syscall duration |
| `comm`, `syscall`, `family` | String | Process name, syscall name and family |
| `pid`, `tid` | UInt32 | Process and thread IDs |
| `fd` | Int32 | File descriptor; `-1` when the syscall has none (not `0`, which is a real descriptor) |
| `ret` | Int64 | Return value as seen at `sys_exit`; negative values are errno results, except the kernel-internal restart codes -512, -513, -514 and -516, which are interruptions rather than errors (see the `is_error` rule below) |
| `bytes` | UInt64 | Classified payload bytes |
| `address_space_bytes` | UInt64 | Virtual address space added, removed or moved by `mmap`, `munmap`, `mremap` (the larger of old and new size) and `brk` (how far the program break moved since the process's previous `brk`; the first `brk` seen for a process and `brk(0)` queries report 0), rounded up to whole host pages. `msync`, `mprotect`, `madvise` and `mlock*` do not change the address space and report 0. `brk` is tracked per process, not per address space: a `vfork`/`CLONE_VM` child shares its parent's heap, so its first `brk` reports 0 and the parent's next `brk` may absorb heap movement the child caused (exec resets the baseline) |
| `requested_sleep_ns` | Int64 | Requested relative sleep duration; `-1` unknown (null/invalid timespec, `TIMER_ABSTIME`), `9223372036854775807` for requests too large for Int64 (e.g. `sleep infinity`) |
| `nfds` | Int32 | Poll/select count or epoll `maxevents` |
| `timeout_ns` | Int64 | Polling timeout; `-1` infinite, `-2` unknown |
| `file`, `old_file` | String | Resolved path and source path for rename/link calls |
| `is_error` | Bool | Whether the return is a negative errno the program can observe (-1 to -4095, except -512, -513, -514 and -516). See [Restart codes and `is_error`](#restart-codes-and-is_error) |
| `filter_epoch` | UInt64 | Filter generation at capture time |
| `epoll_op` | String | `epoll_ctl` ADD, MOD or DEL |
| `epoll_target_fd` | Int32 | Target descriptor of `epoll_ctl` |
| `epoll_events` | UInt32 | Requested epoll event mask |

Fields that do not apply to a row use zero or an empty string, except `fd` (`-1`) and
`timeout_ns` (`-1`/`-2`), where zero is a real value. In particular, `file` is the
new path for rename and link calls, and `old_file` is the source path.

A row whose syscall has no file (for example `sync`) has an empty `file` and
`fd = -1`. The terminal views and `-plain` show such rows with the placeholder `N:file`, but the
placeholder is display text only and is never written to a Parquet recording, to the stream CSV
export of the `e` key (both use an empty `file` and `fd = -1`) or to the `.ior.zst` flamegraph
record (an empty path, which `ior collapsed -fields path` shows as `[unknown]`). Only the
`-plain` stdout CSV prints `N:file`, because it is a display stream. `WHERE file != ''`
therefore selects exactly the rows that have a file, and a file really named `N:file` is stored
under that name. To count descriptor-carrying rows use `fd >= 0`. Recordings made before
this change hold `N:file` and `fd = -1` in those rows; filter them with
`file NOT IN ('', 'N:file')`.

### Stream CSV export columns

The TUI stream CSV export (`e`, and `x`/`X`/`E` on the Stream tab) carries the same per-event
fields as the recording, in this order:
`seq, time_ns, gap_ns, latency_ns, comm, pid, tid, syscall, fd, ret, bytes, file, error, family,
requested_sleep_ns, nfds, timeout_ns, address_space_bytes, old_file, epoll_op, epoll_target_fd,
epoll_events`. The names match the Parquet columns above, except that `error` is the Parquet
`is_error`; `filter_epoch` exists only in recordings. New columns are only ever appended, so a
script that indexes by position keeps working. `old_file` (rename/link source, `file` being the
destination), `address_space_bytes` and the `epoll_*` columns follow the same zero/empty rules
as in the recording. The synthetic warning lines the Stream tab shows (`Trace stopped: ...`,
recorder failures) are UI notes with a wall-clock time and placeholder pid/ret, so they are not
exported; like a recording, the CSV holds only traced syscalls with their boot-clock `time_ns`.
Unlike the recording, the CSV writes `comm`, `file` and `old_file` as traced, without the UTF-8
repair.

### Restart codes and `is_error`

When a signal interrupts a blocked syscall, the kernel leaves an internal restart code in the
return register: -512 (`ERESTARTSYS`), -513 (`ERESTARTNOINTR`), -514 (`ERESTARTNOHAND`) or
-516 (`ERESTART_RESTARTBLOCK`). The `sys_exit` tracepoint, which ior reads, fires before the
signal-delivery path decides what user space gets, so these raw values are what `ret` holds.
ior keeps them visible in `ret` but sets `is_error` to `false` and does not count them as
errors (error counters, the errors-only filter, `is_error`). The filter `ret == -512` still
matches, so the rows can be found on purpose.

What the program experiences depends on the restart code and on whether a signal handler ran
(Linux x86, `arch/x86/kernel/signal.c`; see also signal(7), "Interruption of system calls and
library functions by signal handlers"):

- The call is transparently restarted, and the program never saw a failure, when either no
  handler ran (`SIGSTOP`/`SIGCONT`, a ptrace attach, cgroup freezer, a signal whose action is
  ignore or default-continue), or a handler ran and the code allows a restart after it:
  - -513 (`ERESTARTNOINTR`) is always restarted, with or without a handler.
  - -512 (`ERESTARTSYS`) is restarted when no handler ran, or when the handler was installed with
    `SA_RESTART`.
  - -514 (`ERESTARTNOHAND`) is restarted only when no handler ran.
  - -516 (`ERESTART_RESTARTBLOCK`) is re-executed via `restart_syscall` only when no handler ran.
  The row with the restart code is followed by a second row for the restarted call (for -516 that
  is `restart_syscall`, which carries no requested sleep).
- The program gets a real `EINTR` when a handler ran and the code does not allow a restart:
  -512 without `SA_RESTART`, -514 (`ERESTARTNOHAND`, for example `pause` or `sigsuspend`) and -516 (a relative `clock_nanosleep`/`nanosleep` interrupted by a handled
  signal) always. ior still shows the restart code with `is_error=false` in that case, because
  the rewrite to -4 happens after `sys_exit`. ior cannot tell that case from a transparent
  restart.
- A call that itself returns `-EINTR` (-4), for example `epoll_wait` when a signal is
  pending, is a genuine result: `ret=-4`, `is_error=true`. Only the four restart codes are
  excluded. `-515` (`ENOIOCTLCMD`) is not a restart code and stays an error.

Folding the restart row and its continuation into one row is not done yet (task fs2).

### Invalid UTF-8 in `comm`, `file` and `old_file`

These columns are Parquet STRING (UTF-8) columns, and strict readers such as DuckDB reject
every query that touches a column holding an invalid byte. Traced text is not always valid
UTF-8: the kernel cuts `comm` at 15 bytes even in the middle of a multi-byte character, and any
local user can create a file name with arbitrary bytes. So that recordings stay queryable, ior
sanitizes these three columns when it writes them:

- A partial multi-byte character at the end of `comm` (the kernel's cut) is dropped, so
  `ääääääääää` is stored as `äääääää`. The same is done for `file` and `old_file`, but only for
  a captured path that is exactly as long as the capture limit (255 bytes), or for the 255
  bytes plus the `...` ior appends to an over-long `getcwd` path. Only in those cases can ior
  tell that the path was cut mid-character. A relative path resolved against its directory
  descriptor is trimmed before it is joined to the directory, so the joined `file` value may
  be longer than 255 bytes. A shorter path that ends in a stray lead byte is a real (odd)
  file name and is escaped like any other invalid byte, as described next.
- Any other invalid byte is stored as the four characters `\xHH` in lower-case hex (the notation
  `-escape` uses), so a file named `f`, byte 0xff, `inv` is stored as `f\xffinv`. This includes a
  `comm` such as `a`, byte 0xff, `b` set with `prctl(PR_SET_NAME)`. Valid characters are never
  changed.

The mapping is not reversible: a name that literally contains the characters `\xff` is stored
the same as one containing the byte 0xff, and a backslash is not doubled. To find affected
rows, search for the two characters `\x` in the column.

This sanitizing always happens for Parquet output, whatever `-escape` says: `-escape` only
controls terminal output (`-plain`, `ior collapsed`) and has no effect on recordings.
Recordings made before this change may still hold raw invalid bytes in these columns, and
DuckDB keeps rejecting queries that touch the affected column in those files; they are not
rewritten. ClickHouse reads them fine, and `count(*)` or queries that skip the affected column
work in DuckDB too.

## Queries

Replace `recording.parquet` in these queries with the filename mounted at `/data`.

```sql
DESCRIBE TABLE file('/data/recording.parquet', Parquet);

SELECT syscall, count(*) AS calls
FROM file('/data/recording.parquet', Parquet)
GROUP BY syscall
ORDER BY calls DESC
LIMIT 15;

SELECT syscall, ret, count(*) AS calls
FROM file('/data/recording.parquet', Parquet)
WHERE is_error
GROUP BY syscall, ret
ORDER BY calls DESC
LIMIT 15;

SELECT syscall, count(*) AS calls,
       quantile(0.50)(latency_ns) AS p50_ns,
       quantile(0.99)(latency_ns) AS p99_ns
FROM file('/data/recording.parquet', Parquet)
GROUP BY syscall
ORDER BY p99_ns DESC
LIMIT 15;

SELECT file, sum(bytes) AS total_bytes, count(*) AS calls
FROM file('/data/recording.parquet', Parquet)
WHERE file != ''
GROUP BY file
ORDER BY total_bytes DESC
LIMIT 15;

SELECT intDiv(time_ns, 10000000) AS bucket_10ms,
       count(*) AS calls, sum(bytes) AS bytes
FROM file('/data/recording.parquet', Parquet)
GROUP BY bucket_10ms
ORDER BY bucket_10ms;
```

### Sampled recordings

A recording of a run with an explicit sampling rate (`-syscall-sampling-syscalls read=10`,
`-syscall-sampling-families`) holds only a sample of the sampled syscalls: about 1 in N
invocations of a rate-N syscall is written as a row, and none of a rate-0 (aggregate-only)
one. The file footer says so, in two key/value pairs that are absent from a recording that
traced everything:

- `ior.sampling`: the effective rates, for example `read=10,write=0`. A family-wide rate
  (`-syscall-sampling-families FS=10`) is named once, as `FS=10` (upper-case family names,
  lower-case syscall names), not once per syscall; an explicit per-syscall rate is listed
  next to it (`FS=10,read=5`). Only syscalls whose probe was actually attached are named.
- `ior.sampling.totals`: the exact population of each sampled syscall that was invoked,
  written when the recording ends, as JSON, for example
  `[{"syscall":"read","rate":10,"traced":110,"counted_only":890,"total":1000}]`:
  `traced` is the number of invocations ior handed to the recorder, `counted_only` the
  invocations only the kernel counted, `total` their sum. `traced` is not always the
  number of rows in the file: a row the recorder queue shed (`events were dropped
  (parquet recorder queue overflow)` on stderr) or a pair of a probe that is not active is
  counted as traced but has no row, so compare `total`, not the row count, with the
  population. When events were lost (the run statistics say
  `ring buffer drops: N` or `records discarded at stop: N`), the lost rows are in neither `traced` nor `counted_only`: every
  element then carries `"lower_bound":true` and its numbers are a lower bound (the true
  total is at least that). The value is the word `unavailable` when the totals cannot be
  trusted at all (a filter the kernel counters cannot apply, or a failed read of them).

Row counts of sampled syscalls in such a file are therefore not the population; use
`ior.sampling.totals` for that. The kernel counts carry no bytes, files or latency
percentiles: those stay sampled. Read the footer with, for example,
`SELECT decode(key), decode(value) FROM parquet_kv_metadata('trace.parquet')` in DuckDB. `R` recordings made from the TUI are not marked.

`time_ns` is a boot-relative clock, so join it to wall time only if you have an independent
boot-time reference.

## Check a recording

`mage parquetValidate` uses ClickHouse in Docker. It reads the latest timestamp-named
`*.parquet` in the repo root unless `PARQUET_FILE` is set:

```sh
mage parquetValidate
PARQUET_FILE=/absolute/path/to/trace.parquet mage parquetValidate
```

The target checks for all 23 columns, a nonzero row count, a nonzero minimum `time_ns`, and
a `seq` range with `max(seq) > min(seq)`. That last check does not prove row-by-row
ordering, and a one-row file fails it.
