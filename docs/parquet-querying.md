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
| `fd` | Int32 | File descriptor, when applicable |
| `ret` | Int64 | Return value as seen at `sys_exit`; negative values are errno results, except the kernel-internal restart codes -512, -513, -514 and -516, which are interruptions rather than errors (see the `is_error` rule below) |
| `bytes` | UInt64 | Classified payload bytes |
| `address_space_bytes` | UInt64 | Memory-region extent, when applicable |
| `requested_sleep_ns` | Int64 | Requested relative sleep duration; `-1` unknown (null/invalid timespec, `TIMER_ABSTIME`), `9223372036854775807` for requests too large for Int64 (e.g. `sleep infinity`) |
| `nfds` | Int32 | Poll/select count or epoll `maxevents` |
| `timeout_ns` | Int64 | Polling timeout; `-1` infinite, `-2` unknown |
| `file`, `old_file` | String | Resolved path and source path for rename/link calls |
| `is_error` | Bool | Whether the return is a negative errno the program can observe (-1 to -4095, except -512, -513, -514 and -516). See [Restart codes and `is_error`](#restart-codes-and-is_error) |
| `filter_epoch` | UInt64 | Filter generation at capture time |
| `epoll_op` | String | `epoll_ctl` ADD, MOD or DEL |
| `epoll_target_fd` | Int32 | Target descriptor of `epoll_ctl` |
| `epoll_events` | UInt32 | Requested epoll event mask |

Fields that do not apply to a row use zero or an empty string. In particular, `file` is the
new path for rename and link calls, and `old_file` is the source path.

### Restart codes and `is_error`

When a signal interrupts a blocked syscall, the kernel leaves an internal restart code in the
return register: -512 (`ERESTARTSYS`), -513 (`ERESTARTNOINTR`), -514 (`ERESTARTNOHAND`) or
-516 (`ERESTART_RESTARTBLOCK`). The `sys_exit` tracepoint, which ior reads, fires before the
signal-delivery path decides what user space gets, so these raw values are what `ret` holds.
ior keeps them visible in `ret` but sets `is_error` to `false` and does not count them as
errors (error counters, the errors-only filter, `is_error`). The filter `ret == -512` still
matches, so the rows can be found on purpose.

What the program experiences depends on the signal:

- No handler ran (`SIGSTOP`/`SIGCONT`, a ptrace attach, cgroup freezer) or the handler was
  installed with `SA_RESTART`: the kernel re-executes the call. The row with the restart code
  is followed by a second row for the restarted call (for `-516` that is `restart_syscall`, which
  carries no requested sleep). The program never saw a failure.
- A handler ran without `SA_RESTART`, or the call is never restarted after a handler (a relative
  `clock_nanosleep`/`nanosleep` interrupted by a handled signal, `-516`): the program gets a real
  `EINTR`, but ior still shows -512/-514/-516 with `is_error=false`, because the rewrite to
  -4 happens after `sys_exit`. ior cannot tell that case from a transparent restart.
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
