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
| `ret` | Int64 | Return value; negative values are errno results |
| `bytes` | UInt64 | Classified payload bytes |
| `address_space_bytes` | UInt64 | Memory-region extent, when applicable |
| `requested_sleep_ns` | Int64 | Requested relative sleep duration; `-1` unknown (null/invalid timespec, `TIMER_ABSTIME`), `9223372036854775807` for requests too large for Int64 (e.g. `sleep infinity`) |
| `nfds` | Int32 | Poll/select count or epoll `maxevents` |
| `timeout_ns` | Int64 | Polling timeout; `-1` infinite, `-2` unknown |
| `file`, `old_file` | String | Resolved path and source path for rename/link calls |
| `is_error` | Bool | Whether the return is a negative errno |
| `filter_epoch` | UInt64 | Filter generation at capture time |
| `epoll_op` | String | `epoll_ctl` ADD, MOD or DEL |
| `epoll_target_fd` | Int32 | Target descriptor of `epoll_ctl` |
| `epoll_events` | UInt32 | Requested epoll event mask |

Fields that do not apply to a row use zero or an empty string. In particular, `file` is the
new path for rename and link calls, and `old_file` is the source path.

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
