# Querying ior Parquet recordings with ClickHouse

ior can record I/O events to a Parquet file (press `R` in TUI, or use the `-parquet` flag in headless mode). This document explains
how to explore those recordings interactively using `clickhouse local`, which is bundled
inside the standard `clickhouse/clickhouse-server` Docker image. No server, no persistent
state, no installation needed beyond Docker.

---

## Prerequisites

- Docker running locally (`docker info` must succeed)
- A recording file, e.g. `ior-recording-20260313-170234.parquet`

---

## Schema

| Column | Type | Description |
|---|---|---|
| `seq` | UInt64 | Monotonically increasing event sequence number |
| `time_ns` | UInt64 | Absolute timestamp (nanoseconds since boot) |
| `gap_ns` | UInt64 | Time since previous event (ns) |
| `latency_ns` | UInt64 | Syscall duration (ns) |
| `comm` | String | Process name |
| `pid` | UInt32 | Process ID |
| `tid` | UInt32 | Thread ID |
| `syscall` | String | Syscall name (e.g. `read`, `openat`) |
| `fd` | Int32 | File descriptor |
| `ret` | Int64 | Return value (negative = errno) |
| `bytes` | UInt64 | Bytes transferred (0 if not applicable) |
| `file` | String | File path (empty if not resolved) |
| `is_error` | Bool | True when `ret` is a negative errno |
| `filter_epoch` | UInt64 | Filter generation at capture time |

---

## Running a query

The general pattern mounts the directory containing the file as `/data` inside the container:

```sh
docker run --rm \
  -v /path/to/recording/dir:/data:ro \
  clickhouse/clickhouse-server:latest \
  clickhouse local -q "SELECT ... FROM file('/data/recording.parquet', Parquet)"
```

For convenience, set shell variables:

```sh
FILE="ior-recording-20260313-170234.parquet"
DIR="$(pwd)"   # or the absolute directory containing the file
IMG="clickhouse/clickhouse-server:latest"

docker run --rm -v "$DIR:/data:ro" "$IMG" clickhouse local -q \
  "SELECT ... FROM file('/data/$FILE', Parquet)"
```

---

## Example queries

### Inspect the schema

```sql
DESCRIBE TABLE file('/data/recording.parquet', Parquet)
```

```
seq           UInt64
time_ns       UInt64
gap_ns        UInt64
latency_ns    UInt64
comm          String
pid           UInt32
tid           UInt32
syscall       String
family        String
fd            Int32
ret           Int64
bytes         UInt64
file          String
is_error      Bool
filter_epoch  UInt64
```

### Row count

```sql
SELECT count(*) FROM file('/data/recording.parquet', Parquet)
```

### Top syscalls by call count

```sql
SELECT syscall, count(*) AS n
FROM file('/data/recording.parquet', Parquet)
GROUP BY syscall
ORDER BY n DESC
LIMIT 15
```

```
read        61800
ioctl       14642
statx       10916
close        8660
openat       6310
write        6053
...
```

### Error breakdown

```sql
SELECT syscall, ret, count(*) AS n
FROM file('/data/recording.parquet', Parquet)
WHERE is_error
GROUP BY syscall, ret
ORDER BY n DESC
LIMIT 15
```

```
read     -11   23597   -- EAGAIN (non-blocking, normal)
statx     -2    1216   -- ENOENT
ioctl    -25     540   -- ENOTTY
openat    -2     376   -- ENOENT
...
```

### Latency percentiles per syscall

```sql
SELECT
    syscall,
    count(*) AS n,
    quantile(0.50)(latency_ns) AS p50_ns,
    quantile(0.90)(latency_ns) AS p90_ns,
    quantile(0.99)(latency_ns) AS p99_ns
FROM file('/data/recording.parquet', Parquet)
GROUP BY syscall
ORDER BY p99_ns DESC
LIMIT 15
```

```
fdatasync    11   1745501   9444892   9994682   -- ~10ms p99, flushes to disk
fallocate    31     35062    487162    589146
rename        3    126619    170921    180889
ftruncate    59      5449     35776    100399
ioctl     14642      1155      8845     63626
...
```

### Top files by I/O bytes

```sql
SELECT file, sum(bytes) AS total_bytes, count(*) AS ops
FROM file('/data/recording.parquet', Parquet)
WHERE file != ''
GROUP BY file
ORDER BY total_bytes DESC
LIMIT 15
```

```
/home/paul/.mozilla/firefox/.../cookies.sqlite-wal   7082880   432
/dev/ptmx                                            1590757  1472
/proc/3680458/smaps                                  1555387   419
...
```

### Activity by process

```sql
SELECT comm, pid, count(*) AS n, sum(bytes) AS total_bytes
FROM file('/data/recording.parquet', Parquet)
GROUP BY comm, pid
ORDER BY n DESC
LIMIT 15
```

### Slow syscalls (above threshold)

```sql
SELECT time_ns, comm, pid, syscall, file, latency_ns
FROM file('/data/recording.parquet', Parquet)
WHERE latency_ns > 1000000   -- 1ms
ORDER BY latency_ns DESC
LIMIT 20
```

### Event timeline (10ms buckets)

```sql
SELECT
    intDiv(time_ns, 10000000) AS bucket_10ms,
    count(*) AS events,
    sum(bytes) AS bytes
FROM file('/data/recording.parquet', Parquet)
GROUP BY bucket_10ms
ORDER BY bucket_10ms
```

---

## Automated validation

The `mage parquetValidate` target runs schema, row-count, and sanity checks
against the latest `*.parquet` in the repo root:

```sh
env GOTOOLCHAIN=auto mage parquetValidate

# Or against a specific file:
PARQUET_FILE=ior-recording-20260313-170234.parquet env GOTOOLCHAIN=auto mage parquetValidate
```

It checks:
1. All 14 expected columns are present
2. Row count > 0
3. `seq` is monotonically ordered and `time_ns` is non-zero
