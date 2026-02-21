# ClickHouse Integration Plan for IOR

This document outlines the implementation plan for integrating ClickHouse database output into IOR, supporting both real-time streaming and batch file export.

## Overview

| Mode | Format | Use Case | Expected Throughput |
|------|--------|----------|---------------------|
| **Streaming** | Native TCP protocol | Real-time ingestion to ClickHouse | 100K-1M events/sec |
| **File Dump** | Parquet | Batch export for later import | Same (offline processing) |

## Architecture

### Current Data Flow
```
BPF → Ring Buffer → eventLoop → event.Pair → [flamegraph workers | console output]
```

### Proposed Data Flow
```
BPF → Ring Buffer → eventLoop → event.Pair → [clickhouse-stream | parquet-writer | flamegraph | console]
```

---

## Part 1: ClickHouse Streaming (Native TCP Protocol)

### 1.1 Dependencies

Add to `go.mod`:
```go
require (
    github.com/ClickHouse/clickhouse-go/v2 v2.23.0
)
```

### 1.2 New Package Structure

```
internal/
├── clickhouse/
│   ├── client.go        # Connection management, connection pooling
│   ├── schema.go        # Table schema definitions and DDL
│   ├── writer.go        # Batch writer with buffering
│   ├── config.go        # Configuration (host, port, database, table)
│   └── client_test.go   # Unit tests
```

### 1.3 ClickHouse Table Schema

```sql
CREATE TABLE ior_events (
    timestamp_ns    UInt64,           -- Event timestamp (nanoseconds)
    pid             UInt32,           -- Process ID (high cardinality, no LowCardinality)
    tid             UInt32,           -- Thread ID (high cardinality, no LowCardinality)
    comm            LowCardinality(String),
    syscall_name    LowCardinality(String),
    trace_id        UInt32,
    event_type      UInt8,            -- ENTER_OPEN_EVENT, EXIT_OPEN_EVENT, etc.
    
    -- Result
    ret_value       Int64,            -- Syscall return value
    ret_type        UInt32,           -- Return type classification
    
    -- File information
    fd              Int32,
    filename        String,
    pathname        String,
    oldname         String,
    newname         String,
    
    -- Flags and metadata
    flags           Int32,
    
    -- Calculated fields (from event.Pair)
    duration_ns     UInt64,           -- Duration of syscall
    duration_to_prev_ns UInt64,       -- Time since previous syscall
    
    -- Additional context
    hostname        LowCardinality(String),
    collection_id   UUID,             -- Groups events from same collection run
    ingested_at     DateTime64(3) DEFAULT now64(3),

    -- Secondary indices for high-cardinality fields
    INDEX idx_pid pid TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_tid tid TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(fromUnixTimestamp64Nano(timestamp_ns))
ORDER BY (timestamp_ns, pid, tid)
SETTINGS index_granularity = 8192;
```

**Cardinality Considerations:**
| Field | Cardinality | Encoding | Reason |
|-------|-------------|----------|--------|
| `pid` | High (thousands) | Plain UInt32 | PIDs can range into thousands per server; bloom filter index for point lookups |
| `tid` | Very High (tens of thousands) | Plain UInt32 | TIDs are numerous in threaded workloads; bloom filter index for point lookups |
| `comm` | Low (hundreds) | LowCardinality | Limited number of unique process names |
| `syscall_name` | Very Low (~100) | LowCardinality | Fixed set of syscalls |
| `hostname` | Very Low | LowCardinality | Usually single host per collection |
| `filename` | Medium-High | Plain String | Depends on workload; could use token bloom filter |

**Optimization Notes:**
- **Bloom filter indices** on `pid` and `tid` enable efficient point lookups on these high-cardinality fields without bloating storage
- `LowCardinality` only for truly low-cardinality fields (`comm`, `syscall_name`, `hostname`)
- Partitioning by day for efficient time-based queries and TTL
- Ordering by `(timestamp_ns, pid, tid)` for time-range queries and per-process/thread analysis
- `collection_id` UUID to group events from the same tracing session

### 1.4 Implementation Details

#### 1.4.1 Configuration (`internal/clickhouse/config.go`)

```go
package clickhouse

type Config struct {
    Host         string        // ClickHouse host (default: localhost)
    Port         int           // ClickHouse port (default: 9000)
    Database     string        // Database name (default: ior)
    Table        string        // Table name (default: ior_events)
    User         string        // Username
    Password     string        // Password
    BatchSize    int           // Events per batch (default: 10000)
    FlushTimeout time.Duration // Max time before flush (default: 1s)
    MaxOpenConns int           // Connection pool size (default: 4)
    Async        bool          // Enable async inserts (default: true for high throughput)
}

func DefaultConfig() Config {
    return Config{
        Host:         "localhost",
        Port:         9000,
        Database:     "ior",
        Table:        "ior_events",
        BatchSize:    10000,
        FlushTimeout: time.Second,
        MaxOpenConns: 4,
        Async:        true,
    }
}

func ConfigFromFlags() Config {
    // Read from command-line flags
}
```

#### 1.4.2 Client (`internal/clickhouse/client.go`)

```go
package clickhouse

import (
    "context"
    "github.com/ClickHouse/clickhouse-go/v2"
    "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

type Client struct {
    conn   driver.Conn
    config Config
}

func NewClient(ctx context.Context, config Config) (*Client, error) {
    conn, err := clickhouse.Open(&clickhouse.Options{
        Addr: []string{fmt.Sprintf("%s:%d", config.Host, config.Port)},
        Auth: clickhouse.Auth{
            Database: config.Database,
            Username: config.User,
            Password: config.Password,
        },
        MaxOpenConns:   config.MaxOpenConns,
        MaxIdleConns:   config.MaxOpenConns,
        ConnMaxLifetime: time.Hour,
        DialTimeout:    time.Second * 10,
        Settings: clickhouse.Settings{
            "max_execution_time": 60,
        },
        Compression: &clickhouse.Compression{
            Method: clickhouse.CompressionLZ4,
        },
        BlockBufferSize: 10,
    })
    if err != nil {
        return nil, err
    }
    return &Client{conn: conn, config: config}, nil
}

func (c *Client) Close() error {
    return c.conn.Close()
}
```

#### 1.4.3 Batch Writer (`internal/clickhouse/writer.go`)

Key design for 100K-1M events/sec:
- **Double buffering**: While one buffer is being sent, the other is being filled
- **Sync.Pool for event rows**: Reduce GC pressure
- **Async inserts**: ClickHouse async mode for lower latency
- **Connection pooling**: Multiple connections for parallel inserts

```go
package clickhouse

import (
    "context"
    "sync"
    "time"
    
    "ior/internal/event"
)

type EventRow struct {
    TimestampNs     uint64
    Pid             uint32
    Tid             uint32
    Comm            string
    SyscallName     string
    TraceId         uint32
    EventType       uint8
    RetValue        int64
    RetType         uint32
    Fd              int32
    Filename        string
    Pathname        string
    Oldname         string
    Newname         string
    Flags           int32
    DurationNs      uint64
    DurationToPrev  uint64
    Hostname        string
    CollectionId    string
}

type Writer struct {
    client       *Client
    config       Config
    
    bufferMu     sync.Mutex
    buffer       []*EventRow
    bufferSize   int
    
    flushTimer   *time.Timer
    flushCh      chan struct{}
    
    ctx          context.Context
    cancel       context.CancelFunc
    wg           sync.WaitGroup
    
    pool         sync.Pool
}

func NewWriter(ctx context.Context, client *Client, config Config) *Writer {
    ctx, cancel := context.WithCancel(ctx)
    w := &Writer{
        client:     client,
        config:     config,
        buffer:     make([]*EventRow, 0, config.BatchSize),
        flushCh:    make(chan struct{}, 1),
        ctx:        ctx,
        cancel:     cancel,
        pool: sync.Pool{
            New: func() interface{} { return &EventRow{} },
        },
    }
    w.flushTimer = time.AfterFunc(config.FlushTimeout, w.triggerFlush)
    go w.flushLoop()
    return w
}

func (w *Writer) Write(ep *event.Pair) error {
    row := w.pool.Get().(*EventRow)
    w.populateRow(row, ep)
    
    w.bufferMu.Lock()
    w.buffer = append(w.buffer, row)
    shouldFlush := len(w.buffer) >= w.config.BatchSize
    w.bufferMu.Unlock()
    
    if shouldFlush {
        w.triggerFlush()
    }
    return nil
}

func (w *Writer) triggerFlush() {
    select {
    case w.flushCh <- struct{}{}:
    default:
    }
}

func (w *Writer) flushLoop() {
    for {
        select {
        case <-w.flushCh:
            w.flush()
        case <-w.ctx.Done():
            w.flush()
            return
        }
    }
}

func (w *Writer) flush() {
    w.bufferMu.Lock()
    if len(w.buffer) == 0 {
        w.bufferMu.Unlock()
        return
    }
    buffer := w.buffer
    w.buffer = make([]*EventRow, 0, w.config.BatchSize)
    w.bufferMu.Unlock()
    
    ctx := clickhouse.Context(w.ctx, clickhouse.WithSettings(clickhouse.Settings{
        "async_insert":          1,
        "wait_for_async_insert": 0,
    }))
    
    batch, err := w.client.conn.PrepareBatch(ctx, 
        "INSERT INTO ior_events (timestamp_ns, pid, tid, comm, syscall_name, ...)")
    if err != nil {
        return
    }
    
    for _, row := range buffer {
        batch.Append(
            row.TimestampNs, row.Pid, row.Tid, row.Comm,
            row.SyscallName, row.TraceId, row.EventType,
            row.RetValue, row.RetType, row.Fd, row.Filename,
            row.Pathname, row.Oldname, row.Newname, row.Flags,
            row.DurationNs, row.DurationToPrev, row.Hostname,
            row.CollectionId,
        )
        w.pool.Put(row)
    }
    
    batch.Send()
}

func (w *Writer) Close() {
    w.cancel()
    w.wg.Wait()
    w.flushTimer.Stop()
}
```

#### 1.4.4 Schema Management (`internal/clickhouse/schema.go`)

```go
package clickhouse

func (c *Client) CreateTableIfNotExists(ctx context.Context) error {
    ddl := `CREATE TABLE IF NOT EXISTS ior_events (...)`
    return c.conn.Exec(ctx, ddl)
}
```

### 1.5 Integration with Event Loop

Modify `internal/eventloop.go`:

```go
func (e *eventLoop) run(ctx context.Context, rawCh <-chan []byte) {
    var chWriter *clickhouse.Writer
    if flags.Get().ClickHouseEnable {
        chClient, err := clickhouse.NewClient(ctx, clickhouse.ConfigFromFlags())
        if err != nil {
            panic(err)
        }
        defer chClient.Close()
        chWriter = clickhouse.NewWriter(ctx, chClient, clickhouse.ConfigFromFlags())
        defer chWriter.Close()
    }
    
    for ep := range e.events(ctx, rawCh) {
        switch {
        case flags.Get().ClickHouseEnable:
            chWriter.Write(ep)
            ep.Recycle()
        case flags.Get().FlamegraphEnable:
            e.flamegraph.Ch <- ep
        // ... rest
        }
    }
}
```

### 1.6 New Command-Line Flags

Add to `internal/flags/flags.go`:

```go
type Flags struct {
    // ... existing fields ...
    
    // ClickHouse streaming
    ClickHouseEnable   bool
    ClickHouseHost     string
    ClickHousePort     int
    ClickHouseDatabase string
    ClickHouseTable    string
    ClickHouseUser     string
    ClickHouseBatchSize int
    ClickHouseAsync    bool
}

func parse() {
    // ... existing flags ...
    
    flag.BoolVar(&singleton.ClickHouseEnable, "clickhouse", false, 
        "Enable ClickHouse streaming output")
    flag.StringVar(&singleton.ClickHouseHost, "ch-host", "localhost", 
        "ClickHouse host")
    flag.IntVar(&singleton.ClickHousePort, "ch-port", 9000, 
        "ClickHouse native port")
    flag.StringVar(&singleton.ClickHouseDatabase, "ch-db", "ior", 
        "ClickHouse database")
    flag.StringVar(&singleton.ClickHouseTable, "ch-table", "ior_events", 
        "ClickHouse table")
    flag.StringVar(&singleton.ClickHouseUser, "ch-user", "", 
        "ClickHouse user")
    flag.IntVar(&singleton.ClickHouseBatchSize, "ch-batch", 10000, 
        "ClickHouse batch size")
}
```

---

## Part 2: Parquet File Export

### 2.1 Dependencies

Add to `go.mod`:
```go
require (
    github.com/parquet-go/parquet-go v0.23.0
)
```

### 2.2 New Package Structure

```
internal/
├── parquet/
│   ├── writer.go        # Parquet file writer
│   ├── schema.go        # Parquet schema definition
│   └── writer_test.go   # Unit tests
```

### 2.3 Parquet Schema

```go
package parquet

import "github.com/parquet-go/parquet-go"

type EventRow struct {
    TimestampNs     uint64 `parquet:"timestamp_ns"`
    Pid             uint32 `parquet:"pid"`
    Tid             uint32 `parquet:"tid"`
    Comm            string `parquet:"comm,dict"`
    SyscallName     string `parquet:"syscall_name,dict"`
    TraceId         uint32 `parquet:"trace_id"`
    EventType       uint8  `parquet:"event_type"`
    RetValue        int64  `parquet:"ret_value"`
    RetType         uint32 `parquet:"ret_type"`
    Fd              int32  `parquet:"fd"`
    Filename        string `parquet:"filename"`
    Pathname        string `parquet:"pathname"`
    Oldname         string `parquet:"oldname"`
    Newname         string `parquet:"newname"`
    Flags           int32  `parquet:"flags"`
    DurationNs      uint64 `parquet:"duration_ns"`
    DurationToPrev  uint64 `parquet:"duration_to_prev_ns"`
    Hostname        string `parquet:"hostname,dict"`
    CollectionId    string `parquet:"collection_id"`
}
```

**Parquet Optimizations:**
- `dict` encoding for low-cardinality strings (`comm`, `syscall_name`, `hostname`)
- Zstd compression (same as current GOB files)
- Row groups of ~128MB for efficient querying
- Column pruning - ClickHouse only reads needed columns

### 2.4 Implementation

#### 2.4.1 Writer (`internal/parquet/writer.go`)

```go
package parquet

import (
    "context"
    "fmt"
    "os"
    "sync"
    "time"
    
    "github.com/parquet-go/parquet-go"
    "github.com/parquet-go/parquet-go/compress/zstd"
    "ior/internal/event"
)

type Writer struct {
    file       *os.File
    writer     *parquet.GenericWriter[EventRow]
    
    bufferMu   sync.Mutex
    buffer     []EventRow
    bufferSize int
    
    rowGroupSize int
    
    ctx    context.Context
    cancel context.CancelFunc
}

type WriterConfig struct {
    Filename      string
    BatchSize     int
    RowGroupSize  int
    Compression   parquet.Compression
}

func DefaultWriterConfig() WriterConfig {
    hostname, _ := os.Hostname()
    return WriterConfig{
        Filename:     fmt.Sprintf("%s-%s.parquet", hostname, time.Now().Format("2006-01-02_15:04:05")),
        BatchSize:    10000,
        RowGroupSize: 100000,
        Compression:  parquet.Zstd,
    }
}

func NewWriter(ctx context.Context, config WriterConfig) (*Writer, error) {
    file, err := os.Create(config.Filename)
    if err != nil {
        return nil, err
    }
    
    writer := parquet.NewGenericWriter[EventRow](file,
        parquet.Compression(&zstd.Codec{Level: zstd.DefaultLevel}),
        parquet.RowGroupSize(config.RowGroupSize),
    )
    
    ctx, cancel := context.WithCancel(ctx)
    return &Writer{
        file:         file,
        writer:       writer,
        buffer:       make([]EventRow, 0, config.BatchSize),
        bufferSize:   config.BatchSize,
        rowGroupSize: config.RowGroupSize,
        ctx:          ctx,
        cancel:       cancel,
    }, nil
}

func (w *Writer) Write(ep *event.Pair) error {
    row := EventRow{
        TimestampNs:    ep.EnterEv.GetTime(),
        Pid:           ep.EnterEv.GetPid(),
        Tid:           ep.EnterEv.GetTid(),
        Comm:          ep.Comm,
        SyscallName:   ep.EnterEv.GetTraceId().Name(),
        DurationNs:     ep.Duration,
        DurationToPrev: ep.DurationToPrev,
    }
    
    w.bufferMu.Lock()
    w.buffer = append(w.buffer, row)
    shouldFlush := len(w.buffer) >= w.bufferSize
    w.bufferMu.Unlock()
    
    if shouldFlush {
        return w.flush()
    }
    return nil
}

func (w *Writer) flush() error {
    w.bufferMu.Lock()
    defer w.bufferMu.Unlock()
    
    if len(w.buffer) == 0 {
        return nil
    }
    
    _, err := w.writer.Write(w.buffer)
    w.buffer = w.buffer[:0]
    return err
}

func (w *Writer) Close() error {
    w.cancel()
    if err := w.flush(); err != nil {
        return err
    }
    if err := w.writer.Close(); err != nil {
        return err
    }
    return w.file.Close()
}
```

### 2.5 ClickHouse Import Command

After generating a Parquet file:

```bash
# Local file import
clickhouse-client --query "
  INSERT INTO ior.ior_events 
  FROM INFILE 'hostname-2024-01-15_10:30:00.parquet' 
  FORMAT Parquet"

# Or via HTTP (remote server)
curl -X POST 'http://clickhouse:8123/?query=INSERT+INTO+ior.ior_events+FORMAT+Parquet' \
  --data-binary @hostname-2024-01-15_10:30:00.parquet
```

### 2.6 New Command-Line Flags

Add to `internal/flags/flags.go`:

```go
// Parquet file output
ParquetEnable    bool
ParquetFilename  string
ParquetBatchSize int
ParquetRowGroupSize int
```

---

## Part 3: Shared Components

### 3.1 Event-to-Row Converter

Both ClickHouse and Parquet need to convert `event.Pair` to a row format:

```go
// internal/export/convert.go

package export

import (
    "ior/internal/event"
    "ior/internal/types"
)

type EventRow struct {
    TimestampNs     uint64
    Pid             uint32
    Tid             uint32
    Comm            string
    SyscallName     string
    TraceId         uint32
    EventType       uint8
    RetValue        int64
    RetType         uint32
    Fd              int32
    Filename        string
    Pathname        string
    Oldname         string
    Newname         string
    Flags           int32
    DurationNs      uint64
    DurationToPrev  uint64
    Hostname        string
    CollectionId    string
}

func PairToRow(ep *event.Pair, hostname, collectionId string) EventRow {
    row := EventRow{
        TimestampNs:    ep.EnterEv.GetTime(),
        Pid:           ep.EnterEv.GetPid(),
        Tid:           ep.EnterEv.GetTid(),
        Comm:          ep.Comm,
        SyscallName:   ep.EnterEv.GetTraceId().Name(),
        TraceId:       uint32(ep.EnterEv.GetTraceId()),
        DurationNs:     ep.Duration,
        DurationToPrev: ep.DurationToPrev,
        Hostname:      hostname,
        CollectionId:  collectionId,
    }
    
    switch enter := ep.EnterEv.(type) {
    case *types.OpenEvent:
        row.EventType = types.ENTER_OPEN_EVENT
        row.Filename = types.StringValue(enter.Filename[:])
        row.Flags = enter.Flags
    case *types.FdEvent:
        row.EventType = types.ENTER_FD_EVENT
        row.Fd = enter.Fd
    }
    
    if ret, ok := ep.ExitEv.(*types.RetEvent); ok {
        row.RetValue = ret.Ret
        row.RetType = ret.RetType
    }
    
    return row
}
```

### 3.2 Output Mode Selector

```go
// internal/output/output.go

package output

type Output interface {
    Write(ep *event.Pair) error
    Close() error
}

func NewOutput(ctx context.Context, flags flags.Flags) (Output, error) {
    switch {
    case flags.ClickHouseEnable:
        return clickhouse.NewWriter(ctx, ...)
    case flags.ParquetEnable:
        return parquet.NewWriter(ctx, ...)
    case flags.FlamegraphEnable:
        return flamegraph.NewCollector(ctx, ...)
    default:
        return &consoleOutput{}, nil
    }
}
```

---

## Part 4: Performance Considerations

### 4.1 Throughput Targets: 100K-1M events/sec

| Component | Strategy |
|-----------|----------|
| **Memory** | `sync.Pool` for EventRow reuse, avoid allocations in hot path |
| **Buffering** | Double buffering: fill one buffer while sending another |
| **Batching** | Batch inserts: 10K-100K rows per batch |
| **Compression** | LZ4 for streaming (fast), Zstd for files (compact) |
| **Concurrency** | Multiple writer goroutines with separate connections |
| **Backpressure** | Drop events if buffer full (configurable), report stats |

### 4.2 Memory Budget

For 1M events/sec with 10KB per event row:
- Raw: 10GB/sec (too high)
- With batching and buffering: ~100MB buffer is sufficient

Buffer sizing:
- 100K events × ~200 bytes per row = ~20MB per buffer
- Double buffering = ~40MB total

### 4.3 ClickHouse Server-Side Settings

```sql
SET max_insert_block_size = 1048576;
SET max_block_size = 65536;
SET async_insert_max_data_size = 10000000;
SET async_insert_busy_timeout_ms = 1000;
```

---

## Part 5: Testing Strategy

### 5.1 Unit Tests

```
internal/clickhouse/
├── client_test.go      # Mock server tests
├── writer_test.go      # Buffer management, batch logic
└── schema_test.go      # DDL generation

internal/parquet/
├── writer_test.go      # File writing, schema validation
└── convert_test.go     # Event to row conversion
```

### 5.2 Integration Tests

```bash
docker run -d --name clickhouse -p 9000:9000 clickhouse/clickhouse-server
make test-integration-clickhouse
make test-integration-parquet
```

### 5.3 Benchmark Tests

```go
// internal/bench_test.go
func BenchmarkClickHouseWriter(b *testing.B) {}

func BenchmarkParquetWriter(b *testing.B) {}
```

---

## Part 6: Implementation Order

### Phase 1: Foundation
1. Add dependencies to `go.mod`
2. Create `internal/export/convert.go` - shared row conversion
3. Create `internal/output/output.go` - output interface

### Phase 2: Parquet Export
1. Create `internal/parquet/` package
2. Add parquet flags to `internal/flags/`
3. Integrate with `internal/eventloop.go`
4. Add unit tests
5. Test ClickHouse import

### Phase 3: ClickHouse Streaming
1. Create `internal/clickhouse/` package
2. Add ClickHouse flags to `internal/flags/`
3. Implement double-buffering writer
4. Integrate with `internal/eventloop.go`
5. Add unit tests and integration tests

### Phase 4: Polish
1. Performance benchmarks and optimization
2. Documentation
3. Error handling and recovery
4. Metrics/monitoring integration

---

## Part 7: Usage Examples

### Parquet Export

```bash
# Capture to Parquet file
ior -parquet -name my_trace -duration 60

# Import to ClickHouse
clickhouse-client --query "
  INSERT INTO ior.ior_events 
  FROM INFILE 'myhost-2024-01-15_10:30:00.parquet' 
  FORMAT Parquet"
```

### Real-time Streaming

```bash
# Stream to ClickHouse
ior -clickhouse -ch-host ch-server.example.com -ch-db ior -duration 300

# With authentication
ior -clickhouse -ch-host ch.example.com -ch-user app -ch-password secret
```

### Query Examples

```sql
-- Top 10 slowest syscalls by average duration
SELECT 
    syscall_name,
    count() as total,
    avg(duration_ns) as avg_duration,
    quantile(0.99)(duration_ns) as p99_duration
FROM ior_events
WHERE timestamp_ns > now() - INTERVAL 1 HOUR
GROUP BY syscall_name
ORDER BY avg_duration DESC
LIMIT 10;

-- Events per process
SELECT 
    pid,
    comm,
    count() as total_events,
    sum(duration_ns) / 1e9 as total_duration_sec
FROM ior_events
WHERE collection_id = 'uuid-here'
GROUP BY pid, comm
ORDER BY total_events DESC;

-- Per-thread I/O activity (leverages bloom filter on tid)
SELECT 
    pid,
    tid,
    comm,
    count() as total_events,
    sum(duration_ns) / 1e9 as total_duration_sec,
    uniqExact(syscall_name) as unique_syscalls
FROM ior_events
WHERE collection_id = 'uuid-here'
GROUP BY pid, tid, comm
ORDER BY total_events DESC
LIMIT 50;

-- Thread with most I/O latency (bloom filter helps for specific tid lookup)
SELECT 
    pid, tid, comm,
    sum(duration_ns) / 1e6 as total_latency_ms,
    avg(duration_ns) as avg_latency_ns,
    count() as event_count
FROM ior_events
WHERE tid = 12345  -- bloom filter index used here
  AND collection_id = 'uuid-here'
GROUP BY pid, tid, comm;

-- Most accessed files
SELECT 
    filename,
    count() as access_count,
    sum(duration_ns) / 1e9 as total_duration_sec
FROM ior_events
WHERE filename != ''
GROUP BY filename
ORDER BY access_count DESC
LIMIT 20;
```

---

## Appendix A: File Sizes Estimation

For 1M events:
| Format | Size (estimated) |
|--------|------------------|
| GOB + zstd (current) | ~50-80 MB |
| Parquet + zstd | ~40-60 MB |
| RowBinary | ~60-80 MB |
| JSON (not recommended) | ~200-300 MB |

---

## Appendix C: ClickHouse Optimization Strategies

### C.1 High Cardinality Optimization

**Problem**: Fields like `tid` (thread ID) can have tens of thousands of unique values, making standard indexing inefficient.

| Technique | Description | Best For |
|-----------|-------------|----------|
| **Bloom Filter Index** | Probabilistic index for point lookups (~1% storage overhead) | `WHERE tid = 12345` |
| **Minmax Index** | Stores min/max values per granule | Range queries on numeric fields |
| **Set Index** | Stores unique values per granule (limited to ~N values) | Low-medium cardinality |
| **Token Bloom Filter** | Bloom filter on tokens in string | `WHERE hasToken(filename, 'log')` |

```sql
-- Bloom filter for point lookups on high-cardinality fields
INDEX idx_tid tid TYPE bloom_filter(0.01) GRANULARITY 4,
INDEX idx_pid pid TYPE bloom_filter(0.01) GRANULARITY 4,

-- Minmax for range queries on timestamps (already default, but explicit)
INDEX idx_duration duration_ns TYPE minmax GRANULARITY 1,

-- Token bloom filter for filename substring searches
INDEX idx_filename_tokens filename TYPE tokenbf_v1(512, 3, 0) GRANULARITY 4
```

**Bloom Filter Parameters**:
- `0.01` = 1% false positive rate (lower = more accurate, larger index)
- `GRANULARITY 4` = index covers 4 granules (8192 × 4 = 32768 rows)

#### C.1.1 Are Bloom Filter Results Inexact?

**No - query results are ALWAYS exact.** Bloom filters only affect performance, not correctness.

```
How Bloom Filter Indices Work:
+---------------------------------------------------------------+
| QUERY: SELECT * FROM ior_events WHERE tid = 12345             |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
| STEP 1: Check bloom filter index for each granule             |
|                                                               |
| Granule 1 (rows 1-8192):     Bloom says "MAYBE" -> READ IT    |
| Granule 2 (rows 8193-16384): Bloom says "DEFINITELY NOT"      |
|                              -> SKIP                          |
| Granule 3 (rows 16385-24576): Bloom says "MAYBE" -> READ IT   |
| ...                                                           |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
| STEP 2: Read the "MAYBE" granules and filter EXACTLY          |
|                                                               |
| Result: ALL rows where tid = 12345 (no false positives)       |
+---------------------------------------------------------------+
```

**False Positive Impact**: The bloom filter might say "MAYBE contains tid=12345" for a granule that doesn't actually have it. This causes ClickHouse to read that granule unnecessarily - wasting I/O but NOT affecting result correctness.

**False Negatives**: Impossible. Bloom filters never produce false negatives. If the value exists, the bloom filter will always say "MAYBE".

**Trade-off**:
| Bloom Filter Size | False Positive Rate | Storage Overhead | Unnecessary Reads |
|-------------------|---------------------|------------------|-------------------|
| Smaller | Higher (~5%) | ~0.5% | More wasted I/O |
| Larger | Lower (~0.01%) | ~2% | Less wasted I/O |

**Recommendation**: Use `bloom_filter(0.01)` for 1% false positive rate - good balance between index size and read efficiency.

#### C.1.2 Projections vs Materialized Views

Both optimize query performance, but work differently:

| Aspect | Projection | Materialized View |
|--------|------------|-------------------|
| **Data storage** | Same table, different physical order | Separate table |
| **Automatic sync** | Yes - part of the same table | Yes - triggered on INSERT |
| **Query rewrite** | Automatic - ClickHouse picks best projection | Must query MV explicitly |
| **Aggregation** | Can pre-aggregate | Often used for aggregation |
| **Space overhead** | Copies ALL columns (unless aggregated) | Only stores aggregated result |
| **Best for** | Different sort orders, same columns | Pre-computed aggregations |

---

### C.1.3 Projections Explained

**What is a Projection?**

A projection is an alternative physical representation of the SAME data within the SAME table. Think of it as "same data, sorted differently for different queries."

**Example Problem**: Your main table is ordered by `(timestamp_ns, pid, tid)` for time-range queries. But you also need fast queries by thread:

```sql
-- This query is SLOW because tid is last in ORDER BY
SELECT * FROM ior_events WHERE tid = 12345;
-- Must scan almost all data!
```

**Solution - Add a Projection**:

```sql
CREATE TABLE ior_events (
    timestamp_ns UInt64,
    pid UInt32,
    tid UInt32,
    comm String,
    syscall_name String,
    duration_ns UInt64,
    -- ... other columns ...
)
ENGINE = MergeTree()
ORDER BY (timestamp_ns, pid, tid)  -- Primary order: time-first
PARTITION BY toYYYYMMDD(fromUnixTimestamp64Nano(timestamp_ns));

-- Add projection for thread-centric queries
ALTER TABLE ior_events ADD PROJECTION proj_by_thread (
    SELECT * ORDER BY (pid, tid, timestamp_ns)
);

-- Materialize the projection (build it for existing data)
ALTER TABLE ior_events MATERIALIZE PROJECTION proj_by_thread;
```

**How it works**:

```
INSERT INTO ior_events VALUES (1000, 1, 100, 'app', 'read', 50);
INSERT INTO ior_events VALUES (2000, 1, 100, 'app', 'write', 30);
INSERT INTO ior_events VALUES (1500, 2, 200, 'db', 'read', 40);

Main storage (ORDER BY timestamp_ns, pid, tid):
+--------------+-----+-----+------+-------------+-------------+
| timestamp_ns | pid | tid | comm | syscall_name| duration_ns |
+--------------+-----+-----+------+-------------+-------------+
| 1000         | 1   | 100 | app  | read        | 50          |
| 1500         | 2   | 200 | db   | read        | 40          |
| 2000         | 1   | 100 | app  | write       | 30          |
+--------------+-----+-----+------+-------------+-------------+

Projection proj_by_thread (ORDER BY pid, tid, timestamp_ns):
+--------------+-----+-----+------+-------------+-------------+
| timestamp_ns | pid | tid | comm | syscall_name| duration_ns |
+--------------+-----+-----+------+-------------+-------------+
| 1000         | 1   | 100 | app  | read        | 50          |
| 2000         | 1   | 100 | app  | write       | 30          |
| 1500         | 2   | 200 | db   | read        | 40          |
+--------------+-----+-----+------+-------------+-------------+
```

**Query optimization**:

```sql
-- Query 1: Time range - uses main storage
SELECT * FROM ior_events 
WHERE timestamp_ns BETWEEN 1000 AND 1800;
-- Reads rows in order: (1000,1,100), (1500,2,200) - efficient!

-- Query 2: Thread lookup - uses projection AUTOMATICALLY
SELECT * FROM ior_events WHERE tid = 100;
-- ClickHouse sees projection has better ORDER BY for this query
-- Uses proj_by_thread: rows (1,100,1000), (1,100,2000) are adjacent!
```

**Aggregating Projection** (smaller storage):

```sql
-- Pre-aggregated projection - stores only aggregated data
ALTER TABLE ior_events ADD PROJECTION proj_hourly_stats (
    SELECT 
        toStartOfHour(fromUnixTimestamp64Nano(timestamp_ns)) as hour,
        syscall_name,
        count() as event_count,
        sum(duration_ns) as total_duration,
        avg(duration_ns) as avg_duration
    GROUP BY hour, syscall_name
);

ALTER TABLE ior_events MATERIALIZE PROJECTION proj_hourly_stats;
```

**Storage comparison**:
```
Main table:        1,000,000,000 rows × ~200 bytes = ~200 GB
proj_by_thread:    1,000,000,000 rows × ~200 bytes = ~200 GB (full copy)
proj_hourly_stats: ~100,000 rows × ~50 bytes = ~5 MB (aggregated!)
```

**When to use projections**:
- Different access patterns on the same raw data
- Query patterns known upfront
- Can afford storage overhead (projections copy data)

---

### C.1.4 Materialized Views Explained

**What is a Materialized View?**

A materialized view is a SEPARATE table that is automatically populated and maintained when data is inserted into the source table.

**Example Problem**: You frequently query per-thread statistics:

```sql
-- This is slow - scans billions of rows every time
SELECT pid, tid, comm, count(), sum(duration_ns)
FROM ior_events
WHERE timestamp_ns > now() - INTERVAL 1 HOUR
GROUP BY pid, tid, comm;
```

**Solution - Create a Materialized View**:

```sql
-- Step 1: Create the target table (stores the aggregated data)
CREATE TABLE ior_thread_stats (
    day Date,
    hour DateTime,
    pid UInt32,
    tid UInt32,
    comm LowCardinality(String),
    syscall_name LowCardinality(String),
    event_count UInt64,
    total_duration_ns UInt64
)
ENGINE = SummingMergeTree()  -- Automatically sums duplicates
PARTITION BY day
ORDER BY (day, hour, pid, tid, syscall_name);

-- Step 2: Create the materialized view (transforms INSERTs)
CREATE MATERIALIZED VIEW ior_thread_stats_mv TO ior_thread_stats AS
SELECT
    toDate(fromUnixTimestamp64Nano(timestamp_ns)) as day,
    toStartOfHour(fromUnixTimestamp64Nano(timestamp_ns)) as hour,
    pid,
    tid,
    comm,
    syscall_name,
    count() as event_count,
    sum(duration_ns) as total_duration_ns
FROM ior_events
GROUP BY day, hour, pid, tid, comm, syscall_name;
```

**How it works**:

```
INSERT INTO ior_events (timestamp_ns, pid, tid, comm, syscall_name, duration_ns, ...)
VALUES (1704067200000000000, 1, 100, 'app', 'read', 50, ...);

                              |
                              v
+---------------------------------------------------------------+
| ior_events (main table)                                       |
| Receives the full row                                         |
+---------------------------------------------------------------+
                              |
                              | TRIGGER: materialized view
                              v
+---------------------------------------------------------------+
| ior_thread_stats_mv transformation                            |
| Groups and aggregates:                                        |
|   day=2024-01-01, hour=2024-01-01 00:00:00                    |
|   pid=1, tid=100, comm='app', syscall_name='read'             |
|   event_count=1, total_duration_ns=50                         |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
| ior_thread_stats (target table)                               |
| Stores only the aggregated row                                |
+---------------------------------------------------------------+
```

**Query the materialized view**:

```sql
-- Query the aggregated table (MUCH faster!)
SELECT 
    pid, tid, comm,
    sum(event_count) as total_events,
    sum(total_duration_ns) / 1e9 as total_seconds
FROM ior_thread_stats
WHERE day = today() AND hour > now() - INTERVAL 6 HOUR
GROUP BY pid, tid, comm
ORDER BY total_events DESC
LIMIT 10;
```

**Real-time aggregation example**:

```sql
-- Per-minute syscall latency tracking
CREATE TABLE ior_latency_minute (
    minute DateTime,
    syscall_name LowCardinality(String),
    p50_ns UInt64,
    p90_ns UInt64,
    p99_ns UInt64,
    count UInt64
)
ENGINE = SummingMergeTree()
ORDER BY (minute, syscall_name);

-- Materialized view with quantile aggregation
CREATE MATERIALIZED VIEW ior_latency_minute_mv TO ior_latency_minute AS
SELECT
    toStartOfMinute(fromUnixTimestamp64Nano(timestamp_ns)) as minute,
    syscall_name,
    quantile(0.50)(duration_ns) as p50_ns,
    quantile(0.90)(duration_ns) as p90_ns,
    quantile(0.99)(duration_ns) as p99_ns,
    count() as count
FROM ior_events
GROUP BY minute, syscall_name;

-- Query for real-time monitoring
SELECT minute, syscall_name, p99_ns / 1e6 as p99_ms, count
FROM ior_latency_minute
WHERE minute > now() - INTERVAL 1 HOUR
ORDER BY minute, p99_ns DESC;
```

**When to use materialized views**:
- Pre-computed aggregations (counts, sums, quantiles)
- Different granularity (hourly, daily summaries)
- Dashboards and real-time monitoring
- When you can afford slight delay (async update)

**Important considerations**:
```sql
-- MVs are populated only for NEW data, not historical
-- To backfill existing data:
INSERT INTO ior_thread_stats
SELECT ... FROM ior_events WHERE ... GROUP BY ...;

-- MVs can be chained (MV feeding another MV)
-- MVs can be suspended/resumed:
SYSTEM STOP MERGES ior_thread_stats;
SYSTEM START MERGES ior_thread_stats;
```

---

### C.1.5 Comparison Summary

```
PROJECTION: Same table, different order
+--------------------------------------------------------------+
| ior_events (main table)                                      |
| ORDER BY (timestamp_ns, pid, tid)                            |
| +-- Part 1: [rows sorted by time...]                         |
| +-- Part 2: [rows sorted by time...]                         |
+--------------------------------------------------------------+
        |
        +-- PROJECTION proj_by_thread
            +--------------------------------------------------+
            | Same data, ORDER BY (pid, tid, timestamp_ns)    |
            | +-- Part 1: [rows sorted by thread...]           |
            | +-- Part 2: [rows sorted by thread...]           |
            +--------------------------------------------------+

MATERIALIZED VIEW: Separate table, transformed data
+--------------------------------------------------------------+
| ior_events (source table)                                    |
| 1,000,000,000 rows x 200 bytes = 200 GB                     |
+--------------------------------------------------------------+
        |
        | INSERT triggers transformation
        v
+--------------------------------------------------------------+
| ior_thread_stats (target table)                              |
| 100,000 rows x 50 bytes = 5 MB                               |
| Aggregated: count, sum, avg per thread per hour              |
+--------------------------------------------------------------+
```

**Choose Projection when**:
- Need different sort orders for same raw data
- Query patterns vary (time-range vs thread-lookup)
- Storage overhead is acceptable

**Choose Materialized View when**:
- Need pre-aggregated results
- Query same aggregations repeatedly
- Want to reduce data volume significantly
- Building dashboards/monitoring

**Avoid for High Cardinality**:
- `LowCardinality()` - only for fields with <10k unique values
- First position in `ORDER BY` - kills compression

### C.2 Large Data Volume Optimization

**Problem**: Billions of rows, terabytes of data need efficient storage and query.

| Technique | Description | Impact |
|-----------|-------------|--------|
| **Partitioning** | Split data by time (day/month) | Faster deletes, pruning, TTL |
| **Compression Codecs** | ZSTD, LZ4, Delta, Gorilla | 5-10x storage reduction |
| **TTL** | Automatic data expiration | Storage management |
| **Projections** | Pre-computed alternative ORDER BY | Multiple query patterns |
| **Materialized Views** | Pre-aggregations | Faster analytics |

```sql
CREATE TABLE ior_events (
    -- ... columns ...
    
    -- Compression codecs per column type
    timestamp_ns    UInt64 CODEC(Delta, ZSTD(3)),
    pid             UInt32 CODEC(ZSTD(3)),
    tid             UInt32 CODEC(ZSTD(3)),
    comm            LowCardinality(String) CODEC(ZSTD(3)),
    syscall_name    LowCardinality(String) CODEC(ZSTD(3)),
    duration_ns     UInt64 CODEC(Delta, ZSTD(3)),
    filename        String CODEC(ZSTD(3)),
    
    -- Indices
    INDEX idx_tid tid TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_pid pid TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(fromUnixTimestamp64Nano(timestamp_ns))
ORDER BY (timestamp_ns, pid, tid)
TTL timestamp_ns + INTERVAL 30 DAY DELETE  -- Auto-delete after 30 days
SETTINGS 
    index_granularity = 8192,
    min_bytes_for_wide_part = '10M';  -- Compact parts until 10MB
```

**Compression Codec Selection**:

| Column Type | Recommended Codec | Reason |
|-------------|-------------------|--------|
| Timestamps | `Delta(8), ZSTD(3)` | Delta encoding + compression |
| IDs (pid, tid) | `ZSTD(3)` | General compression |
| Low-cardinality strings | `LowCardinality, ZSTD(3)` | Dictionary + compression |
| Durations | `Delta, ZSTD(3)` | Sequential values compress well |
| Filenames | `ZSTD(3)` or `ZSTD(1)` | High compression if CPU-bound |
| Flags/enums | `ZSTD(3)` | Small value range |

### C.3 Combined: High Cardinality + Large Data Volume

**The Challenge**: Billions of rows with high-cardinality fields (tid, filename) require both efficient storage AND fast point lookups.

**Strategy 1: Optimal ORDER BY**

```sql
-- Rule: Low cardinality first, high cardinality last
-- BAD: ORDER BY (tid, timestamp_ns)  -- Kills compression
-- GOOD: ORDER BY (timestamp_ns, pid, tid)  -- Time-based locality

ORDER BY (timestamp_ns, pid, tid)
```

This enables:
- Time-range queries: `WHERE timestamp_ns BETWEEN x AND y` (primary key efficiency)
- Per-process queries: `WHERE timestamp_ns BETWEEN x AND y AND pid = 123`
- Per-thread queries: `WHERE timestamp_ns BETWEEN x AND y AND pid = 123 AND tid = 456`

**Strategy 2: Projections for Different Access Patterns**

```sql
CREATE TABLE ior_events (
    -- ... columns ...
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(fromUnixTimestamp64Nano(timestamp_ns))
ORDER BY (timestamp_ns, pid, tid)

-- Projection 1: Thread-centric queries (fast tid lookup)
PROJECTION proj_by_thread
(
    SELECT *
    ORDER BY (pid, tid, timestamp_ns)
)

-- Projection 2: Syscall analytics (aggregation-heavy)
PROJECTION proj_by_syscall
(
    SELECT 
        syscall_name,
        toStartOfHour(fromUnixTimestamp64Nano(timestamp_ns)) as hour,
        pid,
        count() as event_count,
        sum(duration_ns) as total_duration,
        avg(duration_ns) as avg_duration,
        quantile(0.99)(duration_ns) as p99_duration
    GROUP BY syscall_name, hour, pid
)
;
```

**Strategy 3: Materialized Views for Pre-Aggregation**

```sql
-- Real-time per-thread stats (much smaller table)
CREATE MATERIALIZED VIEW ior_thread_stats_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (day, pid, tid, syscall_name)
AS SELECT
    toDate(fromUnixTimestamp64Nano(timestamp_ns)) as day,
    pid,
    tid,
    comm,
    syscall_name,
    count() as event_count,
    sum(duration_ns) as total_duration_ns
FROM ior_events
GROUP BY day, pid, tid, comm, syscall_name;

-- Query the materialized view instead (100-1000x faster)
SELECT pid, tid, sum(event_count), sum(total_duration_ns)/1e9 as sec
FROM ior_thread_stats_mv
WHERE day = today() AND tid = 12345
GROUP BY pid, tid;
```

**Strategy 4: Sampling for Exploratory Queries**

```sql
-- Sample 1% of data for quick exploration
SELECT syscall_name, count() as cnt, avg(duration_ns) as avg_dur
FROM ior_events
SAMPLE 0.01  -- Only scan 1% of rows
WHERE timestamp_ns > now() - INTERVAL 1 DAY
GROUP BY syscall_name
ORDER BY cnt DESC;
```

### C.4 Complete Optimized Schema

```sql
CREATE TABLE ior_events (
    -- Core fields
    timestamp_ns    UInt64 CODEC(Delta(8), ZSTD(3)),
    pid             UInt32 CODEC(ZSTD(3)),
    tid             UInt32 CODEC(ZSTD(3)),
    comm            LowCardinality(String) CODEC(ZSTD(3)),
    syscall_name    LowCardinality(String) CODEC(ZSTD(3)),
    trace_id        UInt16 CODEC(ZSTD(3)),
    event_type      UInt8 CODEC(T64, ZSTD(3)),
    
    -- Result
    ret_value       Int64 CODEC(ZSTD(3)),
    ret_type        UInt8 CODEC(T64, ZSTD(3)),
    
    -- File information
    fd              Int32 CODEC(ZSTD(3)),
    filename        String CODEC(ZSTD(3)),
    pathname        String CODEC(ZSTD(3)),
    oldname         String CODEC(ZSTD(3)),
    newname         String CODEC(ZSTD(3)),
    
    -- Flags
    flags           Int32 CODEC(ZSTD(3)),
    
    -- Calculated
    duration_ns     UInt64 CODEC(Delta, ZSTD(3)),
    duration_to_prev_ns UInt64 CODEC(Delta, ZSTD(3)),
    
    -- Context
    hostname        LowCardinality(String) CODEC(ZSTD(3)),
    collection_id   UUID CODEC(ZSTD(3)),
    ingested_at     DateTime64(3) DEFAULT now64(3) CODEC(Delta, ZSTD(3)),

    -- Data skipping indices
    INDEX idx_pid pid TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_tid tid TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_duration duration_ns TYPE minmax GRANULARITY 2,
    INDEX idx_syscall syscall_name TYPE set(100) GRANULARITY 4,
    INDEX idx_filename_token filename TYPE tokenbf_v1(256, 2, 0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(fromUnixTimestamp64Nano(timestamp_ns))
ORDER BY (timestamp_ns, pid, tid)
TTL timestamp_ns + INTERVAL 90 DAY DELETE
SETTINGS 
    index_granularity = 8192,
    min_bytes_for_wide_part = '10M',
    min_rows_for_wide_part = 100000;

-- Projections for different access patterns
ALTER TABLE ior_events ADD PROJECTION proj_by_pid_tid (
    SELECT * ORDER BY (pid, tid, timestamp_ns)
);

ALTER TABLE ior_events ADD PROJECTION proj_by_syscall_hour (
    SELECT 
        syscall_name,
        toStartOfHour(fromUnixTimestamp64Nano(timestamp_ns)) as hour,
        pid,
        count() as cnt,
        sum(duration_ns) as total_dur,
        avg(duration_ns) as avg_dur
    GROUP BY syscall_name, hour, pid
);

ALTER TABLE ior_events MATERIALIZE PROJECTION proj_by_pid_tid;
ALTER TABLE ior_events MATERIALIZE PROJECTION proj_by_syscall_hour;
```

### C.5 Query Optimization Tips

```sql
-- 1. Always include time range (partition pruning)
-- GOOD
SELECT * FROM ior_events 
WHERE timestamp_ns > now() - INTERVAL 1 HOUR AND tid = 12345;

-- BAD (scans all partitions)
SELECT * FROM ior_events WHERE tid = 12345;

-- 2. Use PREWHERE for filter pushdown on large columns
SELECT count() 
FROM ior_events
PREWHERE syscall_name = 'open'  -- Filter before reading other columns
WHERE timestamp_ns > now() - INTERVAL 1 HOUR;

-- 3. Leverage projections explicitly
SET allow_experimental_projection_optimization = 1;
SELECT syscall_name, sum(cnt) 
FROM ior_events 
WHERE timestamp_ns > now() - INTERVAL 1 DAY
GROUP BY syscall_name;  -- Will use proj_by_syscall_hour

-- 4. Use materialized views for frequent aggregations
SELECT * FROM ior_thread_stats_mv WHERE day = today();

-- 5. Parallel replica reads for large scans
SET max_parallel_replicas = 3;
SELECT count() FROM ior_events WHERE timestamp_ns > now() - INTERVAL 7 DAY;
```

### C.6 Storage Estimation

For 1 billion events (1 day at ~11.5K events/sec):

| Metric | Estimate |
|--------|----------|
| Raw row size | ~200 bytes |
| Uncompressed | ~200 GB |
| With ZSTD compression | ~30-50 GB |
| With projections | +20-30% additional |
| Bloom filter indices | +1-2% |
| Total storage per day | ~40-65 GB |

With 90-day TTL: ~3.6-6 TB total storage.

### C.7 Server Configuration

```xml
<!-- /etc/clickhouse-server/config.d/ior.xml -->
<clickhouse>
    <!-- For high-cardinality + large data -->
    <merge_tree>
        <index_granularity>8192</index_granularity>
        <min_bytes_for_wide_part>10485760</min_bytes_for_wide_part>
        <min_rows_for_wide_part>100000</min_rows_for_wide_part>
        <max_suspicious_broken_parts>5</max_suspicious_broken_parts>
    </merge_tree>
    
    <!-- Memory for queries -->
    <max_memory_usage>16000000000</max_memory_usage>  <!-- 16GB -->
    <max_memory_usage_for_all_queries>20000000000</max_memory_usage_for_all_queries>
    
    <!-- Insert performance -->
    <max_insert_block_size>1048576</max_insert_block_size>
    <min_insert_block_size_rows>100000</min_insert_block_size_rows>
    
    <!-- Background merges -->
    <background_pool_size>16</background_pool_size>
    <background_merges_mutations_concurrency_ratio>4</background_merges_mutations_concurrency_ratio>
</clickhouse>
```

---

## Appendix B: Alternative Approaches Considered

| Approach | Pros | Cons | Verdict |
|----------|------|------|---------|
| Arrow IPC | Standard, fast | Larger files | Good for streaming, not file storage |
| Protobuf | Compact, schema evolution | Requires CH parsing | Overkill |
| CSV | Simple | No compression, no types | Not suitable |
| Native format | Most efficient for CH | Not portable | Consider for streaming |