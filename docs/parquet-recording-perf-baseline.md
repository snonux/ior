# Parquet Recording Performance Baseline

Captured on 2026-03-13 from the benchmark task using the current Parquet recording implementation.

## Reproduction

Run the pipeline benchmark profiler:

```bash
env GOTOOLCHAIN=auto mage benchProf
```

This writes timestamped pipeline profiles under `bench-profiles/`. The baseline captured for this run was:

- `bench-profiles/pipeline-20260313-054719-cpu.prof`
- `bench-profiles/pipeline-20260313-054719-mem.prof`
- `bench-profiles/pipeline-20260313-054719-block.prof`

Useful follow-up commands:

```bash
env GOTOOLCHAIN=auto go tool pprof -top bench-profiles/pipeline-20260313-054719-cpu.prof
env GOTOOLCHAIN=auto go tool pprof -top -sample_index=alloc_space bench-profiles/pipeline-20260313-054719-mem.prof
env GOTOOLCHAIN=auto go tool pprof -top -sample_index=inuse_space bench-profiles/pipeline-20260313-054719-mem.prof
env GOTOOLCHAIN=auto go tool pprof -top bench-profiles/pipeline-20260313-054719-block.prof
```

## Baseline Numbers

`mage benchProf` recorded the parquet-specific pipeline benchmarks at:

- `BenchmarkPipelineHeadlessParquetCapture`: `14.20 ms/op`, `2000 pairs/op`, `347159 B/op`, `7212 allocs/op`
- `BenchmarkPipelineTUIParquetRecording`: `19.13 ms/op`, `2000 pairs/op`, `994016 B/op`, `19873 allocs/op`

Interpretation:

- The TUI recording path is about 35% slower than the headless parquet path for the same synthetic stream.
- The TUI recording path allocates about 2.9x more memory per operation because it also exercises the stats engine, ring buffer, live trie, and stream fanout path.

## CPU Findings

Top CPU samples were still dominated by the core event-loop path rather than parquet serialization itself:

- `(*eventLoop).processRawEvent` and `(*eventLoop).tracepointExited` were the heaviest cumulative runtime buckets.
- `file.NewFdWithPid` and `os.Readlink` remained a large cumulative cost in exit handling and fd/path materialization.
- Channel scheduling (`runtime.chansend`, `runtime.chanrecv`, `runtime.selectgo`) stayed visible, especially in the TUI fanout path.
- Parquet-specific work was present but secondary: `parquet.(*Recorder).runSession`, `parquet.(*Writer).Close`, parquet-go column flushing, and Zstd compression showed up as meaningful but not dominant contributors.

## Allocation Findings

Allocation-space profile highlights:

- `benchmarkPipelineMix` still accounted for the single largest allocation bucket because it rebuilds the synthetic raw-event stream for each benchmark run.
- `os.Readlink`, `file.(*FdFile).Dup`, and `file.NewFdWithPid` remained major allocators in the traced event path.
- TUI-only structures added measurable cost:
  - `tui/eventstream.NewRingBuffer`
  - `parquet.newRecordingSession`
  - `benchmarkPipelineTUIParquet`
- Parquet writer lifecycle allocations were visible but bounded:
  - parquet-go column buffers
  - Zstd encoder initialization
  - recorder session queue allocation

Retained in-use memory was modest and dominated by parquet-go writer buffers and Zstd encoder state during flush/close:

- `parquet-go/internal/memory.newSlice`
- parquet column buffer construction
- Zstd encoder initialization blocks

## Contention Findings

The block profile did not show a recorder lock hotspot. It was dominated by channel waits:

- `runtime.chanrecv2`: about 65.8% of blocked time
- `runtime.chanrecv1`: about 31.8% of blocked time

Most blocked time came from long-lived background workers waiting on channels, especially comm resolver workers. That means the current parquet path does not yet show a major mutex-contention bottleneck; the bigger costs are work done per event and the extra TUI fanout/allocation load.

## Optimization Targets

These are the highest-value targets for the follow-up optimization task:

- Reduce fd/path resolution overhead in the event loop, especially `Readlink`-driven work in `file.NewFdWithPid`.
- Lower TUI recording allocations by reusing stream fanout buffers and reducing ring-buffer/session setup churn.
- Revisit recorder/session and parquet writer setup costs if recordings are started frequently in short sessions.
- Only optimize parquet compression or flush behavior after confirming they dominate a focused headless profile; they are not currently the primary cost center.

## Verified Follow-up Win

After profiling, the first optimization pass removed the extra TUI `streamEvents` channel hop and pushed directly into the mutex-protected ring buffer.

Re-run command:

```bash
env GOTOOLCHAIN=auto mage benchProf
```

Optimized pipeline artifacts:

- `bench-profiles/pipeline-20260313-055321-cpu.prof`
- `bench-profiles/pipeline-20260313-055321-mem.prof`
- `bench-profiles/pipeline-20260313-055321-block.prof`

Benchmark comparison for the changed path:

| Benchmark | Before | After | Change |
| --- | --- | --- | --- |
| `BenchmarkPipelineTUIParquetRecording` | `19.13 ms/op`, `994016 B/op`, `19873 allocs/op` | `16.51 ms/op`, `992334 B/op`, `19866 allocs/op` | about `13.7%` faster with a small allocation reduction |

Notes:

- `BenchmarkPipelineHeadlessParquetCapture` also moved between runs, but that path was not changed; treat that difference as benchmark noise rather than a verified optimization win.
- Post-change CPU samples still show the event loop and fd/path resolution dominating overall cost, so the next optimization pass should stay focused on those areas instead of tuning parquet compression first.
