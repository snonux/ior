# Domain 3 — Stats Engine & Aggregation (Audit Report)

> Historical audit evidence for the commit named below. Use [README.md](../README.md) and [AGENTS.md](../AGENTS.md) for current behavior.

**Project**: ior (I/O Riot NG) at `/home/paul/git/ior`
**Audit basis**: `PLAN-PROJECT-AUDIT.md` (repo root), section "## Domain 3 — Stats Engine & Aggregation", items 3.1–3.4 (11 checklist bullets).
**Commit audited**: `1cf389203f149743688115b104bd55807cbb90f0` (HEAD; working tree additionally carries the known uncommitted deletion of `docs/syscall-tracing-plan.md`, see F6).
**Auditor constraints**: no root access, no source modifications, no `mage build`/`mage test` (orchestrator already ran `mage test`: all green except the known `TestSyscallTracingPlanBytesClassificationStaysInSync` failure). Domain 3 is pure Go (stats engine + event-loop glue) and was fully verifiable statically plus with targeted local test runs:

```
$ go test -count=1 ./internal/statsengine/        → ok  (all statsengine tests pass)
$ go test -race -count=1 ./internal/statsengine/ → ok  (race detector clean)
$ go test -count=1 -run TestSyscallTracingPlanBytesClassificationStaysInSync ./internal/generate/
  → FAIL: read syscall tracing plan: open /home/paul/git/ior/docs/syscall-tracing-plan.md: no such file or directory   (known finding F6, do-not-fix)
```

Per the audit instructions, byte classification (plan bullet 3.1b names the deleted doc) was verified against `retClassifications` in `internal/generate/` instead.

---

## 3.1 Ingestion Accuracy

**Plan item**: "Review `internal/statsengine/engine.go` to confirm that `Ingest(ep *event.Pair)` updates: per-syscall call counts, per-syscall total and average latency, per-file byte totals (using the Read/Write/Transfer classification), per-process metrics, histogram bucket counts. Verify that byte classification uses the exact syscall lists documented in `docs/syscall-tracing-plan.md`. Confirm that address-space extent (`TotalAddressSpaceBytes`) is accumulated separately from byte-transfer metrics."

### 3.1a — `Ingest` updates all five aggregate dimensions — **PASS**

Evidence — `internal/statsengine/engine.go:152-175` (`Ingest`), all under `e.mu.Lock()`:

```go
e.totalSyscalls++
e.totalBytes += pair.Bytes
e.totalAddressSpaceBytes += pair.AddressSpaceBytes
e.totalLatency += pair.Duration
e.totalGap += pair.DurationToPrev

e.updateErrorAndByteClasses(pair)   // totalErrors++ (ret<0); totalRead/WriteBytes by RetType
e.syscalls.Add(pair)                // per-syscall
e.families.Add(pair)                // per-family
e.files.Add(pair)                   // per-file
e.processes.Add(pair)               // per-process
e.latencyHist.Increment(pair.Duration)      // latency histogram buckets
e.gapHist.Increment(pair.DurationToPrev)    // gap histogram buckets
e.latencySeries.Add(...); e.gapSeries.Add(...); e.throughputSeries.Add(...)
```

Per-dimension confirmation:
- **Per-syscall counts + total/average latency**: `internal/statsengine/syscall.go:79-99` (`syscallAccumulator.Add`): `stats.count++`, `stats.totalLatency += pair.Duration`, `updateMinMax`, reservoir-sampled latencies (`addSample`, cap 10 000, `syscall.go:186-200`) for percentiles; average is derived at snapshot time as `totalLatency/max(count,1)` plus cached P50/P95/P99 (`syscall.go:239-252`, recompute step-gated at `syscallPercentileRecomputeStepDefault = 256`). Error count per syscall at `syscall.go:98`.
- **Per-file byte totals via Read/Write/Transfer classification**: `internal/statsengine/filerank.go:145-163` (`addBytes`) switches on `retEv.RetType`: `READ_CLASSIFIED` → `bytesRead`, `WRITE_CLASSIFIED` → `bytesWritten`, `TRANSFER_CLASSIFIED` → both (documented file-centric semantics). Top-N bounded via a min-heap (`updateHeap`, `filerank.go:165-185`) with cardinality guard (`compactIfNeeded`, `filerank.go:187-198`).
- **Per-process metrics**: `internal/statsengine/process.go:60-87` — count, bytes, latency per PID with best-effort PID-reuse handling (comm change resets the lifetime's counters).
- **Histogram bucket counts**: `internal/statsengine/histogram.go:40-49` (`Increment`) — 8 buckets with boundaries `1_000 … 1_000_000_000` (`histogram.go:22-30`), byte-identical to the kernel-side aggregate bucket boundaries in `internal/c/filter.c:5-15` (`ior_histogram_bucket_index`) and to `syscallAggregateLatencyBucketLowerNs/UpperNs` in `internal/syscall_aggregate_consumer.go:22-41`, so kernel-merged bucket counts (see 3.4) land in the same buckets.
- Cross-checking test: `TestEngineIngestAndSnapshotIntegration` (`internal/statsengine/engine_test.go:34-99`) asserts totals (3 syscalls, 1 error, 170 bytes), transfer counting in both read+write totals (ReadBytes 120/2s = 60/s, WriteBytes 70/2s = 35/s), latency/gap means, histogram totals, top-N file truncation, and process rows.

### 3.1b — Byte classification lists — **PASS** (verified against `retClassifications`; doc deletion is the known finding F6)

Evidence:
- The doc named by the plan is **deleted in the working tree** (`git status`: ` D docs/syscall-tracing-plan.md`), which is exactly what breaks the known-failing drift test. It still exists at HEAD, and its committed "Bytes vs Non-Bytes Classification" lists were compared against the code (`git show HEAD:docs/syscall-tracing-plan.md`):
  - ReadClassified (24): `fgetxattr, flistxattr, getdents, getdents64, getrandom, getxattr, getxattrat, lgetxattr, listxattr, listxattrat, llistxattr, mq_timedreceive, msgrcv, pread64, preadv, preadv2, process_vm_readv, read, readlink, readlinkat, readv, recvfrom, recvmsg, syslog`
  - TransferClassified (5): `copy_file_range, sendfile64, splice, tee, vmsplice`
  - WriteClassified (8): `process_vm_writev, pwrite64, pwritev, pwritev2, sendmsg, sendto, write, writev`
- These match `retClassifications` in `internal/generate/classify.go:606-672` **exactly** (same 37 keys, same classifications), including deliberate non-listings documented in code comments: `msgsnd` and `mq_timedsend` return status codes, not byte counts, and stay UNCLASSIFIED (commented at `classify.go:646-653, 660-666`; locked by tests `TestClassifyMqSyscallPairsAcceptedAndClassified` `classify_test.go:345-366` and `TestBatchMessageSyscallPairsDeferByteClassification` for `sendmmsg`/`recvmmsg`).
- Classification flow end-to-end: `generate.ClassifyRet` → generated BPF handler `ev->ret_type = <CLASS>` (`internal/generate/bpfhandler.go:151-153`; e.g. `internal/c/generated_tracepoints.c:1329` `ev->ret_type = READ_CLASSIFIED`) → decoded Go-side `RetEvent.RetType` (`internal/types/fastdecode.go:139`) → consumed by `bytesFromRet` (`internal/eventloop_exit.go:663-673`, returns the return value only for READ/WRITE/TRANSFER with `Ret > 0`) and by the engine (`engine.go:179-197`, `filerank.go:145-163`).
- The only broken piece is the drift test itself (`internal/generate/docs_drift_test.go:19-58` `TestSyscallTracingPlanBytesClassificationStaysInSync`), which fails solely on `open …/docs/syscall-tracing-plan.md: no such file or directory` — i.e., the file is missing, not that the lists diverged. Known finding, intentionally not fixed/restored (F6).

### 3.1c — `TotalAddressSpaceBytes` accumulated separately — **PASS**

Evidence:
- Separate accumulator field: `engine.go:163` `e.totalAddressSpaceBytes += pair.AddressSpaceBytes`, distinct from `e.totalBytes += pair.Bytes` (`engine.go:161`); separate snapshot fields `TotalAddressSpaceBytes` / `AddressSpaceBytesPerSec` (`snapshot.go:22, 33`, populated at `engine.go:297-298`).
- `pair.AddressSpaceBytes` is only ever set from `MemEvent` payloads — `applyAddressSpaceBytes` (`internal/eventloop_exit.go:627-640`): `munmap` → `Length`, `mremap` → `max(Length, Length2)` (`eventloop_exit.go:674-686`), and only for successful calls (`retEv.Ret >= 0`); classified byte syscalls (`pair.Bytes`) can never feed the address-space accumulator and vice versa.
- Test: `TestEngineTracksAddressSpaceBytesSeparately` (`engine_test.go:134-158`) ingests `munmap`+`mremap` and asserts `TotalBytes == 0` while `TotalAddressSpaceBytes == 12288` and rate = 6144/s.

**Item 3.1 verdict: PASS (all three bullets).**

---

## 3.2 Snapshot Consistency

**Plan item**: "Review `internal/statsengine/engine.go` (`Snapshot()` method) to confirm it captures all mutable state under `mu.Lock()` via `captureSnapshotInputs()`, then releases the lock before building sub-snapshots concurrently via `errgroup`. Verify that rate fields (`SyscallRatePerSec`, `ErrorRatePerSec`, `AddressSpaceBytesPerSec`, `ReadBytesPerSec`, `WriteBytesPerSec`) are computed using `elapsed.Seconds()` where `elapsed = now.Sub(startedAt)` … no 'previous snapshot' delta. Check that the snapshot includes per-family aggregates (`Snapshot.Families`) required by the Non-IO tab."

### 3.2a — Lock-then-errgroup snapshot construction — **PASS**

Evidence — `internal/statsengine/engine.go`:
- `captureSnapshotInputs()` (`engine.go:211-236`) takes `e.mu.Lock()` and copies **every** mutable engine field: `now`, `startedAt`, all 8 totals, the three time series (`Values()` copies), and the per-accumulator inputs — `e.syscalls/families/files/processes/latencyHist/gapHist.snapshotInputs()` are all invoked *inside* the locked section (note: `syscallAccumulator.snapshotInputs` also runs `ensurePercentiles()` — a sort of up to 10 000 samples — under the lock; a performance consideration, not a correctness issue).
- `Snapshot()` (`engine.go:312-340`) then calls `buildSubSnapshots(in, elapsed)` **without holding the lock**; `buildSubSnapshots` (`engine.go:241-284`) runs six sub-builders concurrently in an `errgroup.Group`, propagating any sub-builder error to the caller. All sub-builders operate only on the copied `snapshotInputs` value (freshly-allocated slices; no aliasing of live engine state), so the lock-free phase is race-free — confirmed clean under `go test -race ./internal/statsengine/`.
- (All six current sub-builders always return `nil` errors — the error plumbing is "reserved for future validation" per comments at `syscall.go:138-140`, `filerank.go:100-103` — but the errgroup wiring the plan describes is present and correct.)
- Immutability of the returned snapshot: `NewSnapshotWithFamilies` defensively clones every slice-backed input (`snapshot.go:132-153`), asserted by `TestNewSnapshotDefensivelyCopiesSlices` (`snapshot_test.go:9`).

### 3.2b — Rate fields: totals ÷ elapsed-since-reset, no previous-snapshot delta — **PASS**

Evidence — `internal/statsengine/engine.go`:
- `Snapshot()` computes `elapsed := nonNegativeDuration(in.now.Sub(in.startedAt))` (`engine.go:318`); `startedAt` is set only at construction (`engine.go:108`) and on `Reset()` (`engine.go:129`) — never on snapshot. There is **no delta storage** anywhere in the engine (no "previous snapshot" fields; grep over `internal/statsengine/*.go` finds none).
- `populateSnapshotFields` (`engine.go:287-310`): `rateDiv := elapsed.Seconds()`; `SyscallRatePerSec/ErrorRatePerSec/AddressSpaceBytesPerSec/ReadBytesPerSec/WriteBytesPerSec = safeRate(total, rateDiv)` with `safeRate` returning 0 for `elapsedSeconds <= 0` (`syscall.go:254-258`).
- The same convention applies to sub-rows: `SyscallSnapshot.RatePerSec`, `FamilySnapshot.RatePerSec`, `ProcessSnapshot.RatePerSec` all use `safeRate(count, elapsed.Seconds())` (`syscall.go:239`, `family.go:96`, `process.go:121`).
- Tests pin the semantics: `TestEngineIngestAndSnapshotIntegration` expects 3 syscalls over a fake-clock 2 s window → `SyscallRatePerSec == 1.5`, `ErrorRatePerSec == 0.5` (`engine_test.go:64-73`), and `TestEngineResetClearsAccumulatedStats` (`engine_reset_test.go:20-37`) shows `Elapsed` restarts near zero after reset, i.e. rates are per-since-reset, exactly as the plan states.

### 3.2c — Snapshot includes per-family aggregates (`Snapshot.Families`) — **PASS (with major plan-vs-code drift, Finding F1)**

Evidence the snapshot *includes* families:
- Engine: `familyAccumulator.Add` on every ingest (`family.go:40-59`) and `AddAggregate` for kernel-aggregate rows (`family.go:62-83`); `captureSnapshotInputs` includes `e.families.snapshotInputs()` (`engine.go:229`); `buildSubSnapshots` builds `ss.families` via errgroup (`engine.go:247-251`); `Snapshot()` passes them to `NewSnapshotWithFamilies` (`engine.go:327-329`); accessor `Families()`/`FamiliesCount()` at `snapshot.go:231-239`.
- Tests: `TestEngineAggregatesSyscallFamilies` (`engine_test.go:101-129`) asserts per-family counts/errors/bytes/mean-latency rows (FS, Polling, Process); `TestAggregateEndToEndFamilyRowPopulated` (`internal/eventloop_aggregate_test.go:433-481`) proves aggregate-only ingestion also fills family rows; `snapshot_test.go:54, 96` pin family row ordering (rank-based, `family.go:104-108`).

**Drift**: the "Non-IO tab" these rows were "required by" **no longer exists**. The dashboard tab registry (`internal/tui/dashboard/tabregistry.go:63-160`) registers exactly 7 tabs (Flame, Overview, Syscalls, Files, Processes, Latency+Gaps, Stream); the Non-IO tab was deliberately removed in commit `57363811c2e1` ("feat(dashboard): drop Non-IO tab; add Family column to Syscalls tab", ancestor of HEAD), replaced by a sortable Family column on the Syscalls tab sourced from `SyscallSnapshot.TraceID.Family()` (`internal/tui/dashboard/syscalls.go:73, 108-109, 260`) and by the `[/]` family-scope cycle (`internal/tui/familycycle.go`). Consequently `Snapshot.Families()` is currently **dead in production**: repo-wide grep finds non-test consumers of neither `Families()` nor `FamiliesCount()` — only the statsengine tests and the testflames fixture test reference them (`testfixture_test.go:44-53`). `AGENTS.md` ("dashboard includes a dedicated Non-IO tab backed by per-family aggregate rows"), `docs/tutorial/tutorial.md:72, 116, 215` (tab 8), and the audit plan itself (Domain 3 3.2c and Domain 5 5.2) are all stale. See Finding F1.

**Item 3.2 verdict: PASS (all three bullets; 3.2c carries drift finding F1).**

---

## 3.3 Reset Behavior

**Plan item**: "Verify that `internal/statsengine/engine_reset_test.go` (or equivalent) passes and covers: manual reset (triggered in TUI by pressing `r`, which calls `Engine.Reset()` from the runtime bindings), auto-reset (the `I` key cycles the auto-reset cadence through presets: off → 10s → 30s → 1m → 2m → 5m, as shown in the TUI help), reset while events are being ingested (concurrency safety — `Reset()` holds `mu.Lock()` while zeroing all counters and re-allocating sub-structures). Confirm that reset clears the stats engine (`Engine.Reset()`), the live trie (`LiveTrie.Reset()` or equivalent), and the dashboard snapshot source. Note: the stream ring buffer (`streamrow.RingBuffer`) also has a `Reset()` method; verify whether it is called during a baseline reset or not."

### 3.3a — Reset test coverage (manual / auto-reset presets / concurrent ingest) — **FAIL (coverage gap; see Finding F2)**

The plan's claim is only two-thirds true:

- **Test passes**: `TestEngineResetClearsAccumulatedStats` (`internal/statsengine/engine_reset_test.go:9-37`) passes — verified by `go test -count=1 ./internal/statsengine/` (and under `-race`).
- **Manual reset covered — yes**: it ingests one pair, snapshots, asserts non-zero, calls `e.Reset()`, and asserts all totals (`TotalSyscalls`, `TotalBytes`, `TotalAddressSpaceBytes`, `TotalErrors`) are cleared and `Elapsed` restarts near zero. The TUI `r`-key path is separately covered end-to-end by `TestTUIIntegration_Global_ResetClearsCounts` and `TestTUIIntegration_Flame_ResetBaseline` (`internal/tui_integration_test.go:1869-1886, 563-575`).
- **Auto-reset cadence presets covered — yes, but by "equivalent" tests in the TUI packages, not by `engine_reset_test.go`**: the preset cycle `off → 10s → 30s → 1m → 2m → 5m` lives in `internal/tui/tracelifecycle.go:181-189` (`autoResetCycle`) and matches the TUI help verbatim (`internal/tui/help.go:73`, binding `I` at `internal/tui/common/keys.go:85`). Locked by `TestNextAutoResetIntervalCyclesThroughPresets` and `TestNextAutoResetIntervalAdvancesCustomValueToNextPreset` (`internal/tui/tui_test.go:2216-2261`), the tick machinery by `TestAutoResetTickIgnoredWhileBlurred` / `TestAutoResetTickResumesOnFocusRegain` (`internal/tui/dashboard/model_test.go:1611-1720`), and the live `I` key by `TestTUIIntegration_Global_AutoResetCycleShowsInterval` (`tui_integration_test.go:1887-1906`). The default cadence `-resetTimer` (camelCase, default `DefaultResetTimer = 30s`, `internal/flags/flags.go:73-101, 218`) arms the timer in TUI init (`internal/tui/tui.go:396-398`).
- **Reset while events are being ingested — NOT covered by any test**: repo-wide search finds no test that runs `Engine.Reset()` (or `IngestSyscallAggregates`) concurrently with `Ingest()`/`Snapshot()` — `grep "go func" internal/statsengine/*_test.go` is empty; the only concurrent stress tests target the flamegraph trie (`internal/tui/flamegraph/stress_test.go`, `internal/flamegraph/livetrie_test.go`), not the stats engine. `engine_reset_test.go` itself is purely sequential.
- **The concurrency-safety property itself holds** (which is why this is a coverage FAIL, not a functional one): `Reset()` (`engine.go:123-149`) holds `e.mu.Lock()` (line 128) while zeroing all 8 totals and re-allocating every sub-structure (`newSyscallAccumulator/newFamilyAccumulator/newFileRankerWithConfig/newProcessAccumulatorWithConfig/newHistogram/newRingTimeSeries` ×3) and restarting `startedAt` — exactly as the plan describes. Every other mutator (`Ingest` line 157, `IngestSyscallAggregates` `aggregate.go:22`) and every reader (`captureSnapshotInputs` line 212) takes the same mutex, so reset-during-ingest cannot observe a half-zeroed engine. `go test -race ./internal/statsengine/` is clean, though it cannot exercise the missing scenario.

### 3.3b — Reset clears engine, live trie, dashboard snapshot source; stream-buffer question — **PASS (stream-buffer answer recorded as Finding F3)**

Evidence — the reset path (identical for `r` and auto-reset ticks):
- `r` key: binding `Refresh: "reset baseline" → "r"` (`internal/tui/common/keys.go:84`) → `handleShortcutKey` (`internal/tui/dashboard/model.go:686-687`) → `resetBaselineCmd()` (`model.go:967-981`).
- Auto-reset tick: `handleAutoResetTick` (`model.go:1005-1022`) explicitly "fires the same reset path as the `r` key (live trie + stats engine)" via `m.resetBaselineCmd()`, re-arming the next tick; generation counter + `m.focused` gate drop stale/blurred ticks (tested in `model_test.go:1611-1720`).
- `resetBaselineCmd` clears:
  1. the **live trie**: `m.liveTrie.Reset()` (`model.go:969`; `LiveTrie.Reset` clears data and advances the version — `TestLiveTrieResetClearsDataAndAdvancesVersion`, `internal/flamegraph/livetrie_test.go:179-204`);
  2. the **stats engine via the dashboard snapshot source**: `resettable.Reset()` (`model.go:975-976`) where the dashboard's source is `lateBoundDashboardSource{runtime: rt}` (`internal/tui/tui.go:467`), whose `Reset()` (`tui.go:1291-1301`) forwards to the runtime bindings' dashboard snapshot source — which is the very same `*statsengine.Engine` wired at trace start (`bindings.SetDashboardSnapshotSource(rt.snapSource)`, `internal/ior.go:237`; `snapSource == accumulator == components.engine`, `ior.go:199-203`). So "dashboard snapshot source" and "stats engine" are one object and both bullet-phrasings are satisfied by the single `Engine.Reset()`.
- **Stream ring buffer is NOT reset during a baseline reset.** `streamrow.RingBuffer.Reset()` (`internal/streamrow/ringbuffer.go:71-76`) has exactly one production caller: `runtimeBindings.resetStreamBuffer()` (`internal/tui/tui.go:214-221`), which is invoked only when a *new trace session* starts (`handlePidSelected` / `handleTidSelected`, `tui.go:914, 936`). Neither `resetBaselineCmd` nor `handleAutoResetTick` touches it. User-visible consequence (recorded as F3): after pressing `r` (or an auto-reset tick), Overview/Syscalls totals restart from zero while the Stream tab still shows pre-reset rows, and a stream CSV export after reset would contain pre-reset events against post-reset aggregate totals. Nothing in the code or docs marks this as intended vs. overlooked.

**Item 3.3 verdict: PASS for functional behavior / FAIL for the test-coverage claim in bullet 3.3a (no concurrent-reset test anywhere; engine_reset_test.go covers manual reset only, auto-reset presets covered by equivalent TUI tests).**

---

## 3.4 Aggregate-Only Sampling Sink

**Plan item**: "Review `internal/syscall_aggregate_consumer.go` and related tests. Verify that when a syscall is in aggregate-only mode (`rate=0`), the kernel-side map aggregates counts/latency without emitting ring-buffer events, and the user-space consumer (`aggregateSrc`) merges these aggregates into the stats engine. Confirm that aggregate-only syscalls still appear in the dashboard with correct totals even though no individual stream rows are produced."

### 3.4a — Consumer and tests reviewed — **PASS**

`internal/syscall_aggregate_consumer.go` reviewed in full:
- `Drain()` (lines 91-127) iterates `syscall_aggregate_map`, decodes each value (little-endian; per-CPU variants are summed across CPUs via `decodeRawSyscallAggregatePerCPU`, lines 141-162, stride-aligned to 8 bytes), converts to per-drain **deltas** against `last[traceID]` (`diff`, lines 233-257) so the engine receives only new counts, and approximates min/max latency for the delta window from the delta histogram (`latencyExtremaFromHistogram`, lines 259-278).
- Go/C schema lock: `rawSyscallAggregate` mirrors the C `struct syscall_aggregate` in `internal/c/maps.h:13-20` (count, errors, total/min/max duration, 8-bucket histogram), asserted by `TestSyscallAggregateSchemaMatchesCStruct` (`internal/syscall_aggregate_schema_test.go:16-55`).
- Tests: `TestSyscallAggregateConsumerDrainEmitsDeltas` (per-CPU summing + delta math incl. histogram diffs, `syscall_aggregate_consumer_test.go:130+`), `TestRawSyscallAggregateDiffReturnsOnlyNewCounts`, per-CPU size/empty rejection tests, and `TestBuildSyscallSamplingRatesFamilyAndSyscallOverride` / `TestBuildAggregateOnlyTraceIDs` (lines 15-45) for the rate plumbing.

### 3.4b — rate=0 aggregates kernel-side, no ring events, user-space merge into stats engine — **PASS**

Evidence:
- **Kernel side, rate=0 suppresses emission but still aggregates**: `internal/c/filter.c:57-67` `ior_should_emit_trace` — rate 0 returns 0 ("A zero rate means aggregate-only mode"), rate 1 emits all, rate N emits 1-in-N via prandom. `ior_on_syscall_enter` stores `emit_event` per-TID (`filter.c:69-76`); the generated handlers return before `bpf_ringbuf_reserve` when it is 0 (e.g. futex: `internal/c/generated_tracepoints.c:13673-13676` enter, `13698-13700` exit). Meanwhile `ior_on_syscall_exit` **always** calls `ior_update_syscall_aggregate` when enter/exit trace IDs match (`filter.c:110-120`), and `ior_update_syscall_aggregate` (`filter.c:25-55`) updates count/errors/total/min/max and the 8-bucket histogram in `syscall_aggregate_map` using `BPF_ANY` — regardless of `emit_event`.
- **User-space wiring**: `newSyscallAggregateConsumer(module)` at trace setup (`internal/ior.go:588` `el.aggregateSrc = aggregateConsumer`); the event loop starts `aggregateDrainer.Start(ctx, aggregateDrainEvery, …)` with `defaultAggregateDrainEvery = 1s` (`internal/eventloop_runtime.go:44-50`, `internal/eventloop.go:24, 119-120`); the sink is the stats engine (`el.aggregateSink = snapSource` — the engine — `internal/ior.go:281-282`); results flow through `handleAggregateDrainResult → aggregateSink.IngestSyscallAggregates(rows)` (`eventloop_runtime.go:53-62`).
- **Merge logic**: `Engine.IngestSyscallAggregates` (`internal/statsengine/aggregate.go:17-50`) adds Count/Errors/TotalLatency to engine totals, `syscallAccumulator.AddAggregate` (`syscall.go:102-120`, min/max merge across batches), `familyAccumulator.AddAggregate` (`family.go:62-83`), and `latencyHist.AddBucketCounts` (`histogram.go:51-59`) — the last using the identical bucket boundaries as the kernel. It correctly does not touch `totalBytes`/`totalRead`/`totalWrite`/`totalGap` (kernel aggregate rows carry no byte/gap data).
- **Row gating** (`internal/aggregate_drainer.go:70-88`): only trace IDs in `aggregateOnlyTraceIDs` (built from rate==0 entries via `buildAggregateOnlyTraceIDs`, `syscall_aggregate_consumer.go:223-231`, seeded from `cfg` at `internal/ior.go:392`) are ingested, and ingestion is blocked entirely while a filter with any unsupported dimension is active (`aggregateIngestAllowedForFilter`, lines 96-112) — intentional and tested (see 3.4 evidence tests below; INFO finding F4/F5 on the semantics).
- **Defaults**: TUI mode keeps `futex, futex_wait, futex_wake, futex_requeue, futex_waitv, clock_gettime` at rate 0 (`internal/flags/sampling.go:9-16, 31-37`); the promotion to rate 1 happens **only** in raw output modes (`promoteAggregateOnlyForRawOutput` gated by `cfg.IsRawOutputMode()`, `internal/flags/flags.go:282-283`), so the TUI dashboard genuinely depends on this drain path for those syscalls.
- **End-to-end tests** (all in `internal/eventloop_aggregate_test.go`, green per the orchestrator's `mage test`): `TestAggregateEndToEndDrainIntoStatsEngine` (210-281: totals, per-syscall row, histogram buckets), `TestAggregateEndToEndMultipleDrainTicksAccumulate` (284-337: multi-tick accumulation, cross-batch min 50/max 200), `TestAggregateEndToEndNonDesignatedSyscallsFiltered` (339-385: clock_gettime rows dropped), `TestAggregateEndToEndFilterGateBlocksIngestion` (391-431), `TestAggregateEndToEndFamilyRowPopulated` (433-481), plus drainer unit tests `TestAggregateDrainerTickFiltersAggregateOnlyTraceIDs` … `TestStartAggregateDrainLoopFinalFlushesOnStop` (46-208, including the final flush on stop).

### 3.4c — Aggregate-only syscalls appear in dashboard totals without stream rows — **PASS**

Evidence:
- **Appear with correct totals**: the dashboard renders from `statsengine.Snapshot` produced by the same engine the drainer feeds (wiring chain: `IngestSyscallAggregates` → engine → `bindings.SetDashboardSnapshotSource(engine)` → dashboard `StatsTickMsg`). `TestIngestSyscallAggregatesUpdatesSnapshot` (`internal/statsengine/aggregate_test.go:9-60`) asserts a futex aggregate row surfaces in `snap.Syscalls()` with Count=3/Errors=1/min/max and that `TotalSyscalls`, `TotalErrors`, `LatencyHistogram.Total` include the merged counts; the e2e tests in 3.4b repeat this through the real drain loop (futex Count=5 then 10 across ticks).
- **No individual stream rows**: kernel-side, rate 0 returns before both `bpf_ringbuf_reserve` calls (enter and exit, cited above), so no events reach the ring buffer at all; user-side, the drainer's `handleAggregateDrainResult` feeds *only* the stats engine (`eventloop_runtime.go:53-62`) — it never pushes into `streamBuf`/`streamrow`, so no stream/Parquet rows can be produced for aggregate-only syscalls. (The TUI stream sink is exclusively the per-event `printCb`, `internal/ior.go:256-284`.)
- No double counting: per-event ingestion for these syscalls never happens (no ring events), and the drainer drops any row not in `aggregateOnlyTraceIDs`, so sampled (rate N>1) syscalls are not double-counted via both paths.
- Runtime confirmation against a live BPF map requires root — but the only privileged dependency is the map source, which the e2e tests stub; the kernel side is fully covered by static review of `filter.c` + generated handlers + the schema test. No separate BLOCKED item is needed for this domain.

**Item 3.4 verdict: PASS (all three bullets).**

---

## Findings

No functional FAILs in the stats engine itself. Confirmed issues / drift / coverage gaps, by severity:

**F1 — MEDIUM (plan/doc-vs-code drift + dead production data path)** — The "Non-IO tab" referenced by plan bullet 3.2c (and Domain 5 5.2, `AGENTS.md:78`, `docs/tutorial/tutorial.md:72,116,215`) was removed in commit `57363811c2e1` ("drop Non-IO tab; add Family column to Syscalls tab"); the dashboard now has 7 tabs (`internal/tui/dashboard/tabregistry.go:63-160`). Family data now surfaces via the Syscalls tab's sortable **Family column** (`internal/tui/dashboard/syscalls.go:73,108-109,260`) sourced from `SyscallSnapshot.TraceID.Family()` — *not* from `Snapshot.Families`. As a result the engine still builds `FamilySnapshot` rows on every snapshot (`engine.go:229, 247-251`; `family.go`) but `Snapshot.Families()`/`FamiliesCount()` have **no production consumer** (repo grep: only `internal/statsengine` tests and the testflames fixture test reference them). Cost: family accumulation + sorting on every dashboard tick for data nobody renders, plus misleading docs. *Repro*: `grep -rn "Families()" --include="*.go" internal | grep -v _test` → only `snapshot.go` definition. *Suggested fix* (do not apply during audit): either re-surface family aggregates somewhere in the dashboard (e.g. a family filter/summary on Overview) or stop building family snapshots in the hot path and update `AGENTS.md`, the tutorial, and this audit plan.

**F2 — MEDIUM (test-coverage gap; the one FAIL bullet)** — Plan bullet 3.3a claims `engine_reset_test.go` (or equivalent) covers "reset while events are being ingested". No test anywhere exercises `Engine.Reset()` (or `IngestSyscallAggregates`) concurrently with `Ingest()`/`Snapshot()`; `engine_reset_test.go:9-37` covers manual reset only, and the auto-reset preset coverage lives in the TUI packages (`tui_test.go:2216-2261`, `dashboard/model_test.go:1611-1720`, `tui_integration_test.go:1869-1906`). The implementation is safe by lock discipline (`engine.go:128` Reset under `e.mu.Lock`, all mutators/readers take the same mutex; re-allocation of sub-structures under the lock), so this is a missing regression guard, not a live bug. *Repro*: `grep -rn "go func" internal/statsengine/*_test.go` → no matches. *Suggested fix*: add a statsengine stress test (N goroutines ingesting synthetic pairs + periodic `Reset()` + `Snapshot()` under `-race` / `mage testRace`).

**F3 — LOW (behavior observation; answers the plan's open question)** — `streamrow.RingBuffer.Reset()` is **not** called during a baseline reset (`r` key or auto-reset tick). Its only production caller is `runtimeBindings.resetStreamBuffer()` (`internal/tui/tui.go:214-221`), invoked only when a new trace session starts (`handlePidSelected`/`handleTidSelected`, `tui.go:914, 936`); `resetBaselineCmd` (`dashboard/model.go:967-981`) resets only trie + engine. Consequence: after a reset, dashboard aggregates restart at zero while the Stream tab retains pre-reset rows, and a post-reset CSV export mixes pre-reset stream events with post-reset totals. Whether this is intended (stream = "recent events", reset = "aggregate baseline") is undocumented. *Suggested fix*: decide and document; if stream should clear on reset, call the stream reset from `resetBaselineCmd` (it already returns a `StatsTickMsg` cmd, so wiring is trivial).

**F4 — INFO (documented filter gating of aggregates)** — Aggregate rows are dropped whenever any runtime filter component is set (`aggregateIngestAllowedForFilter`, `internal/aggregate_drainer.go:96-112`: errors-only, syscall/comm/file patterns, FD/latency/gap/bytes/retval, PID, TID), intentional and locked by `TestAggregateEndToEndFilterGateBlocksIngestion` and `TestAggregateDrainerTickRejectsPIDAndTIDFilters`. Users should be aware `futex`/`clock_gettime` totals silently vanish from the dashboard while such a filter is active, even though the kernel keeps aggregating them. No action required beyond docs.

**F5 — INFO (sampled-syscall counts available but unused)** — For rate N>1 syscalls the kernel aggregate map accumulates *full* invocation counts (`ior_update_syscall_aggregate` runs on every exit, `filter.c:110-120`), but the user-space drainer discards rows for any trace ID not in `aggregateOnlyTraceIDs` (`aggregate_drainer.go:79-87`), so the dashboard shows only the sampled subset even though exact counts exist kernel-side. Also, `IngestSyscallAggregates` cannot update byte/gap totals (kernel rows carry no bytes/gaps), so aggregate-only syscalls contribute to counts/latency but never to `TotalBytes` or gap statistics. Both are reasonable design tradeoffs; worth a docs note.

**F6 — INFO (known, out of scope, do-not-fix per instructions)** — `docs/syscall-tracing-plan.md` is deleted in the working tree (uncommitted), causing the known `mage test` failure `TestSyscallTracingPlanBytesClassificationStaysInSync` (`internal/generate/docs_drift_test.go:19`) with `open …/docs/syscall-tracing-plan.md: no such file or directory` (reproduced here). This audit confirmed via `git show HEAD:docs/syscall-tracing-plan.md` that the committed doc's Read/Transfer/Write lists match `retClassifications` (`internal/generate/classify.go:606-672`) exactly — the classification itself is in sync; only the doc file is missing. Not fixed or restored, per audit constraints.

**Cross-references to other audit domains** (per the audit split; not double-counted here):
- Live TUI auto-reset/reset UX (`r`/`I` during a real trace) and Non-IO tab expectations → Domain 5 (which will hit the same F1 drift for its "tab 8" bullet).
- Sampling-rate flag semantics and raw-mode promotion → Domain 6.3.

---

## Domain Summary

Domain 3 was audited at commit `1cf3892` entirely statically plus with targeted non-mage test runs (`go test`/`go test -race` on `internal/statsengine`, both green; the `internal` package's aggregate e2e suite reported green by the orchestrator's `mage test`); nothing in this domain requires root, so there are no BLOCKED items. **Verdict counts (11 plan bullets): 10 PASS, 1 FAIL (F2 — no test covers reset during concurrent ingest), 0 N-A, 0 BLOCKED-needs-root; per item: 3.1 PASS, 3.2 PASS, 3.3 PASS-functional/FAIL-on-the-test-coverage-claim, 3.4 PASS.** The stats engine is in good shape: `Ingest` updates all five documented dimensions (per-syscall counts/latency with reservoir-sampled percentiles, per-file Read/Write/Transfer byte totals, per-process rows, latency+gap histograms, plus sparkline series) behind a single mutex; byte classification is exactly the 37-syscall table in `retClassifications` (Read 24 / Transfer 5 / Write 8, matching the deleted doc's committed lists — the failing drift test is purely the missing file); address-space extent is accumulated through a fully separate field and pipeline; snapshots capture all mutable state under the lock and build sub-snapshots lock-free via errgroup with defensive cloning; rates are totals ÷ elapsed-since-reset with no previous-snapshot delta, exactly as documented; the reset path (manual `r` and the `I`-key auto-reset cycle off→10s→30s→1m→2m→5m, default 30s) clears engine, live trie, and dashboard snapshot source (all verified, with the stream ring buffer confirmed *not* to be cleared on baseline resets — an undocumented decision worth an explicit call); and the aggregate-only sink works end-to-end: rate=0 syscalls are counted/latency-histogrammed in `syscall_aggregate_map` without any ring-buffer emission and are drained each second as per-TID deltas into the same engine that feeds the dashboard, so `futex`/`clock_gettime` show correct totals with zero stream rows. The one FAIL is a missing regression test for concurrent reset (the lock discipline makes it safe today), and the notable drift is that the Non-IO tab these family rows were built for was removed while `Snapshot.Families` — still built on every tick — now has no production consumer, leaving stale claims in AGENTS.md, the tutorial, and this audit plan. None of the findings block production use; F1 and F2 deserve follow-up, F3 needs a documented product decision, and F6 remains the pre-existing known issue.