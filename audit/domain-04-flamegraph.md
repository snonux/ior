# Domain 4 — Flamegraph & Output Formats (Audit Report)

**Project**: ior (I/O Riot NG) at `/home/paul/git/ior`
**Audit basis**: `PLAN-PROJECT-AUDIT.md` (repo root), section "## Domain 4 — Flamegraph & Output Formats", items 4.1–4.4 (16 checklist bullets).
**Commit audited**: `90b6569d1cb2d9ab0279fec997e0b5e15b648f5e` (HEAD, "audit(domain-03): stats engine & aggregation verification report"); the working tree additionally carries the known uncommitted deletions of `docs/syscall-tracing-plan.md` and `docs/clickhouse-streaming-plan.md` (pre-existing, cross-referenced in domain-01/02/03 reports; not restored per audit constraints).
**Auditor constraints**: no root access (`sudo -n true` fails), no source modifications, no `mage build`/`mage test` (orchestrator already ran `mage test`: every package green except the known `TestSyscallTracingPlanBytesClassificationStaysInSync` failure caused by the deleted `docs/syscall-tracing-plan.md`). Every plan bullet that requires a live trace (`sudo ./ior -plain|-flamegraph|-parquet …`, `zstdcat` of a real trace, parquet files from live runs) is marked **BLOCKED-needs-root** and was instead verified via code review, targeted non-mage test runs, and the existing root-gated integration tests.

**Verification commands run** (all read-only; no artifacts left in the repo — helper outputs went to `/tmp`):

```
$ go test -count=1 ./internal/flamegraph/ ./internal/parquet/ ./internal/flags/ ./internal/streamrow/ ./internal/collapse/
  ok  ior/internal/flamegraph   ok  ior/internal/parquet
  ok  ior/internal/flags        ok  ior/internal/streamrow   [no test files: collapse]
$ go test -race -count=1 ./internal/flamegraph/ ./internal/parquet/ ./internal/streamrow/   → ok (race-clean)
$ IOR_STRESS_TEST=1 go test -count=1 -run TestLiveTrieStressHighRateConcurrentSnapshot ./internal/flamegraph/
  livetrie_test.go:695: stress ingest rate: 947 events/sec (50000 events in 52.77165611s)
  --- PASS (52.78s)
$ # internal package (needs libbpfgo CGO env — replicated manually from Magefile.go goEnv(), no mage targets invoked):
$ LIBBPFGO=$PWD/../libbpfgo CGO_CFLAGS="-I$LIBBPFGO/output -I$LIBBPFGO/selftest/common" \
  CGO_LDFLAGS="-lelf -lzstd $LIBBPFGO/output/libbpf/libbpf.a" \
  go test -count=1 -run 'TestHeadlessParquet|TestValidateRunConfig|TestDispatchRun|TestShouldIngestTracePair|TestTuiTraceStarter' ./internal/
  → ok  ior/internal
$ go test -count=1 -run 'TestWriteStreamCSV|TestExportRowsToCSV|TestEnsureCSVFilename' ./internal/tui/eventstream/   → ok
$ go run ./audit/check/flameroundtrip                 # pre-existing Domain-4 helper (see below)
$ IOR_AUDIT_KEEP=1 go run ./audit/check/flameroundtrip # + zstd -lv / zstdcat / od / grep on the artifact
$ go run ./audit/check/parquetwrite /tmp/audit-d4.parquet   # new helper added this session
$ pyarrow 21.0.0 (venv) reading /tmp/audit-d4.parquet      # independent reader verification
```

Two verification helpers live under `audit/check/` (permitted area): `flameroundtrip/main.go` was already present from an earlier, interrupted Domain-4 audit session (reviewed, then re-run; it writes only into a fresh `/tmp` dir) and `parquetwrite/main.go` was added this session (writes a synthetic Parquet file through the **production** `parquet.Recorder` path to `/tmp`, no BPF involved). No compiled binaries were left in the repo.

---

## 4.1 Live Trie Correctness

**Plan item**: "Review `internal/flamegraph/livetrie.go` to confirm that `Ingest(ep *event.Pair)` increments the correct node path based on `CollapsedFields` and `CountField`. Verify that the trie supports the configured collapse keys (`comm`, `tracepoint`, `path`, and any custom fields). Confirm that `Reset()` clears the trie without leaking child-node memory. Run `mage test` and confirm all `livetrie_test.go` assertions pass."

### 4.1a — `Ingest` increments the correct node path from CollapsedFields/CountField — **PASS**

Evidence — the full ingest chain:
- `LiveTrie.Ingest(ep)` (`internal/flamegraph/livetrie.go:102-105`) converts the pair to a record via `eventPairToRecord` (`livetrie.go:328-343`: `Path`, `TraceID`, `Comm`, `Pid`, `Tid`, `Flags`, and `Cnt{Count:1, Duration, DurationToPrev, Bytes}` — the pair's data is copied before the caller recycles it, locked by `TestLiveTrieIngestCopiesBeforeRecycle`).
- `AddRecord` (`livetrie.go:117-146`) reads the leaf weight via `record.Cnt.ValueByName(countField)` (`counter.go:38-53`: `count`/`duration`/`durationToPrev`/`bytes`) and the optional height weight via `heightField`, then builds the node path with `buildFrames(record, fields)` and commits under `lt.mu.Lock()` with a version bump. A config change between read and commit is detected (`countField != lt.countField || … || !slices.Equal(fields, lt.fields)`) and the record is retried against the new config — no lost or mis-attributed increments.
- `buildFrames` (`livetrie.go:345-357`) walks the configured fields **in order** using `IterRecord.StringByName` (`iordata.go:206-223`): `path` → path components each become their own frame (`strings.Split(Path, "/")` re-joined with `;/`, then split again on `;`); `comm`, `tracepoint`, `pid`, `tid`, `flags` are single frames (flags join with `|`, `file.Flags.String()` at `internal/file/flags.go:66-88`, so no accidental frame splitting).
- `insertTriePath` (`internal/flamegraph/trie_insert.go:4-22`) follows/creates one child node per frame and adds `value`/`heightValue` **at the leaf** (`node.value += value`); additive aggregation is exact.
- Production wiring: `runtimeComponents.liveTrie = flamegraph.NewLiveTrie(b.cfg.CollapsedFields, b.cfg.CountField, "")` (`internal/runtime_builder.go:45`), with defaults `CollapsedFields = ["comm","tracepoint","path"]`, `CountField = "count"` (`internal/flags/flags.go:113-114`, `-fields`/`-count` override at `flags.go:245-253`, validation at `flags.go:254-262`). The TUI ingests via the per-event printCb (`internal/ior.go:271` `rt.liveTrie.Ingest(ep)`).
- Behavior locked by tests (all green): `TestLiveTrieIngestAndSnapshotRoundTrip`, `TestLiveTrieIngestIsAdditive` (bytes count field: 10+15=25), `TestLiveTrieCommTracepointPathAggregatesSameSyscallAcrossPaths` (same syscall across paths/PIDs aggregates to Total=2 under `svc;enter_read`), `TestLiveTrieVersionIncrementsPerIngest`, `TestLiveTrieSetCountFieldSwitchesMetricAndResetsBaseline`, height-metric tests (`livetrie_test.go:14-42, 52-71, 74-88, 185-215`).

### 4.1b — Configured collapse keys (`comm`, `tracepoint`, `path`, "custom") — **PASS (with drift note)**

The supported key set is a **closed enum**: `path, comm, tracepoint, pid, tid, flags` (`internal/collapse/fields.go:5-11`, `ValidFields()`), and count fields `count, duration, durationToPrev, bytes` (`fields.go:13-18`). So the trie supports the three keys the plan names **plus** `pid`/`tid`/`flags` (all exercised via `StringByName`, `iordata.go:206-223`; `pid` used by tests e.g. `TestLiveTrieIngestAndSnapshotRoundTrip`). Drift: the plan's "and any custom fields" does not exist — arbitrary field names are rejected at CLI parse (`flags.go:256-258` `invalid field for collapse`) and at runtime reconfiguration (`normalizeLiveTrieFields`, `livetrie.go:236-263`, locked by `TestLiveTrieReconfigureRejectsInvalidFields`). Count fields are likewise enum-constrained with invalid values coerced to `"count"` at construction (`livetrie.go:54-62`). Note: `AddressSpaceBytes`/`RequestedSleepNs` are intentionally not available as count fields (not in `Counter`).

### 4.1c — `Reset()` clears the trie without leaking child-node memory — **PASS**

Evidence — `LiveTrie.Reset()` (`livetrie.go:152-156`) → `resetLocked()` (`livetrie.go:78-84`): replaces `lt.root` with a freshly allocated node (the entire old subtree becomes unreferenced and GC-eligible), zeroes `maxDepth`, and bumps `version` (so stale version-keyed caches can never be served). `invalidateCache()` (`livetrie.go:86-99`) nils **both** caches — `cacheJSON` (SnapshotJSON) and `treeCache` (SnapshotTree) — which are the only other places old-trie-derived data is retained; `SnapshotTree` returns freshly allocated node trees (`buildSnapshotWithTotal` allocates per snapshot, `livetrie.go:379-434`), so a previously returned tree retained by the TUI is by-design safe and cannot keep the new trie's contents stale. SetCountField/SetHeightField/Reconfigure all route through the same `resetLocked` + `invalidateCache`. Tests: `TestLiveTrieResetClearsDataAndAdvancesVersion` (`livetrie_test.go:179-204`: version advances, snapshot total 0, new baseline ingests correctly) and the reconfigure/metric-switch reset tests — all green, race-clean. No retained references to old child nodes were found anywhere in the package.

### 4.1d — All `livetrie_test.go` assertions pass — **PASS**

The orchestrator's `mage test` ran green for this package. Locally: `go test -count=1 ./internal/flamegraph/` → `ok` (every `livetrie_test.go` assertion, including `TestLiveTrieConcurrentIngestAndSnapshot`, `TestLiveTrieConcurrentAddRecordAndMetricToggle`, and the cache-race test `TestLiveTrieSnapshotJSONSkipsStaleCacheWrite`), `go test -race` → clean, and the opt-in stress test `TestLiveTrieStressHighRateConcurrentSnapshot` (`IOR_STRESS_TEST=1`) → **PASS** in 52.8 s: `Version == 50000`, snapshot totals match exactly, and heap growth stayed within the test's 512 MiB bound.

**Item 4.1 verdict: PASS (all four bullets; drift note on "custom fields" in 4.1b).**

---

## 4.2 Offline Recorder (.ior.zst)

**Plan item**: "Review `internal/flamegraph/recorder.go` to confirm that `AddPair()` and `Write()` produce valid collapsed-stack lines. Trace a known workload (e.g., `docs/tutorial/scripts/workload.sh`), write `.ior.zst`, and decompress with `zstdcat`. Feed the decompressed output into `flamegraph.pl` and confirm it renders a valid SVG with recognizable stack frames. Verify that counts and weights in the `.ior.zst` file match the total event count observed in the TUI for the same trace duration."

### 4.2a — `AddPair()`/`Write()` produce valid collapsed-stack lines — **FAIL (format drift; Finding F1; aggregation itself correct)**

What the code actually does (all functionally sound):
- `Recorder.AddPair` → `iorData.addEventPair` (`internal/flamegraph/iordata.go:63-67`): each pair folds into `map[recordKey]Counter` keyed by `(Path, TraceID, Comm, Pid, Tid, Flags)` with `Counter{Count, Duration, DurationToPrev, Bytes}` summed on collision (`iordata.go:69-92`, `Counter.add` at `counter.go:22-28`).
- `Recorder.Write` → `serializeToFile` (`iordata.go:95-135`): builds the filename `<hostname>-<name>-<2006-01-02_15:04:05>.ior.zst` (empty name → `"default"`, `iordata.go:100-102`), **gob-encodes the whole records map** into a zstd writer (`DataDog/zstd`), flushes/closes in the right order, and atomically publishes via `<file>.tmp` → `os.Rename`.
- Round-trip verified without root via `go run ./audit/check/flameroundtrip` (production `NewRecorder`→`AddPair`×3→`Write`→`LoadFromFile`): two identical pairs aggregate to `{Count:2 Duration:30 DurationToPrev:12 Bytes:192}`; a distinct pair stays separate `{Count:1 Duration:30 Bytes:0}`; produced filename `rocky-auditflame-2026-09-01_17:06:46.ior.zst` confirms the `<hostname>-<name>-<timestamp>.ior.zst` pattern (also asserted for plan item 8.2).

**But the on-disk format is not collapsed-stack text.** `zstd -lv` shows a valid single zstd frame (185 B compressed, magic `28 b5`); `zstdcat` output is a **binary gob stream** — `od -c` shows gob type descriptors (`Path`, `TraceID`, `Comm`, `Pid`, `Tid`, `Flags`, `Count`, `Duration`, `DurationToPrev`, `Bytes`), and `zstdcat file | grep -c ";"` → **0** semicolons: there are no `frame;frame count` lines anywhere in the payload. Repo-wide search finds **no** collapsed-stack text writer and **no** `.ior.zst → flamegraph.pl` converter (`cmd/` contains only `ior`, `ioworkload`, `filewriter`; no `flamegraph.pl` reference exists in Go code). The recorder's own comment calls it "the legacy .ior.zst format" used by integration tests (`recorder.go:5-6`), and `LoadFromFile` (`iordata.go:54-60`) is only consumed by `integrationtests/parse.go` and the testflames fixture. AGENTS.md's "`.ior.zst` — compressed collapsed stacks for offline FlameGraph generation" is therefore inaccurate at the file-format level: the file is a *flamegraph-ready record store*, and collapsed stacks could only be derived from it via `LoadFromFile` + `buildFrames` — a path that exists only inside the LiveTrie/TUI renderer. See Finding F1.

### 4.2b — Trace a known workload, write `.ior.zst`, decompress with `zstdcat` — **BLOCKED-needs-root** (live trace requires root)

Non-root evidence recorded:
- `zstdcat` decompression itself verified on a real recorder-produced file (above): the zstd frame is valid and round-trips through the production `loadFromFile` (gob+zstd) without error.
- The end-to-end workload→`.ior.zst` flow is covered by the existing root-gated integration suite: `integrationtests/harness.go:189-196` runs `ior -flamegraph -name <scenario> -pid <pid> -duration N` against the `ioworkload` binary and every `integrationtests/*_test.go` scenario asserts on the parsed records via `LoadTestResult` (`parse.go:13-25`). These tests skip here with "requires root for BPF" (`integrationtests/helpers_test.go:18-19`), matching the orchestrator's environment facts.

### 4.2c — Feed decompressed output into `flamegraph.pl`, confirm valid SVG — **BLOCKED-needs-root (and structurally impossible per current format; Finding F1)**

The live-run part needs root. Additionally, the step as written cannot succeed even with root: `flamegraph.pl` consumes collapsed-stack text lines, but `zstdcat *.ior.zst` yields a binary gob stream (4.2a evidence: zero semicolons, gob type descriptors). No SVG can be produced by `zstdcat … | flamegraph.pl` from the current format; the plan's Domain 8.2.3 repeats the same impossible instruction. Until a converter (or a collapsed-text output mode) exists, this bullet cannot pass.

### 4.2d — Counts and weights in `.ior.zst` match TUI totals for the same trace duration — **BLOCKED-needs-root** (requires two live runs)

Code-review + test evidence in lieu of the live comparison:
- In `-flamegraph` mode the recorder is the **sole** consumer of every emitted pair: `maybePrependFlamegraphConfigure` (`internal/ior.go:474-487`) installs `printCb = recorder.AddPair; ep.Recycle()`, wrapped only by the probe-active gate (`configureEventLoopOutput`, `ior.go:437-448`). There is no TUI in this mode at all (`plainTraceModeHandler` owns `-flamegraph`, `ior_mode_registry.go:196-211`), so "compare with the TUI for the same duration" inherently means two separate runs.
- Within the file, Σ`Count` over all records equals the number of recorded pairs exactly (per-key `Counter.add`), and per-key weights (Duration/DurationToPrev/Bytes) are exact sums — locked by `TestAddPath`/`TestMerge` (`iordata_test.go:25-58, 60-108`) and the round-trip helper output above.
- The root-gated integration tests assert count/weight fidelity against a known workload: `AssertEventsPresent` sums `rec.Cnt.Count` per matching record (`expectations.go:17-31`), `assertEventBytesAtLeast` asserts transferred bytes ≥ payload (e.g. `readwrite_test.go:6-27`), plus comm/PID purity checks.
- Two by-design divergences make a literal TUI-vs-file comparison approximate: (1) sampling rates `N>1` reduce file counts to the sampled subset (kernel emits 1-in-N, `internal/c/filter.c` `ior_should_emit_trace`); (2) a user-explicit `-syscall-sampling-syscalls x=0` keeps `x` suppressed in `-flamegraph` (promotion preserves explicit zeros, see 4.4c) while a TUI run would show `x`'s aggregate counts from the drain path. Default aggregate-only syscalls are promoted to rate 1 in this mode, so defaults do **not** diverge.

**Item 4.2 verdict: bullet (a) FAIL (format drift F1 — aggregation/persistence correct but the file is a gob map, not collapsed-stack lines); bullets (b), (c), (d) BLOCKED-needs-root — with (c) additionally blocked by the format itself (F1) and (b)/(d) carrying the non-root evidence above.**

---

## 4.3 Parquet Output

**Plan item**: "Review `internal/ior_parquet_sink.go` and `internal/parquet/`. Run a headless Parquet trace (`sudo ./ior -parquet /tmp/test.parquet -duration 5 -trace-syscalls read,write`). Load `/tmp/test.parquet` with `pyarrow` or `parquet-tools` and verify: schema matches `internal/types/` generated structs, row count equals expected number of events, `requested_sleep_ns` field is populated for sleep tracepoints. Confirm that Parquet output respects the filter epoch (does not include rows filtered out after the trace starts)."

### 4.3a — Review of `internal/ior_parquet_sink.go` and `internal/parquet/` — **PASS**

Reviewed in full; the pipeline is sound:
- **Headless sink** (`internal/ior_parquet_sink.go`): `configure` (`:38-47`) wires `el.printCb` to `streamrow.New(seq.Next(), ep)` → `recorder.Record(row, 0)` → `ep.Recycle()`; any recorder error calls `fail(err)` (`:48-56`) which latches the first error and **cancels the trace context** (fail-fast rather than silently truncated files). `runHeadlessParquet` (`:95-140`) starts the recorder with `NewFileMetadata("headless")`, drains the shutdown watcher and profiling goroutines, then `recorder.Stop()` and joins sink/stop errors.
- **Bounded queue + background flush** (`internal/parquet/recorder.go`): queue capacity **4096** (`defaultRecorderQueueCapacity`, `:12`), batch size 256, ticker flush every 250 ms; a dedicated `runSession` goroutine (`:182-210`) drains the queue, flushes on batch-full or tick, and on `Stop` drains the remaining queue, flushes, and finalizes. `enqueue` (`:326-345`) is non-blocking: on a full queue it flips the session to failed with `ErrRecorderQueueFull` and closes `stopC`; the session then aborts the writer (temp file removed) and `Stop()` returns the terminal error. Locked by `TestRecorderFailsOnQueueOverflow` (overflow → abort + terminal Stop error + `Status.LastError`), `TestRecorderStopReturnsTerminalErrorOnRepeatedCalls`, `TestRecorderRoundTrip` (row **and epoch** fidelity via `reflect.DeepEqual`), `TestWriterRoundTripAndFinalize` — all green locally, race-clean.
- **Writer file lifecycle** (`internal/parquet/writer.go:56-160`): writes to `<path>.tmp`, zstd-compressed row groups (8192 rows/group, 256 KiB pages), `Close` finalizes the footer then `os.Rename`s atomically; `Abort` removes the temp file. File-level metadata `ior.hostname` / `ior.mode` / `ior.started_at_unix_nano` / `ior.version` (`schema.go:100-121`).
- **Mode gating**: `-parquet` is mutually exclusive with `-plain`, `-flamegraph`, `--testflames`, `--testliveflames`, and content filters (`-comm`, `-path`, `-tid`, active `GlobalFilter`) — `headlessParquetModeHandler.validate` (`ior_mode_registry.go:198-216`, locked by `TestValidateRunConfigRejectsParquetWithPlain/…ContentFilters/…GlobalFilter`, `TestValidateRunConfigAllowsParquetWithPIDFilter`); `-pid` is allowed for focused recordings. Root gate before any BPF load: `deps.getEUID() != 0 → errRootPrivilegesRequired` (`ior_mode_registry.go:221-224`).

### 4.3b — Run a headless Parquet trace — **BLOCKED-needs-root**

`sudo -n` fails in this environment; the live run could not be executed. Code path verified instead: `headlessParquetModeHandler` → `runHeadlessParquet` → `setupHeadlessParquetInfra` (BPF module, ring buffer, trace ctx, event loop; teardown stops `rb` before closing the module) → `el.run(ctx, ch)` → `recorder.Stop()`. Root-gated integration coverage exists: `integrationtests/harness.go:216-235` runs `ior -parquet <path> -duration N -pid <pid>` and e.g. `TestSleepRequestedTimespecInParquet` (`integrationtests/sleep_test.go:28-83`) reads the produced file back and asserts on rows.

### 4.3c — Load with `pyarrow`/`parquet-tools`; verify schema / row count / `requested_sleep_ns` — **PASS** (schema and field population verified without root via an independent reader; live-file aspects BLOCKED-needs-root, covered by root-gated integration tests)

A synthetic file was written **through the production recorder** (no BPF needed) by `go run ./audit/check/parquetwrite /tmp/audit-d4.parquet` (5 pairs: two nanosleeps, an `openat` error, a `renameat2`, an `epoll_ctl`) and read back with **pyarrow 21.0.0** (independent reader, not parquet-go):

```
created_by: ior version v1.1.0(build )
num_rows: 5
kv metadata: {'ior.version': 'v1.1.0', 'ior.mode': 'audit-d4', 'ior.started_at_unix_nano': …, 'ior.hostname': 'rocky'}
schema columns (21): seq u64, time_ns u64, gap_ns u64, latency_ns u64, comm str, pid u32, tid u32,
  syscall str, family str, fd i32, ret i64, bytes u64, address_space_bytes u64, requested_sleep_ns i64,
  file str, is_error bool, filter_epoch u64, old_file str, epoll_op str, epoll_target_fd i32, epoll_events u32
rows: nanosleep → requested_sleep_ns=2000000 / 3000000 (0 elsewhere);
      openat ret=-2 → is_error=true, bytes=4096;  renameat2 → file=/tmp/newname, old_file=/tmp/oldname;
      epoll_ctl → epoll_op=ADD, epoll_target_fd=9, epoll_events=2147483673
```

- **Schema**: the 21 columns and types match `internal/parquet/schema.go:12-33` **and** the documented table in `docs/parquet-querying.md:15-37` exactly (field-for-field, including `requested_sleep_ns Int64` and `filter_epoch UInt64`). Precision on the plan's wording: the schema is not a direct mirror of the `internal/types/` generated structs but a flattened projection of `streamrow.Row` (`row.go:21-53`); the per-column lineage from the generated structs was verified end-to-end: `SleepEvent.RequestedNs` (`generated_types.go:2105-2111`) → `pair.RequestedSleepNs` (`eventloop_exit.go:642-651`) → `row.RequestedSleepNs` → `requested_sleep_ns` (`schema.go:86`); likewise `MemEvent`→`address_space_bytes`, `NameEvent.Oldname` (`eventloop_exit.go:88-89`) → `old_file`, `EpollCtlEvent` (`eventloop_exit.go:391-405`) → `epoll_*`, `RetEvent.Ret` → `ret`/`is_error`, `TraceID` → `syscall`/`family`.
- **`requested_sleep_ns` populated for sleep tracepoints**: verified above on the production recorder path (values 2 000 000 / 3 000 000 for nanosleep rows, 0 for others), plus unit tests `TestNewCarriesRequestedSleepNs` (`streamrow/row_test.go:147-160`) and the root-gated integration test `TestSleepRequestedTimespecInParquet`, which asserts on a **live** file: 2 ms for `nanosleep`, 3 ms for relative `clock_nanosleep`, and the `-1` sentinel for TIMER_ABSTIME absolute requests (`sleep_test.go:52-83`).
- **Row count equals expected events**: semantics locked by tests — `TestHeadlessParquetSinkRecordsRows` (`internal/ior_mode_test.go:699-742`: 2 printCb calls → exactly 2 rows, seq 1,2, epoch 0) and `TestRecorderRoundTrip` (3 records → 3 rows, `Status.RowsWritten == 3`); live-file per-family/PID assertions exist in `integrationtests/family_test.go` (`readParquetRecords` via `parquet-go`'s generic reader, `family_test.go:88-115`). Caveat documented: rows are filter-passing, probe-active, sampling-passing pairs (defaults promoted to rate 1 in this mode — see 4.4c), so "expected number of events" must account for explicit sampling overrides.

### 4.3d — Parquet output respects the filter epoch (no rows filtered out after trace start) — **FAIL (narrow: epoch stamping across in-place filter swaps is stale — Finding F4; the "no filtered-out rows" property itself holds)**

Verified **PASS** sub-claim — rows filtered out after trace start are not recorded:
- TUI recording path: the per-event printCb gates every row with `shouldIngestTracePair(el.Filter(), ep)` **before** `rt.recorder.Record(...)` (`internal/ior.go:256-273`); in-place filter swaps update that live filter via the registered setter (`tui.go:175-189 applyLiveFilter` → `SetFilter`), and `TestTuiTraceStarterAppliesLiveFilterSwapInPlace` (`ior_mode_test.go:829-889`, run green here) proves previously-admitted events stop reaching the sink after a swap — the recorder sits on the same callback.
- Headless `-parquet`: content filters are rejected up front (4.3a) and `headlessParquetTraceConfig` (`ior_parquet_sink.go:81-92`) clears `CommFilter`/`PathFilter`/`TidFilter`/`GlobalFilter` (locked by `TestHeadlessParquetTraceConfigPreservesPIDAndClearsContentFilters`), so nothing can be filtered out mid-run; all rows carry `filter_epoch=0` (asserted in `TestHeadlessParquetSinkRecordsRows`).

Verified **FAIL** sub-claim — the epoch value stamped in rows goes stale across in-place filter swaps (Finding F4):
- `tui.go:95-96` documents the intent: "filterEpoch increments on every filter change and is stored in parquet rows", and `reapplyActiveFilter`/`undoGlobalFilter` do call `m.runtime.advanceFilterEpoch()` on every change (`tui.go:1085, 1125`).
- But the recording callback stamps rows with `rt.filterEpoch` (`ior.go:265`), a plain field copied **once** at session wiring (`rt.filterEpoch = bindings.FilterEpoch()`, `ior.go:234`). The preferred in-place swap path (`applyLiveFilter` returns true → no trace restart) never rebuilds the session, so every row recorded after an in-place filter swap still carries the **session-start epoch**, while the bindings' epoch has advanced. Only a full trace restart picks up the new epoch — that path is test-locked (`TestTuiTraceStarterFromRunTracePersistsRecorderAcrossRestarts`, `ior_mode_test.go:746-824`: epochs 0 then 1 across restarts, run green here), which highlights that the in-place path is the uncovered gap. Consequence: within one TUI recording, `filter_epoch` cannot distinguish rows recorded before vs. after an in-place filter swap, contradicting its documented purpose ("Filter generation at capture time", `docs/parquet-querying.md:35`) and the code comment. See F4 for the suggested fix.

**Item 4.3 verdict: (a) PASS; (b) BLOCKED-needs-root; (c) PASS (independent pyarrow verification of schema and requested_sleep_ns on a production-recorder file + unit/root-gated integration tests; live-run row-count aspect blocked); (d) FAIL (F4 — stale filter_epoch across in-place swaps; the no-filtered-rows property verified PASS).**

---

## 4.4 Plain CSV Output

**Plan item**: "Run `sudo ./ior -plain -duration 5 > /tmp/out.csv`. Verify that the CSV header and row format match the documentation. Check that `-plain` promotes default aggregate-only sampling rates to `1` (all events) because there is no TUI aggregate sink. Confirm that CSV rows contain all documented fields (timestamp, pid, tid, comm, syscall, path, latency_ns, bytes, requested_sleep_ns, etc.)."

### 4.4a — Run `sudo ./ior -plain -duration 5 > /tmp/out.csv` — **BLOCKED-needs-root**

Live run requires root (`plainTraceModeHandler.run` gates on `getEUID() != 0 → errRootPrivilegesRequired`, `ior_mode_registry.go:247-251`; the EUID check happens in the mode handler before any BPF module is loaded, `internal/ior.go:32` defines the constant). The output path was verified without root by exercising the exact code the run would execute: `-plain` keeps the event loop's default `printCb` (`internal/eventloop.go:105-112` — `fmt.Println(ep); ep.Recycle()`, i.e. `event.Pair.String()` per row) and prints the header once when `plainMode && !pprofEnable` (`internal/eventloop_runtime.go:23-25`). The `audit/check/flameroundtrip` helper renders one row via the very same `Pair.String()` next to the header constant (transcript below).

### 4.4b — CSV header and row format match the documentation — **FAIL (Finding F2)**

The de-facto documentation of the `-plain` format is the header constant itself (no doc specifies the columns; `docs/build-rocky-linux-9.md:92` only says "a stream of CSV rows"). The header does **not** match the rows:

```
header: durationToPrevNs,durationNs,comm,pid.tid,name,ret,notice,file      → 8 comma-separated columns
row:    00002000,00001000,serv@1234.1235,openat=>0,/tmp/x%(3,O_RDONLY)     → 5 logical fields (6 comma-split)
```

- Header (`internal/event/pair.go:119`) names eight columns: `durationToPrevNs,durationNs,comm,pid.tid,name,ret,notice,file`.
- Rows (`Pair.String()`, `pair.go:121-150`) emit **five** fields: `%08d` gap, `%08d` duration, then `comm@pid.tid` **merged with `@`** into one field, then `name=>ret` **merged with `=>`** into one field, then the file column.
- The `notice` column is **never emitted** anywhere (repo-wide grep: the constant is the only occurrence; inherited unchanged from the 2025-04-16 refactor, commit `2c5499a`).
- The file column itself embeds a comma: `FdFile.String()` renders `name%(fd,FLAGS)` (`internal/file/file.go:120-136`), so every file-bearing row splits into 6 comma-fields while file-less rows split into 5.
- No CSV quoting is used (`encoding/csv` is not involved; a kernel `comm` may legally contain a comma within its 16 bytes, which would shift the row further).

A consumer aligning row columns to the printed header gets wrong values for `pid.tid`, `name`, `ret`, `notice`, and `file`. See Finding F2 for a suggested fix.

### 4.4c — `-plain` promotes default aggregate-only rates to 1 — **PASS**

Evidence:
- `Config.IsRawOutputMode()` returns `PlainMode || FlamegraphOutput || ParquetPath != ""` (`internal/flags/flags.go:93-95`) — exactly the three raw modes.
- `resolveSamplingRates` (`flags.go:281-284`): after merging defaults + user overrides, "In raw output modes … aggregate-only defaults (rate 0) would silently suppress ring-buffer events. Promote those defaults to rate 1 unless the user explicitly requested rate 0."
- `promoteAggregateOnlyForRawOutput` (`internal/flags/sampling.go:52-63`) promotes the six default aggregate-only syscalls (`futex`, `futex_wait`, `futex_wake`, `futex_requeue`, `futex_waitv`, `clock_gettime` — `sampling.go:9-16`) and **preserves user-explicit overrides** (`-syscall-sampling-syscalls futex=0` stays 0).
- The promoted rates actually reach the kernel: `setupBPFModule` → `applySyscallSamplingRates(cfg, bpfModule)` (`internal/ior_bpfsetup.go:67`) writes them into `syscall_sampling_rate_map` (`internal/syscall_aggregate_consumer.go:270-283`), consumed in-kernel by `ior_should_emit_trace` in `internal/c/filter.c` (rate 1 emits all events; rate 0 emits none).
- Locked by tests, all run green here: `TestPlainModePromotesAggregateOnlyDefaults` (`sampling_test.go:106-120`: all six defaults → 1), `TestFlamegraphModePromotesAggregateOnlyDefaults` (`:122-130`), `TestParquetModePromotesAggregateOnlyDefaults` (`:132-140`), `TestPlainModePreservesExplicitAggregateOnly` (`:142-155`: explicit `futex=0` stays 0 while `clock_gettime` is promoted), `TestTUIModeKeepsAggregateOnlyDefaults` (`:157+`: TUI keeps 0). The root-gated integration test `TestPerSyscallSamplingAggregateOnlySuppressesRingbufEvents` (`integrationtests/sampling_test.go:4-33`) asserts the explicit-zero semantics end-to-end in `-flamegraph` output (`openat=0` absent, `close` present).

### 4.4d — CSV rows contain all documented fields (timestamp, pid, tid, comm, syscall, path, latency_ns, bytes, requested_sleep_ns, etc.) — **FAIL for `-plain` (Finding F3; the plan's field list belongs to the stream-export CSV / Parquet schema)**

`-plain` rows carry only: gap (`durationToPrevNs`), latency (`durationNs`), merged `comm@pid.tid`, merged `name=>ret`, and the file column. There is **no timestamp, no bytes, no requested_sleep_ns, and no separate pid/tid columns** in the row format (`pair.go:121-150`; the helper transcript in 4.4b shows the complete row). The field set the plan names matches a *different*, richer output of this project:
- the **TUI stream-export CSV** (`ior-stream-<ts>.csv`, AGENTS.md's documented export path): header `seq,time_ns,gap_ns,latency_ns,comm,pid,tid,syscall,fd,ret,bytes,file,error,family,requested_sleep_ns` (`internal/tui/eventstream/export.go:185`, rows at `:186-206`), test-locked by `TestWriteStreamCSVAppendsFamilyColumn` (`export_test.go:201-241`, run green here) — that format contains every listed field (timestamp=`time_ns`, latency=`latency_ns`, bytes, requested_sleep_ns, separate pid/tid);
- the **Parquet schema** (4.3c), whose 21 columns also match the plan's field list.
The plan conflates `-plain` with the stream-export/Parquet schema. The stream-export format is complete and correct; `-plain` itself is the reduced legacy format. See Finding F3.

**Item 4.4 verdict: (a) BLOCKED-needs-root; (b) FAIL (F2 — header/row mismatch); (c) PASS; (d) FAIL (F3 — documented fields absent from `-plain`; present in the stream-export CSV and Parquet, which the plan appears to conflate with `-plain`).**

---

## Findings

**F1 — MEDIUM (plan/doc-vs-code drift; affects 4.2a-c and plan 8.2.3, AGENTS.md)** — The `.ior.zst` file is a **zstd-compressed gob-serialized `map[recordKey]Counter`**, not collapsed-stack text. Verified: `zstdcat` output is binary gob with gob type descriptors and zero `;` characters; no collapsed-stack writer or `.ior.zst → flamegraph.pl` converter exists anywhere in the repo (grep over `internal/`, `cmd/`, `tools/`); `flamegraph.LoadFromFile` is consumed only by integration tests and the testflames fixture; `recorder.go:5-6` labels the format "legacy". Consequence: the documented workflow (`zstdcat *.ior.zst | flamegraph.pl`) cannot produce an SVG; AGENTS.md's "compressed collapsed stacks for offline FlameGraph generation" misdescribes the artifact. The aggregation itself is correct and round-trips (4.2a evidence). *Repro*: `go run ./audit/check/flameroundtrip` then `zstdcat <file> | grep -c ';'` → 0. *Suggested fix* (not applied): either add a tiny converter subcommand (LoadFromFile + buildFrames → `frame;frame… count` lines, e.g. reusing `LiveTrie`-style frame building) or correct AGENTS.md/the audit plan to describe the actual record-store format and its supported consumers.

**F2 — MEDIUM (output-format bug, `-plain`)** — The `-plain` header (`durationToPrevNs,durationNs,comm,pid.tid,name,ret,notice,file`, `internal/event/pair.go:119`, 8 columns) does not describe the rows emitted by `Pair.String()` (`pair.go:121-150`, 5 fields): `comm` and `pid.tid` are merged with `@`, `name` and `ret` are merged with `=>`, the `notice` column is never emitted (vestigial since commit `2c5499a`, 2025-04-16), and the unquoted file column embeds a comma (`name%(fd,FLAGS)`, `internal/file/file.go:120-136`), so file-bearing rows split into 6 comma-fields. Machine-parsing `-plain` output against its own header yields wrong column values. *Repro*: any `-plain` run, or root-free via the helper transcript in 4.4b. *Suggested fix*: either emit rows that match the header (separate `comm`, `pid.tid`, `name`, `ret` columns; drop or implement `notice`; quote via `encoding/csv`) or change the header to the actual 5-field layout and document it.

**F3 — MEDIUM (plan-vs-code drift, `-plain` field set)** — `-plain` rows lack timestamp, bytes, `requested_sleep_ns`, and separate pid/tid columns; the plan's "all documented fields" list corresponds to the TUI stream-export CSV (`internal/tui/eventstream/export.go:185`, `ior-stream-<ts>.csv`) and the Parquet schema, both of which are complete and test-locked. *Repro*: compare `pair.go:121-150` against the export header. *Suggested fix*: document `-plain`'s actual reduced column set (ideally while fixing F2), or extend `-plain` to emit the full `streamrow.Row` schema like the stream export.

**F4 — MEDIUM (bug, Parquet `filter_epoch` in TUI recordings)** — Rows recorded after an **in-place** runtime filter swap carry a stale `filter_epoch`. `tui.go:95-96` documents "filterEpoch increments on every filter change and is stored in parquet rows" and the TUI does advance the bindings' epoch on every change (`tui.go:1085, 1125`), but the recording printCb stamps rows with `rt.filterEpoch` (`internal/ior.go:265`), a value copied once at session wiring (`ior.go:234`). The preferred in-place swap path (`applyLiveFilter`, `tui.go:175-189`) never rebuilds the session, so pre-swap and post-swap rows in the same recording share one epoch and cannot be distinguished — contradicting `docs/parquet-querying.md:35` ("Filter generation at capture time"). Full trace restarts stamp correctly (test-locked by `TestTuiTraceStarterFromRunTracePersistsRecorderAcrossRestarts`, epochs 0→1); headless `-parquet` is unaffected (always 0; content filters rejected). *Repro* (static chain): `ior.go:234` (copy) → `tui.go:1085` (advance, no rebuild) → `ior.go:265` (stamps frozen value). *Suggested fix*: capture a `FilterEpoch() uint64` provider (closure over the runtime bindings) instead of the value, and read it at record time; add a regression test asserting the epoch advances across an in-place swap while a recorder is attached.

**F5 — INFO (performance observation; cross-ref Domain 9)** — The gated stress test (`TestLiveTrieStressHighRateConcurrentSnapshot`, run with `IOR_STRESS_TEST=1`) reports ingest throughput of ~947 events/sec with 3 readers polling `SnapshotJSON` every 2 ms at 50 000 distinct paths: every ingest bumps the version, so each reader tick rebuilds and re-marshals the full tree (O(N log N)). The production flame tab uses the `SnapshotTree` cache with the same invalidation pattern at the 250 ms fast-refresh cadence — correctness is unaffected (memory bound respected, totals exact), but high-cardinality traces pay a full rebuild per refresh tick.

**F6 — INFO (dead/test-only code paths)** — (a) `eventLoopConfig.collapsedFields`/`countField` are populated at `internal/ior.go:386-389` but never read by the event loop (grep confirms zero readers) — leftovers from before the LiveTrie moved to RuntimeBuilder; (b) `internal/flamegraph/trie.go`'s `trie.add`/`computeTotals` and `iorData.merge`/`serialize`/`deserialize` have only test callers. Harmless; pruning would reduce confusion.

**F7 — INFO (by-design divergence in raw-mode counts)** — In all three raw modes, syscalls with a user-explicit rate of 0 contribute **no rows and no aggregate counts** (there is no aggregate sink; promotion preserves explicit zeros — `sampling.go:58-63`). A default-listed syscall (e.g. `futex`) therefore shows TUI aggregate totals in TUI mode but zero rows in `-plain`/`-flamegraph`/`-parquet` unless promoted. Documented in the flag help (`0=aggregate-only`) and locked by `TestPerSyscallSamplingAggregateOnlySuppressesRingbufEvents`; worth a docs note next to the promotion rule in AGENTS.md.

**F8 — INFO (known, out of scope, do-not-fix per instructions)** — The working tree carries the uncommitted deletions of `docs/syscall-tracing-plan.md` (causing the known `mage test` failure `TestSyscallTracingPlanBytesClassificationStaysInSync`) and `docs/clickhouse-streaming-plan.md` (not referenced by any live doc). Not restored or modified, per audit constraints.

**Cross-references to other domains**: the TUI flame tab's live rendering of `SnapshotTree` and the recording modal's start/stop cycle are Domain 5 items (5.3, 5.6); the stream ring buffer's export snapshot copying is Domain 2 (2.3); the aggregate-only kernel/user-space machinery behind the promotion rule (4.4c) is Domain 3 (3.4) / Domain 6 (6.3); BPF-side rate-map semantics are Domain 1 (1.2).

---

## Domain Summary

Domain 4 was audited at commit `90b6569` statically, with targeted non-mage test runs (all green, race-clean, plus the opt-in livetrie stress test), a root-free round-trip of the real `.ior.zst` recorder, and — for Parquet — an independent pyarrow 21.0.0 read-back of a file produced through the production recorder path; every bullet requiring a live root trace is marked BLOCKED-needs-root per the audit instructions, with the equivalent live behavior covered by code review plus the repo's root-gated integration tests. **Verdict counts over the 16 plan bullets: 7 PASS, 4 FAIL, 0 N-A, 5 BLOCKED-needs-root; per item: 4.1 PASS (4/4), 4.2 mixed (1 FAIL — the format claim — plus 3 BLOCKED runtime bullets), 4.3 mixed (2 PASS, 1 BLOCKED, 1 FAIL on filter-epoch stamping), 4.4 mixed (1 PASS, 2 FAIL, 1 BLOCKED).** The live trie is in excellent shape: ingest builds the exact configured frame path from `CollapsedFields`/`CountField` with additive, race-clean aggregation over a closed six-key enum (comm/tracepoint/path/pid/tid/flags — no arbitrary "custom" fields, a small plan drift), reset swaps in a fresh root and invalidates both snapshot caches so nothing leaks, and all livetrie tests including the 50 k-event stress run pass. The offline recorder's aggregation and atomic `<hostname>-<name>-<timestamp>.ior.zst` publication are correct, but the file is a gob-in-zstd record store, not the collapsed-stack text the plan, Domain 8.2.3, and AGENTS.md promise — there is no `flamegraph.pl` path from it, which is the domain's most significant drift (F1). Parquet is the strongest output: a 21-column schema that matches both its documentation and an independent reader, faithful lineage from the generated event structs, `requested_sleep_ns` populated for sleep syscalls, a bounded 4096-slot queue with background batching that aborts loudly on overflow, and correct exclusion of filtered-out rows — marred only by the stale `filter_epoch` stamped across in-place filter swaps (F4). Plain mode's sampling promotion is fully implemented and test-locked, but its printed header actively misdescribes its rows (merged `@`/`=>` fields, a never-emitted `notice` column, an unquoted comma inside the file column — F2) and it lacks the timestamp/bytes/requested_sleep_ns fields the plan attributes to it (those live in the TUI stream-export CSV and Parquet — F3). None of the findings involve data corruption in the artifacts that are produced; F1 (format/docs) and F4 (epoch fidelity) deserve follow-up first, F2/F3 need a documented decision on `-plain`'s intended format, and the runtime claims that remain blocked here (workload trace → zstdcat → SVG, live count matching, live `-plain`/`-parquet` runs) should be re-executed once root is available, using the plan's commands as written.