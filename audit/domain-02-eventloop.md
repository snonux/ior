# Domain 2 — Event Loop & Data Pipeline (Audit Report)

> Historical audit evidence for the commit named below. Use [README.md](../README.md) and [AGENTS.md](../AGENTS.md) for current behavior.

**Project**: ior (I/O Riot NG) at `/home/paul/git/ior`
**Audit basis**: `PLAN-PROJECT-AUDIT.md` (repo root), section "## Domain 2 — Event Loop & Data Pipeline", items 2.1–2.3.
**Commit audited**: `1cf3892` ("audit(domain-10): security & privilege model verification report"); working tree additionally has uncommitted deletions of `docs/clickhouse-streaming-plan.md` and `docs/syscall-tracing-plan.md` (pre-existing, known).
**Auditor constraints**: no root access (`sudo -n true` fails) — live ring-buffer runtime checks are static-only or BLOCKED-needs-root. Orchestrator already ran `mage test` (all packages green except the known `TestSyscallTracingPlanBytesClassificationStaysInSync` failure in `internal/generate` caused by the working-tree deletion of `docs/syscall-tracing-plan.md`). No source modified, no `mage build`/`mage test` re-run. Targeted unit tests were re-run read-only with the mage CGO environment replicated by hand (see commands below); the pinned dependency `../libbpfgo` is at `v0.9.2-libbpf-1.5.1` (`git -C ../libbpfgo describe --tags`).

**Scope reviewed**: `internal/eventloop.go`, `internal/eventloop_state.go`, `internal/eventloop_runtime.go`, `internal/eventloop_exit.go`, `internal/eventloop_comm.go`, `internal/eventloop_output.go`, `internal/aggregate_drainer.go`, `internal/event/` (event.go, pair.go), `internal/ior.go` (`setupTraceInfra`), `internal/ior_bpfsetup.go` (`setupEventChannel`), `internal/ior_parquet_sink.go`, `internal/streamrow/` (ringbuffer.go, row.go), `internal/config/buffers.go`, `internal/c/maps.h` + `internal/c/generated_tracepoints.c` (kernel-side emit path), and libbpfgo `buf-ring.go` / `libbpf_cb.go` / `module.go`.

---

## 2.1 Ring Buffer Consumption

**Plan item**: "Review `internal/ior_bpfsetup.go` (where `bpfModule.InitRingBuf("event_map", ch)` and `rb.Poll(300)` are called) and `internal/ior.go` (`setupTraceInfra` …) to confirm that the ring buffer is initialised with the correct map name and that the polling goroutine is started. Verify that the Go channel (`ch`) … has bounded capacity (`DefaultChannelBufferSize` = 4096 in `internal/config`); confirm what happens when this channel fills (events from the ring buffer are dropped by libbpfgo, not silently accepted). Confirm that the consumer gracefully handles `ctx.Done()` by stopping the ring buffer (`rb.Stop()`) before closing the BPF module (`bpfModule.Close()`). Verify this in the `teardown()` function in `internal/ior.go`."

### 2.1a — Ring buffer initialised with correct map name; polling goroutine started — **PASS**

Evidence:
- `internal/ior_bpfsetup.go:100-107` (`setupEventChannel`):
  ```go
  ch := make(chan []byte, appconfig.DefaultChannelBufferSize)
  rb, err := bpfModule.InitRingBuf("event_map", ch)
  if err != nil { return nil, nil, err }
  rb.Poll(300)
  ```
- The map name matches the kernel-side definition: `internal/c/maps.h:1-6` declares the ring-buffer map as `event_map SEC(".maps")` (`BPF_MAP_TYPE_RINGBUF`, compile-time default `max_entries 1 << 24`).
- The compile-time size is intentionally overridden at load time: `internal/bpfsetup.go:26-29` — `resizeBPFMaps` → `resizeBPFMap(bpfModule, "event_map", uint32(cfg.EventMapSize))`, called from `setupBPFModule` (`internal/ior_bpfsetup.go:55`) **before** `BPFLoadObject` (`internal/ior_bpfsetup.go:57`), so the resize happens pre-load where libbpf accepts it. `cfg.EventMapSize` defaults to `appconfig.DefaultEventMapSize` (`internal/flags/flags.go:108`) = `DefaultChannelBufferSize * 16` = 65536 (`internal/config/buffers.go:8-9`), and negative/zero values are rejected in flag validation (`internal/flags/flags.go:304-306`).
- `rb.Poll(300)` starts the consumer goroutine: libbpfgo `RingBuffer.Poll` (`../libbpfgo/buf-ring.go:16-19`) spawns `go rb.poll(timeout)` looping over `C.ring_buffer__poll(rb.rb, 300)` (`buf-ring.go:90-110`), so a 300 ms poll timeout as documented.
- Wiring from `internal/ior.go`: `setupTraceInfra` (`internal/ior.go:533`) calls `setupEventChannel(bpfModule)` at `internal/ior.go:553` and returns `eventCh` to `runTraceWithContext` (`internal/ior.go:513`), which feeds it to `el.run(ctx, ch)` (`internal/ior.go:525`). The headless Parquet path wires the same channel (`internal/ior_parquet_sink.go:157`, `setupHeadlessParquetInfra` → `setupEventChannel`).

### 2.1b — Channel has bounded capacity 4096; overflow behaviour verified — **PASS (with plan-vs-code drift, see Finding F1)**

Evidence:
- Bounded capacity confirmed: `internal/config/buffers.go:6` — `DefaultChannelBufferSize = 4096`; used verbatim at `internal/ior_bpfsetup.go:101`.
- **Overflow semantics differ from the plan's parenthetical.** libbpfgo does **not** drop events when the channel is full — its ring-buffer callback performs a **blocking** send. `../libbpfgo/libbpf_cb.go:26-29`:
  ```go
  //export ringbufferCallback
  func ringbufferCallback(ctx unsafe.Pointer, data unsafe.Pointer, size C.int) C.int {
      ch := eventChannels.get(uint(uintptr(ctx))).(chan []byte)
      ch <- C.GoBytes(data, size)
      return C.int(0)
  }
  ```
  ior passes the plain channel to `InitRingBuf` (`internal/ior_bpfsetup.go:101-102`) with no non-blocking wrapper, so a full channel blocks inside `ring_buffer__poll`, i.e. it applies **backpressure**: the kernel ring buffer then fills, and the drop happens **kernel-side** when `bpf_ringbuf_reserve` returns NULL. All 731 generated emit sites handle that uniformly by silently skipping, e.g. `internal/c/generated_tracepoints.c:746-748`:
  ```c
  struct socket_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct socket_event), 0);
  if (!ev)
      return 0;
  ```
  (`rg -c "if \(!ev\)" internal/c/generated_tracepoints.c` → 731; no drop counter exists anywhere in `internal/c/`.)
- The property the plan actually cares about — "not silently accepted", i.e. the pipeline never fabricates or silently swallows events into a full channel — holds: every event is either delivered intact to the event loop or dropped whole at reserve time. However, the **drop itself is silent**: there is no lost-events callback for ring buffers in libbpfgo (`perfLostCallback` exists only for perf buffers, `../libbpfgo/libbpf_cb.go:19-23`), and ior's end-of-run `stats()` (`internal/eventloop.go:207-258`) reports only tracepoint counts and enter/exit ID mismatches — no ring-buffer loss telemetry. See Finding F1 and cross-reference to plan item 9.2.
- Shutdown deadlock safety of the blocking design is handled: libbpfgo `RingBuffer.Stop()` (`../libbpfgo/buf-ring.go:32-60`) spawns drain goroutines (`for range eventChan`) before `rb.wg.Wait()`, so a callback blocked on the full channel is always released during teardown.

### 2.1c — `ctx.Done()` handling; `rb.Stop()` before `bpfModule.Close()` in `teardown()` — **PASS**

Evidence:
- `setupTraceInfra` builds the teardown closure at `internal/ior.go:590-602` in the documented order:
  ```go
  teardown = func() {
      // Stop the ring-buffer polling goroutine before the module is closed.
      // rb.Stop() is idempotent; bpfModule.Close() calls rb.Close() for the C struct.
      rb.Stop()
      if err := mgr.Close(); err != nil {
          logln("BPF probe manager close error:", err)
      }
      releaseBindings()
      bpfModule.Close()
      stopSignals()
  }
  ```
  `rb.Stop()` (line 593) strictly precedes `mgr.Close()` (596), `releaseBindings()` (599), `bpfModule.Close()` (600) and `stopSignals()` (601). The identical ordering is duplicated in the headless-Parquet cleanup (`internal/ior_parquet_sink.go:216-227`) and in every early-error path of `setupTraceInfra` (`internal/ior.go:564-566, 575-577, 583-585`: `cancel(); stopSignals(); rb.Stop(); bpfModule.Close()`).
- Idempotency claim verified in the pinned dependency: `RingBuffer.Stop()` returns immediately when `rb.stop == nil` and resets `rb.stop = nil` on completion (`../libbpfgo/buf-ring.go:32-60`), so the later `bpfModule.Close()` → `rb.Close()` → `Stop()` path (`../libbpfgo/module.go:184-200`, `Module.Close` closes all owned ring buffers) is a safe no-op for the goroutine stop and still frees the C struct.
- Consumer-side `ctx.Done()` handling: the events goroutine selects on `<-ctx.Done()` and closes the pairs channel on exit (`internal/eventloop_runtime.go:99-129`); `run()` then drains and returns (`eventloop_runtime.go:14-42`). Verified live by test:
  ```
  $ go test -count=1 -v -run 'TestEventsStopsOnContextCancel|TestEventsIgnoresEmpty|TestEventsPanicInCallback' ./internal/
  --- PASS: TestEventsStopsOnContextCancelWithoutRawData (0.00s)
  --- PASS: TestEventsPanicInCallbackIsRecoveredAndNotified (0.00s)
  --- PASS: TestEventsIgnoresEmptyRawPayload (0.05s)
  ```
  (run with the mage CGO env replicated: `CGO_CFLAGS="-I$PWD/../libbpfgo/output -I$PWD/../libbpfgo/selftest/common" CGO_LDFLAGS="-lelf -lzstd $PWD/../libbpfgo/output/libbpf/libbpf.a" LIBBPFGO=$PWD/../libbpfgo`)
- Ordering guarantee at runtime: `runTraceWithContext` (`internal/ior.go:508-527`) reaches its deferred `teardown()` only after `el.run(ctx, ch)` has returned — and `run` returns only after the events goroutine exited — so `rb.Stop()` never races a live consumer; the channel close performed inside `rb.Stop()` can therefore never hit a "send on closed channel" from the (already-exited) consumer side. Signal → cancel wiring is `setupTraceContext` (`internal/ior.go:409`: `signal.Notify(SIGINT, SIGTERM)` → `cancel()`).
- Pipeline goroutine hygiene: `run()` defers `close(e.done)`, `shutdownCommResolver()` (eventloop_runtime.go:15-16; `commResolver.shutdown` closes the lookup queue and waits on `workersWG`, `internal/eventloop_comm.go:186-198`) and stops the aggregate drain loop via the returned stop func (`eventloop_runtime.go:17-18`, `internal/aggregate_drainer.go:52-72` — stop closes `stop`, waits `<-done`, then performs a final flush `handle(d.Tick())`). Final-flush-on-stop verified by test:
  ```
  $ … go test -count=1 -v -run 'TestStartAggregateDrainLoopFinalFlushesOnStop' ./internal/
  --- PASS: TestStartAggregateDrainLoopFinalFlushesOnStop (0.00s)
  ```

**Item 2.1 verdict: PASS** (all three sub-bullets; overflow-mechanism wording in the plan is inaccurate — see F1).

---

## 2.2 Enter/Exit Pair Matching

**Plan item**: "Review the pairing logic in `internal/eventloop_state.go` (`pairTracker`). Confirm that pending enter events are keyed by **TID alone** … Verify that unmatched enter events are evicted by **LRU size-based pruning** (default cap `defaultMaxPendingEnterEvs` = 16384) … Verify that unmatched exit events … are discarded — the `consume()` method returns `(nil, false)` … Check that the event loop correctly handles `name_to_handle_at` / `open_by_handle_at` pairing, which uses `pendingHandleTracker` (also TID-keyed) … Review `internal/event/pair.go` to confirm that the `Pair` struct captures all fields required by downstream consumers and that `Recycle()` properly zeroes all fields (`*e = Pair{}`) before returning to the `sync.Pool`."

### 2.2a — Pending enters keyed by TID alone — **PASS**

Evidence:
- `internal/eventloop_state.go:215-221`:
  ```go
  type pairTracker struct {
      enters    map[uint32]*event.Pair // pending enter events, keyed by TID
      enterAges map[uint32]uint64      // insertion order per TID, for LRU eviction
      prevTimes map[uint32]uint64      // previous pair's exit time per TID, for DurationToPrev
      ...
  ```
  `set` keys on `enterEv.GetTid()` (`eventloop_state.go:241`), `consume` on the exit's TID (`eventloop_state.go:254-263`; called from `tracepointExited` at `internal/eventloop_runtime.go:221`). No composite (pid,tid) key anywhere.
- The single-in-flight-syscall-per-TID invariant makes TID keying correct, and the code additionally guards the failure modes: a same-TID re-enter while an enter is pending (dropped exit) recycles the stale pair first (`eventloop_state.go:243-245`), and a wrong-syscall exit is caught by the ID adjacency check (`internal/eventloop_runtime.go:232-237`):
  ```go
  if ep.EnterEv.GetTraceId()-1 != ep.ExitEv.GetTraceId() {
      e.numTracepointMismatches++
      e.notifyWarning("Dropped tracepoint pair with mismatched enter/exit IDs")
      ep.Recycle(); return
  }
  ```
  (Convention verified against generated IDs: enter = exit+1, e.g. `1847: "enter_socket", 1846: "exit_socket"`, `internal/types/generated_types.go:36-37`.)
- Edge-case test coverage in `TestEventloop` subtests, all passing:
  ```
  --- PASS: TestEventloop/ExitOnlyTest  /EnterOnlyTest /MismatchedPairTest /OutOfOrderTest /CrossThreadTest
  --- PASS: TestEventloop (0.03s)  — ok ior/internal 0.038s
  ```
  `ExitOnlyTest` (exit with no pending enter → no output, `internal/eventloop_test.go:3007-3021`), `MismatchedPairTest` (`:3042-3076`), `OutOfOrderTest` — exit before enter dropped, "multiple enters before exit (only last should match)" (`:3079-3090`).
- Residual theoretical staleness: if an unmatched enter outlives kernel TID reuse and the recycled TID performs the *same* syscall, a mispair with garbage timing could slip past the ID check. Exposure is bounded by the LRU cap (see 2.2b) and by the `CalculateDurations` underflow clamp (`internal/event/pair.go:93-105`, Duration forced to 0 when exit < enter). This is inherent to the TID-keyed design the plan endorses — noted as an observation, not a finding.

### 2.2b — Unmatched enters evicted by LRU size-based pruning, cap 16384 — **PASS (with caveat → Finding F2)**

Evidence:
- Cap constant: `internal/eventloop.go:20` — `defaultMaxPendingEnterEvs = 16384`; applied by `pairTracker.limit()` when `maxSize == 0` (`eventloop_state.go:285-290`).
- Prune is size-based (no timeout), called on every `set` (`eventloop_state.go:249`): `prune()` (`:277-283`) evicts down to `trimTarget(limit)` via `trimLRU` (`:297-318`), which sorts keys by `enterAges` (monotonic counter, `:247`) and deletes the oldest `len(state)-target` entries. `trimTarget(limit) = limit - limit/cacheTrimDivisor` = `16384 - 4096` = 12288 (`:337-343`, `cacheTrimDivisor = 4`, `eventloop.go:22`) — i.e. prune evicts slightly *below* the cap (25% hysteresis), a minor nuance versus the plan's "evicts oldest entries when the map exceeds the limit".
- Evicted pairs are recycled back to the pool, not leaked: `trimOldestPendingPairs` passes a cleanup callback `pair.Recycle()` into `trimLRU` (`eventloop_state.go:320-326`).
- The pending-enter map itself therefore cannot grow unboundedly. Verified by test:
  ```
  $ … go test -count=1 -v -run 'TestTracepointEnteredPrunesOldestPendingPairs|TestConsumeEnterEventClearsPendingPairMetadata' ./internal/
  --- PASS: TestTracepointEnteredPrunesOldestPendingPairs (0.00s)
  --- PASS: TestConsumeEnterEventClearsPendingPairMetadata (0.00s)
  ```
  (`internal/eventloop_cleanup_test.go:11-61` asserts oldest TID evicted, newer retained, ages map trimmed in lock-step, and that `consume` clears both `enters` and `enterAges`.)
- **Caveat**: `prevTimes` (`eventloop_state.go:218`) — the third per-TID map — has **no eviction at all** (entries added in `setPrevTime`, `:270-275`, never removed). Growth is bounded only by the number of distinct TIDs ever observed, not by the 16384 cap. Same for `commResolver.comms` (`internal/eventloop_comm.go:16`). See Finding F2.

### 2.2c — Unmatched exits discarded — **PASS**

Evidence:
- `consume` returns `(nil, false)` for an unknown TID (`internal/eventloop_state.go:254-263`); the caller drops and recycles the exit event (`internal/eventloop_runtime.go:220-226`):
  ```go
  ep, ok := e.pairs.consume(exitEv.GetTid())
  if !ok {
      exitEv.Recycle()
      return
  }
  ```
- Nil-map safety (consume before any set) is documented and handled (`eventloop_state.go:252-253` comment; Go nil-map reads return zero values).
- Behavioural test: `TestEventloop/ExitOnlyTest` sends both an `exit_read` FdEvent and an exit-open RetEvent with no preceding enters and asserts **no** pairs are produced (`internal/eventloop_test.go:3007-3021` + the "expected no more events" assertion in the shared harness at `:133-137`). Full run: `--- PASS: TestEventloop (0.03s)`.

### 2.2d — `name_to_handle_at` / `open_by_handle_at` cross-syscall pairing via `pendingHandleTracker` — **PASS**

Evidence:
- Tracker is TID-keyed with its own LRU cap: `internal/eventloop_state.go:23-30` (`paths map[uint32]string; pathAges map[uint32]uint64`), `set`/`consume`/`delete`/`prune` at `:169-213`, default limit `defaultMaxPendingHandleEntries = 8192` (`internal/eventloop.go:21`), prune to `trimTarget` = 6144 via `trimOldestPendingHandles` (`:330-333`).
- Producer side — `handlePathExit` (`internal/eventloop_exit.go:94-103`): when the completed pair's enter tracepoint is `name_to_handle_at` (name comparison is valid: `TraceId.Name()` returns the bare syscall name, `internal/types/generated_types.go:52-58`, `traceId2Name[1146/1145] = "name_to_handle_at"`; constant `sysEnterNameToHandleAtName = "name_to_handle_at"` at `internal/eventloop.go:15`), a successful call (Ret ≥ 0) stores the pathname keyed by TID and recycles the pair without emitting it:
  ```go
  e.pendingHandleState().set(pathEv.GetTid(), types.StringValue(pathEv.Pathname[:]))
  ep.Recycle()
  return false
  ```
  A failed call (Ret < 0) recycles and emits nothing (`:96-99`).
- Consumer side — `handleOpenByHandleAtExit` (`internal/eventloop_exit.go:223-256`): consumes the pending pathname for the TID and registers fd→path; on a failed open (fd < 0) or malformed exit it deletes the pending entry and recycles the pair (`:228-236`); when no handle is pending it falls back to a pid-derived fd file (`:239-250`).
- Tests:
  ```
  $ … go test -count=1 -v -run 'TestPendingHandleTracker|TestOpenByHandleAtFailure' ./internal/
  --- PASS: TestPendingHandleTrackerRetainsRecentlyUsedEntries (0.00s)
  --- PASS: TestOpenByHandleAtFailureClearsPendingHandle (0.00s)
  --- PASS: TestEventloop/NameToHandleAtTest   (part of TestEventloop, ok)
  ```
  (`internal/eventloop_cleanup_test.go:94-133` covers LRU retention of pending handles and clearing on failed open_by_handle_at; the happy path is `TestEventloop/NameToHandleAtTest`.)

### 2.2e — `Pair` captures downstream fields; `Recycle()` zeroes before pool return — **PASS**

Evidence:
- `internal/event/pair.go:18-50`: `Pair` carries `EnterEv`, `ExitEv`, `File`, `Comm`, `Duration`, `DurationToPrev`, `Bytes`, `AddressSpaceBytes`, `RequestedSleepNs`, `Epoll`+`HasEpoll`, `Oldname` — every dimension the documented consumers need (stream rows consume all of them: `internal/streamrow/row.go:76-110` `New(seq, pair)`; stats engine / trie ingest the same struct). Timing semantics documented at `pair.go:7-14` and implemented with clock-skew clamps in `CalculateDurations` (`pair.go:81-107`).
- `NewPair` zeroes on checkout (`pair.go:81-85`: `*e = Pair{EnterEv: enterEv}`) and `Recycle` zeroes on return (`pair.go:182-191`):
  ```go
  func (e *Pair) Recycle() {
      if e.EnterEv != nil { e.EnterEv.Recycle() }
      if e.ExitEv != nil { e.ExitEv.Recycle() }
      // Zero all fields via struct literal to prevent stale data on pool reuse.
      *e = Pair{}
      poolOfEventPairs.Put(e)
  }
  ```
  Both the enter and exit events are themselves recycled into their own pools (`internal/types/generated_types.go:919-921` etc.). Verified by test:
  ```
  $ go test -v -run 'TestPairRecycle|TestPairCalculate' ./internal/event/
  --- PASS: TestPairCalculateDurationsFirstEvent / WithPreviousExit / NegativeDelta
  --- PASS: TestPairRecycleHandlesMissingExitEvent
  ok ior/internal/event 0.006s
  ```

**Item 2.2 verdict: PASS** (all five sub-bullets; `prevTimes` caveat recorded as Finding F2).

---

## 2.3 Object Pooling & Memory Safety

**Plan item**: "Verify that `event.Pair` objects are pooled using `sync.Pool` (`poolOfEventPairs` in `internal/event/event.go`) and that `Recycle()` zeroes all fields (`*e = Pair{}`) before returning to the pool. Run a long-duration trace (e.g., 10 minutes) and monitor RSS … Review `internal/streamrow/ringbuffer.go` to understand its semantics: `RingBuffer` is a **fixed-capacity circular buffer** (`capacity = 10000`) that **overwrites the oldest entry** when full … but auditors should confirm this overwrite semantics is acceptable for stream export snapshots. Verify that `streamrow.Row` values are value types (not pointers) in the ring buffer, so overwritten entries are not leaked; confirm that snapshot export (`Snapshot()`) copies rows safely under RWMutex."

### 2.3a — `event.Pair` pooled via `sync.Pool`; zeroing verified — **PASS**

Evidence:
- Pool: `internal/event/event.go:9-11` — `var poolOfEventPairs = sync.Pool{New: func() any { return &Pair{} }}`; lifecycle contract documented in `EventLifecycle` (`event.go:16-20`, "call Recycle exactly once").
- Zeroing on both get (`pair.go:81-85`) and put (`pair.go:182-191`) — quoted under 2.2e.
- Ownership audit — every path that emits or drops a pair recycles it exactly once (no double-put, no leak found):
  - default printCb: `fmt.Println(ep); ep.Recycle()` (`internal/eventloop.go:111`); pprof mode: `ep.Recycle()` (`internal/eventloop.go:198-204`, `configureOutputCallback`); `emit` fallback recycles (`internal/eventloop_output.go:27-34`).
  - probe-inactive wrapper recycles (`internal/ior.go:436-450`, `configureEventLoopOutput`).
  - TUI printCb recycles on all branches (`internal/ior.go:256-277`, `makeTUIEventLoopConfigurer`), flamegraph recorder path (`internal/ior.go:475-487`: `recorder.AddPair(ep); ep.Recycle()`), headless Parquet sink (`internal/ior_parquet_sink.go:37-43`: records the row then `ep.Recycle()`).
  - pairing drop paths: mismatched ID, filter mismatch (`finishPair`, `eventloop_exit.go:603-611`), malformed handlers (`recyclePair`, `:614-618`), LRU eviction (`trimOldestPendingPairs`), same-TID re-enter (`eventloop_state.go:243-245`).
  - One drop path omits the recycle (comm-filter enter drop, `internal/eventloop_runtime.go:214-216`) — harmless (GC reclaims) but a contract inconsistency: **Finding F3**.
- Note (informational, not a finding): the *typed* event pools (e.g. `poolOfOpenEvents`, `internal/types/generated_types.go:896-921`) do not zero on `Put` and rely on the next `New*Event` fully overwriting the fixed-size struct via `binary.Read` (with explicit zeroing on decode failure, `:899-904`). All struct fields are fixed-size arrays/scalars (no strings/slices — otherwise `binary.Read` would error), so no stale references can survive a reuse.

### 2.3b — 10-minute live trace with RSS monitoring — **BLOCKED-needs-root**

- A live trace requires loading the BPF object (root-gated by the mode handlers, see the Domain 10 report), and `sudo -n true` fails in this environment. Not executable here; cross-referenced to the Domain 8/9 runtime tasks.
- Static mitigation evidence collected instead: (i) all pool-backed hot objects (`Pair`, typed events) are recycled on every code path audited above except the one in F3; (ii) all pipeline maps are LRU-capped (`enters` 16384, `pendingHandles` 8192, `procFdCache` 8192, comm lookup queue 512 with non-blocking enqueue, `internal/eventloop_comm.go:177-183`) — **except** `prevTimes` and `commResolver.comms` (Finding F2); (iii) the stream ring buffer is fixed at 10000 rows; (iv) `mage testRace` was green in the orchestrator run (no data races in the event loop).
- Verdict: **BLOCKED-needs-root** for the live RSS measurement; the static memory-safety review is otherwise clean except F2/F3.

### 2.3c — `streamrow.RingBuffer`: fixed capacity 10000, overwrite-oldest; acceptable for export snapshots — **PASS**

Evidence:
- `internal/streamrow/ringbuffer.go:5` — `const RingBufferCapacity = 10000`; `NewRingBuffer` allocates exactly that (`:18-20`).
- `Push` (`:24-37`) appends while below capacity, then overwrites at `start` and advances it — overwrite-oldest semantics, and `totalPushed` keeps counting overwritten rows so loss is at least observable via `TotalPushed()` vs `Len()` (`:64-69`).
- Acceptability for export: this is the TUI "latest N events" view by design (plan acknowledges the intent); the CSV export modal (`e`) exports the current snapshot, i.e. the **most recent 10 000 rows** of the filtered stream. No documented ior artifact promises a complete event log from the TUI (headless complete-output modes are `-plain`/`-parquet`, which bypass the ring buffer and write every row). One consequence worth stating: a TUI export of a busy trace is a tail sample, not a full trace — documented behaviour, not a defect.
- Verified by tests:
  ```
  $ go test -v -run 'TestRingBuffer' ./internal/streamrow/
  --- PASS: TestRingBufferPushAndSnapshot / TestRingBufferWrapsAroundCapacity /
           TestRingBufferSnapshotOnEmpty / TestRingBufferReset
  ok ior/internal/streamrow 0.047s
  ```
  (`internal/streamrow/ringbuffer_test.go:9-115`, including wrap-around ordering assertions).

### 2.3d — `Row` values are value types; overwritten entries not leaked; `Snapshot()` copies under RWMutex — **PASS**

Evidence:
- Storage is `buf []Row` (`internal/streamrow/ringbuffer.go:12`); `streamrow.Row` is a plain value struct with value-receiver methods (`internal/streamrow/row.go:10-51`; `var _ globalfilter.Candidate = Row{}` asserts the value form, `row.go:113-114`). Overwriting `r.buf[idx] = ev` drops the last reference to the old row's strings, which the GC reclaims — no pointer-retention leak.
- `Snapshot()` (`:40-52`) copies rows into a fresh slice under `r.mu.RLock()`:
  ```go
  out := make([]Row, r.size)
  for i := 0; i < r.size; i++ {
      out[i] = r.buf[(r.start+i)%RingBufferCapacity]
  }
  ```
  in insertion order; `Push`/`Reset` hold the write lock (`:26, 74`), so a snapshot can never observe a torn buffer. `Reset` uses `clear(r.buf)` so overwritten-era strings are dropped rather than retained (`:71-80`).
- Tests: `TestRingBufferPushAndSnapshot`, `TestRingBufferWrapsAroundCapacity`, `TestRingBufferReset` (above) cover copy correctness, wrap ordering, and reset.

**Item 2.3 verdict: PASS** statically (three of four sub-bullets); the live long-duration RSS check is **BLOCKED-needs-root**.

---

## Findings

**F1 — Plan-vs-code drift: channel-full behaviour is backpressure + silent kernel-side drop, not a libbpfgo drop; no loss telemetry anywhere.**
Severity: MEDIUM (measurement integrity / observability; no corruption, no deadlock).
Where: plan item 2.1 parenthetical; `internal/ior_bpfsetup.go:100-107`; `../libbpfgo/libbpf_cb.go:26-29` (blocking `ch <-`); `internal/c/generated_tracepoints.c` (731× `if (!ev) return 0;`); `internal/eventloop.go:207-258` (`stats()` has no loss counter).
Repro (needs root, cross-ref Domain 9.2): run a >100k syscalls/s workload (e.g. a tight read/write loop) with a deliberately small `-mapSize` (e.g. 4096); the 4096-slot channel backs up, `ring_buffer__poll` stalls in the callback, the kernel ring buffer wraps, and events disappear with zero indication in the UI, `stats()`, or `dmesg`.
Suggested fix (do not apply per audit rules): keep a BPF counter (or use `bpf_ringbuf_query_stats`/`ringbuf` loss accounting) incremented on reserve failure, expose it via `stats()` and a TUI warning row; alternatively correct the plan text to describe the actual backpressure design. Cross-reference: plan item 9.2 explicitly requires drop reporting — currently unimplemented.

**F2 — Unbounded per-TID maps: `pairTracker.prevTimes` and `commResolver.comms` have no eviction.**
Severity: MEDIUM (slow monotonic memory growth on long traces with heavy thread churn; no correctness impact).
Where: `internal/eventloop_state.go:218, 270-275` (`prevTimes` never pruned — in contrast to its sibling `enters`/`enterAges`, which are LRU-capped at 16384); `internal/eventloop_comm.go:16, 90-100` (`comms` cache only ever grows).
Repro: trace a workload churning short-lived threads (e.g. a process farm or `systemd`-style spawn storms) for hours; both maps retain one entry per distinct TID ever seen. Worst case is bounded by the kernel TID space (`pid_max` ≤ 4 194 304 on 64-bit) → potentially hundreds of MB of map overhead in pathological cases.
Suggested fix: LRU-cap `prevTimes` (it already has the age-counter pattern in the same struct to copy) and cap `comms` (e.g. reuse `trimLRU`), or evict entries on observed thread-exit tracepoints (`enter_exit`).

**F3 — Enter events dropped in the comm-filter branch are never `Recycle()`d.**
Severity: LOW (contract violation only; GC reclaims the object, no leak or staleness is possible).
Where: `internal/eventloop_runtime.go:214-216` — the `else` branch of `tracepointEntered` notifies a warning but does not recycle `enterEv`, unlike the sibling filtered-enter path which does (`eventloop_runtime.go:179-181`, `ev.Recycle()`) and unlike every other drop path in the loop. The `EventLifecycle` contract says "call Recycle exactly once" (`internal/event/event.go:16-20`).
Repro: run with `-comm <pattern>`; any enter whose TID has no cached comm yet takes this branch (behaviour is asserted by `TestTracepointEnteredMissingCommWithCommFilterNotifies`, `internal/eventloop_error_handling_test.go:184-214`, which documents the drop but not the missing recycle).
Suggested fix: add `enterEv.Recycle()` after the warning in the `else` branch.

**Observations (no action required):**
- TID-keyed pairing is theoretically vulnerable to kernel TID reuse pairing a stale pending enter with a recycled TID's same-syscall exit; exposure is bounded by the 16384-entry LRU cap and the enter/exit ID adjacency check, and `CalculateDurations` clamps negative durations to 0 (`internal/event/pair.go:93-105`). Inherent to the plan-endorsed design.
- With an active comm filter, pairs whose comm has not yet been resolved are intentionally dropped (warning emitted) until the async procfs lookup completes — a documented, deliberate attribution window, not a bug.
- `prune()` evicts to 75% of the cap (`trimTarget`, `internal/eventloop_state.go:337-343`) rather than exactly to the limit — a benign hysteresis nuance versus the plan wording.

---

## Domain Summary

Domain 2 is in strong shape: all 12 checklist sub-bullets were executed, with **11 PASS** and **1 BLOCKED-needs-root** (the live 10-minute RSS run; 0 FAIL, 0 N-A). The ring buffer is wired to the correct `event_map` with a bounded 4096-slot channel, teardown provably stops polling before closing the BPF module on every path, enter/exit pairing is correctly TID-keyed with LRU-capped pending state and verified edge-case tests (exit-only, out-of-order, mismatched, cross-thread, name_to_handle_at/open_by_handle_at), and the pooled `event.Pair` plus the value-typed 10000-slot stream ring buffer are both memory-safe with copy-under-lock snapshots. Three findings were recorded: F1 (MEDIUM — the plan's claimed "libbpfgo drops on full channel" is actually backpressure plus *silent* kernel-side `bpf_ringbuf_reserve` failure, with no loss telemetry anywhere, also failing plan 9.2's reporting requirement), F2 (MEDIUM — `prevTimes` and the comm cache are the only per-TID maps without eviction and grow monotonically with distinct TIDs on long traces), and F3 (LOW — one drop path skips `Recycle()`, a pool-contract inconsistency with no runtime impact). The event loop and data pipeline are functionally correct for production use; F1's observability gap and F2's growth vector are the two items worth fixing before relying on ior for long-duration, high-churn traces.