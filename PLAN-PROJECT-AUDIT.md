# I/O Riot NG (ior) — Project Overview

> Historical project overview and audit plan. It records the scope used for the 2026 audit; use [README.md](./README.md) and [AGENTS.md](./AGENTS.md) for current behavior.

## What It Is

**I/O Riot NG** (abbreviated **ior**) is a Linux-only, BPF-based tracing tool that intercepts synchronous system calls and analyses how long each one takes. It is the spiritual successor to the original I/O Riot project (which used SystemTap and C). The NG rewrite is built in **Go**, **C**, and **BPF** (via `libbpfgo`).

At its core, `ior` attaches eBPF tracepoint probes to the kernel's syscall entry and exit points, captures timing and metadata for each call, and presents the results through a rich terminal UI (TUI) or headless output formats.

## What It Is Supposed To Do

### 1. Trace Synchronous I/O Syscalls
- Classify ~300+ Linux syscalls into the families **FS**, **Network**, **Memory**, **IPC**, **Process**, **Signals**, **Time**, **Polling**, **Security**, **AIO**, **Sched**, and **Misc**, and attach BPF probes to the selected subset. **Default attach set: the FS family only** — every other family is opt-in via `-trace-families` / `-trace-kinds` / `-trace-syscalls` (`internal/tracepoints/dimension_selector.go`).
- Capture enter/exit event pairs to compute per-syscall latency.
- Classify syscalls by payload direction: **Read**, **Write**, **Transfer**, or **Non-bytes**.
- Track additional dimensions such as file path, process name (`comm`), PID, TID, and address-space extent.

### 2. Provide a Real-Time TUI Dashboard
- Launch with an interactive **PID picker** (searchable process list) so the user can select which process(es) to trace.
- Present a multi-tab dashboard inside the terminal using the **Bubble Tea** TUI framework:
  1. **Flamegraph** — live, in-terminal flamegraph that rebuilds as events arrive.
  2. **Overview** — high-level summary of syscall activity.
  3. **Syscalls** — per-syscall breakdown with counts and latencies.
  4. **Files** — file-centric view of I/O operations.
  5. **Processes** — per-process aggregation.
  6. **Latency + Gaps** — histograms and timing gaps.
  7. **Stream** — live event stream (exportable to CSV).
- Support fast-refresh cadences for the flamegraph and stream tabs.
- Allow runtime filtering without restarting the BPF trace.
- Support an **export modal** (`e` key) to write the current stream snapshot to a CSV file.

### 3. Generate Offline FlameGraphs
- Aggregate traced events into a compressed gob record map (`.ior.zst`, one zstd frame wrapping a gob-encoded record map) and derive flamegraph.pl-ready collapsed stacks from recordings via `ior collapsed <file>.ior.zst`.
- Maintain a **live trie** data structure that continuously accumulates stack samples for real-time flamegraph rendering.

### 4. Support Headless / Automated Modes
- **`-plain`** — disables the TUI and emits raw CSV rows to `stdout`.
- **`-flamegraph`** — writes an aggregated `.ior.zst` recording (gob record map in a zstd frame); `ior collapsed <file>.ior.zst` derives flamegraph.pl-ready collapsed stacks from it.
- **`-parquet <path>`** — writes every traced syscall row to an Apache Parquet file for downstream analytics.
- All headless modes can be constrained by duration (`-duration`) and filters.

### 5. Offer Flexible Filtering and Sampling
- **Attach-time selectors**: `-trace-families`, `-trace-kinds`, `-trace-syscalls`.
- **Exclusion filters**: `-no-trace-families`, `-no-trace-kinds`, `-no-trace-syscalls`.
- **Global runtime filter**: apply PID, TID, path, and command-name filters dynamically inside the TUI.
- **Sampling rates**: per-family and per-syscall sampling (`0` = aggregate-only, `1` = every event, `N` = 1-in-N). Defaults keep noisy syscalls (e.g., `futex`, `clock_gettime`) in aggregate-only mode so they do not flood the event ring buffer.

### 6. Be Portable via CO-RE
- Use **libbpf CO-RE** (Compile-Once, Run-Everywhere) so a single statically linked binary can run on any BTF-enabled kernel without recompiling the BPF object per host or kernel version.
- The build produces a fully static binary (`ior`) that can be copied to any Linux host and run with `sudo`.

## Architecture at a Glance

| Layer | Responsibility |
|-------|-------------|
| `cmd/ior/main.go` | Entry point; wires TUI runners and dispatches to `internal.Run`. |
| `internal/c/` | BPF C code (`ior.bpf.c`, `filter.c`, `generated_tracepoints.c`, maps, types). |
| `internal/event/` | Decodes kernel ring-buffer payloads into typed Go event pairs. |
| `internal/eventloop*.go` | Drives the BPF ring-buffer consumer, matches enter/exit pairs, and fans out to downstream sinks. |
| `internal/statsengine/` | In-memory accumulator and snapshot engine for dashboard metrics. |
| `internal/flamegraph/` | Live trie, offline recorder, and test fixtures for flamegraph data. |
| `internal/tui/` | Bubble Tea orchestration, key maps, styles, screen routing, and the export modal. |
| `internal/tui/dashboard/` | Tab renderers (flamegraph, overview, syscalls, files, processes, latency, stream). |
| `internal/flags/` | CLI flag parsing, config construction, and trace-filter building. |
| `internal/generate/` | Code generators that parse `/sys/kernel/tracing` to produce C and Go tracepoint handlers and type mappings. |

## Key Output Artifacts

- **TUI dashboard** (default) — interactive real-time view.
- **`ior-stream-<timestamp>.csv`** — explicit CSV export from the TUI stream tab.
- **`.ior.zst`** — compressed collapsed stacks for offline FlameGraph generation.
- **Parquet files** — columnar storage for bulk trace analytics.

## Build & Deployment Model

- Build orchestration uses **Mage** (not Make).
- Primary build path: `mage buildDocker` compiles a fully static binary inside a Rocky Linux 9 container.
- Cross-glibc targeting: `mage buildDockerEl8` produces `ior.el8` for RHEL/Rocky/Alma 8 hosts.
- Native builds are supported on Fedora / Rocky Linux 9 with local Go, clang, and `libbpfgo`.
- Code generation (`mage generate`) is required after modifying tracepoint definitions.

## Target Audience

- Systems engineers and SREs who need to understand which syscalls are consuming time in a running process.
- Developers debugging I/O latency, path-level hotspots, or syscall-level performance regressions.
- Anyone who wants an in-terminal, real-time alternative to `strace -T` combined with FlameGraph visualization.

---

# Audit Plan — Verifying Correctness of All Functionality

This section defines a structured audit plan an independent auditor should execute to verify that every documented behavior, invariant, and output format is implemented correctly. The plan is broken into ten domains. For each domain, the auditor must inspect source code, run automated tests, perform targeted manual experiments, and record pass/fail conclusions with evidence.

---

## Domain 1 — BPF Kernel-Side Correctness

**Goal**: ensure the eBPF programs safely and accurately capture syscall metadata, respect filters, and forward events to the ring buffer without corruption or verifier violations.

### 1.1 Tracepoint Coverage & Accuracy
- [ ] Verify that `internal/tracepoints/generated_tracepoints.go` contains the exact set of tracepoints listed in `docs/syscall-tracing-plan.md`.
- [ ] Cross-check each generated tracepoint handler in `internal/c/generated_tracepoints.c` against the kernel's `syscalls/sys_enter_*` and `syscalls/sys_exit_*` tracepoint layouts using `/sys/kernel/tracing/events/syscalls/` on a target host.
- [ ] Confirm that `enter` handlers record `pid`, `tid`, `timestamp`, `trace_id`, and syscall-specific arguments (e.g., `fd`, `path`, `size`, `flags`).
- [ ] Confirm that `exit` handlers capture the return value (`ret`) and complement the `enter` event with the same `pid`/`tid` identity.
- [ ] Verify that `internal/generate/` regenerates the exact same `generated_tracepoints.c` and Go files when run against the target kernel's tracing directory (`mage generate`).

### 1.2 BPF Map & Ring Buffer Integrity
- [ ] Inspect `internal/c/maps.h` for map definitions: ring buffer (`event_map`), enter-state map (`syscall_enter_state_map`), aggregate map (`syscall_aggregate_map`), sampling-rate map (`syscall_sampling_rate_map`), and context maps (`socketpair_ctx_map`, `pipe_ctx_map`, `eventfd_flags_map`).
- [ ] Verify that the ring buffer map size (`EventMapSize`) matches the value wired through `flags.Config` and `bpfsetup.go`. Note: `maps.h` declares a compile-time default (`1 << 24`), but `resizeBPFMaps` in `bpfsetup.go` overrides it at load time from `cfg.EventMapSize` (itself defaulting to `DefaultEventMapSize` = 65536 in `internal/config`).
- [ ] Check that map lookups and updates in BPF code use `BPF_ANY` semantics (not `BPF_NOEXIST` / `BPF_EXIST`) for enter-state, aggregate, and context maps. Verify that `BPF_ANY` is appropriate for each call site (e.g., enter-state should overwrite a stale entry rather than fail on `BPF_NOEXIST`).
- [ ] Confirm that `internal/c/filter.c` enforces PID and TID filtering at the **kernel side** via global variables (`PID_FILTER`, `TID_FILTER`, `IOR_PID_FILTER`) before events are emitted to the ring buffer. Note: comm and path filtering are **not** performed in BPF; they are applied in the Go-side event loop (`globalfilter`).

### 1.3 BPF Verifier & Safety
- [ ] Build the BPF object (`mage build`) and confirm zero verifier warnings on kernels 5.x, 6.x, and the CI/development kernel.
- [ ] Audit `internal/c/ior.bpf.c` and `filter.c` for unbounded loops, null-pointer dereferences, or out-of-bounds memory accesses that could fail the verifier.
- [ ] Confirm that all helper calls (`bpf_get_current_pid_tgid`, `bpf_ktime_get_boot_ns`, `bpf_probe_read_user_str`, etc.) use the correct return-code handling. Note: the BPF code uses `bpf_ktime_get_boot_ns` (not `bpf_ktime_get_ns`) for timestamps; verify that the Go-side reader (`internal/event/` and `internal/types/`) uses matching clock semantics.
- [ ] Verify that string reads from user space (`filename` in `open_event`, `comm` in event structs) are bounded by `MAX_FILENAME_LENGTH` (256) and `MAX_PROGNAME_LENGTH` (16) respectively, as defined in `internal/c/types.h`.

---

## Domain 2 — Event Loop & Data Pipeline

**Goal**: ensure the Go-side event loop consumes the ring buffer without loss, correctly pairs enter/exit events, and fans out to downstream consumers.

### 2.1 Ring Buffer Consumption
- [ ] Review `internal/ior_bpfsetup.go` (where `bpfModule.InitRingBuf("event_map", ch)` and `rb.Poll(300)` are called) and `internal/ior.go` (`setupTraceInfra` which calls `setupEventChannel` and wires teardown including `rb.Stop()`) to confirm that the ring buffer is initialised with the correct map name and that the polling goroutine is started.
- [ ] Verify that the Go channel (`ch`) between the ring-buffer poller and the event loop has bounded capacity (`DefaultChannelBufferSize` = 4096 in `internal/config`); confirm what happens when this channel fills (events from the ring buffer are dropped by libbpfgo, not silently accepted).
- [ ] Confirm that the consumer gracefully handles `ctx.Done()` by stopping the ring buffer (`rb.Stop()`) before closing the BPF module (`bpfModule.Close()`). Verify this in the `teardown()` function in `internal/ior.go`.

### 2.2 Enter/Exit Pair Matching
- [ ] Review the pairing logic in `internal/eventloop_state.go` (`pairTracker`). Confirm that pending enter events are keyed by **TID alone** (`map[uint32]*event.Pair`), not by a composite key. This is correct because Linux syscalls are blocking per TID — only one syscall can be in-flight per TID at a time.
- [ ] Verify that unmatched enter events are evicted by **LRU size-based pruning** (default cap `defaultMaxPendingEnterEvs` = 16384), not by a timeout. The `prune()` method evicts oldest entries when the map exceeds the limit; confirm this is sufficient to prevent unbounded growth.
- [ ] Verify that unmatched exit events (where no pending enter exists for the TID) are discarded — the `consume()` method returns `(nil, false)` and the event loop drops them.
- [ ] Check that the event loop correctly handles `name_to_handle_at` / `open_by_handle_at` pairing, which uses `pendingHandleTracker` (also TID-keyed) for cross-syscall context.
- [ ] Review `internal/event/pair.go` to confirm that the `Pair` struct captures all fields required by downstream consumers and that `Recycle()` properly zeroes all fields (`*e = Pair{}`) before returning to the `sync.Pool`.

### 2.3 Object Pooling & Memory Safety
- [ ] Verify that `event.Pair` objects are pooled using `sync.Pool` (`poolOfEventPairs` in `internal/event/event.go`) and that `Recycle()` zeroes all fields (`*e = Pair{}`) before returning to the pool.
- [ ] Run a long-duration trace (e.g., 10 minutes) and monitor RSS with `ps` or `/proc/pid/status` to confirm stable memory usage (no unbounded growth).
- [ ] Review `internal/streamrow/ringbuffer.go` to understand its semantics: `RingBuffer` is a **fixed-capacity circular buffer** (`capacity = 10000`) that **overwrites the oldest entry** when full. This is intentional for the TUI stream view (showing the latest N events), but auditors should confirm this overwrite semantics is acceptable for stream export snapshots.
- [ ] Verify that `streamrow.Row` values are value types (not pointers) in the ring buffer, so overwritten entries are not leaked; confirm that snapshot export (`Snapshot()`) copies rows safely under RWMutex.

---

## Domain 3 — Stats Engine & Aggregation

**Goal**: ensure that the in-memory stats engine computes accurate counts, latencies, byte totals, and snapshots.

### 3.1 Ingestion Accuracy
- [ ] Review `internal/statsengine/engine.go` to confirm that `Ingest(ep *event.Pair)` updates:
  - per-syscall call counts,
  - per-syscall total and average latency,
  - per-file byte totals (using the Read/Write/Transfer classification),
  - per-process metrics,
  - histogram bucket counts.
- [ ] Verify that byte classification uses the exact syscall lists documented in `docs/syscall-tracing-plan.md`.
- [ ] Confirm that address-space extent (`TotalAddressSpaceBytes`) is accumulated separately from byte-transfer metrics.

### 3.2 Snapshot Consistency
- [ ] Review `internal/statsengine/engine.go` (`Snapshot()` method) to confirm it captures all mutable state under `mu.Lock()` via `captureSnapshotInputs()`, then releases the lock before building sub-snapshots concurrently via `errgroup`. Sub-snapshots are built lock-free.
- [ ] Verify that rate fields (`SyscallRatePerSec`, `ErrorRatePerSec`, `AddressSpaceBytesPerSec`, `ReadBytesPerSec`, `WriteBytesPerSec`) are computed using `elapsed.Seconds()` where `elapsed = now.Sub(startedAt)`. Note: there is no "previous snapshot" delta — rates are computed from total counters divided by total elapsed time since last reset, not from the delta between two consecutive snapshots.
- [ ] Check that the Syscalls tab shows the per-syscall Family column, classified via `TraceId.Family()` (no per-family aggregate rows are built in the snapshot).

### 3.3 Reset Behavior
- [ ] Verify that `internal/statsengine/engine_reset_test.go` (or equivalent) passes and covers:
  - manual reset (triggered in TUI by pressing `r`, which calls `Engine.Reset()` from the runtime bindings),
  - auto-reset (the `I` key cycles the auto-reset cadence through presets: off → 10s → 30s → 1m → 2m → 5m, as shown in the TUI help),
  - reset while events are being ingested (concurrency safety — `Reset()` holds `mu.Lock()` while zeroing all counters and re-allocating sub-structures).
- [ ] Confirm that reset clears the stats engine (`Engine.Reset()`), the live trie (`LiveTrie.Reset()` or equivalent), and the dashboard snapshot source. Note: the stream ring buffer (`streamrow.RingBuffer`) also has a `Reset()` method; verify whether it is called during a baseline reset or not.

### 3.4 Aggregate-Only Sampling Sink
- [ ] Review `internal/syscall_aggregate_consumer.go` and related tests.
- [ ] Verify that when a syscall is in aggregate-only mode (`rate=0`), the kernel-side map aggregates counts/latency without emitting ring-buffer events, and the user-space consumer (`aggregateSrc`) merges these aggregates into the stats engine.
- [ ] Confirm that aggregate-only syscalls still appear in the dashboard with correct totals even though no individual stream rows are produced.

---

## Domain 4 — Flamegraph & Output Formats

**Goal**: ensure that offline and live flamegraph data structures produce correct, deterministic collapsed stacks.

### 4.1 Live Trie Correctness
- [ ] Review `internal/flamegraph/livetrie.go` to confirm that `Ingest(ep *event.Pair)` increments the correct node path based on `CollapsedFields` and `CountField`.
- [ ] Verify that the trie supports the configured collapse keys (`comm`, `tracepoint`, `path`, and any custom fields).
- [ ] Confirm that `Reset()` clears the trie without leaking child-node memory.
- [ ] Run `mage test` and confirm all `livetrie_test.go` assertions pass.

### 4.2 Offline Recorder (.ior.zst)
- [ ] Review `internal/flamegraph/recorder.go` to confirm that `AddPair()` aggregates event pairs into the record map and `Write()` serializes it as a gob-in-zstd `.ior.zst` recording (not collapsed-stack text).
- [ ] Trace a known workload (e.g., `docs/tutorial/scripts/workload.sh`), write `.ior.zst`, and read it back with `flamegraph.LoadFromFile` (or the `ior collapsed` subcommand).
- [ ] Run `ior collapsed <file>.ior.zst | flamegraph.pl > flame.svg` and confirm it renders a valid SVG with recognizable stack frames.
- [ ] Verify that counts and weights in the `.ior.zst` file match the total event count observed in the TUI for the same trace duration.

### 4.3 Parquet Output
- [ ] Review `internal/ior_parquet_sink.go` and `internal/parquet/`.
- [ ] Run a headless Parquet trace (`sudo ./ior -parquet /tmp/test.parquet -duration 5 -trace-syscalls read,write`).
- [ ] Load `/tmp/test.parquet` with `pyarrow` or `parquet-tools` and verify:
  - schema matches `internal/types/` generated structs,
  - row count equals expected number of events,
  - `requested_sleep_ns` field is populated for sleep tracepoints.
- [ ] Confirm that Parquet output respects the filter epoch (does not include rows filtered out after the trace starts).

### 4.4 Plain CSV Output
- [ ] Run `sudo ./ior -plain -duration 5 > /tmp/out.csv`.
- [ ] Verify that the CSV header and row format match the documentation.
- [ ] Check that `-plain` promotes default aggregate-only sampling rates to `1` (all events) because there is no TUI aggregate sink.
- [ ] Confirm that rows carry the seven `-plain` columns `durationToPrevNs,durationNs,comm,pid.tid,name,ret,file` (`event.EventStreamHeader`). The richer schema (`seq,time_ns,gap_ns,latency_ns,comm,pid,tid,syscall,fd,ret,bytes,file,error,family,requested_sleep_ns`) belongs to the **TUI stream CSV export**, not to `-plain`.

---

## Domain 5 — TUI Dashboard & User Interaction

**Goal**: ensure that the Bubble Tea TUI renders accurately, responds to input, and does not lose data during navigation.

### 5.1 PID Picker
- [ ] Launch `sudo ./ior` and verify the initial screen shows a searchable process list.
- [ ] Test filtering by typing process names; confirm that the list narrows in real time.
- [ ] Test arrow-key navigation and Enter selection; confirm the dashboard starts tracing the selected PID.
- [ ] Verify that the PID picker respects the configured `PidFilter` when provided via CLI.

### 5.2 Tab Navigation & Rendering
- [ ] For each tab (1–7), verify:
  - correct shortcut key activates it,
  - `tab`/`shift+tab` cycle tabs (`h`/`l` and `left`/`right` are **table-column** navigation, not tab switching),
  - tab content refreshes without crashing,
  - numeric keys (`1`–`7`) jump directly.
- [ ] Test that `H` toggles the help panel and that help text reflects the current mode (e.g., export disabled when `-tuiExport=false`).
- [ ] Verify that the Syscalls tab (shortcut `3`) shows the per-syscall Family column and that it matches the `TraceId.Family()` classification.

### 5.3 Flamegraph Tab
- [ ] Start a trace and switch to tab `1`; confirm the flamegraph renders bars with recognizable labels.
- [ ] Run a continuously varying workload and confirm bars grow/shift in real time (not just static once).
- [ ] Test with `-tui-fast-refresh=0` and confirm the flamegraph still updates: `0` clears the override and the flame/stream tabs fall back to their built-in 200ms tick constants (high-frequency refresh is never fully disabled).

### 5.4 Stream Tab & Export
- [ ] Switch to the Stream tab and confirm live rows appear with correct fields.
- [ ] Press `e` to open the export modal; it is an **options** picker (no filename shown). Confirm that submitting it writes `ior-stream-<timestamp>.csv` — the name is generated at submit time. The filename-proposing modal is the Stream tab's `X` ("export as") modal.
- [ ] Complete the export and verify the written file contains the same rows visible in the stream snapshot (respecting any active filters).
- [ ] Verify that when `-tuiExport=false`, the `e` key hint is hidden and the export modal does not open.

### 5.5 Runtime Filter Stack
- [ ] Inside the TUI, apply filters (PID, TID, path, comm) one at a time and in combination.
- [ ] Confirm that the dashboard updates immediately without restarting the BPF trace.
- [ ] Verify that the filter stack is persisted across trace restarts (if applicable) and that the BPF probes are not re-attached.
- [ ] Check that the stream export respects the currently active filter stack.

### 5.6 Recording Modal (Parquet)
- [ ] Review `internal/tui/recordingmodal.go` — note: this is the **Parquet recording** modal (opened by pressing `R`), **not** the `.ior.zst` flamegraph recorder. The `.ior.zst` output is only produced in headless `-flamegraph` mode.
- [ ] Verify that the Parquet recording start/stop cycle (keys `R` → enter filename → `R` again to stop) creates a `.parquet` file with correct schema and row data.
- [ ] Confirm that recording does not block the event loop or UI refresh (the `parquet.Recorder` uses a bounded queue and background flush goroutine).

---

## Domain 6 — Filtering & Sampling

**Goal**: ensure that attach-time selectors, exclusion filters, runtime global filters, and sampling rates all behave exactly as documented.

### 6.1 Attach-Time Filters
- [ ] For each selector flag (`-trace-families`, `-trace-kinds`, `-trace-syscalls`), run a trace with a single value and confirm via `ps` / `proc` or BPF probe list that only matching tracepoints are attached.
- [ ] For each exclusion flag (`-no-trace-families`, `-no-trace-kinds`, `-no-trace-syscalls`), confirm that matching tracepoints are **not** attached even when an include flag would otherwise select them.
- [ ] Verify that `./ior --help` lists all valid enum values and that invalid values produce a clear error at startup.

### 6.2 PID/TID Filters (Kernel-Side) and Comm/Path Filters (User-Side)
- [ ] Run `sudo ./ior -pid <pid>` and confirm (via BPF global variable inspection or `/sys/kernel/debug/tracing/trace_pipe` if available) that events for other PIDs are dropped in-kernel by the `filter()` function in `internal/c/filter.c`. Note: PID filtering uses the `IOR_PID_FILTER` global (auto-set to `ior`'s own PID) and `PID_FILTER` global; there are **no separate BPF maps** for PID filtering.
- [ ] Run `sudo ./ior -tid <tid>` and repeat the verification. Note: TID filtering also uses a global variable (`TID_FILTER`), not a BPF map.
- [ ] Run `sudo ./ior -comm <substring>` and verify that only matching processes appear. **Important**: comm filtering is **not** performed in BPF — it is applied in the Go-side event loop via `globalfilter.Filter`. Events for all processes still cross the ring buffer; they are filtered after decoding.
- [ ] Run `sudo ./ior -path <substring>` and verify that path filtering works. **Important**: path filtering is also **user-side only** (applied in `globalfilter`), not in BPF.
- [ ] Verify that the `filter()` function in `internal/c/filter.c` always filters out `ior`'s own PID (via `IOR_PID_FILTER`) even when no explicit `-pid` is provided, so the tracer never traces itself.

### 6.3 Sampling Rates
- [ ] Review `internal/flags/sampling.go` and `internal/ior_bpfsetup.go`.
- [ ] Run with `-syscall-sampling-syscalls futex=0,read=1,write=5` (the syntax is `name=rate`; colons are rejected).
- [ ] Verify that `futex` appears only in aggregate totals (no stream rows / no Parquet rows).
- [ ] Verify that `read` emits every event.
- [ ] Verify that `write` emits roughly 1 in 5 events (statistically over a large sample).
- [ ] Confirm that in `-plain` or `-flamegraph` or `-parquet` mode, default aggregate-only rates (e.g., `futex=0`) are **promoted to `1`** because there is no TUI aggregate sink.

### 6.4 Global Filter (Runtime)
- [ ] Review `internal/globalfilter/` (especially `filter.go` and `pair.go`) and `internal/tui/filterstack.go`.
- [ ] Note that `globalfilter.Filter.MatchPair()` is a **user-space** filter that supports more dimensions than the BPF-side filter: it can match on syscall name, comm, file path, FD, latency, gap, error status, and byte count — none of which are available in the BPF filter. The BPF-side filter only matches on PID and TID (global variables). These are **not** the same semantics; the user-space filter is strictly more expressive.
- [ ] Confirm that runtime filter changes (via `filterStack.push()`) update the event loop via `SetFilter()` on `filterPtr` (an `atomic.Pointer[globalfilter.Filter]`), and that BPF probes are **not** detached or re-attached.
- [ ] Verify that the `-pid` and `-tid` CLI flags set initial BPF global variables in addition to the user-space filter, meaning those PIDs/TIDs are filtered at both the kernel and user level for consistency.

---

## Domain 7 — Build, Generation & CO-RE Portability

**Goal**: ensure that the build pipeline produces a valid, statically linked, CO-RE-enabled binary and that code generation is deterministic.

### 7.1 Code Generation Determinism
- [ ] Run `mage generate` on a clean tree and confirm `git diff` shows no changes (or only expected changes if the kernel tracepoint set differs).
- [ ] Verify that `internal/generate/` reads from `/sys/kernel/tracing` and that the generated C handlers are syntactically valid (compile with `mage build`).
- [ ] Confirm that `internal/types/generated_types.go` maps C struct fields to Go fields with correct sizes and alignments.

### 7.2 Static Linking & Portability
- [ ] Run `mage buildDocker` and confirm the resulting `ior` binary is fully static (`ldd ior` should report `not a dynamic executable` or equivalent).
- [ ] Copy the binary to a different kernel version (with BTF enabled) and run `sudo ./ior -duration 5 -plain`; confirm it starts and emits events without recompilation.
- [ ] Repeat the portability test on the `ior.el8` binary (`mage buildDockerEl8`) on a Rocky Linux 8 host.

### 7.3 CI / Test Coverage
- [ ] Run `mage world` and confirm it completes with zero errors (`clean` → `generate` → `test` → `build`).
- [ ] Run `mage testRace` and confirm no data races are detected.
- [ ] Run `mage bench` and record baseline numbers; ensure no benchmark panics.
- [ ] Run `mage integrationTest` and confirm all integration tests pass.

---

## Domain 8 — Integration & End-to-End Scenarios

**Goal**: validate complete user journeys from CLI invocation to output artifact.

### 8.1 TUI Journey
1. `sudo ./ior`
2. Select a process via PID picker.
3. Navigate all 7 tabs.
4. Apply a runtime filter.
5. Export stream to CSV.
6. Trigger a reset (`r`).
7. Stop trace (`q` or Ctrl-C).
8. Verify no kernel resources are leaked (`bpftool prog list`, `bpftool map list`).

### 8.2 Headless Flamegraph Journey
1. `sudo ./ior -flamegraph -duration 10 -name mytrace`
2. Confirm `<hostname>-mytrace-<YYYY-MM-DD_HH:MM:SS>.ior.zst` is created in the current directory (filename pattern is `<hostname>-<flamegraphName>-<timestamp>.ior.zst`; see `internal/flamegraph/iordata.go`).
3. Run `ior collapsed <hostname>-mytrace-<...>.ior.zst | flamegraph.pl > flame.svg` and confirm it renders a valid SVG with recognizable stack frames (the `.ior.zst` payload itself is a gob record map, not collapsed text).
4. Confirm total event count in the file matches TUI count for the same workload.

### 8.3 Parquet Journey
1. `sudo ./ior -parquet /tmp/bulk.parquet -duration 30 -trace-families FS,Network`
2. Confirm file is written and non-empty.
3. Load into a Parquet reader and verify schema, row count, and filter-family compliance.

### 8.4 Filtered Trace Journey
1. `sudo ./ior -trace-syscalls openat,read,write -no-trace-kinds null -pid 1234`
2. Confirm in TUI or `-plain` that only `openat`, `read`, and `write` events appear for PID 1234.

---

## Domain 9 — Performance & Resource Safety

**Goal**: ensure that `ior` does not exhaust CPU, memory, or kernel resources under heavy load.

### 9.1 CPU & Memory Profiling
- [ ] Run `mage benchProf` (or equivalent pprof-enabled build) against a high-throughput workload.
- [ ] Review the resulting CPU profile for unexpected hotspots in the event loop or stats engine.
- [ ] Review the heap profile for unbounded allocations (especially string copies, `streamrow` objects, or trie nodes).

### 9.2 Ring Buffer Backpressure
- [ ] Generate a workload with >100k syscalls/sec (e.g., tight `read`/`write` loop).
- [ ] Monitor `/sys/kernel/debug/tracing/trace_pipe` or `dmesg` for ring-buffer loss messages.
- [ ] Confirm that the event loop reports dropped events (via warning callback or stats output) rather than silently skipping them.

### 9.3 Long-Duration Stability
- [ ] Run a 1-hour trace with auto-reset enabled (`-resetTimer=30s`). Note: the actual flag is `-resetTimer` (camelCase), not `-reset-timer`.
- [ ] Verify that RSS remains stable (±10%) throughout the run.
- [ ] Confirm that the dashboard remains responsive and that tab switching does not hang.

---

## Domain 10 — Security & Privilege Model

**Goal**: ensure that privilege checks, BPF loading, and data exposure are handled safely.

### 10.1 Root Privilege Gate
- [ ] Run `./ior` (without `sudo`) and confirm it exits with a clear error message (`tracing requires root privileges (run with sudo)`).
- [ ] Review `internal/ior_mode_registry.go` to confirm the EUID check (`deps.getEUID() != 0`) is the **first statement of the `run()` method** of every trace-requiring mode handler (`plainTraceModeHandler`, `tuiModeHandler`, `headlessParquetModeHandler`), so it fires **before** any BPF module is loaded. It is not in `validate()`. Note: some modes (like `testFlamesModeHandler`) skip the root check intentionally because they don't need BPF. The root check is not in `internal/ior.go` — it is in the mode registry.
- [ ] Verify that the error constant is `errRootPrivilegesRequired` defined in `internal/ior.go`.

### 10.2 BPF Resource Cleanup
- [ ] After every trace run, run `bpftool prog list` and `bpftool map list` and confirm no orphaned `ior` programs or maps remain.
- [ ] Review the `teardown()` function created in `setupTraceInfra()` in `internal/ior.go` to confirm it calls `rb.Stop()`, `mgr.Close()` (with error logging), `releaseBindings()`, `bpfModule.Close()`, and `stopSignals()` in the correct order.
- [ ] Verify that `mgr.Close()` (which detaches BPF probes and releases kernel resources) logs any errors rather than swallowing them. The `teardown` closure contains an explicit `if err := mgr.Close(); err != nil { logln("BPF probe manager close error:", err) }` pattern.

### 10.3 Kernel Data Exposure
- [ ] Confirm that the BPF programs do not capture sensitive data beyond syscall arguments (e.g., no full memory dumps, no raw buffer contents).
- [ ] Verify that `bpf_probe_read_user_str` is bounded and that path strings are truncated to safe lengths before reaching user space.

### 10.4 Signal Handling
- [ ] Send `SIGINT` and `SIGTERM` during a trace; confirm graceful shutdown within a few seconds.
- [ ] Verify that the signal handler (in `setupTraceContext()` in `internal/ior.go`) calls `cancel()` on the context, which triggers the event loop to stop. The ring buffer stop (`rb.Stop()`) and BPF module close (`bpfModule.Close()`) happen in the deferred `teardown()` — confirm that `rb.Stop()` is called before `bpfModule.Close()`.
- [ ] In TUI mode, verify that Bubble Tea's internal cancellation cooperates with the trace context cancellation so that pressing `q` also triggers a clean shutdown.

---

## Audit Deliverables

The auditor should produce a single report containing:
1. **Per-domain checklist** with every item marked `PASS`, `FAIL`, or `N/A`.
2. **Evidence logs** for manual experiments (shell transcripts, file hashes, screenshot references).
3. **Bug findings** with severity, reproduction steps, and suggested fixes.
4. **Coverage gap analysis** identifying any functionality not covered by tests or manual experiments.
5. **Final sign-off** statement on whether the project is fit for production use on BTF-enabled Linux hosts.

---
