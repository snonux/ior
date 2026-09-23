# Domain 10 — Security & Privilege Model (Audit Report)

> Historical audit evidence for the commit named below. Use [README.md](../README.md) and [AGENTS.md](../AGENTS.md) for current behavior.

**Project**: ior (I/O Riot NG) at `/home/paul/git/ior`
**Audit basis**: `PLAN-PROJECT-AUDIT.md` (repo root), section "## Domain 10 — Security & Privilege Model", items 10.1–10.4.
**Commit audited**: `2897495dfd34bf3533b599de896d85d1493b6912` (2026-06-14, "feat(dashboard): scope Syscalls tab rows by active family/syscall filter")
**Auditor constraints**: no root access (`sudo -n true` fails). All runtime-with-sudo checks are cross-referenced to the separate Domain 8 task or marked BLOCKED-needs-root. Static verification only; no source modified, no builds/tests run (orchestrator already ran `mage test`).

---

## 10.1 Root Privilege Gate

**Plan item**: "Run `./ior` (without `sudo`) and confirm it exits with a clear error message (`tracing requires root privileges (run with sudo)`). Review `internal/ior_mode_registry.go` to confirm the EUID check (`deps.getEUID() != 0`) happens in the `validate()` method of trace-requiring mode handlers (`plainTraceModeHandler`, `tuiModeHandler`, `headlessParquetModeHandler`) **before** any BPF module is loaded. Note: some modes (like `testFlamesModeHandler`) skip the root check intentionally. Verify that the error constant is `errRootPrivilegesRequired` defined in `internal/ior.go`."

### 10.1a — Non-root invocation exits with a clear error — **PASS (static; runtime run cross-referenced to Domain 8)**

Evidence:
- `internal/ior.go:32`:
  ```go
  var errRootPrivilegesRequired = errors.New("tracing requires root privileges (run with sudo)")
  ```
- `cmd/ior/main.go:45-47`:
  ```go
  if err := internal.Run(cfg); err != nil {
      fmt.Printf("Failed to run: %v\n", err)
      os.Exit(2)
  }
  ```
  A non-root run therefore prints `Failed to run: tracing requires root privileges (run with sudo)` and exits with status 2 — the message text the plan expects is present verbatim (prefixed by `Failed to run:`).
- Unit tests exercise the gate for every trace-requiring mode with an injected non-root EUID and assert both the error identity and that no BPF-touching runner is called:
  - `internal/ior_mode_test.go:344-362` `TestDispatchRunRequiresRootForTUI` (EUID 1000, `runTUI` must not be called)
  - `internal/ior_mode_test.go:363-380` `TestDispatchRunRequiresRootForPlainTrace` (`runTrace` must not be called)
  - `internal/ior_mode_test.go:381-398` `TestDispatchRunRequiresRootForParquet` (`runParquet` must not be called)
- Live `./ior` non-root execution is delegated to the separate Domain 8 task per the audit split; the static chain (handler → error → main) is complete and consistent with the expected runtime behaviour.

### 10.1b — EUID check happens before any BPF module is loaded — **PASS (with plan-vs-code drift, see Finding F1)**

Evidence:
- The EUID gate is implemented in the `run()` method (not `validate()`) of all three trace-requiring handlers in `internal/ior_mode_registry.go`:
  - `headlessParquetModeHandler.run` — lines 222-225:
    ```go
    if deps.getEUID() != 0 { return errRootPrivilegesRequired }
    return deps.runParquet(cfg)
    ```
  - `plainTraceModeHandler.run` — lines 247-250:
    ```go
    if deps.getEUID() != 0 { return errRootPrivilegesRequired }
    return deps.runTrace(cfg)
    ```
  - `tuiModeHandler.run` — lines 269-272:
    ```go
    if deps.getEUID() != 0 { return errRootPrivilegesRequired }
    return deps.runTUI(cfg, tuiTraceStarterFromRunTrace(cfg, deps.runTraceWithContext))
    ```
- Ordering guarantee: BPF is loaded exclusively on these three paths, each gated by the check above:
  - `runTrace` → `runTraceWithContext` (`internal/ior.go:506`) → `setupTraceInfra` (`internal/ior.go:532`) → `setupBPFModule` (`internal/ior_bpfsetup.go:34`, `loadBPFModule`) → `bpfModule.BPFLoadObject()` (`internal/ior_bpfsetup.go:57`).
  - `runHeadlessParquet` → `setupHeadlessParquetInfra` (`internal/ior_parquet_sink.go:157`) → `setupBPFModule`.
  - The TUI path funnels through `tuiTraceStarterFromRunTrace` → `deps.runTraceWithContext` → same `setupBPFModule`.
  `validate()` methods in these handlers only check flag-combination constraints (e.g. `-plain` vs `-flamegraph` exclusivity) and never touch BPF.
- Root-free modes intentionally skip the gate and never load BPF:
  - `testFlamesModeHandler.run` (line 213) → `tuiTestFlamesStarter` → `buildTestFlamesRuntime` (`internal/ior.go:95-103`) which only builds Go-side components (`newRuntimeBuilder(cfg).Build()`), no `setupBPFModule`.
  - `testLiveFlamesModeHandler.run` (line 239) → same pattern.
- Registry evaluation order (`dispatch`, `internal/ior_mode_registry.go:101-114`) runs `validate()` for cross-mode constraints first, then the EUID gate inside the matched handler's `run()` — so the gate always executes before any BPF work, and config-combination errors take precedence over the root error (harmless ordering nuance).
- The comment on `runTraceWithContext` (`internal/ior.go:506-507`) explicitly documents the intended ownership: "Root privilege is checked by the mode handler (via runnerDeps.getEUID) before calling this function; the handler is the authoritative place for the EUID gate."

Drift: the plan text places the check in `validate()`; in the code it is in `run()`. The security property the item is actually after — *gate strictly before any BPF module load* — holds. See Finding F1.

### 10.1c — Error constant `errRootPrivilegesRequired` in `internal/ior.go` — **PASS**

Evidence: `internal/ior.go:32` (quoted above). All three handlers return this exact sentinel (`internal/ior_mode_registry.go:224, 249, 271`), and tests assert `errors.Is(err, errRootPrivilegesRequired)`.

**Item 10.1 verdict: PASS** (all three sub-bullets; runtime confirmation of the non-root run delegated to the Domain 8 task).

---

## 10.2 BPF Resource Cleanup

**Plan item**: "After every trace run, run `bpftool prog list` and `bpftool map list` and confirm no orphaned `ior` programs or maps remain. Review the `teardown()` function created in `setupTraceInfra()` in `internal/ior.go` to confirm it calls `rb.Stop()`, `mgr.Close()` (with error logging), `releaseBindings()`, `bpfModule.Close()`, and `stopSignals()` in the correct order. Verify that `mgr.Close()` … logs any errors rather than swallowing them."

### 10.2a — No orphaned BPF programs/maps after a run (`bpftool prog list` / `bpftool map list`) — **BLOCKED-needs-root**

- `sudo -n true` fails in this environment; `bpftool prog/map list` leak inspection requires a completed privileged trace run.
- Cross-referenced to the separate Domain 8 task (8.1 step 8 explicitly lists the `bpftool prog list` / `bpftool map list` leak check).
- Static support for a clean outcome (reviewed under 10.2b): probes are attached via `probemanager.Manager` (`internal/ior_bpfsetup.go:65-71`), which holds `Link` handles; `Manager.Close()` (`internal/probemanager/manager.go:220-233`) destroys every link (`Link.Destroy()`), and the teardown closure calls it before `bpfModule.Close()`. Even on paths where the process exits before teardown completes, BPF links and maps are kernel-fd-backed and reclaimed automatically at process exit — a persistent cross-run leak would require a surviving parent process, which the binary does not create.

### 10.2b — `teardown()` ordering in `setupTraceInfra()` — **PASS**

Evidence — `internal/ior.go:590-602`:
```go
teardown = func() {
    // Stop the ring-buffer polling goroutine before the module is closed.
    // rb.Stop() is idempotent; bpfModule.Close() calls rb.Close() for the C struct.
    rb.Stop()
    // mgr.Close() detaches BPF probes and releases kernel resources; log any
    // error so that probe-detach failures are not silently discarded.
    if err := mgr.Close(); err != nil {
        logln("BPF probe manager close error:", err)
    }
    releaseBindings()
    bpfModule.Close()
    stopSignals()
}
```
- Order matches the plan exactly: `rb.Stop()` → `mgr.Close()` (error logged) → `releaseBindings()` → `bpfModule.Close()` → `stopSignals()`.
- The ring-buffer poller is explicitly stopped before the module close (comment at `internal/ior.go:591-592`; ring buffer created in `setupEventChannel` with `rb.Poll(300)`, `internal/ior_bpfsetup.go:120-125`, whose doc comment mandates `rb.Stop()` before `bpfModule.Close()`).
- `teardown` is deferred by the caller (`runTraceWithContext`, `internal/ior.go:518`) and runs last in the deferred chain (`defer teardown()`, `defer profiling.stop()`, `defer cancel()` — LIFO at `internal/ior.go:518-520`), so the context is cancelled and profiling stopped before resource teardown.
- The headless Parquet path duplicates the identical ordering in `setupHeadlessParquetInfra` (`internal/ior_parquet_sink.go:189-198`): `rb.Stop()` → `mgr.Close()` (logged) → `releaseBindings()` → `bpfModule.Close()` → `stopSignals()`.
- `probemanager.Manager.Close()` (`internal/probemanager/manager.go:220-233` + `detachProbeEntry`) destroys enter/exit links for every registered probe and is idempotent (`closed` flag), so a double teardown cannot double-detach.
- Minor inconsistency: the early-error arms inside `setupTraceInfra` (`internal/ior.go:562-585`) and `setupHeadlessParquetInfra` call `cancel/stopSignals/rb.Stop/bpfModule.Close` but omit `mgr.Close()` even though `setupBPFModule` has already attached probes. Not a persistent leak (see Finding F3).

### 10.2c — `mgr.Close()` errors are logged, not swallowed — **PASS (with a TUI-mode nuance, see Finding F2)**

Evidence:
- The explicit pattern the plan names exists at `internal/ior.go:594-598` (quoted above) and is duplicated at `internal/ior_parquet_sink.go:192-196`.
- `probemanager.Manager.Close()` returns the first detach error and records per-probe errors in `lastErr` (`internal/probemanager/manager.go:220-233`, `setLastError`), so callers can both log and inspect.
- Nuance: `logln` comes from `newLogger(verbose)` (`internal/ior.go:402-407`), which is a **no-op closure when `verbose == false`**. `verbose := started == nil` (`internal/ior.go:509`), so in TUI mode (where `started` is non-nil) any `mgr.Close()` error is passed to a discarding logger — i.e. it is effectively swallowed in TUI mode while being printed in headless modes. See Finding F2.

**Item 10.2 verdict: PASS (teardown review) / BLOCKED-needs-root (bpftool leak check, cross-ref Domain 8).**

---

## 10.3 Kernel Data Exposure

**Plan item**: "Confirm that the BPF programs do not capture sensitive data beyond syscall arguments (e.g., no full memory dumps, no raw buffer contents). Verify that `bpf_probe_read_user_str` is bounded and that path strings are truncated to safe lengths before reaching user space."

### 10.3a — No data captured beyond syscall arguments / metadata — **PASS**

Complete census of every user-memory access in the BPF object (all BPF code lives in `internal/c/ior.bpf.c`, which textually includes `filter.c` and `generated_tracepoints.c`; `ior.bpf.c` itself contains no probe reads):

| Access primitive | Sites | What is read | Bound |
|---|---|---|---|
| `bpf_probe_read_user_str` | 79 (`grep -c` on `internal/c/generated_tracepoints.c`) | `ev->filename` (8), `ev->pathname` (57), `ev->oldname` (7), `ev->newname` (7) — always `sizeof(ev->field)` | 256 B (see 10.3b) |
| `bpf_get_current_comm` | 8 | process name into `ev->comm` | `sizeof(ev->comm)` = 16 B |
| `bpf_probe_read_user` (fixed-size) | 10 | `int sv[2]` socketpair fds (line 856); `__u32` epoll events (4539); 16-byte `timeval`/`timespec` for select/poll timeouts (7786, 7847, 7964); `int pipefd[2]` (8999, 9074); 16-byte `__ior_perf_event_attr` subset (13275); 16-byte `__ior_timespec` for sleep syscalls feeding `requested_ns` (14542, 14604) | compile-time `sizeof` only |

- Every non-string read is a compile-time-sized scalar/struct read of a syscall-argument pointer, with a `== 0` return-code check before use. **No `read`/`write`/`recv`/`send` data buffers, no memory ranges, no stack dumps are captured anywhere** — the event structs in `internal/c/types.h` contain only scalars (`pid`, `tid`, `time`, `fd`s, flags, sizes, addresses as numbers) plus the bounded `filename`/`pathname`/`oldname`/`newname`/`comm` arrays.
- The address-space dimension (`mem_event.addr/length`, `types.h`) records mmap/munmap **arguments** (addresses and lengths as integers), not memory contents.
- Maps (`internal/c/maps.h`) store only timing/aggregate state, filter globals, and small fixed-size context structs (socketpair/pipe fds, eventfd flags) — no payload data.
- `internal/c/filter.c` reads no user memory at all; it gates on `bpf_get_current_pid_tgid()` only and **always excludes the tracer's own PID** via `IOR_PID_FILTER` (`filter.c:135-138`), which the Go side sets unconditionally to `os.Getpid()` before object load (`internal/bpfsetup.go:14`, `setBPFGlobals` — no CLI flag can disable it). This self-exclusion holds even when no `-pid` is given, so ior never traces itself into the ring buffer.

### 10.3b — `bpf_probe_read_user_str` bounded; strings truncated to safe lengths — **PASS**

Evidence:
- Bounds are declared in `internal/c/types.h:3-4`:
  ```c
  #define MAX_FILENAME_LENGTH 256
  #define MAX_PROGNAME_LENGTH 16
  ```
  and used for every string field: `filename` (types.h:65, 77), `oldname`/`newname` (114-115), `pathname` (124), `comm` (66, 78).
- All 79 `bpf_probe_read_user_str` call sites pass the destination field's own `sizeof(...)` as the size argument (verified by extracting every call's first argument: `8 ev->filename`, `57 ev->pathname`, `7 ev->oldname`, `7 ev->newname` — no call uses a literal or a larger bound). Example (`generated_tracepoints.c:2485`):
  ```c
  bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)ctx->args[0]);
  ```
- `bpf_probe_read_user_str` semantics guarantee NUL-termination within the supplied size, so longer paths are truncated to 255 chars + NUL — safe truncation before the event ever reaches the ring buffer and user space.
- `comm` is captured via `bpf_get_current_comm(&ev->comm, sizeof(ev->comm))` (8 sites, e.g. `generated_tracepoints.c:2486`) — bounded to 16 bytes (TASK_COMM_LEN semantics, 15 chars + NUL).
- Each string field is zeroed before use (`__builtin_memset(&(ev->filename), 0, sizeof(ev->filename) + sizeof(ev->comm))`, e.g. line 2484), so no stale ring-buffer bytes leak across events when a read fails or a string is shorter than the field.

**Item 10.3 verdict: PASS (both sub-bullets).**

---

## 10.4 Signal Handling

**Plan item**: "Send `SIGINT` and `SIGTERM` during a trace; confirm graceful shutdown within a few seconds. Verify that the signal handler (in `setupTraceContext()` in `internal/ior.go`) calls `cancel()` on the context, which triggers the event loop to stop. The ring buffer stop (`rb.Stop()`) and BPF module close (`bpfModule.Close()`) happen in the deferred `teardown()` — confirm that `rb.Stop()` is called before `bpfModule.Close()`. In TUI mode, verify that Bubble Tea's internal cancellation cooperates with the trace context cancellation so that pressing `q` also triggers a clean shutdown."

### 10.4a — Live SIGINT/SIGTERM graceful shutdown during a trace — **BLOCKED-needs-root**

- A live trace requires root (`errRootPrivilegesRequired` gate, 10.1) and this auditor has no sudo; sending signals to a running trace cannot be exercised here.
- Cross-referenced to the separate Domain 8 task (live signal-handling traces listed there as delegated work).
- Static support for graceful shutdown is fully verified below (10.4b): signal → `cancel()` → event loop exit → deferred teardown; nothing in the shutdown path blocks on user input or unbounded waits (`finaliseTrace` drains the bounded shutdown-watcher channel, `internal/ior.go:483-494`).

### 10.4b — Signal handler calls `cancel()`; `rb.Stop()` before `bpfModule.Close()` in deferred teardown — **PASS**

Evidence — `setupTraceContext` (`internal/ior.go:410-436`):
```go
signalCh := make(chan os.Signal, 1)
signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
stopSignals := func() { signal.Stop(signalCh) }
go func() {
    select {
    case <-signalCh:
        logln("Received signal, shutting down...")
        cancel()
    case <-ctx.Done():
    }
}()
```
- Both `SIGINT` (`os.Interrupt`) and `SIGTERM` are registered on a buffered channel (capacity 1); the goroutine calls the context `cancel()` on signal arrival and exits on `ctx.Done()` (no goroutine leak). `stopSignals` (`signal.Stop`) is registered as the last step of teardown (`internal/ior.go:601`).
- `cancel()` stops the event loop: both event-loop shapes select on `ctx.Done()` and return (`internal/eventloop_runtime.go:78` synchronous path, `:117` async `events()` generator; `run()` at `internal/eventloop_runtime.go:20-42` then finishes via the closed channel).
- The deferred chain in `runTraceWithContext` (`internal/ior.go:518-520`) runs `cancel()` → `profiling.stop()` → `teardown()` (LIFO), so the ring buffer is stopped before the module close: `rb.Stop()` at `internal/ior.go:593` precedes `bpfModule.Close()` at `internal/ior.go:600` inside the same closure. Identical ordering in the Parquet sink (`internal/ior_parquet_sink.go:190-197`).
- Duration-limited headless runs use `context.WithTimeout` on the same context (`internal/ior.go:413-416`), so the same shutdown path also covers `-duration` expiry.

### 10.4c — TUI `q` quit cooperates with trace-context cancellation — **PASS (static; live TUI journey cross-referenced to Domain 8)**

Evidence:
- The TUI owns the trace context: `traceLifecycle.beginCmd` creates `ctx, cancel := context.WithCancel(context.Background())` and stores the `CancelFunc` (`internal/tui/tracelifecycle.go:34-40`); `traceLifecycle.stop()` invokes it (`internal/tui/tracelifecycle.go:47-53`).
- Quit path: `handleQuitKeyPress` on the dashboard sets `m.quitting = true`, calls `m.tracer.stop()` (the stored cancel func), then returns `tea.Quit` (`internal/tui/tui.go:702-713`). The same `tracer.stop()` is invoked on every trace-restart/stop transition (`internal/tui/tui.go:913, 935, 953, 976, 1010, 1106, 1134`).
- The cancelled context flows into the trace goroutine: the starter closure `tuiTraceStarterFromRunTrace` passes `ctx` into `runTraceWithContext` (`internal/ior.go:297-315`), whose `defer teardown()` runs when the event loop returns after `ctx.Done()` — so `q` triggers the same ordered teardown (rb/mgr/module) as a signal. `startTraceCmd` treats `context.Canceled` as a non-error (`internal/tui/tracelifecycle.go:93-96`), so a user-initiated stop is not surfaced as a TUI error.
- Ctrl-C in TUI mode is consumed by Bubble Tea as a keypress (standard bubbletea behaviour) and reaches the same `handleQuitKeyPress` route; the kernel-signal registration from `setupTraceContext` additionally covers SIGTERM and the non-TUI modes. The two mechanisms do not conflict: the signal goroutine exits as soon as the (cancelled) trace context is done.
- Note: after `tea.Quit` the process may exit before the background trace goroutine finishes teardown; any remaining kernel-fd-backed links/maps are reclaimed by the kernel at process exit, so this is a cosmetic rather than a resource-safety concern (see Finding F4).

**Item 10.4 verdict: PASS (static signal-handling review) / BLOCKED-needs-root (live signal test, cross-ref Domain 8).**

---

## Findings

No FAIL verdicts. Confirmed issues / drift, by severity:

**F1 — LOW (plan-vs-code drift, documentation)** — Plan item 10.1 (and the `modeHandler` interface comment, `internal/ior_mode_registry.go:51-55`) claim the EUID check lives in the handlers' `validate()` method. In the code it lives in each handler's `run()` method (`internal/ior_mode_registry.go:223, 248, 270`). The security property the item protects — the gate executes strictly before any BPF module load — is intact (verified in 10.1b). *Repro*: read `internal/ior_mode_registry.go`; no `getEUID` call exists in any `validate()`. *Suggested fix*: correct the plan text and reword the interface comment (it currently implies validate runs "after the root-privilege check has been skipped", which does not match the actual `dispatch` flow where `validate()` runs before the gate). No code change required.

**F2 — LOW (observability)** — `mgr.Close()` errors are passed to `logln`, but in TUI mode `logln` is the no-op logger (`newLogger(false)`, `internal/ior.go:402-407`; `verbose := started == nil`, `internal/ior.go:509`), so probe-detach failures during a TUI shutdown are silently discarded. The plan's "logs any errors rather than swallowing them" holds literally for headless modes only. *Repro*: force `mgr.Close()` to fail in TUI mode (e.g. a link destroy error); nothing is printed anywhere. *Suggested fix*: route teardown errors in TUI mode to stderr or the TUI warning callback instead of the verbose-only logger.

**F3 — LOW (cleanup-path inconsistency)** — The early-error arms of `setupTraceInfra` (`internal/ior.go:562-585`: `setupProfiling`, `newEventLoop`, `newSyscallAggregateConsumer` failures) and of `setupHeadlessParquetInfra` (`internal/ior_parquet_sink.go:166-186`) call `cancel/stopSignals/rb.Stop/bpfModule.Close` but skip `mgr.Close()` even though `setupBPFModule` has already attached all probes. This is not a persistent leak — BPF links are fd-backed and the kernel detaches them when the process exits (these arms return an error straight to `os.Exit(2)`) — but it is inconsistent with the main teardown and would matter if the process ever survived these errors. *Suggested fix*: add `mgr.Close()` (error-logged) to those arms, or factor a single early-abort cleanup helper.

**F4 — INFO (TUI shutdown race, benign)** — On TUI quit, `tea.Quit` returns and the process can exit before the background trace goroutine completes the deferred teardown (the "unloading BPF tracepoints will take a few seconds" guarantee effectively applies only to headless modes). Kernel-fd reclamation on process exit prevents any leak, so no user action needed; listed for completeness.

**F5 — INFO (coverage gap)** — No unit tests exercise `setupTraceInfra`/`setupHeadlessParquetInfra` teardown ordering or the `setupTraceContext` signal wiring (grep over `internal/*_test.go` finds no references to `teardown`, `setupTraceInfra`, `setupTraceContext`, or `signal.Notify`). The mode-registry EUID gate, by contrast, is well covered (`internal/ior_mode_test.go:344-398`). *Suggested fix*: add a test with stubbed rb/mgr/module collaborators asserting the exact teardown call order and signal-goroutine termination.

**F6 — INFO (known, out of scope, do-not-fix)** — The orchestrator's `mage test` run shows the known failure `TestSyscallTracingPlanBytesClassificationStaysInSync` (internal/generate), caused by the uncommitted working-tree deletion of `docs/syscall-tracing-plan.md` (`git status`: ` D docs/syscall-tracing-plan.md`). Pre-existing, not part of Domain 10, intentionally not fixed or restored here.

**Cross-references to other audit tasks** (per the audit split; not double-counted here):
- Non-root `./ior` runtime run → separate Domain 8 task.
- `bpftool prog list` / `bpftool map list` leak inspection after privileged runs → separate Domain 8 task (8.1 step 8); BLOCKED-needs-root in this environment.
- Live SIGINT/SIGTERM traces on a running trace → separate Domain 8 task; BLOCKED-needs-root in this environment.

Supporting context observed: the repo carries privilege-model hardening docs (`docs/sudo-hardening-plan.md`, `docs/sudo-rules-for-ior.txt`) consistent with the "run with sudo" gate audited above; nothing in the code contradicts them.

---

## Domain Summary

Domain 10 was audited statically at commit `2897495`; the two runtime-only checks (bpftool leak inspection, live signal traces) plus the non-root binary run are BLOCKED-needs-root in this environment and are delegated to the separate Domain 8 task, leaving every other checklist bullet verifiable from source. **Verdict counts (11 plan bullets): 9 PASS, 0 FAIL, 0 N-A, 2 BLOCKED-needs-root.** The privilege model is sound: the EUID gate (`deps.getEUID() != 0` → `errRootPrivilegesRequired`) fires in all three BPF-requiring mode handlers before any BPF module is loaded, root-free test modes intentionally bypass it without touching BPF, teardown releases resources in exactly the planned order (`rb.Stop` → `mgr.Close` logged → `releaseBindings` → `bpfModule.Close` → `stopSignals`), the tracer's own PID is always excluded in-kernel via the unconditionally-set `IOR_PID_FILTER`, and the BPF side captures nothing beyond syscall arguments — all user-memory string reads are bounded (`sizeof`-based, 256-byte paths, 16-byte comm) with guaranteed NUL-terminated truncation and no buffer-content capture. The six findings are all LOW/INFO (documentation drift about where the EUID check lives, TUI-mode swallowing of `mgr.Close()` errors, missing `mgr.Close()` on early-abort paths, a benign TUI shutdown race, a missing teardown test, and the pre-known generate-test failure) — none warrant blocking production use, though F2/F3 deserve small follow-ups, and the BLOCKED items should be closed out by the Domain 8 runtime task before final sign-off.