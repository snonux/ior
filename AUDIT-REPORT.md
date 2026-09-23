# I/O Riot NG (ior) — Project Audit Report

> Historical audit snapshot at commit `2897495`. Findings describe that tree; use [README.md](./README.md) and [AGENTS.md](./AGENTS.md) for current behavior.

**Audit basis**: `PLAN-PROJECT-AUDIT.md` (repo root), all ten domains, executed 2026-08-31/09-01.
**Commit audited**: `2897495dfd34bf3533b599de896d85d1493b6912` ("feat(dashboard): scope Syscalls tab rows by active family/syscall filter").
**Environment**: Rocky Linux 9, kernel `5.14.0-687.36.1.el9_8.x86_64`, no interactive tty, no general root — live tracing was executed through purpose-scoped sudoers NOPASSWD rules (`sudo -n /home/paul/git/ior/ior`, `…/integrationtests.test`, `bpftool btf dump`, read-only tracefs `find|cat`), discovered during Domain 7.
**Method**: one fresh-context auditor per domain (Domains 1–7, 10) plus orchestrator-executed live journeys (Domains 8–9, after subagent usage limits); every plan bullet carries a verdict with file:line or command-transcript evidence in `audit/domain-01…10-*.md`; raw transcripts and read-only verification helpers under `audit/check/`.

---

## 1. Per-domain verdict summary

142 tracked bullets (138 plan bullets + 4 extra runtime evidence checks in Domain 8):

| Domain | Report | PASS | FAIL | N-A | BLOCKED |
|---|---|---|---|---|---|
| 1 — BPF Kernel-Side Correctness | `audit/domain-01-bpf.md` | 9 | 1 | 0 | 3 |
| 2 — Event Loop & Data Pipeline | `audit/domain-02-eventloop.md` | 11 | 0 | 0 | 1 |
| 3 — Stats Engine & Aggregation | `audit/domain-03-statsengine.md` | 10 | 1 | 0 | 0 |
| 4 — Flamegraph & Output Formats | `audit/domain-04-flamegraph.md` | 7 | 4 | 0 | 5 |
| 5 — TUI Dashboard & Interaction | `audit/domain-05-tui.md` | 20 | 0 | 1 | 0 |
| 6 — Filtering & Sampling | `audit/domain-06-filtering.md` | 18 | 0 | 0 | 0 |
| 7 — Build, Generation & CO-RE | `audit/domain-07-build.md` | 2 | 4 | 3 | 1 |
| 8 — Integration & E2E Journeys | `audit/domain-08-e2e.md` | 12 (+4) | 1 | 0 | 4 |
| 9 — Performance & Resource Safety | `audit/domain-09-perf.md` | 5 | 0 | 4 | 0 |
| 10 — Security & Privilege Model | `audit/domain-10-security.md` | 9 | 0 | 0 | 2 |
| **Total** | | **107** | **11** | **8** | **16** |

Highlights per domain (details in each report):

- **D1**: All 731 generated handlers verified for identity/args/bounds; maps and `BPF_ANY` semantics correct; PID/TID kernel-side gating confirmed pre-reserve in every handler. Live tracefs cross-check and verifier load blocked (root) — mitigated by x86-64 ABI spot-checks and Domain 7's root runs.
- **D2**: Ring-buffer init/poll, TID-keyed pairing, LRU prune (16384), pool recycling, teardown ordering all correct. Two unbounded per-TID maps and zero drop observability are the gaps.
- **D3**: Ingest/Snapshot/reset/aggregate-only sink all verified correct (incl. `-race` on the package); `Snapshot.Families` is now a dead data path; no concurrent-reset regression test exists.
- **D4**: Live trie and Parquet sink solid (independent pyarrow verification); `.ior.zst` is gob-in-zstd (not collapsed stacks) and `-plain` CSV header/format is wrong relative to rows; `filter_epoch` goes stale on in-place filter swaps.
- **D5**: 20/21 PASS via the 62/62 in-process integration suite (real CSV/Parquet writes, `-race` green, vet clean); export flag doesn't gate Stream shortcuts; help text says 1..8 for 7 tabs.
- **D6**: 18/18 — kernel-side PID/TID-only filtering, raw-mode rate promotion, atomic filter swap without probe re-attach, `-pid`/`-tid` dual-path consistency all verified (126 mapped unit tests + 8 root-gated integration tests).
- **D7**: Static linking fully confirmed; per-kernel regeneration byte-deterministic; but a genuine data race (HIGH), a tree-dirtying generate, a broken `mage integrationTest` target, and newer-kernel-specific committed artifacts. Real integration suite (root): 192 PASS / 1 SKIP / 9 FAIL — all nine kernel/policy-caused on el9_8.
- **D8**: All three headless journeys executed live as root: flamegraph (exact filename pattern, 73k syscalls, clean shutdown), Parquet (69,088 rows == counter, family-compliant under pyarrow), filtered trace (234k rows; only allowed syscalls, only the pinned PID). Runtime root-gate verified (exit 2, exact message). The `flamegraph.pl` step is impossible by design (gob format).
- **D9**: `mage bench` 416 results, zero panics; 60s live run RSS flat at ±0.1% under 3.2M events with exact row fidelity; `-plain` lossless at ~84k syscalls/s; `-parquet` aborts whole-run on queue-full at ~85k syscalls/s.
- **D10**: EUID gate fires before any BPF load on all three trace-requiring modes; tracer never traces itself; all string reads bounded; teardown ordering correct. Runtime checks cross-referenced to Domain 8.

## 2. Evidence index

- Per-item reports with file:line evidence: `audit/domain-01-bpf.md` … `audit/domain-10-security.md`.
- Command transcripts: `audit/check/01…10-*.log` (generate determinism ×2, build, static-linking, docker, C↔Go sizes, world, testRace ×4, integration ×2 incl. root run, e2e help/flamegraph/parquet/filtered, bench).
- Read-only verification helpers (all build clean, `gofmt` clean): `audit/check/main.go` (doc-vs-generated cross-check), `flameroundtrip/` (`.ior.zst` write/load round-trip), `parquetwrite/` (production Parquet writer smoke), `tuihelp/` (help-overlay assertion), `_gosizes/`, `cevidence/`.

## 3. Confirmed findings (severity, repro, suggested fix)

### HIGH

| ID | Finding | Repro | Suggested fix |
|---|---|---|---|
| H1 (D7 F1) | Data race in `tui/common.ApplyPalette()`: rewrites ~20 package-level style globals unsynchronized while bubbletea's renderer reads them in `View()` — also reachable at runtime via `tea.BackgroundColorMsg` → `applyTheme`. 20 race reports; 9 TUI tests fail under `-race`; `mage testRace` can never pass. | `mage testRace` (or `go test -race ./internal/tui/...`); transcripts `audit/check/07*-tui-race-*.log` | Make theme state immutable per render (styles struct threaded through models), or guard the globals with `sync.RWMutex`/`atomic.Value`; apply the initial palette before any goroutine starts. |

### MEDIUM

| ID | Finding | Repro | Suggested fix |
|---|---|---|---|
| M1 (D1 F2) | `sys_exit_seccomp` / `sys_exit_init_module` / `sys_exit_delete_module` emit `null_event` without `ret` (name-pinned classification, `internal/generate/classify.go:396-401`) → stream/CSV/Parquet rows always show `ret=0, is_error=false`. | Trace those syscalls failing; inspect rows | Un-pin the exit side to `KindRet`; `mage generate`; regenerate types. |
| M2 (D2 F1 / D9 Y2) | No drop observability: kernel-side `bpf_ringbuf_reserve` NULL drops are silent; no loss counter in BPF, `stats()`, or TUI (libbpfgo channel send is blocking → backpressure, drops happen kernel-side). | Sustained >170k events/s (D9 runs showed none at tested rates, but nothing would report it) | Per-CPU drop-counter map surfaced in stats/TUI. |
| M3 (D2 F2 / D9 Y3) | `pairTracker.prevTimes` (`eventloop_state.go:218`) and `commResolver.comms` (`eventloop_comm.go:16`) have no eviction → unbounded growth with thread-churning targets. | Long trace of a process pool; watch RSS | LRU-cap both maps like `enters` (16384). |
| M4 (D3 F1) | `Snapshot.Families` built every snapshot but has no consumer since the Non-IO tab removal (`5736381`); AGENTS.md/tutorial/plan still document tab 8. | `rg Snapshot.Families` — only producer + tests | Remove the dead path or re-consume it; fix docs. |
| M5 (D3 F2) | No test exercises `Engine.Reset()` concurrently with ingest (plan overstates `engine_reset_test.go` coverage; implementation itself is lock-safe). | — | Add a concurrent reset-vs-ingest regression test. |
| M6 (D4 F1 / D8 X1) | `.ior.zst` is a gob-in-zstd record map, **not** collapsed-stack text; the documented `zstdcat | flamegraph.pl` journey is structurally impossible (AGENTS.md + plan wrong). | `zstdcat *.ior.zst | head` (gob type descriptor visible) | Ship a collapsed-stack text mode or a converter; fix AGENTS.md/plan. |
| M7 (D4 F2 / D8 X2–X3) | `-plain` CSV: 8-column header over 5-field merged rows (`comm@pid.tid`, `name=>ret`, `file%(flags)`); unquoted comma inside the file column breaks parsers; ASCII banner/status lines share stdout with data. | `sudo -n …/ior -plain -duration 5` (see `09-e2e-filtered.log`) | Emit a header matching the rows, quote fields, route status to stderr. |
| M8 (D4 F3) | `-plain` lacks timestamp/bytes/`requested_sleep_ns` fields the plan documents (plan conflates `-plain` with the TUI stream-export CSV, which is correct and test-locked). | Compare `-plain` header vs `internal/export` schema | Align docs or add the fields to `-plain`. |
| M9 (D4 F4) | Parquet `filter_epoch` frozen at session start: in-place filter swaps advance the bindings' epoch but rows keep stamping the old one (`ior.go:234/265` vs `tui.go:1085`); only restarts stamp correctly. | Swap filter mid-recording; inspect `filter_epoch` column | Propagate the current epoch at row-stamp time. |
| M10 (D5 F1) | `-tuiExport=false` does not disable the Stream tab's `x`/`X`/`E` export shortcuts (`internal/tui/eventstream/model.go:264-301`); hints always shown. | Start TUI with the flag; press `x` — CSV still written | Gate the shortcuts and hints on the flag. |
| M11 (D7 F2) | `mage generate` overwrites `internal/c/generated_tracepoints.c` before its own strict diff gate — a failing generate leaves a 2712-line dirty tree. | Run generate where inputs are unavailable | Generate to a temp file, compare, then atomically replace. |
| M12 (D7 F3) | `mage integrationTest` target is broken: compiles `integrationtests.test` to repo root but execs it with `Dir="integrationtests"` → file-not-found, output discarded, 20.9 MB binary left behind. | `mage integrationTest` | Fix the exec path/working dir; clean up the binary. |
| M13 (D7 F4) | Committed generated artifacts are newer-kernel-specific (mseal, statmount, *xattrat, lsm_*, … absent on 5.14 el9_8): regeneration on this host produces a large diff (per-kernel regeneration itself is byte-deterministic). | `mage generate` on el9; `git diff --stat` | Document the generation host/kernel; rely on `buildDocker`'s `IOR_FORCE_GENERATE=1` flow. |
| M14 (D9 Y1) | Parquet recorder: when its bounded 4096-slot queue saturates (~85k syscalls/s sustained), the entire run aborts (`Failed to run: parquet recorder queue is full`, exit 2) and **no partial output file is written** — all captured events lost. | 4× dd workloads + `-parquet -duration 10` (D9 transcript) | Shed/block with a warning + drop counter, flush partial output on overflow; consider sizing vs `EventMapSize`. |

### LOW / INFO

D1: F3 `ptrace_event._pad` never zeroed (4 stale bytes submitted); F4 `openat2` flags never captured (design gap); F5 stale comment re `RetEvent`. — D2: F3 comm-filtered enter events skip `Recycle()`. — D3: F3 stream ring not reset on baseline resets (undocumented); F4/F5 aggregates dropped under runtime filters (intentional); sampled 1-in-N full counts never merged user-side. — D4: F5–F8 livetrie snapshot-rebuild cost under high cardinality (~947 ev/s); dead `eventLoopConfig` fields; rate-0 raw-mode zeros (by design). — D5: F2 help says "1..8" for 7 tabs; F3 vacuous export-hint test; F4 unreachable dashboard help bar; drift D1–D5 (Non-IO tab, `h`/`l` are column nav, fast-refresh=0 → 200 ms const, `e` modal semantics, stale AGENTS.md TUI section). — D6: F1 unvalidated `-pid`/`-tid` sentinels (`-pid -2` wraps to huge uint32 → silent empty trace); F2 explicit family `=0` not promoted in raw modes → family vanishes; F3 `flags.BuildTraceFilter` glue untested; F4/F5 default-rate precedence + aggregate gating under filters; drift D1–D4 (sampling syntax `name=rate`, help examples vs enums, dimension list subset, FS-only default attach set). — D7: F5 `IOR_FORCE_GENERATE=0` still forces; F6 `clean`/`world` deletes gitignored `vmlinux.h`; F7/F8 benign warnings. — D8: X4 short traces miss `openat` for long-running targets (timing caveat); X5 positive CO-RE graceful degradation (~570 attached, 32 skipped, no error). — D9: Y4 0.01–0.03% enter/exit mismatches at peak rates; Y5 positive `-plain` fidelity. — D10: F1 plan drift (`validate()` vs `run()` — property intact); F2 `mgr.Close()` errors silenced in TUI (`logln` no-op when not verbose); F3 early-error arms skip `mgr.Close()`; F4/F5 benign `tea.Quit` race with teardown; no teardown-ordering tests.

### Known pre-existing issue (decision required, not fixed per audit constraints)

The **uncommitted working-tree deletion of `docs/syscall-tracing-plan.md`** (and `docs/clickhouse-streaming-plan.md`) breaks `TestSyscallTracingPlanBytesClassificationStaysInSync` (`internal/generate`) under `mage test` — the only test failure in the suite. Domain 1 additionally observed doc-drift failures in `internal/tracepoints` when those packages were run directly (2 tests), and noted the generated sets still match the doc at HEAD. **Decision needed**: restore the docs (suite fully green), or commit the deletion and remove/rewrite the drift tests and the plan references.

## 4. Coverage gap analysis (root-gated / deferred follow-up)

A root-enabled / tty-enabled follow-up session should close:

1. **D1**: direct tracefs layout cross-check (partially covered via sudoers read rule + Domain 7 generate runs); live verifier load on 5.x/6.x kernels.
2. **D2/D9**: 10-min/1-hour RSS soak with a **thread-churning** workload (M3 risk case); `mage benchProf` CPU/heap profile review.
3. **D4/D8**: `flamegraph.pl` rendering — impossible until M6 is addressed; interactive TUI journey (tty), `bpftool prog|map list` leak checks (no sudoers rule), live SIGINT/SIGTERM delivery to a root ior (non-root cannot signal it).
4. **D7**: cross-kernel portability run on a second host with a different kernel; docker-based `buildDocker`/`buildDockerEl8` (docker unavailable here).
5. **D9**: tty responsiveness under load; 1-hour auto-reset run.
6. **Docs**: AGENTS.md and `PLAN-PROJECT-AUDIT.md` need refresh (7 tabs, Non-IO removal, `.ior.zst` format, `-plain` format, `flamegraph.pl` claims, sampling syntax).

*Closure-gate note (2026-09-03)*: item 3's `flamegraph.pl` blocker is lifted —
`ior collapsed` (M6) now produces collapsed stacks from a `.ior.zst` recording —
and item 6 is done (see §5). Items 1, 2, 4 and 5 are unchanged and still need a
root/tty/second-kernel session; item 4 additionally gates the one open
verification risk in §6 (proving `mage generate` reproduces the committed
artifacts byte-for-byte on a matching kernel).

## 5. Finding resolution status (audit closure gate, 2026-09-03)

**Verification method**: every row below was re-checked against the working tree
at commit `48aed39` by reading the code, the generated artifacts and the tests —
commit messages and task annotations were treated as claims to verify, not as
evidence. Commit ids name where each change landed.

### 5.1 HIGH

| ID | Status | Landed in | Verified how |
|---|---|---|---|
| H1 | **FIXED** | `7374f35` | `internal/tui/common/styles.go`: theme state is a single `atomic.Pointer[Theme]` (`currentTheme`); `ApplyPalette` stores a freshly built immutable snapshot, `Current()` loads it, `init()` publishes the default palette before any goroutine exists. The `internal/tui/styles.go` mirror is gone and a repo-wide grep finds no package-level mutable `lipgloss.Style` globals left in `internal/tui/**`. `mage testRace` reports zero data races (see §5.6). |

### 5.2 MEDIUM

| ID | Status | Landed in | Verified how |
|---|---|---|---|
| M1 | **FIXED** | `88ea09a` | `internal/generate/classify.go` now pins only the **enter** side (`sys_enter_seccomp`/`sys_enter_init_module`/`sys_enter_delete_module`). In `internal/c/generated_tracepoints.c`: 364 `sys_exit_*` handlers, 364 of them call `ior_on_syscall_exit(tid, …, ctx->ret)`, and **zero** exit handlers emit a `null_event`. `generated_tracepoints_result.txt` re-derives byte-identically from the committed C using the Magefile's own extraction rule (`/// ` lines, `LC_ALL=C sort`). |
| M2 | **FIXED** | `55f8cff` | `ringbuf_drop_map` (single-slot `BPF_MAP_TYPE_PERCPU_ARRAY`) in `internal/c/maps.h`; `ior_count_ringbuf_drop()` in `internal/c/filter.c`; the generator emits the counting NULL-reserve branch (`internal/generate/bpfhandler.go:92`) and **731 of 731** `bpf_ringbuf_reserve` sites in the committed C call it. Userspace: `ringbufDropCounter` (per-CPU sum) + `ringbufDropMonitor` polled once per second, wired through `attachRingbufDropCounter` from **both** `setupTraceInfra` (`internal/ior.go:646`) and `setupHeadlessParquetInfra` (`internal/ior_parquet_sink.go:205`); `stats()` always prints `ring buffer drops: N (N/s, N% of events)`. |
| M3 | **FIXED** | `b3452b9` | `pairTracker.prevTimes` is LRU-capped via `prevTimeAges` + `prunePrevTimes` + the shared `trimLRU` helper (`internal/eventloop_state.go`); `commResolver.comms` is LRU-capped via `commAges`, `setCommLocked` and `pruneCommsLocked` (`internal/eventloop_comm.go`). Caps reuse `defaultMaxPendingEnterEvs` (16384) and `defaultMaxPendingHandleEntries` (8192). |
| M4 | **FIXED** (dead path removed) | `348dcf8` | `internal/statsengine/family.go` is deleted; no `Families`/`FamilySnapshot`/`familyAccumulator` symbol remains anywhere in `internal/statsengine`. Docs updated (see also the leftover fixed by this gate, §5.5). |
| M5 | **FIXED** | `1d95fd4` | `TestEngineResetConcurrentWithIngestAndSnapshot` (`internal/statsengine/engine_reset_test.go:42`) runs concurrent ingesters against `Reset()` and a snapshot reader. |
| M6 | **FIXED** (option b: converter) | `6594d04` | `.ior.zst` stays gob-in-zstd; `internal/flamegraph/collapsed.go` + `internal.RunCollapsedConverter` + the `ior collapsed` dispatch in `cmd/ior/main.go:26` emit flamegraph.pl-ready collapsed stacks. `PLAN-PROJECT-AUDIT.md` journeys now read `ior collapsed <file>.ior.zst \| flamegraph.pl`. |
| M7 | **FIXED** | `6840863` | `EventStreamHeader` is 7 columns and `Pair.String()` emits exactly those 7 unmerged columns with `quoteCSVField` (byte-identical to `encoding/csv`); the vestigial `notice` column is gone. Banner and status lines go to stderr (`printStartupBanner`, `logStatus`), leaving stdout data-only in `-plain`. |
| M8 | **RESOLVED AS DOCUMENTED** (docs aligned; fields deliberately not added) | `6840863` | `-plain` keeps its reduced field set; the schema is documented in `README.md`, `docs/tutorial/tutorial.md` and `docs/build-rocky-linux-9.md`, and the plan no longer conflates it with the richer TUI stream-export CSV. Rationale: `-plain` is the low-overhead line format; timestamp/bytes/`requested_sleep_ns` remain available through the stream export and Parquet schemas. |
| M9 | **FIXED** | `9a9085f` | `tuiRuntime.filterEpoch` became `filterEpochFn func() uint64` (bound to `bindings.FilterEpoch`), read through `currentFilterEpoch()` at row-stamp time (`internal/ior.go:315`). Regression test `TestTuiTraceStarterInPlaceFilterSwapAdvancesRecordedEpoch` asserts epochs 0,1 across an in-place swap. Headless `-parquet` intentionally still stamps 0 — it has no interactive filter swaps. |
| M10 | **FIXED** | `27bc012` | `eventstream.Model.exportEnabled` + `SetExportEnabled`, wired construction-time from `KeyMap.ExportEnabled()` (`internal/tui/dashboard/model.go:166`); `handleStreamExportKey` returns `(false,false)` when disabled so `x`/`X`/`E` fall through unhandled and write nothing; hints gated in `internal/tui/common/keys.go` and `internal/tui/help.go`. |
| M11 | **FIXED** | `9638254` | `Magefile.go` renders to a temp file (`writeTempRender`), runs the strict gate (`stageTracepointsResultGate`) and only then replaces the committed artifact (`adoptTracepointsResult`). Re-confirmed live by this gate: a failing `mage generate` on this host leaves the tree pristine (§5.6). |
| M12 | **FIXED** | `9638254` | `runIntegrationTestBinary` execs the binary by **absolute** repo-root path with `Dir="integrationtests"`, wires stdout/stderr, and falls back to `sudo -n -E` when not root; the binary is registered in `Clean`. Re-confirmed live by this gate: `mage integrationTest` finds and runs the suite (§5.6). |
| M13 | **DOCUMENTED — accepted, not "fixed"** | `ca56fe7` | `AGENTS.md` gained the "Generation host / kernel" section describing the newer-kernel pinning, the diff gate, `IOR_FORCE_GENERATE`, and the `buildDocker` regeneration flow. The underlying condition is unchanged by design and remains the reason `mage generate`/`mage world` cannot complete on this el9_8 host (§5.6). |
| M14 | **FIXED** | `be1aaa7` | `recordingSession.enqueue` sheds the row and counts it (`internal/parquet/recorder.go:365`) instead of killing the session; `Status().RowsDropped` exposes it live and at finish; `isFatalRecorderError` keeps headless runs alive on overflow; `Stop()` flushes the partial file; the TUI status bar shows `(dropped N)`. |

### 5.3 LOW / INFO

| Item | Status | Landed in | Note |
|---|---|---|---|
| D1 F3 — `ptrace_event._pad` never zeroed | **FIXED** | `88ea09a` | Generator emits `ev->_pad = 0;` (`internal/generate/bpfhandler.go:602`), present in the committed C. |
| D1 F4 — `openat2` flags never captured | **WONTFIX (documented)** | `88ea09a` | Flags live inside `struct open_how` behind `args[2]`; capturing them needs a guarded `bpf_probe_read_user` that could not be verifier-tested here. Documented in `docs/syscall-tracing-plan.md` ("Known Argument-Capture Gaps") and in the generator comment; the handler emits the `-1` "not captured" sentinel. |
| D1 F5 — stale `RetEvent` comment | **FIXED** | `88ea09a` | `internal/event/interface_assertions.go` now describes the kind-specific ret carriers correctly. |
| D2 F3 — comm-filtered enters skipped `Recycle()` | **FIXED** | `b3452b9` | `internal/eventloop_runtime.go:265`. |
| D3 F3 — stream ring not reset on baseline resets | **DOCUMENTED + test-locked** | `1d95fd4`, `9aacbf3` | Retention is deliberate (the stream is a chronological log, not an aggregate); documented on `resetBaselineCmd` and locked by `TestTUIIntegration_Global_ResetKeepsStreamRows`, whose stale-frame weakness was itself fixed in `9aacbf3`. |
| D3 F4/F5 — aggregates dropped under runtime filters | **WONTFIX (by design)** | — | Kernel aggregates carry no comm/path dimension, so ingesting them under a content filter would report unfiltered counts. Behaviour unchanged and intentional. |
| D3 — sampled 1-in-N full counts never merged user-side | **NOT RESOLVED** | — | Re-verified as still live at `48aed39` (see §5.5). Follow-up task `b1`. |
| D4 F5 — livetrie snapshot rebuild cost at high cardinality | **ACCEPTED (no action)** | — | Performance observation only; totals and memory bounds are exact. Left on the deferred list in §4. |
| D4 F6 — dead `eventLoopConfig.collapsedFields`/`countField` | **FIXED** | `ca56fe7` | Fields removed. (F6(b) test-only trie helpers left as-is — harmless.) |
| D4 F7 — explicit rate-0 zeros in raw modes | **DOCUMENTED (by design)** | `8e8d746`, `ca56fe7` | AGENTS.md and the flag help now state that default aggregate-only rates and explicit **family** zeros are promoted to 1 in raw modes, while user-explicit per-syscall zeros are preserved. |
| D4 F8 — uncommitted docs deletions | **FIXED** | `b68f3c9` | See "docs decision" below. |
| D5 F2 — help said "1..8" for 7 tabs | **FIXED** | `da6c7f6` | `internal/tui/help.go:83` reads `1..7`. |
| D5 F3 — vacuous export-hint test | **FIXED** | `27bc012` | Replaced by real both-directional gating tests. |
| D5 F4 — unreachable dashboard help bar | **FIXED** | `da6c7f6` | Bound to `F1` (`internal/tui/dashboard/model.go:654`), with an `H`-must-not-toggle regression guard. |
| D5 D1–D5 — TUI documentation drift | **FIXED** | `348dcf8`, `27bc012`, `ca56fe7` | AGENTS.md TUI section rewritten (7 tabs, `h`/`l` column nav, fast-refresh=0 semantics, `e` modal semantics, export gating). |
| D6 F1 — unvalidated `-pid`/`-tid` | **FIXED** | `8e8d746` | `validateProcessID` rejects everything outside `{-1} ∪ [1, pid_max]`, with `pid_max` read from `/proc/sys/kernel/pid_max` and a test seam. |
| D6 F2 — explicit family `=0` not promoted in raw modes | **FIXED** | `8e8d746` | `promoteAggregateOnlyForRawOutput` promotes family zeros after family expansion; explicit per-syscall overrides still win. |
| D6 F3 — `flags.BuildTraceFilter` untested | **FIXED** | `8e8d746` | `internal/flags/tracefilter_test.go` + `validation_test.go`. |
| D6 F4/F5, D6 D1–D4 | **FIXED / no action** | `8e8d746`, `ca56fe7` | Precedence behaviour was already correct; the flag help now enumerates families/kinds and the `name=rate` syntax, and the plan's FS-only default-attach claim is corrected. |
| D7 F5 — `IOR_FORCE_GENERATE=0` still forced | **FIXED** | `9638254` | `forceGenerateFromEnv` honours `0/no/false` and warns on unknown values. |
| D7 F6 — `clean`/`world` deleted `vmlinux.h` | **FIXED** | `9638254` | `cleanBPFArtifacts` preserves it and sweeps only `*.o` and orphaned temp renders. |
| D7 F7/F8 — benign build warnings, kernel-coupled integration scenarios | **NO ACTION** | — | Warnings originate in the bpftool-dumped `vmlinux.h`; the integration-scenario failures are kernel/policy-caused on 5.14 (see §5.6). |
| D8 X4 / D9 Y4 / D9 Y5 / D8 X5 | **NO ACTION (informational)** | — | Timing caveat, 0.01–0.03 % enter/exit mismatch at peak (already reported in the `Statistics:` block), and two positive results. |
| D10 F1 — plan drift (`validate()` vs `run()`) | **FIXED** | `ca56fe7` | Plan text corrected. |
| D10 F2 — `mgr.Close()` errors silenced in TUI | **FIXED** | `df61989` | Teardown errors route through an always-on stderr logger (`logTeardown`). |
| D10 F3 — early-error arms skipped `mgr.Close()` | **FIXED** | `df61989` | All early-abort arms of `setupTraceInfra`/`setupHeadlessParquetInfra` go through the shared `closeTraceInfra` in canonical order. |
| D10 F4 — benign `tea.Quit`/teardown race | **WONTFIX (benign)** | — | Kernel reclaims fd-backed links/maps at process exit. |
| D10 F5 — no teardown-ordering tests | **FIXED** | `df61989` | `internal/ior_teardown_test.go` asserts the 5-step order, nil-skipping, error routing and the signal/duration cancel paths. |
| Docs decision (uncommitted plan deletions) | **RESOLVED** | `b68f3c9` | `docs/syscall-tracing-plan.md` restored (drift-test-enforced, README-referenced), the stale `docs/clickhouse-streaming-plan.md` deletion committed, `PLAN-PROJECT-AUDIT.md` committed. `mage test` has been fully green since. |

### 5.4 Finding discovered during the fix run (not in the original report)

| ID | Status | Landed in | Note |
|---|---|---|---|
| Ret-carrying exits dropped user-side | **FIXED** | `48aed39` | `streamrow.New` filled `RetVal`/`IsError` only for `*types.RetEvent`, so the 22 kind-specific ret-carrying exits (accept/accept4, pipe/pipe2, socketpair, the eventfd/pidfd family) reported `ret=0, is_error=false` even though their kernel structs carry `ret`. The types generator now emits `GetRet() int64` for every struct with a scalar `ret` member (5 in `internal/types/generated_types.go`, all verified present), `event.RetCarrier` names the contract, and the four sibling drop sites were converted too: `event.Pair.String()` (`-plain` ret column), `globalfilter` `ReturnValue`/`ErrorValue`, and `statsengine` `totalErrors` + per-syscall `Errors`. |

### 5.5 Not genuinely resolved — follow-up tasks created by this gate

1. **`b1` (LOW, from the original report)** — *sampled 1-in-N full counts never merged user-side*. Re-verified live at `48aed39`: `internal/c/filter.c` `ior_on_syscall_exit()` updates the kernel aggregate for **every** paired exit, but `aggregateDrainer.filterRowsForIngest()` only ingests rows whose trace id is in `aggregateOnlyTraceIDs`, and `buildAggregateOnlyTraceIDs()` populates that set **only for sampling rate 0**. A syscall sampled 1-in-N therefore contributes only its emitted 1/N pairs to the stats engine, and its kernel-side full count is discarded — totals under-report those syscalls by roughly N. No fix task owned this item and no wontfix rationale was recorded anywhere, so it is carried forward rather than closed.
2. **`a1` (guardrail hygiene, pre-existing)** — `go vet ./...` is red at HEAD on `cmd/ioworkload/scenario_sysv.go:76:30` ("possible misuse of unsafe.Pointer"): `shmWrite` converts the `uintptr` address returned by `SYS_SHMAT` into a pointer for `unsafe.Slice`. Pre-existing since `b7a63e9` (2026-06-01, which predates the audited commit) and outside the audit's finding set, but it means the `go vet ./...` guardrail cannot be reported as clean.

**Hygiene applied by this gate** (in the same commit as this section):

- `gofmt -w` on the eight files that were `gofmt`-dirty at `48aed39` — `audit/check/{_gosizes/main.go,main.go,parquetwrite/main.go,tuihelp/main.go}`, `cmd/ioworkload/scenario_sleep.go`, `internal/eventloop_sleep_test.go`, `internal/generate/family.go`, `internal/tui/flamegraph/renderer_test.go`. All changes are formatting-only (map-literal alignment, one import reordering in `audit/check/main.go`, two trailing blank lines); `git diff -w` shows no semantic change. `gofmt -l .` is now empty.
- Fixed a leftover M4 documentation drift the fix tasks missed: `docs/syscall-tracing-plan.md` "Runtime Notes" still advertised the removed `Non-IO` tab (shortcut `8`) backed by `Snapshot.Families`. That file was restored by the docs decision (`b68f3c9`) *after* the M4 commit (`348dcf8`) had swept the other docs, so the stale paragraph came back with it. It now describes the 7-tab dashboard and the Syscalls-tab Family column. The `internal/generate` and `internal/tracepoints` drift tests were re-run green after the edit.

### 5.6 Guardrail re-run at closure (2026-09-03, same host as the audit)

Host: Rocky Linux 9, kernel `5.14.0-687.36.1.el9_8.x86_64`, Go 1.26.2, non-root
with the same purpose-scoped sudoers rules the audit used.

| Guardrail | Result | Detail |
|---|---|---|
| `mage test` | **PASS** (exit 0) | 28/28 packages `ok`, zero failures. The docs-drift failure that was the audit's only red test is gone (`b68f3c9`). |
| `mage testRace` | **PASS on rerun** (exit 0); first run exit 1 | Run 2: 28/28 packages `ok`, **zero `WARNING: DATA RACE`**. Run 1 also reported **zero data races** but failed one test, `TestTUIIntegration_AllTabs_RenderPopulatedAndKeepChrome` — a pre-existing frame-timing assumption in the test (it asserts the abbreviated tab label `1:Flm`, which only renders when the tab bar width is under 90; under full-suite load the wide 160-column layout landed before the assertion). 5/5 green in isolation under `-race` and 3/3 green for the whole `./internal` package under `-race`. Tracked as `c1`; the H1 guarantee (no data races) held in both runs. |
| `mage integrationTest` | **RUNS**; exit 1 with 9 failures out of 202 tests | The target itself is fixed (M12): it compiled the binary, exec'd it as root through the sudoers rule and streamed the output. All 9 failures are the kernel/policy-caused ones documented in the audit for el9_8: `TestMountFsManagementSyscalls` (`statmount` absent on 5.14), `TestIouring{Setup,Enter,Register}` (`io_uring_setup: operation not permitted` — disabled by policy) and five `xattr` tests (`function not implemented`: the four `*xattrat` ones plus `TestXattrSetxattr`, which deliberately reuses the `xattr-getxattrat` scenario — audit D7 F8). This matches the audit's 192 PASS / 1 SKIP / 9 FAIL baseline. |
| `gofmt -l .` | **PASS** (empty) | Eight pre-existing dirty files were formatted by this gate (§5.5). |
| `go vet ./...` | **FAIL** (exit 1) | One pre-existing finding: `cmd/ioworkload/scenario_sysv.go:76:30: possible misuse of unsafe.Pointer`. Nothing else. Tracked as `a1`. |
| `mage world` | **CANNOT COMPLETE HERE** (exit 1 at `generate`) | The strict diff gate aborts with exactly **32 deletions and 0 additions** — the newer-kernel handlers (`statmount`, `*xattrat`, `uprobe`/`uretprobe`, …) that this 5.14 host cannot see. This is M13 behaving as documented, not a regression. Three side-effects were verified in the same run: the working tree was left **pristine** with no `.new`/`.tmp-*` transients (M11 fix, live), `internal/c/vmlinux.h` survived the `clean` phase (D7 F6 fix, live), and `mage clean` removed the leftover `integrationtests.test` binary (M12 fix, live). `mage build` was run afterwards to restore the binaries. |

Additional live evidence collected while running the above: the BPF object
loads `ringbuf_drop_map` successfully on every integration-test attach
(`libbpf: map 'ringbuf_drop_map': created successfully`) and every run's
`Statistics:` block now ends with `ring buffer drops: 0 (0.00/s, 0.00% of
events)` — M2 exercised end-to-end against the real verifier on a 5.14 kernel.

## 6. Final sign-off (revised at the audit closure gate, 2026-09-03)

*This supersedes the conditional pass recorded on 2026-09-01. That sign-off is
kept below for the record.*

**Pass — with two carried-forward items and two environment limitations.**

Every HIGH and MEDIUM finding in §3 now has a landed fix or an explicit,
recorded decision, verified against the tree at `48aed39` by reading the code
and the generated artifacts rather than by trusting commit messages. The two
findings that made the original sign-off conditional are closed: H1 (the
`ApplyPalette` data race) is gone — the theme is a single immutable snapshot
published through `atomic.Pointer`, and a full `go test ./... -race` run
reports **zero** data races — and the docs decision landed, so `mage test` is
fully green for the first time since the audit.

**What this gate verified directly** (commands and results in §5.6): `mage
test` green across all 28 packages; `mage testRace` green across all 28
packages with zero race reports; `mage integrationTest` builds and actually
runs the suite as root through the scoped sudoers rule (the target used to
exec a path that did not exist); `gofmt -l .` empty; every §3 finding
re-checked in the source.

**What this gate could not verify in this environment, and why:**

- **`mage world` cannot complete here.** It runs `mage generate`, whose strict
  diff gate correctly aborts on this host: the committed artifacts were
  generated on a kernel substantially newer than this box's
  `5.14.0-687.36.1.el9_8`, so regeneration would delete ~32 handlers that only
  exist on newer kernels (M13, documented in AGENTS.md). The gate leaving the
  tree pristine on that failure is itself the M11 fix working as designed, and
  was re-confirmed. `mage world`'s other three phases were each exercised
  separately (`mage clean` implicitly through the build, `mage test`,
  `mage build` via `mage integrationTest`). **A host whose kernel matches the
  generation kernel — or the rootful `buildDocker` flow — is still required to
  prove `mage generate` reproduces the committed artifacts byte-for-byte.**
  This is the single largest residual risk in the M1/M2 fixes: both changed the
  generator and had their generated output spliced in and cross-checked
  (`generated_tracepoints_result.txt` re-derives byte-identically from the
  committed C; 364/364 exit handlers carry `ctx->ret`; 731/731 reserve sites
  count drops; `mage build` compiles the BPF object and the relocation count
  confirms every handler references `ringbuf_drop_map`) rather than produced by
  a clean end-to-end `mage generate`.
- **`go vet ./...` is not clean**, on one pre-existing finding unrelated to the
  audit (`cmd/ioworkload/scenario_sysv.go:76`, `unsafeptr`); see follow-up
  `a1`.
- **No live high-throughput re-validation.** The M2 drop counter and the M14
  parquet shedding path are verified by code and unit/stress tests, not by
  reproducing the original ~85k syscalls/s Domain 9 scenario. The deferred
  coverage list in §4 (thread-churning soak for M3, tty journeys, cross-kernel
  portability, `bpftool` leak checks) is unchanged.

**Carried forward — not resolved, tracked as tasks** (§5.5): `b1` (sampled
1-in-N full counts still never merged user-side, a LOW finding from the
original report that no fix task owned) and `a1` (the `go vet` guardrail).
`c1` tracks a pre-existing flaky TUI integration test that failed once under
full-suite race load and passed on rerun — a frame-timing assumption in the
test, with no data race behind it.

### Original sign-off (2026-09-01, superseded by the above)


**Conditional pass — fit for production use on BTF-enabled Linux hosts, with required follow-ups.**

The core tracing pipeline is verified correct end-to-end, including live root execution: BPF capture with kernel-side PID/TID gating (731 handlers), TID-keyed pairing, stats aggregation, filtering/sampling semantics (18/18), live headless journeys with exact output fidelity, flat RSS under sustained load, static CO-RE binaries that gracefully degrade across kernels, and a sound privilege model. Test coverage is unusually deep in the TUI (62 in-process integration tests) and broad across flags/filters.

Before production reliance: **H1 (ApplyPalette data race) must be fixed** — it makes the `mage testRace` guardrail permanently red. For high-throughput capture, **M14 (parquet total-abort on queue-full)** and **M2 (no drop observability)** should be addressed; for correctness-of-output, **M1** (null-event exits misreport `ret`) and **M9** (stale `filter_epoch`). The remaining mediums are mostly output-format/documentation drift (M4, M6–M8, M10–M13) that erode trust in the docs rather than the tool. The one pre-existing test failure stems from the uncommitted docs deletion and needs an explicit decision (restore vs. remove drift tests).


— Compiled by the audit closure gate (task `20`, `+audit`), 2026-09-01. All ten domain tasks (`s,t,u,v,w,x,y,z,00,10`) completed; per-domain reports committed individually; guardrails re-run at gate time: `mage test` fails only the known drift test, `gofmt -l audit/` clean.