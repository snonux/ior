# I/O Riot NG (ior) — Project Audit Report

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

## 5. Final sign-off

**Conditional pass — fit for production use on BTF-enabled Linux hosts, with required follow-ups.**

The core tracing pipeline is verified correct end-to-end, including live root execution: BPF capture with kernel-side PID/TID gating (731 handlers), TID-keyed pairing, stats aggregation, filtering/sampling semantics (18/18), live headless journeys with exact output fidelity, flat RSS under sustained load, static CO-RE binaries that gracefully degrade across kernels, and a sound privilege model. Test coverage is unusually deep in the TUI (62 in-process integration tests) and broad across flags/filters.

Before production reliance: **H1 (ApplyPalette data race) must be fixed** — it makes the `mage testRace` guardrail permanently red. For high-throughput capture, **M14 (parquet total-abort on queue-full)** and **M2 (no drop observability)** should be addressed; for correctness-of-output, **M1** (null-event exits misreport `ret`) and **M9** (stale `filter_epoch`). The remaining mediums are mostly output-format/documentation drift (M4, M6–M8, M10–M13) that erode trust in the docs rather than the tool. The one pre-existing test failure stems from the uncommitted docs deletion and needs an explicit decision (restore vs. remove drift tests).

— Compiled by the audit closure gate (task `20`, `+audit`), 2026-09-01. All ten domain tasks (`s,t,u,v,w,x,y,z,00,10`) completed; per-domain reports committed individually; guardrails re-run at gate time: `mage test` fails only the known drift test, `gofmt -l audit/` clean.