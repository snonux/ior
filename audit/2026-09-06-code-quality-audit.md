# Code-Quality Audit — 2026-09-06

- **Repo:** ior, branch `develop`, HEAD `2ddd880` (plus an uncommitted WIP rewrite of
  `internal/eventloop_state.go` — see finding B1).
- **Scope:** root package, `cmd/...` (ior, filewriter, ioworkload), `internal/...`
  including the embedded C/BPF sources; `audit/` tooling excluded; tests secondary.
- **Method:** five independent fresh-context audits — `go-best-practices`,
  `100-go-mistakes`, `find-code-bugs` (defect sweep), `solid-principles`,
  `beyond-solid-principles`. Guardrails actually run against a pristine export of
  HEAD: `gofmt -l` clean, `go build ./...` OK, `go vet` clean (incl. the documented
  `-unsafeptr=false ./cmd/ioworkload` exemption), full `-short` unit suite green,
  `go test -race` green on statsengine/streamrow/parquet/flamegraph/probemanager,
  `errcheck ./...` ≈160 sites (mostly intentional). `staticcheck` was NOT run
  (not installed).
- **Tasks:** every finding below carries its `ask` task ID. Gate task **e2**
  (`+audit`) depends on all of them: 22, 32, 42, 52, 62, 72, 82, 92, a2, b2, c2, d2.

## How to use this document

- **Fixing agent:** work the tasks via `ask` (`ask info <id>` has full context per
  task). This file is the cross-finding overview; the per-finding "Verify" lines
  are the acceptance criteria. Do not mark the checkbox here — the reviewing agent
  does that.
- **Reviewing agent (later pass):** for each finding, confirm the fix at the stated
  locations, run the "Verify" steps, then tick `- [x] REVIEWED:` with the commit
  hash that fixed it. When all boxes are ticked and `ask list` shows tasks
  22–d2 done, complete gate task e2 after re-running:
  `go build ./...`, `go vet ./...` (+ `-unsafeptr=false ./cmd/ioworkload`),
  `go test -race ./...`, `gofmt -l .`, `errcheck ./...`
  (or `mage vet` / `mage testRace` / `mage fmtCheck` / `mage lint` if present).

## Findings summary

| Category | HIGH | MEDIUM | LOW |
|---------------------|------|--------|-----|
| Bugs / defects | 1 | 1 | 1 |
| SOLID | 1 | 4 | 5 |
| Architecture | 1 | 4 | 4 |
| Go Best Practices¹ | 1 | 4 | 12 |
| **Total (raw)** | **4** | **13** | **22** |

¹ go-best-practices + 100-go-mistakes combined. Raw counts overlap on purpose:
the fd-tracker refactor is the HIGH in three categories; either-name filtering and
the comm timeout each surfaced twice. After dedup: **12 distinct HIGH/MEDIUM
findings**, all tasked below, plus untasked LOW findings at the end.

---

## Part 1 — Confirmed bugs (find-code-bugs; tag `+bugfix`)

### B1 — HIGH — Unfinished fdTracker (pid, fd) re-keying: tree does not compile — task 22 (relates to started task u1)

- **Where:** `internal/eventloop_state.go` (uncommitted WIP) vs. call sites
  `internal/eventloop_exit.go:61,155,214,246,293,300,326,356,361,381,419,424,447,497,526,586,658,675`
  and allocations `internal/eventloop.go:152,178` (still `make(map[int32]file.File)`).
- **What:** the WIP re-keys `fdTracker.files` to composite `(pid, fd)` `map[uint64]`
  keys and widens `get/set/delete/closeRange` signatures, but no call site was
  updated. `go vet`/`mage build`/`mage test` fail on `ior/internal` and
  `ior/cmd/ior` ("not enough arguments in call to e.fdState().set", …).
- **Why the refactor matters (HEAD defect, task u1):** at HEAD the fd table is keyed
  by descriptor number alone across all traced processes — fd 3 of process A and
  fd 3 of process B share one entry, so rows print another process's filename and
  one process's `close()` evicts another's mapping. Corrupts file attribution in
  every system-wide trace (observed live 2026-09-04).
- **Fix:** pass the event's `Pid` at each call site (available as `fdEv.Pid`,
  `dup3Ev.Pid`, …), update the two allocations, evict on process exit as well as
  close, re-check LRU cap sizing.
- **Verify:** `mage vet && mage testRace` green; new test with two pids sharing an
  fd number asserting each row keeps its own file.
- [x] REVIEWED (commit: `7b266b4`): fix confirmed correct

### B2 — MEDIUM — TUI "trace started" signal fires before the last fallible setup steps — task 32

- **Where:** `internal/ior.go` `setupTraceInfra` (signalTraceStarted ~641 precedes
  `newEventLoop` ~643 and `newSyscallAggregateConsumer` ~649); consumer side
  `tuiTraceStarterFromRunTrace` ~388–395.
- **What:** if `newEventLoop` fails (e.g. filter-modal Comm pattern >16 chars →
  `ValidateTracepointFields` error on the next PID-reselect restart) or the
  aggregate map is missing (stale `IOR_BPF_OBJECT`), the starter already returned
  success; the error goes to an undrained `errCh` and is discarded. TUI shows a
  live, empty dashboard with no error, forever.
- **Fix:** signal started only after all fallible setup completes (or drain/route
  late errors into the TUI error path).
- **Verify:** force a late setup failure (oversized comm pattern via filter modal,
  or stale `IOR_BPF_OBJECT`) and assert the TUI surfaces the error instead of an
  empty dashboard; regression test if feasible.
- [x] REVIEWED (commit: `1eb08df`): fix confirmed correct

### B3 — LOW — Drop-counter read failures swallowed in headless modes; end-of-run stats then assert "ring buffer drops: 0" — task 42

- **Where:** `internal/eventloop_runtime.go:79-82` (`handleRingbufDropResult`
  warning branch).
- **What:** drop-counter *read failures* go only through `notifyWarning`, which is a
  no-op when `warningCb` is nil (`-plain`, `-flamegraph`, headless `-parquet`) —
  unlike the drop-delta branch just below, which falls back to stderr. If `Total()`
  errors every time, final stats print `ring buffer drops: 0` (documented in-code
  as an explicit "no loss" statement) when loss is actually unknown.
- **Fix:** mirror the drop-delta branch's stderr fallback for read failures, and/or
  print "drops: unknown" when reads failed.
- **Verify:** simulate `Total()` failure in headless mode; stderr shows the warning
  and final stats no longer claim zero drops as fact.
- [x] REVIEWED (commit: `330694d`): fix confirmed correct

### Suspicious but unconfirmed (deliberately NOT tasked)

- `cmd/ioworkload/scenario_aio.go` (`ioSubmitWrite` ~182–207, `withAioTarget`):
  AIO write buffer address stored as integer in the iocb; `runtime.KeepAlive(buf)`
  covers only the submit, so the kernel may read the buffer after GC could reclaim
  it. No observable failure today (deferred `io_destroy` drains; harness never
  checks content).
- Stale comm on tid reuse — already tracked as pre-existing task **x1**; not re-filed.

---

## Part 2 — Design/convention findings, HIGH+MEDIUM (tag `+codequality`)

### D1 — HIGH — "Either-name" filter contract re-implemented at four stages — task 52

- **Source:** SOLID (OCP/LSP, HIGH) + architecture (DRY, MEDIUM).
- **Where:** `internal/globalfilter/trace.go:29-66,143-151` (`MatchPair` vs
  `MatchPairEitherName` vs `MatchesEitherName`); consumers
  `internal/eventloop_exit.go:698` (`finishPairEitherName`),
  `internal/ior.go:399-414` (`shouldIngestTracePair`),
  `internal/tui/eventstream/model.go:609` + `export.go:130`;
  root cause `internal/file/file.go:183` (`oldnameNewnameFile.Name()` returns only
  the newname).
- **What:** the "match old OR new path" rule for rename-like events must be
  re-chosen correctly by every filtering consumer; the narrow variant is provably
  identical to the wide one whenever `Oldname` is empty, so it exists only as a
  trap. AGENTS.md warns "All three stages must move together"; past bugs
  (`-path <oldname>` rows kept in `-plain` but dropped on the dashboard) came from
  exactly this divergence.
- **Fix:** add `OldNameValue()`/`AllNames()` to the `Candidate` interface (or
  `file.File`), make plain `Matches`/`MatchPair` either-name-aware, delete the
  `*EitherName` API; fitness test asserting all stages agree on a rename fixture.
- **Verify:** `*EitherName` identifiers gone from the tree; cross-stage rename
  fixture test exists and passes.
- [x] REVIEWED (commit: `00d77f4`): fix confirmed correct

### D2 — MEDIUM — Comm-resolver timeout documented but not enforced; can hang shutdown — task 62

- **Source:** architecture (resilience/POLA) + 100-go-mistakes #60 (contexts).
- **Where:** `internal/eventloop_comm.go:17-19` (guarantee in `resolveCommTimeout`
  doc), `:126-133` (default `resolveFn` — blocking `os.ReadFile`/`os.Readlink`,
  `ctx.Err()` checked only afterwards), `:232` (`seedTrackedPidComm`, same issue),
  `:453-466` (`shutdown` waits on `workersWG.Wait()`).
- **What:** a stuck `/proc/<tid>/...` read (frozen cgroup, D-state task — the exact
  scenarios the comments claim to defend against) stalls the worker indefinitely
  and blocks clean event-loop teardown.
- **Fix:** run the procfs read in a helper goroutine and `select` on result vs
  `ctx.Done()` (abandon the stuck goroutine; the epoch machinery guards stale
  results), or give `shutdown()` a deadline; alternatively delete the timeout
  plumbing and fix the comments. Coordinate with pending task x1 (same file).
- **Verify:** a resolver stub that blocks forever no longer prevents `shutdown()`
  from returning within the timeout; comments match actual behavior.
- [x] REVIEWED (commit: `5581959`): fix confirmed correct

### D3 — MEDIUM — `setupTraceInfra`: 8-value return, four hand-permuted teardown arms — task 72 (depends: 32)

- **Source:** SOLID (SRP) + architecture (KISS).
- **Where:** `internal/ior.go:596-662`; teardown repeated at lines 628, 637, 646,
  652; consumed by `runTraceWithContext:571-590`.
- **What:** each error arm hand-repeats `cancel()` + `closeTraceInfra(...)` with
  positionally-correct explicit nils; past audit findings D10-F2/F3 (discarded
  teardown errors, probes left attached) were exactly mis-permuted teardowns here.
- **Fix:** `traceInfra` struct built incrementally; each successful step appends its
  teardown closure; one nil-safe `Close()` runs them LIFO; signature collapses to
  `(*traceInfra, error)`. Land after B2/task 32 (same function).
- **Verify:** no multi-nil teardown calls remain; error paths are
  `infra.Close(); return err`; behavior on early-abort unchanged (probes detached).
- [x] REVIEWED (commit: `8bff09b`): fix confirmed correct

### D4 — MEDIUM — Dashboard Model: per-tab state bag; tab registry doesn't deliver its no-switch contract — task 82

- **Source:** SOLID (SRP/OCP) + architecture (cohesion/POLA).
- **Where:** `internal/tui/dashboard/model.go` (1648 lines; per-tab field clusters
  `syscalls*/files*/filesDir*/processes*` at ~:100-125; ~24 `case Tab...` switches:
  `handleEnterKey` :372-403, `handleSortKey` :482-496, `reanchor*Offset`,
  `max*Rows`, `selected{Syscall,File,Process}Filter`); contract claim at
  `tabregistry.go:25-27`.
- **What:** adding a table tab is shotgun surgery across ~8 places plus
  `common.KeyMap` `One..Seven`, contradicting the registry's stated contract.
- **Fix:** generic `tableTabState[Row, SortKey]` per tab; extend `tabDescriptor`
  with `HandleEnter`/`HandleSort`/row-count hooks (streamModel/flamegraphModel are
  the pattern); migrate tab by tab; keep the registry comment honest until done.
- **Verify:** the triplicated sort/reanchor/filter helpers are gone or generic; the
  registry comment matches reality.
- [x] REVIEWED (commit: `0a9f075`): fix confirmed correct

### D5 — MEDIUM — Trackers don't own their invariants; eventLoop pokes their internals — task 92 (depends: 22, u1)

- **Source:** SOLID (SRP) + architecture (SoC/coupling, LOW there).
- **Where:** `internal/eventloop.go:147-209` (`configuredFDTracker`,
  `configuredCommResolver`, `fdState()`, `commState()`, `pendingHandleState()`
  re-establish invariants and reach into `injected.files`/`injected.pending`/
  `warningFn`); direct field wiring at `internal/ior.go:306-330` (`el.printCb`,
  `el.warningCb`, `el.aggregateSink`).
- **What:** the fd-map representation is spelled in three files — exactly why the
  in-flight re-keying (B1) broke compilation. Encapsulation relies on discipline,
  not the compiler.
- **Fix (after 22/u1 land):** give each tracker `ensureInit()`/usable zero value;
  delete eventLoop-side field-poking; route TUI wiring through setter methods.
  Optional follow-up (not in-scope): split `internal/` into
  `internal/eventloop` / `internal/bpfsetup` / `internal/modes`.
- **Verify:** no direct field access into tracker internals from `eventloop.go`/
  `ior.go`; map representation defined in exactly one file.
- [x] REVIEWED (commit: `93161af`): fix confirmed correct

### D6 — MEDIUM — `internal/runtime` boundary leaks concrete types; runtime downcast — task a2

- **Source:** SOLID (DIP/ISP).
- **Where:** `internal/runtime/runtime.go:131-140`
  (`Recorder() *parquet.Recorder`, `StreamSequencer() *streamrow.Sequencer`);
  downcast `persistent.(streamEventSink)` at `internal/ior.go:246-253`; sole
  core-side recorder use `internal/ior.go:315`.
- **What:** core needs one method but depends on concrete parquet type (untestable
  against a fake; signature changes ripple through the neutral contract);
  `StreamBuffer()` returns the read-side `StreamSource` though core needs push
  access, recovered via a runtime type assertion with a runtime-error fallback.
- **Fix:** declare in `runtime`:
  `RowRecorder interface { Record(streamrow.Row, uint64) error }` (+ start/stop
  surface the TUI needs) and `Sequencer interface { Next() uint64 }`; change
  `StreamBuffer()` to return `runtime.EventSink`; delete the downcast.
- **Verify:** no `*parquet.Recorder`/`*streamrow.Sequencer` in the runtime
  interface; the type assertion at ior.go:246-253 is gone.
- [x] REVIEWED (commit: `ed15ee1`): fix confirmed correct

### D7 — MEDIUM — Mixed value/pointer receivers on TUI Model types — task b2

- **Source:** go-best-practices M1.
- **Where (representative):** `internal/tui/dashboard/model.go:195` (value
  `Update`) vs `:482` (`*Model handleSortKey`);
  `internal/tui/flamegraph/model.go:272` vs `:755,:810`;
  `internal/tui/tui.go:558` vs `:702`;
  `internal/tui/tracefilter/model.go:104` vs `:229`.
- **What:** value-receiver `Update` calls pointer-receiver mutators on a local copy;
  works today, but any pointer-method call on a non-addressable or later-copied
  Model silently loses mutations.
- **Fix:** standardize per type — all-pointer with `*Model` implementing
  `tea.Model` (`internal/tui/eventstream` is the consistent template) or
  value-receiver helpers returning `Model`. Coordinate with D4/task 82 (same files).
- **Verify:** each Model type is single-style; `go vet` copylocks clean; TUI tests
  pass.
- [x] REVIEWED (commit: `b7fc76b`): fix confirmed correct

### D8 — MEDIUM — ~150 undocumented exported identifiers — task c2

- **Source:** go-best-practices M2.
- **Where (representative):** `internal/types/fastdecode.go:57` (`NewOpenEventFast`
  + 22 siblings), `internal/benchutil/eventgen.go:18-264` (21),
  `internal/streamrow/row.go` (12), `internal/globalfilter/filter.go:7,48,69`,
  `internal/event/pair.go:83,126`, `internal/file/file.go:83` (`Dup`).
- **Fix:** identifier-named doc comments, starting with `types`, `globalfilter`,
  `event`, `streamrow`. Excludes generated code and `internal/generate/testdata.go`.
- **Verify:** spot-check the listed identifiers; optionally a doc-comment linter in
  the D9 gate.
- [x] REVIEWED (commits: `b796520`, `37e940d`): fix confirmed correct

### D9 — MEDIUM — No errcheck/lint gate in Mage/CI — task d2

- **Source:** go-best-practices M3 + 100-go-mistakes #16.
- **Where:** `Magefile.go` (Vet/Fmt/FmtCheck at :161/:193/:200, no lint target);
  ~160 `errcheck` sites, 14 inconsistent `//nolint:errcheck` annotations;
  `internal/ior_bpfsetup.go:92` (`mgr.Close()` error dropped in an error-cleanup
  path — the one non-stimulus site worth checking).
- **Fix:** `mage lint` running errcheck (cgo env from `goEnv()`, exclude file for
  intentional `syscall.Close` stimulus sites) or golangci-lint with `.golangci.yml`
  (errcheck+staticcheck); wire into `PrReview`/`World`; make intentional discards
  explicit (`_ =`); check-or-discard `mgr.Close()` at ior_bpfsetup.go:92.
- **Verify:** `mage lint` exists, is in the gates, and passes; fresh unchecked
  errors fail the build.
- [x] REVIEWED (final hardening commit: `1a8ef17`): fix confirmed correct

---

## Part 3 — LOW findings (not tasked; fix opportunistically or via D9's linter)

Bugs/defects LOW is B3 above (tasked). The rest, by source:

1. **[100-go #51]** errno compared with `==`/`!=` instead of `errors.Is`:
   `cmd/ioworkload/scenario_security.go:35`, `scenario_family.go:99`,
   `scenario_sleep.go:18` (siblings already use `errors.Is`, e.g. `scenario_mq.go:91`).
2. **[100-go #48]** panic-on-error `Snapshot()` variants with no production callers:
   `internal/statsengine/histogram.go:69`, `filerank.go:105`, `syscall.go:136`,
   `process.go:96` (engine path at `engine.go:304` propagates errors correctly).
3. **[100-go #54/#79]** unreachable `defer file.Close()`:
   `cmd/filewriter/main.go:16` (function exits only via infinite loop/`os.Exit`).
4. **[100-go #25]** append into sliced/reused backing arrays:
   `internal/tui/eventstream/export.go:266` (`append(parts[1:], path)`),
   `internal/tui/dashboard/model.go:1122`, `internal/tui/eventstream/model.go:160`
   (`append(m.filterStack[:0], ...)` on value-copied Bubble Tea models). Use
   `slices.Clone`.
5. **[gbp L1]** implicit error discards (~150, mostly `syscall.Close` stimulus in
   `cmd/ioworkload/scenario_*.go`; `cmd/ioworkload/scenarios.go:183`;
   `integrationtests/harness.go:54-55,175-180`) — folded into D9.
6. **[gbp L2]** 21 functions over the project's 50-line rule; worst:
   `cmd/ioworkload/scenario_mountfs.go:21` (125),
   `internal/tracepoints/dimension_selector.go:62` (76),
   `internal/generate/classify.go:45` (74) / `:508` (68),
   `internal/tui/flamegraph/renderer.go:487` (68) / `:575` (63),
   `internal/ior.go:596` (67 — resolved by D3).
7. **[gbp L3]** layout: `newEventLoop` after methods (`internal/eventloop.go:114`);
   mid-file decls at `internal/statsengine/engine.go:199`,
   `internal/file/file.go:174`, `internal/globalfilter/filter.go:48`,
   `internal/flags/flags.go:102`, `internal/event/pair.go:126`,
   `internal/eventloop_exit.go:483`.
8. **[gbp L4]** `Version` constant lives at `internal/flags/version.go:10` instead
   of conventional `internal/version.go` (banner-printing lives beside it — may be
   accepted knowingly).
9. **[gbp L5]** package-level mutable state: `defaultRegistry` mutated by
   `SetTUIRunners` (`internal/ior_mode_registry.go:97`, `internal/ior.go:38`);
   exported mutable `var Keys` (`internal/tui/common/keys.go:49`). SOLID rated the
   runner-injection LOW too: consider `Run(cfg, Runners{...})` or at minimum a
   nil-check returning "TUI runners not wired" instead of the nil-func panic
   (`ior_mode_registry.go:271-276`).
10. **[gbp L6]** stutter: `event.EventIdentity`/`event.EventLifecycle`
    (`internal/event/event.go:17,27`), `runtime.RuntimePublisher`/`runtime.RuntimeState`
    (`internal/runtime/runtime.go:113,131`).
11. **[gbp L7]** coverage below 60%: `internal/collapse` (0%), `internal/runtime`
    (0%), `internal/benchutil` (43.1%). Core `internal` is 74.3%.
12. **[SOLID L]** mode-handler mutual-exclusion matrix spread across handlers
    (`internal/ior_mode_registry.go:137-222`; reciprocal checks by convention) —
    declarative `exclusiveWith()` would centralize it.
13. **[SOLID L]** comm-carrier gate hardcoded type switch beside the kind registry
    (`internal/eventloop_runtime.go:277-292`) — a `carriesComm` property on the
    registry entry would prevent silent drops for future comm-carrying kinds.
14. **[SOLID L]** `eventstream.Model` bundles FD-trace/search/export sub-views and
    polled `Consume*Request` flags (`internal/tui/eventstream/model.go:78-84,
    241-279, 696-763, 936-967`; polled by `dashboard/tabregistry.go:267-281`) —
    prefer returned `tea.Cmd` messages.
15. **[SOLID L]** procfs I/O inside `file.NewFdWithPid` constructor
    (`internal/file/file.go:57-81`) with no seam in `fdTracker.resolve` — add a
    `resolveFn` field mirroring the commResolver seam.
16. **[arch L]** trace-ID adjacency assumption: Go pairing uses
    `GetTraceId()-1 != ...` (`internal/eventloop_runtime.go:307`) while
    `internal/c/filter.c:147-149` explicitly avoids numeric adjacency — assert at
    generation time or compare exact exit IDs from the generated table.
17. **[arch L]** wire format in three representations; hand-maintained fast
    decoders (`internal/types/fastdecode.go:19-58`) — emit them from
    `internal/generate/typesgo.go` instead.
18. **[arch L]** synchronous procfs I/O on the consumer goroutine
    (`internal/eventloop_exit.go:597` uncached per-pair `os.Readlink` for getcwd) —
    cache per-tid cwd, invalidate on chdir/exec.

---

## Overall assessment

Defect risk is low and concentrated: three confirmed bugs, and the one serious
correctness issue (cross-process fd aliasing) is what the in-flight refactor (B1)
fixes — finish it, with a cross-process test. Structurally the codebase is in
unusually good shape and visibly hardened by prior audits: correct
core→`internal/runtime`←TUI dependency direction, mode and event-kind registries,
narrow read/write interface splits with compile-time assertions, bounded LRU
state, exemplary failure-mode documentation on the C/BPF boundary. The residual
weakness is one pattern: **invariants held by convention and prose instead of by
types** — distributed either-name contract (D1), promised-but-unimplemented comm
timeout (D2), hand-permuted teardown (D3), a tab registry that doesn't yet keep
its promise (D4), and a flat root package where the compiler can't stop
field-poking (D5; the current compile break is live evidence). Pragmatic order:
land B1/22, then the "make it unrepresentable" tasks (52, 62, 72, 92, a2), then
polish (82, b2, c2, d2). Tension noted: splitting the root `internal` package
would fight the deliberate locality-based file grouping — D5 scopes
encapsulation-via-methods first and leaves the split optional.

## Review-pass checklist (for the reloaded reviewing session)

1. `git log --oneline` since `2ddd880`; map commits to findings B1–B3, D1–D9.
2. Walk every finding above; run its "Verify" line; tick the checkbox with the
   fixing commit hash. Confirm no fix introduced a regression in the neighboring
   findings (D3/D4/D7 share files with B2/82/b2).
3. Re-run the guardrail set (see "How to use this document").
4. `ask list` — confirm 22, 32, 42, 52, 62, 72, 82, 92, a2, b2, c2, d2 all done.
5. Spot-check the Part 3 LOW list: note (don't demand) any that were fixed
   opportunistically.
6. Mark gate task **e2** done; update this file's checkboxes and append a
   "Review outcome" section with date, commit range, and verdict per finding.

## Review outcome — 2026-09-14

The audit was reviewed from its original base `2ddd880` (including the
then-uncommitted fd-tracker work later committed in `7b266b4`) through
`develop` at `37e940d`. The reviewed range is `2ddd880..37e940d` (61 commits).
All twelve closure dependencies — tasks 22, 32, 42, 52, 62, 72, 82, 92, a2,
b2, c2 and d2 — are complete.

| Finding | Verdict | Fix and review evidence |
|---------|---------|-------------------------|
| B1 / 22 | PASS | `(pid, fd)` tracking and cross-process regressions landed in `7b266b4`. |
| B2 / 32 | PASS | Start/error ordering landed in `1eb08df` and was hardened through `5ba2ef9`; shared regular/headless setup in `e8bdd89` preserves the invariant. |
| B3 / 42 | PASS | Headless warning and unknown-counter reporting landed in `330694d` and was hardened through `aaeba32`. |
| D1 / 52 | PASS | The either-name rule is centralized in `Filter.Matches` by `00d77f4`; the cross-stage rename fixture passes. |
| D2 / 62 | PASS | Context-bounded procfs reads and prompt shutdown landed in `5581959`. |
| D3 / 72 | PASS | `traceInfra` lifecycle ownership landed in `8bff09b` and teardown panic/cancel handling was hardened through `b07b456`; `e8bdd89` reuses it for headless Parquet. |
| D4 / 82 | PASS | Generic per-tab state and registry-owned enter/sort hooks landed in `0a9f075`. |
| D5 / 92 | PASS | Tracker-owned initialization and setter-based output wiring landed in `93161af`. |
| D6 / a2 | PASS | Interface-typed runtime capabilities and removal of the downcast landed in `ed15ee1`. |
| D7 / b2 | PASS | Pointer-only main/dashboard/flamegraph models and value-only tracefilter flow landed in `b7fc76b`; race coverage passes. |
| D8 / c2 | PASS | The main documentation sweep landed in `b796520`; closure review found and `37e940d` corrected the final two exported-comment omissions. A production-only `golint` comment scan reports zero findings after the stated generated/testdata exclusions. |
| D9 / d2 | PASS | The lint gate landed in `28cddd8`; behavioural and command-data hardening culminated in `1a8ef17`. `mage lint` reports zero issues and the planted-defect tests pass. |

Part 3 LOW findings were spot-checked. Items 1 and 3 were fixed
opportunistically; item 5 was addressed and deliberately scoped by D9. Items 4
and 6 were partially improved by the receiver and trace-infrastructure
refactors. Items 2 and 7–18 remain accepted, untasked LOW observations. Later
tasks 14, o3, 04, 24 and 34 are separately recorded follow-ups, not dependencies
or blockers for this 2026-09-06 audit cycle.

Closure guardrails were rerun at `37e940d`: `mage fmtCheck`, `mage vet`,
`mage lint` (0 issues), `mage test`, `mage build` and `mage testRace` all passed.
The five existing `vmlinux.h` declaration warnings and static-linker glibc
warnings remain unchanged. No privileged live-BPF end-to-end trace was run.

**Final verdict: PASS.** Every tasked finding is fixed and independently
reviewed, the audit's declared dependency set is complete, and the full local
guardrail set is green.
