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

---

## Part 4 — Syscall tracing semantics audit — 2026-09-14

- **Scope:** every syscall tracepoint in `internal/c/generated_tracepoints_result.txt`
  (360 enter/exit pairs), checked against the Linux man pages (section 2) for:
  the argument slot each generated handler reads (`internal/generate/bpfhandler.go`
  → `internal/c/generated_tracepoints.c`), the classification of the payload
  (`internal/generate/classify.go`), the exit return-value classification
  (`retClassifications`), the userspace state semantics applied per pair
  (`internal/eventloop_exit.go`: fd registration/eviction, dup semantics,
  fcntl, close_range, pipe/socketpair/eventfd descriptor naming, flags), the
  family table (`internal/generate/family.go`), and what the tests actually
  pin (`internal/generate/*_test.go`, `internal/eventloop_*_test.go`,
  `cmd/ioworkload`, `integrationtests`).
- **Method:** the emitted `ev->X = ctx->args[N]` / `bpf_probe_read_user_str(...,
  args[N])` lines of every enter handler were extracted from the committed
  generated C and compared, syscall by syscall, with the kernel signatures in
  `syscalls(2)` and the per-syscall man pages. Kernel tracefs was not readable
  (unprivileged session), so the committed artifact is the reference; no live
  trace was run. No code was changed: every finding is a task.
- **Tasks:** semantic findings S1–S16 → `e4 f4 g4 h4 i4 j4 k4 l4 m4 n4 o4 p4 q4 r4
  s4 t4`; test findings T1–T3 → `u4 v4 w4`. Gate task **x4** (`+audit`) depends on
  all of them. `ask info <id>` carries the full context per task.

### Verified correct (no task)

Argument indices agree with the man pages for the whole traced set, including
the hand-pinned layouts: `mmap` fd at `args[4]`; `pidfd_getfd` pidfd at
`args[0]` (not the target `fd` field); `socketpair` `sv` pointer at `args[3]`;
`kcmp` `idx1/idx2/type` at `args[3]/[4]/[2]`; `move_mount` `from_dfd/to_dfd/flags`
at `args[0]/[2]/[4]`; `close_range` `(first,last,flags)`; `linkat`/`renameat*`
`oldname/newname` at `args[1]/[3]`, `symlinkat` at `args[0]/[2]`; `epoll_ctl`
`events` read from `struct epoll_event` offset 0; `poll/ppoll` nfds at `args[1]`
with timeout at `args[2]`, `select/pselect6` nfds at `args[0]` with timeout at
`args[4]`; `nanosleep` at `args[0]`, `clock_nanosleep` request at `args[2]` with
`TIMER_ABSTIME` (=1) at `args[1]` correctly suppressing the duration;
`add_key` ringid/plen at `args[4]/[3]`, `request_key` destringid at `args[3]`;
`ptrace` data at `args[3]`; `perf_event_open` `attr` layout `{u32 type, u32
size, u64 config}`; `execveat` dirfd/flags at `args[0]/[4]`; `fanotify_mark`
pathname at `args[4]`; `quotactl` special at `args[1]`; `mount` `dir_name` at
`args[1]`; `mq_open` oflag at `args[1]` (real `O_*` word); `open_by_handle_at`
flags at `args[2]`; `mremap` old/new length at `args[1]/[2]`; `pkey_mprotect` /
`remap_file_pages` / `mlock2` / `mseal` / `map_shadow_stack` layouts.

Semantics verified against the man pages: `creat` == `open(O_CREAT|O_WRONLY|
O_TRUNC)`; `dup2(fd, fd)` creates no descriptor; `dup`/`dup2`/`F_DUPFD` clear
`FD_CLOEXEC`, `dup3(O_CLOEXEC)`/`F_DUPFD_CLOEXEC` set it; `F_SETFL` changes only
`O_APPEND|O_ASYNC|O_DIRECT|O_NOATIME|O_NONBLOCK` (merge, not replace); `F_GETFL`
is the authoritative full word; `CLOSE_RANGE_CLOEXEC` (1<<2) closes nothing;
`sendmmsg`/`recvmmsg` return message counts and are deliberately unclassified
(pinned by `integrationtests/retbytes_test.go`); `msgsnd`/`mq_timedsend` return
0 and are unclassified while `msgrcv`/`mq_timedreceive` return byte counts;
`accept` does not inherit status flags from the listening socket; `execve`'s
`sys_exit` fires (ret 0) and its payload comm is the caller's; `rt_sigreturn`
is correctly noreturn — `restore_sigcontext` sets `orig_ax = -1`, so
`ftrace_syscall_exit` bails on `syscall_nr < 0` and `sys_exit_rt_sigreturn`
never fires, matching the empirical note in `codegen.go`. Family assignments
were checked and are defensible; the futex/robust_list and set_tid_address
boundary rules are documented in `family.go`.

Overloaded-but-harmless fields noted, not tasked: `pkey_mprotect` stores `pkey`
in `mem_event.length2` and `remap_file_pages` stores `pgoff` there
(`addressSpaceBytesFromMem` reads `length2` only for `mremap`); `ioctl` `cmd`,
`flock` `cmd`, `fallocate` `mode`, `fadvise64` `advice` are not captured
(fd-only kind, by design).

### Semantic findings (tag `+syscalls`)

#### S1 — MEDIUM — eventfd-kind flags are syscall-specific words rendered as open(2) flags — task e4

- **Where:** `internal/eventloop_exit.go` `handleEventfdExit` (`file.NewFd(fd,
  name, flags)`), `internal/generate/bpfhandler.go` `eventfdFlagsExpr`,
  `internal/file/flags.go`.
- **What:** `fanotify_init` (`FAN_CLOEXEC`=1, `FAN_NONBLOCK`=2; the `O_*` word is
  `event_f_flags` at `args[1]`, not captured), `memfd_create` (`MFD_CLOEXEC`=1,
  `MFD_ALLOW_SEALING`=2, `MFD_HUGETLB`=4), `fsopen`/`fsmount` (`*_CLOEXEC`=1),
  `landlock_create_ruleset` (`_VERSION`=1), `eventfd2` (`EFD_SEMAPHORE`=1),
  `userfaultfd` (`UFFD_USER_MODE_ONLY`=1) all land in `file.Flags`, so bit 1
  prints as `O_WRONLY` and bit 2 as `O_RDWR` in `-plain`/`-flamegraph`. Only the
  `EFD_`/`IN_`/`SFD_`/`TFD_`/`EPOLL_CLOEXEC`/`PIDFD_NONBLOCK` values coincide
  with `O_*`. `signalfd4` with `ufd != -1` also re-registers the existing fd with
  the new flags although `signalfd(2)` applies them only at creation.
- **Verify:** table-driven unit test per trace id asserting `Flags().String()`;
  no eventfd-kind row renders a non-`O_*` bit as `O_WRONLY`/`O_RDWR`.
- [x] REVIEWED (commit: `26a97c6`): PASS.

#### S2 — MEDIUM — `open_tree`/`open_tree_attr` classified as open(2) — task f4

- **Where:** `internal/generate/classify.go` generic rule (name contains "open" +
  `filename` → `KindOpen`); result table rows `sys_enter_open_tree` /
  `sys_enter_open_tree_attr` (`ev->flags = ctx->args[2]`); `handleOpenExit`.
- **What:** `open_tree(2)` flags are `OPEN_TREE_CLONE`=1, `OPEN_TREE_CLOEXEC`,
  `AT_EMPTY_PATH`, `AT_RECURSIVE`, `AT_SYMLINK_NOFOLLOW`, `AT_NO_AUTOMOUNT` — not
  `O_*`. They are rendered as `O_WRONLY`/`O_NONBLOCK`/`O_NOCTTY` and the returned
  fd is registered as a regular open with them.
- **Verify:** explicit classification pinned in `classify_test.go`; `open_tree`
  rows never show `O_*` names for `AT_*` bits; `integrationtests/mountfs_test.go`
  asserts the flags.
- [x] REVIEWED (commit: `16b87b9`): PASS.

#### S3 — MEDIUM — pipe/pipe2 write end registered without `O_WRONLY` — task g4

- **Where:** `handlePipeExit` registers `Fd0` and `Fd1` with the same word;
  `TestHandlePipeExitTracksReturnedFds` pins identical flags on both ends.
- **What:** `pipe(2)`: `pipefd[0]` is the read end, `pipefd[1]` the write end.
  Every `write()` row on the write end prints `O_RDONLY`. `O_NOTIFICATION_PIPE`
  (=`O_EXCL`) renders as `O_EXCL`.
- **Verify:** unit test asserts read end `O_RDONLY`, write end `O_WRONLY`;
  integration pipe scenario asserts `IterRecord.Flags` on the write end.
- [x] REVIEWED (commit: `b6e60c9`): PASS.

#### S4 — MEDIUM — `mmap` captures only the fd; `msync` is a null event — task h4

- **Where:** `classify.go` (`mmap` → `KindFd` via the `fd` field; `msync` pinned
  `KindNull`), `bpfhandler.go` `memFieldOverrides`, `eventloop_exit.go`
  `addressSpaceBytesFromMem` (only `munmap`/`mremap`).
- **What:** `mmap(2)` length/prot/flags never reach userspace, so
  `AddressSpaceBytes` counts unmaps and remaps but never the mapping that created
  a region; `MAP_ANONYMOUS` rows resolve fd `-1` to `E:name%(-1,O_NONE)`;
  `msync(addr, len, flags)` captures nothing.
- **Verify:** mmap rows carry the mapping length; anonymous mappings do not print
  `E:name`; `msync` is a `mem_event`; `integrationtests/mmap_test.go` asserts
  `AddressSpaceBytes` through the parquet path.
- [x] REVIEWED (commit: `e132dc9`): PASS.

#### S5 — MEDIUM — `dirfd` never captured for the `*at()` cohort — task i4

- **Where:** `generateExtraPathname` / `generateExtraOpenWithFields` /
  `generateExtraName` (only the pathname index is emitted; `execveat` is the
  sole exception), `types.h` `path_event`/`open_event`/`name_event`.
- **What:** per `openat(2)` and siblings a relative pathname is resolved against
  `dirfd`, and `AT_EMPTY_PATH`/NULL-pathname calls (`statx`, `utimensat`,
  `fchownat`, `linkat`, `name_to_handle_at`) operate on `dirfd` itself. ior keeps
  only the raw string, so `openat(3, "x")` and `openat(AT_FDCWD, "x")` are
  indistinguishable and empty-path calls yield an empty file with fd `-1`.
- **Verify:** a relative `openat` through a directory fd reports the joined
  path; `AT_EMPTY_PATH` rows report the dirfd's file.
- [x] REVIEWED (commit: `874a477`): PASS.

#### S6 — LOW — `inotify_add_watch` loses the pathname, `fanotify_mark` loses the fd — task j4

- **Where:** `ClassifyFormat` first-matching-field rule (`fd` wins for
  `inotify_add_watch(fd, pathname, mask)`; no `fd`-named field in
  `fanotify_mark(fanotify_fd, flags, mask, dfd, pathname)`).
- **Verify:** an `inotify_add_watch` row shows the watched path and the inotify
  fd; decision pinned in `classify_test.go` and the plan doc.
- [x] REVIEWED (commit: `b328889`): PASS.

#### S7 — LOW — `openat2` flags reported as `-1` — task k4

- **Where:** `generateExtraOpenWithFields` else-branch; documented gap in
  `docs/syscall-tracing-plan.md`; `TestGenerateOpenat2FlagsGapIsDocumented`.
- **What:** `struct open_how { u64 flags; u64 mode; u64 resolve; }` at `args[2]`
  is readable with the same guarded `bpf_probe_read_user` pattern
  `generateExtraPerfOpen` already uses.
- **Verify:** `open-openat2` integration scenario asserts the real `O_*` word.
- [x] REVIEWED (commit: `37569f7`): PASS.

#### S8 — LOW — `accept4` flags dropped; socket type flag bits leak into descriptor names — task l4

- **Where:** `generateExtraAccept`, `handleSocketExit`/`handleSocketpairExit`/
  `handleAcceptExit`, `socketDescriptorName`.
- **What:** `accept4(2)` `SOCK_NONBLOCK|SOCK_CLOEXEC` at `args[3]` are the only
  source of the accepted fd's status flags (not inherited per `accept(2)`);
  `socket(2)` `type` carries the same bits, which end up in
  `socket:<family>:<raw type>:<proto>` names instead of `O_NONBLOCK|O_CLOEXEC`.
- **Verify:** `socket:2:1:0` naming with `SOCK_CLOEXEC` set; `accept4` rows carry
  `O_CLOEXEC`/`O_NONBLOCK`.
- [x] REVIEWED (commit: `5e9f998`): PASS.

#### S9 — MEDIUM — `close(2)` eviction only on `ret == 0` — task m4

- **Where:** `applyFdCloseState`.
- **What:** per `close(2)` NOTES the descriptor is released on Linux even when
  `close` returns `EINTR`/`EIO`; only `EBADF` closes nothing. A stale `(pid, fd)`
  entry survives an `EINTR` close and mislabels the next holder of that number
  until an fd-registering syscall overwrites it.
- **Verify:** unit tests: `-EINTR`/`-EIO`/`0` evict, `-EBADF` keeps.
- [x] REVIEWED (commit: `7983293`): PASS.

#### S10 — LOW — `F_SETFD`/`F_GETFD` ignored while `O_CLOEXEC` is tracked per descriptor — task n4

- **Where:** `applyFcntlFdState` (`F_GETFL`, `F_SETFL`, `F_DUPFD`,
  `F_DUPFD_CLOEXEC` only) vs. `registerDup` (merges `O_CLOEXEC`).
- **Verify:** after `fcntl(fd, F_SETFD, 0)` on an `O_CLOEXEC` descriptor the next
  row no longer prints `O_CLOEXEC`.
- [x] REVIEWED (commit: `9ff880e`): PASS.

#### S11 — LOW — `kcmp` resolves `idx1` against the caller for every type — task o4

- **Where:** `twoFdOverrides` (`kcmp`), `handleTwoFdExit`.
- **What:** per `kcmp(2)` `idx1/idx2` are fds in `pid1`'s/`pid2`'s tables only for
  `KCMP_FILE`; for `KCMP_VM/FILES/FS/SIGHAND/IO/SYSVSEM` they are unused and for
  `KCMP_EPOLL_TFD` `idx2` is a pointer.
- **Verify:** `KCMP_VM` rows carry no file; `KCMP_FILE` on self resolves the right
  file.
- [x] REVIEWED (commit: `408a7db`): PASS.

#### S12 — LOW — `Flags.String()` misdecodes `O_TMPFILE`, hides `O_PATH`, doubles `O_SYNC` — task p4

- **Where:** `internal/file/flags.go`.
- **What:** `O_TMPFILE` (0x410000) prints as `O_DIRECTORY`; `O_PATH` (0x200000) is
  absent (prints `O_RDONLY`); `O_SYNC` ⊃ `O_DSYNC` prints both; `O_LARGEFILE`
  (present in every `F_GETFL`/procfs word on 64-bit) is undecoded.
- **Verify:** `0x410002 → O_RDWR|O_TMPFILE`, `0x200000 → O_PATH`,
  `0x101000 → O_SYNC`.
- [x] REVIEWED (commit: `bcdd787`): PASS.

#### S13 — LOW — size probes counted as bytes read; TRANSFER direction inconsistent — task q4

- **Where:** `retClassifications`, `bytesFromRet`, `statsengine` `RetType`
  switches; `nameOnlyKindsTable` comments for `sendfile64` (captures `out_fd`)
  vs `splice`/`tee`/`copy_file_range` (capture the source).
- **What:** `getxattr(2)`/`listxattr(2)` with `size == 0` return the required size
  and copy nothing; `syslog(2)` actions 9/10 return sizes and 0/1/5–8 return 0;
  all count as "bytes read". Per-file TRANSFER bytes go to the destination for
  `sendfile64` but to the source for its siblings.
- **Verify:** a size-0 `getxattr` row reports 0 bytes; the plan doc states the
  transfer attribution rule and `retbytes_test.go` pins it.
- [x] REVIEWED (commit: `337ff36`): PASS.

#### S14 — LOW — error detection is `ret < 0`, not the errno window `-4095..-1` — task r4

- **Where:** `internal/streamrow/row.go` (`IsError = ret < 0`), `internal/c/filter.c`
  `ior_update_syscall_aggregate`, fd gates in `eventloop_exit.go`.
- **What:** the kernel ABI (`MAX_ERRNO` 4095) is the rule; raw-word returns
  (`mmap`/`brk`/`shmat` addresses) with bit 63 set would be misreported. Not
  reachable on x86_64 user addresses today; three copies of the rule and no
  shared helper.
- **Verify:** one helper with a unit test (`-4096` not an error, `-4095` is).
- [x] REVIEWED (commit: `c8ea259`): PASS.

#### S15 — LOW — identifying payloads not captured; `bpf()` fds never registered — task s4

- **Where:** `eventfdFlagsExpr` (`memfd_create`/`fsopen`/`fsmount` flags only),
  `twoFdOverrides` (`move_mount` fds/flags only), `handleNullExit` (registers
  `io_uring_setup` fds but not `bpf()`'s).
- **What:** `memfd_create` name, `fsopen` `fs_name`, `move_mount` pathnames,
  `fsmount` `fs_fd` are cheap strings/ints that name the object per the man
  pages; `BPF_MAP_CREATE`/`PROG_LOAD`/`OBJ_GET`/`LINK_CREATE` return fds that stay
  unresolved until procfs.
- **Verify:** memfd rows named `memfd:<name>`; `move_mount` rows show the
  destination path; `bpf` fds resolve.
- [x] REVIEWED (commit: `ebe07cc`): PASS.

#### S16 — LOW — epoll wait timeouts not captured; poll `-1` sentinel conflates infinite and unknown — task t4

- **Where:** `classify.go` (`epoll_wait`/`epoll_pwait`/`epoll_pwait2` → `KindFd`),
  `pollOverrides`/`pollTimeoutBody`, `poll_event`.
- **What:** `poll(2)` negative timeout and `ppoll(2)`/`pselect(2)` NULL timespec
  mean infinite; an unreadable timespec is unknown; both are `-1`. The epoll wait
  family's timeouts (`args[3]`) are dropped because the epfd wins.
- **Verify:** `epoll_wait(…, 250)` reports 250 ms; `poll(…, -1)` is
  distinguishable from an `EFAULT` timespec.
- [x] REVIEWED (commit: `f457258`): PASS.

### Test findings (tag `+syscalls`)

#### T1 — MEDIUM — integration tests never assert flags/fd/ret/is_error/epoll/AddressSpaceBytes/RequestedSleepNs — task u4

- **Where:** `integrationtests/expectations.go` (`ExpectedEvent` = path substring,
  tracepoint substring, comm, count), `helpers_test.go` (bytes/duration only),
  `harness.go` (`-flamegraph` run; `RunParquet` available but unused for field
  assertions).
- **What:** every live-kernel semantic in Part 4 (open flags, creat's synthesized
  flags, dup/dup3/`F_DUPFD_CLOEXEC`, `F_GETFL`/`F_SETFL`, `close_range`
  `CLOEXEC`, pipe ends, socketpair `sv`, `epoll_ctl` op/target/events,
  `ppoll`/`pselect6`/`clock_nanosleep` timeouts, `munmap`/`mremap` bytes, the
  `-enoent`/`-ebadf` error scenarios) is checked only with synthetic unit events.
- **Verify:** each listed integration test asserts at least one non-count field;
  a deliberately wrong flags expectation fails.
- [x] REVIEWED (commit: `8e78a77`): PASS.

#### T2 — MEDIUM — no man-page-derived semantics pin over the generated artifact — task v4

- **Where:** `internal/generate/*_test.go` pin individual handlers;
  `generated_tracepoints_result.txt` is a diff-gated golden of whatever was
  generated; `docs_drift_test.go` checks docs vs lists.
- **What:** nothing asserts, for each of the 360 syscalls, that the argument slot
  read is the one the man page names, plus ret classification and family.
- **Verify:** a table-driven test enumerates every enter handler in
  `generated_tracepoints.c` against an explicit expectations map; removing an
  entry fails it; rows the S-tasks will change carry `TODO(<task>)`.
- [x] REVIEWED (commit: `8e811a3`): PASS.

#### T3 — LOW — workload/integration coverage gaps — task w4

- **Where:** `cmd/ioworkload/scenarios.go`, `integrationtests/*_test.go`.
- **What:** no live scenario for `fanotify_init`/`fanotify_mark`, `syslog`, `bpf`,
  `kcmp`, `open_tree_attr`, `msync` range, xattr size-0 probes, relative
  `openat` via dirfd, `statx`/`utimensat` `AT_EMPTY_PATH`, `F_SETFD`/`F_GETFD`,
  `accept4` flag assertions, `memfd_create` name, `signalfd4` on an existing fd,
  epoll wait timeouts.
- **Verify:** every listed syscall is covered by an `ExpectedEvent`, an
  `ExpectedRow`, or an equivalent direct semantic assertion appropriate to its
  output surface.
- [x] REVIEWED (commit: `dbf164a`): PASS.

### Review-pass checklist (Part 4)

1. `ask list` — confirm e4–w4 done; gate x4 READY.
2. Walk S1–S16 and T1–T3, run each Verify line, tick the checkbox with the
   fixing commit hash.
3. Re-run `mage generate` (must be a no-op diff on a host at least as new as
   the generation kernel), `mage fmtCheck`, `mage vet`, `mage lint`,
   `mage test`, `mage testRace`, `mage build`, and the privileged
   `integrationtests` suite.
4. Append a "Review outcome (Part 4)" section with date, commit range and a
   verdict per finding; mark x4 done.

### Review outcome (Part 4) — 2026-09-21

**Finding verdict:** PASS for S1–S16 and T1–T3. The reviewed fixing commits
run from `7983293` through `dbf164a`; this describes the history endpoints,
not an inclusive commit range. The checkbox beside each finding records its
exact fixing commit. Audit-derived follow-up `2e0165a`, found during v4's
review, corrects two syscall return classifications but has no separate
original finding checkbox. Two independent review passes covered S1–S10 and
S11–T3; their focused non-privileged tests passed and their live-test
assertions were inspected. Live assertions requiring syscalls absent from this
host are not claimed as executed successfully. T3's Verify wording was
corrected during review because some semantics intentionally use Parquet
`ExpectedRow` or a direct assertion instead of collapsed-output
`ExpectedEvent`.

| Finding | Verdict | Finding | Verdict | Finding | Verdict |
| --- | --- | --- | --- | --- | --- |
| S1 | PASS | S2 | PASS | S3 | PASS |
| S4 | PASS | S5 | PASS | S6 | PASS |
| S7 | PASS | S8 | PASS | S9 | PASS |
| S10 | PASS | S11 | PASS | S12 | PASS |
| S13 | PASS | S14 | PASS | S15 | PASS |
| S16 | PASS | T1 | PASS | T2 | PASS |
| T3 | PASS |  |  |  |  |

**Guardrails:** `mage fmtCheck`, `mage vet`, `mage lint`, `mage test`,
`mage testRace`, and `mage build` passed at `cfee406`. `mage generate` was
attempted but this host runs `5.14.0-687.42.1.el9_8.x86_64`, older than the
generation kernel; its diff gate correctly refused a deletion-only result for
newer syscalls and left the tree unchanged. The required no-op regeneration on
a host at least as new as the generation kernel therefore remains unverified.

The privileged `mage integrationTest` run exercised many supported live-BPF
scenarios, but it uses `-test.failfast`, so its nonzero result does not prove
that every otherwise-supported scenario ran. The observed host limitations
were: this host sets `/proc/sys/kernel/io_uring_disabled` to `2`, so
`TestIouringEnter` receives `EPERM`; its 5.14 kernel lacks `removexattrat`, so
`TestXattrRemovexattrat` receives `ENOSYS`; and the mountfs integration cannot
complete because the `open_tree_attr`, `statmount`, `listmount`, and `listns`
tracepoints are absent. The scoped sudo rule permits the integration binary
but not changing the host sysctl. These are not Part 4 semantic regressions,
but they mean the full privileged-suite gate is not a pass on this host.

**Gate verdict:** the findings are ready, but x4 remains open pending both the
no-op generation check and a complete privileged integration pass on a
suitable newer-kernel host. Self-review found no simpler trustworthy closure:
forcing generation here would replace reviewed newer-kernel artifacts with an
older subset, and treating unsupported integration scenarios as passes would
weaken the stated gate.

### Independent verification (Part 4) — 2026-09-21

A second, independent pass (not the fixing agent) checked the state of `develop`
at `5a3f82c` against each Part 4 Verify line: the argument captures were
re-extracted from the committed `generated_tracepoints.c`, the exit handlers in
`internal/eventloop_exit.go` were read, the semantics oracle was run, and
descriptor access modes were measured on the live kernel through
`/proc/self/fdinfo`. `mage fmtCheck`, `mage vet`, `mage lint`, `mage test`,
`mage testRace` and `mage build` all passed at `5a3f82c`. No privileged
integration run and no `mage generate` were performed, so the two open items in
the review outcome above stand unchanged.

**Confirmed as landed:** S1–S11, S13–S16, T1–T3. Notable checks: the close
eviction gate is now "anything but `-EBADF`"; pipe ends carry `O_RDONLY` /
`O_WRONLY` (matches fdinfo `00`/`01`); `open_tree*` has its own kind and maps to
`O_PATH` (+`O_CLOEXEC`); `mmap` has a dedicated event with addr/length/prot/
flags/fd and `msync` is a `mem_event`; every `*at()` kind carries its dirfd(s)
and AT flags, with `AT_EMPTY_PATH`/NULL handling gated per syscall and a
read-status field so a faulted read never inherits the dirfd's identity;
`openat2` reads `open_how.flags`; TRANSFER bytes are attributed to the
destination fd consistently (`sendfile64` 0, `splice` 2, `tee` 1,
`copy_file_range` 2); xattr size-0 probes report 0 bytes and `syslog` is
unclassified; the errno window `-4095..-1` is one Go helper plus the same
window in `filter.c`; epoll waits are `poll_event`s with epfd, maxevents and
timeout, with distinct infinite/unknown sentinels; the semantics oracle covers
every enter handler, carries no `TODO` rows and has mutation tests.

**Defects found in the fixes (tasked, added to gate x4):**

#### V1 — MEDIUM — `Flags.String()` drops `O_RDONLY` when any other flag is set — task n8

- **Where:** `internal/file/flags.go` `String()` (regression from `bcdd787`, S12).
- **What:** `O_RDONLY` is emitted only when no other name matched. Measured:
  `0x80000 → O_CLOEXEC`, `0x80800 → O_CLOEXEC|O_NONBLOCK`, while
  `0x80001 → O_WRONLY|O_CLOEXEC`. The S12 Verify cases pass, but the most
  common open in any trace (`O_RDONLY|O_CLOEXEC`) lost its access mode.
- **Verify:** `0x80000` renders `O_RDONLY|O_CLOEXEC`; `O_PATH|O_CLOEXEC` renders
  without `O_RDONLY`.
- [x] REVIEWED (commit: `f60ef1a`): PASS.

#### V2 — MEDIUM — fd-creating syscalls assert access mode `O_RDONLY` — task o8

- **Where:** `socketCreationFlags`/`acceptOpenFlags`, `eventfdOpenFlags` +
  `eventfdOpenFlagMasks` (S1/S8 fixes); `integrationtests/ipc_test.go` pins
  `AccessMode: O_RDONLY` for `eventfd2`, `memfd_create`, `signalfd4`.
- **What:** fdinfo on this host reports `O_RDWR` for socket, socketpair,
  eventfd2, epoll_create1, memfd_create, timerfd_create, signalfd and
  pidfd_open; pidfd_open is additionally always `O_CLOEXEC`; only
  inotify_init1 is `O_RDONLY`. Sockets moved from "unknown" (`-1`) to a
  definite wrong value.
- **Verify:** tracked flags equal the fdinfo word modulo `O_LARGEFILE` for each
  fd-creating trace id; the three integration pins are corrected.
- [x] REVIEWED (commit: `2032a89`): PASS.

**Observations, not tasked:** `two_fd_event` now carries two 256-byte names for
every `close_range`/`kcmp` and `eventfd_event` a 256-byte name for every
eventfd-kind call, which raises ring-buffer pressure for those rows;
`2e0165a` classifies `getcwd` and `sched_getaffinity` returns as bytes read,
which is correct for the raw syscalls but adds non-I/O bytes to read totals;
`AddressSpaceBytes` now also counts `msync` ranges, i.e. it means "extent
touched", not "address space changed"; the oracle's mutation test takes ~56 s
and is not skipped under `-short`.

#### Follow-up verification after V1/V2 — 2026-09-21

V1 was fixed by `f60ef1a`: read-only access mode is emitted alongside other
status flags, while `O_PATH` descriptors still omit `O_RDONLY`. Two fresh
review passes and the full test suite passed. V2 was fixed by `2032a89`:
fd-creating syscall families now carry their kernel access modes, pidfd and
io_uring include their implicit close-on-exec flag, syscall-specific flag
words are translated rather than copied, and families whose complete mode is
not captured remain unknown. The first independent review found four further
edge cases (the `memfd_secret` `FD_CLOEXEC` bit, io_uring's implicit
`O_CLOEXEC`, incomplete legacy `accept4` flags, and missing perf CLOEXEC test
coverage); all four were fixed, and a fresh follow-up review passed.

At `2032a89`, `mage fmtCheck`, `mage vet`, `mage lint`, `mage test`,
`mage testRace`, and `mage build` pass. The affected privileged live scenarios
also pass on this host: `TestEventfd2Basic`, `TestFdFromAirEventfdUsers`,
`TestSocketBasic`, `TestSocketAcceptLifecycle`,
`TestSocketAcceptLifecyclePlain`, and `TestFanotifyFlags`.

`mage generate` was rerun on `5.14.0-687.42.1.el9_8.x86_64`; the diff gate
again refused only deletions for newer-kernel syscalls and left the working
tree unchanged. Therefore the overall x4 gate remains open for the same two
external prerequisites: a no-op generation run on a host at least as new as
the generation kernel, and a complete privileged integration-suite pass on a
host that provides the required newer tracepoints/syscalls and permits
io_uring. The V1/V2 follow-ups themselves are fully reviewed and passing.

#### Second verification pass (Part 4) — 2026-09-21

Independent re-check of `develop` at `dbb4e56`. `mage fmtCheck`, `vet`,
`lint`, `test`, `testRace` and `build` pass. One `mage test` run failed in
`TestMageLintFailsOnAPlantedDefect` with "parallel golangci-lint is running"
because another linter instance was active on the host; the re-run with no
competing linter passed, so that is environmental, not a regression.

- **V1 / n8 — CONFIRMED** (`f60ef1a`): `O_RDONLY` is emitted whenever the
  access-mode bits are clear and `O_PATH` is unset; the composite cases from S12
  are unchanged.
- **V2 / o8 — CONFIRMED with one defect** (`2032a89`): sockets, accept/accept4,
  eventfd/eventfd2, epoll_create/create1, memfd_create, signalfd/signalfd4,
  timerfd_create, pidfd_open (implicit `O_CLOEXEC`), perf_event_open and the
  io_uring_setup fallback register `O_RDWR`; inotify_init/init1 `O_RDONLY`;
  kinds without a known mode (fanotify_init, fsopen, fsmount, landlock) stay
  unknown. Re-measured on the host through fdinfo: legacy `eventfd`,
  `epoll_create` and `userfaultfd` report `02`, `inotify_init` `00`.

#### V3 — LOW — `memfd_secret` close-on-exec mask changed to `FD_CLOEXEC` — task t8

- **Where:** `memfdSecretCloexecFlag` in `internal/eventloop_exit.go`
  (introduced by `2032a89`; previously `O_CLOEXEC`).
- **What:** `memfd_secret(2)` names `FD_CLOEXEC`, but `mm/secretmem.c` accepts
  only `O_CLOEXEC` and rejects bit 1 with `EINVAL`; the repo's own workload
  passes `unix.O_CLOEXEC`. Tracked memfd_secret descriptors therefore lose
  `O_CLOEXEC`. Not measurable on this host (`ENOSYS`).
- **Caveat recorded in the task:** the `userfaultfd` access mode is kernel
  dependent (`O_RDWR` here, `O_RDONLY` on newer mainline).
- **Verify:** `memfd_secret(O_CLOEXEC)` renders `O_RDWR|O_CLOEXEC`.
- [x] REVIEWED (commit: `3a43213`): PASS.

#### Follow-up verification after V3 — 2026-09-21

V3 was fixed by `3a43213`: `memfd_secret` now translates the kernel's
`O_CLOEXEC` input bit, the exact mapping is pinned by the unit table, and the
live integration expectation requires `O_CLOEXEC` when the syscall is
available. On this 5.14 host the probe returns `ENOSYS`, so the live flag
assertion was not executable; the tracepoint presence expectation remains in
place. A fresh independent review confirmed that only `ENOSYS` relaxes the
flag assertion and found no material issue.

At `3a43213`, `mage fmtCheck`, `mage vet`, `mage lint`, `mage test`,
`mage testRace`, and `mage build` pass. The focused privileged
`TestFdFromAirEventfdUsers` scenario also passes subject to the `ENOSYS`
qualification above. The overall x4 gate remains open for the same two
external prerequisites: a no-op generation run on a host at least as new as
the generation kernel, and a complete privileged integration-suite pass on a
host that provides the required newer tracepoints/syscalls and permits
io_uring.

#### Gate run for x4 — 2026-09-21

Run at `a74d0dd` (plus `f1ba4a1`, see V4) on `5.14.0-687.42.1.el9_8`.

- **V3 / t8 — CONFIRMED** (`3a43213`): the `memfd_secret` mask is `O_CLOEXEC`
  again, with the kernel source cited; the unit row is corrected; the live
  assertion is relaxed only on `ENOSYS`; the kernel dependence of the
  `userfaultfd` access mode is documented next to the table.
- **Dependencies:** all 23 gate dependencies are completed.
- **Guardrails:** `mage fmtCheck`, `vet`, `lint`, `test`, `testRace`, `build`
  pass.
- **Generation:** instead of stopping at the diff gate's refusal, the handlers
  were regenerated to stdout on this kernel and compared by name with the
  committed `generated_tracepoints.c`, ignoring the kernel-specific IDs.
  All 699 handlers this kernel can produce are byte-identical. The 32 handlers
  that exist only in the committed artifact belong to 16 syscalls this kernel
  lacks: `file_getattr`, `file_setattr`, `getxattrat`, `setxattrat`,
  `listxattrat`, `removexattrat`, `listmount`, `listns`, `statmount`,
  `open_tree_attr`, `lsm_get_self_attr`, `lsm_set_self_attr`,
  `lsm_list_modules`, `mseal`, `uprobe`, `uretprobe`. Those are pinned only by
  the generator tests and the semantics oracle.
- **Privileged integration suite:** run directly without `-test.failfast`, so
  every test got a verdict: 217 tests, 206 pass, 1 skip (`TestPosixMqBasic`),
  10 fail. Eight failures are host limits, confirmed from their messages:
  `TestXattrGetxattrat`/`Setxattrat`/`Listxattrat`/`Removexattrat` ("function
  not implemented"), `TestMountFsManagementSyscalls` (absent newer
  tracepoints), `TestIouringSetup`/`Register`/`Enter` (`io_uring_disabled=2`,
  "operation not permitted"). The other two were a real defect, V4.

#### V4 — MEDIUM — `ExpectedRow` demanded an exact comm; parquet row tests flaked — task 19

- **Where:** `integrationtests/expectations.go` `matchesRowExpectation`
  (introduced with T1, `8e78a77`).
- **What:** `ExpectedEvent` tolerates the empty comm ior emits before its
  asynchronous procfs lookup lands; `ExpectedRow` did not.
  `TestMmapMremapMunmapAddressSpaceBytesInParquet`, `TestSocketpairBasic` and
  `TestIouringRegisterEbadf` failed only because every captured row had
  `comm=""`; all semantic fields matched. Isolated re-runs failed 4 of 8.
- **Fix:** `f1ba4a1` — an empty row comm matches, a different non-empty comm
  still rejects; unit test added. The three tests then passed 5 of 5 in
  isolation. The full suite was not re-run after the fix.
- [x] REVIEWED (commit: `f1ba4a1`): fixed and verified by the gate run.

**Gate status:** x4 stays open. Everything verifiable on this host is verified.
What remains needs a host whose kernel provides the 16 syscalls above and
permits io_uring: a no-op `mage generate`, and a privileged suite run in which
the eight host-limited tests execute. Recommendation: make those eight tests
probe and `t.Skip` on `ENOSYS`/`EPERM`/absent tracepoints, as
`supportsMemfdSecret` already does, so the suite can go green on RHEL 9 and a
real regression is no longer hidden behind `-test.failfast`.
