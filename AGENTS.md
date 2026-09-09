# AGENTS.md

This file provides guidance to AI coding assistants working with the I/O Riot NG (ior) codebase.

## Build/Test Commands

**Prerequisites**: Ensure `libbpfgo` is cloned at `../libbpfgo` relative to this repository (or set `LIBBPFGO`), pinned to `v0.9.2-libbpf-1.5.1`, and rebuilt with:

```bash
git -C ../libbpfgo checkout v0.9.2-libbpf-1.5.1
git -C ../libbpfgo submodule update --init --recursive
make -C ../libbpfgo libbpfgo-static
```

If builds/tests fail with missing libbpf headers (for example `bpf/bpf.h` not found), rerun the commands above and then run `mage world`. Prefer Mage targets over raw `go test` for packages that import `libbpfgo`; Mage wires the required `CGO_CFLAGS`, `CGO_LDFLAGS`, and `LIBBPFGO` values.

**Vetting**: use `mage vet`, not bare `go vet ./...`. Besides wiring the cgo
environment, it scopes a single analyzer exemption: `cmd/ioworkload` is vetted
with `-unsafeptr=false` because `shmWrite` converts the mapping address
returned by `shmat` into a `[]byte`, which vet cannot distinguish from a raw
integer. Every other package — and every other analyzer in `cmd/ioworkload` —
is vetted normally, so bare `go vet ./...` reports that one known finding and
exits non-zero by design.

**Linting**: use `mage lint`, not bare `golangci-lint run` — for the same
reason as `mage vet`: without the cgo environment every package that imports
libbpfgo fails to typecheck, and the linter reports `bpf/bpf.h: No such file or
directory` instead of any real finding. The configuration is `.golangci.yml`:
errcheck plus staticcheck's SA (correctness) checks, with the ST/QF/S style
families off so the gate stays about bugs rather than taste.

`cmd/ioworkload` is exempt from errcheck for `syscall.Close`/`Munmap`/`Chdir`
and `os.RemoveAll`. That binary exists to make specific syscalls fire so the
tracer has something to observe; by the time its scenarios tear a descriptor
down, the syscall they were written to emit has already been traced, so a
failing teardown carries no information and checking it would bury each
scenario's syscall sequence under 160 `if err != nil` blocks. The exemption is
scoped to that one package *and* to those four calls — `internal/`, `cmd/ior`
and `integrationtests` are checked in full, and an ioworkload scenario that
drops the error of the syscall it exists to exercise is still a finding.

A second, narrower exemption is errcheck's own built-in
`DefaultExcludedSymbols`, which stays on (`disable-default-exclusions` is not
set). That is why unchecked `fmt.Fprintf(os.Stderr, …)` and
`strings.Builder`/`bytes.Buffer` writes are reported nowhere in the tree, while
the same `Fprintf` to a generic `io.Writer` is: `internal/ior_bpfsetup.go:94`
writes an unannotated `fmt.Fprintf(os.Stderr, …)`, while
`integrationtests/harness.go:296` has to write `_, _ = fmt.Fprintln(w, line)`
because `w` is an `io.Writer`. That asymmetry is the default exclusion list,
not an oversight, and unannotated stderr writes are common throughout the
tree.

**What actually runs the gates.** There is no CI in this repo, and `mage world`
cannot complete on a host older than the generation kernel (its `generate` step
is diff-gated; see "Generation host / kernel"). In practice the gates run when
somebody types `mage lint` / `mage world` on a suitable host, so treat them as
a pre-commit habit rather than something enforced for you. `internal/buildgate`
is what pins them. It fails if `World` stops running `FmtCheck`/`Vet`/`Lint`
**or discards their errors**, if `PrReview` stops running `World`, if `Lint`
stops invoking the linter at all, stops covering `./...` with the mage tag, is
pointed at another binary, or is told to exit 0 regardless, if errcheck or staticcheck's SA checks are disabled
(including via `linters.disable`, which overrides `enable`), if the errcheck
exclusion widens to match any Go file outside `cmd/ioworkload` or any call
beyond those four, if a second `.golangci.yaml`/`.toml`/`.json` appears and
shadows the reviewed config, or if a `//nolint` directive — with or without a
space after the slashes — appears anywhere in the tree.

Its config assertions are deny-by-default down to the sections it walks — top
level, `linters`, `linters.settings`, `linters.exclusions` and `issues` — so a
key not on the reviewed list fails the test. That matters because the ways
found so far to silence this gate were each a different key from the one the
tests were watching: `linters.disable` beats `enable`, `exclusions.paths` and
`.presets` beat `exclusions.rules`, `settings.errcheck.exclude-functions`
exempts a function module-wide, and `run.issues-exit-code: 0` or
`run.tests: false` silence it from a section none of those appear in. When
adding a key, read what it does and then add it to the known set in
`internal/buildgate/buildgate_test.go`. `mage lint` also runs
`golangci-lint config verify` before the run itself, because `run` ignores keys
it does not recognize and would otherwise report "0 issues" from a config
nobody reviewed.

Pinning a configuration by its spelling is a losing game, though — three rounds
of review each found another spelling that turned the gate off, twice by a
single character. So the assertion that actually matters is behavioural:
`TestLintConfigRejectsAKnownDefect` runs this repository's `.golangci.yml`
against a throwaway package containing an unchecked error and a dead store, and
requires both to be reported. A configuration that is plausible key by key and
collectively inert fails there regardless of how it was spelled.

`golangci-lint` itself is not pinned (`mage lint` names `@latest` when it is
missing), so a check set can differ between machines; the gate is a floor, not
a contract.

```bash
mage build                             # Build BPF object + Go binary (all is an alias)
mage buildDocker                       # Build ior inside a Rocky Linux 9 container (writes binary to repo root)
mage buildDockerEl8                    # Build ior inside a Rocky Linux 8 container (writes ior.el8 to repo root)
mage test                              # Run all tests
mage testRace                          # Run all tests with the race detector enabled (-race)
TEST_NAME=TestEventloop mage testWithName  # Run specific test
mage integrationTest                   # Build + run integration tests in parallel (parallelism capped to NumCPU)
mage integrationTestSerial             # Build + run integration tests one at a time
mage vet                               # go vet with the libbpfgo cgo env (use instead of bare `go vet ./...`)
mage lint                              # golangci-lint (errcheck + staticcheck SA) with the same cgo env
mage generate     # Generate code (required after modifying tracepoint definitions)
mage bench        # Run benchmarks
mage prReview     # Run PR review baseline: world + benchProf
mage clean        # Clean build artifacts
mage mrproper     # Clean + remove generated outputs (*.zst, *.svg, *.prof, *.pdf, *.tmp…)
mage world        # Clean + generate + fmtCheck + vet + lint + test + build (recommended reset path)
mage demo         # Regen docs/tutorial/ GIFs + screenshots (needs vhs+ttyd, sudo -v warmed)
TAPE=07-stream-live mage demoOne       # Regen one demo tape only
mage installDemoTools  # One-time: install vhs (go install) + ttyd (dnf) — Fedora/RHEL/Rocky only
```

## Demo Pipeline

`docs/tutorial/` holds the reproducible TUI demo: 14 [VHS](https://github.com/charmbracelet/vhs) `.tape` files under `docs/tutorial/tapes/` drive every dashboard tab and headless mode, write GIFs and PNGs into `docs/tutorial/assets/`, and the resulting tutorial is `docs/tutorial/tutorial.md`. Background workload is generated by `docs/tutorial/scripts/workload.sh`. `mage demo` is fully headless (no real terminal window) — safe to run in the background while editing code; the only foreground requirement is one `sudo -v` to pre-warm the sudo timestamp.

## Code Generation

**Run `mage generate` before building when tracepoint definitions change!**

A Mage target generates code from Linux kernel tracepoint data:

```bash
mage generate              # Generate all code (C and Go)
mage generateTracepointsC  # Generate C tracepoint handlers from /sys/kernel/tracing
mage generateTypesGo       # Generate Go types from C structs
mage generateTracepointsGo # Generate Go tracepoint list
```

Generated files (do not edit manually):
- `internal/c/generated_tracepoints.c` - BPF C handlers for syscall tracepoints
- `internal/types/generated_types.go` - Go structs matching C structs + type mappings
- `internal/tracepoints/generated_tracepoints.go` - List of available syscall tracepoints

Generator source code:
- `internal/generate/` - Parser, classifier, and code generation logic

### Generation host / kernel

The generator reads the *running* kernel's `/sys/kernel/tracing` tracepoint
tree, so the committed artifacts are pinned to the kernel they were generated
on. That kernel is substantially newer than RHEL/Rocky 9's `5.14` — the
committed set contains syscalls that only exist on recent mainline kernels
(`mseal`, `statmount`/`listmount`, `getxattrat`/`setxattrat`/`listxattrat`/
`removexattrat`, `lsm_get_self_attr`/`lsm_list_modules`, `open_tree_attr`,
`file_getattr`, …). Consequences:

- Regeneration is byte-deterministic **for a fixed kernel** (ordering is forced
  by `LC_ALL=C find | sort`), but running `mage generate` on an older kernel
  produces a large *deletion* diff, not a reproducibility bug. Do not commit
  such a diff: regenerate on a host at least as new as the generation kernel.
- `mage generate` is diff-gated for exactly this reason: it renders to a temp
  file, diffs the derived `internal/c/generated_tracepoints_result.txt` against
  the committed one, and aborts on *any* difference without touching the
  working tree (`GenerateTracepointsCForce` bypasses the gate).
- `buildDocker`/`buildDockerEl8` run `IOR_FORCE_GENERATE=1 mage generate` **by
  design**: the container regenerates against its own build kernel, and the
  resulting artifacts are throwaway build inputs, never committed back.
- `IOR_FORCE_GENERATE` is parsed strictly: only `1`/`yes`/`true` force;
  `0`/`no`/`false` keep the diff gate; unknown values warn and do not force.
- Attaching degrades gracefully at runtime: tracepoints missing on the running
  kernel are skipped with a warning instead of failing the run, which is why a
  binary generated on a newer kernel still works on `5.14`.

## Architecture

- **Entry point**: `cmd/ior/main.go` - Linux-only BPF-based I/O syscall tracer
- **Core packages**: `/internal/event/` (BPF event handling), `/internal/flamegraph/` (FlameGraph generation), `/internal/c/` (BPF programs)  
- **Output**: TUI dashboard and TUI flamegraphs (no embedded web flamegraph server mode)
- **TUI package**: `/internal/tui/` contains top-level Bubble Tea orchestration (`tui.go`), shared key map (`keys.go`), and styles (`styles.go`).
- **TUI Model receiver policy**: the three Bubble Tea models (`tui.Model`, `dashboard.Model`,
  `flamegraph.Model`) and the stream tab's model use **all-pointer methods** — `*Model`
  implements `tea.Model`, constructors return `*Model`, and every mutator takes
  `*Model` (the `eventstream` template). The filter modal
  (`tracefilter.Model`, like the sibling modals in `tui/probes` and `tui/export`)
  is **all-value-flow** instead: value receivers and every mutator returns the
  updated `Model`, matching its `Open`/`Close`/`Update` API. Do not mix
  receivers within a Model type: a value-receiver `Update` calling a
  pointer-receiver mutator only works while the value happens to be
  addressable, and a non-addressable or later-copied Model silently loses
  those mutations (task b2).
- **Dashboard tabs**: `/internal/tui/dashboard/` contains tab renderers (flame/overview/syscalls/files/processes/latency+gaps/stream) and tab framework model.
- **Export modal**: `/internal/tui/export/model.go` implements the centered modal used for CSV export flow in TUI mode.

## TUI Behavior

- **Default mode** is TUI (`-plain` disables TUI and prints CSV rows to stdout).
- **TUI trace flow** ingests events into the in-memory stats engine; it does **not** continuously write trace rows to disk.
- **File output in TUI** is explicit export only (`e`), writing `ior-stream-<timestamp>.csv` in the current directory from the current filtered stream snapshot. The `e` modal is an options picker (no filename shown); the default filename is generated at submit time (the stream tab's `X` "export as" modal is the one that pre-fills a name).
- **Export toggle flag**: `-tuiExport=true|false` (default `true`) enables or disables TUI stream CSV export at runtime, including the Stream tab's x/X/E shortcuts and their hints.
- **Tab navigation** supports `tab/shift+tab` and numeric keys `1..7` only. `left/right` and `h/l` navigate table columns (and the flame graph); they do not switch tabs.
- **Family visibility**: the Syscalls tab shows a per-syscall Family column classified via `TraceId.Family()`; there is no dedicated Non-IO tab.
- **When export is disabled**, export key hints are hidden from dashboard help and `e` and the Stream tab's x/X/E shortcuts do not open the export modal or write CSV files.
- **Fast-refresh cadence**: `-tui-fast-refresh` (default `250ms`) controls the high-frequency tick interval for the flamegraph and stream tabs; set to `0` to fall back to the built-in 200ms flame/stream tick constants (high-frequency refresh never fully stops — it does not fall back to the slower standard dashboard cadence).
- **Attach-time tracepoint selection**: with no `-trace-*`/`-no-trace-*` flags the default allowlist is the **FS family only** — the other 11 families (`Network`, `Memory`, `Signals`, `Sched`, `IPC`, `Time`, `Process`, `Security`, `Polling`, `AIO`, `Misc`) are opt-in via `-trace-families`/`-trace-kinds`/`-trace-syscalls`. Only the full opt-in set reaches the ~300+ syscalls the generator classifies; the default attaches a subset of them.
- **Sampling / aggregate-only mode**:
  - `-syscall-sampling-families` and `-syscall-sampling-syscalls` control per-family/per-syscall sampling (`0` = aggregate-only, `1` = all events, `N` = 1-in-N).
  - Current defaults include aggregate-only (`0`) for `futex`, `futex_wait`, `futex_wake`, `futex_requeue`, `futex_waitv`, and `clock_gettime`.
  - In raw output modes (`-plain`, `-flamegraph`, headless `-parquet`) the default aggregate-only rates are automatically promoted to `1` because these modes lack a TUI aggregate sink. Explicit per-family rate `0` is also promoted to `1` in raw modes (a family zero would otherwise erase the whole family from output with no aggregate to preserve it); user-explicit `-syscall-sampling-syscalls` overrides are still preserved.
  - **Sampled counts are exact, not scaled.** The kernel aggregates exactly the
    events it does *not* emit (`ior_on_syscall_exit` in `internal/c/filter.c`
    updates `syscall_aggregate_map` only when `emit_event == 0`), so the
    aggregate map and the ring-buffer stream partition the invocations: rate
    `0` contributes everything through the aggregate, rate `N` contributes
    ~1/N through per-event ingestion and the remaining (N-1)/N through the
    aggregate, and rate `1` writes no aggregate row at all. The drainer
    ingests rows for every trace ID whose rate is not `1`
    (`buildAggregateIngestTraceIDs`), so TUI/stats counts, error counts,
    latency totals and the latency histogram for sampled syscalls are the true
    full-population values with no double counting and no scaling estimate.
  - What stays sampled for rate `N` syscalls: per-event detail only — stream
    rows, file/process attribution, byte totals, gaps, and latency percentiles
    come from the ~1/N emitted pairs (kernel aggregate rows carry no bytes,
    gaps, files or processes). Counts/errors/latency-sums/histograms are full.
  - While a runtime filter with an unsupported dimension is active, aggregate
    ingestion is gated off entirely (`aggregateIngestAllowedForFilter`), so
    aggregate-only syscalls disappear and sampled syscalls fall back to their
    1-in-N counts until the filter is cleared.
- **Additional metric dimensions**:
  - Address-space extent accumulator: `TotalAddressSpaceBytes` and `AddressSpaceBytesPerSec` in `statsengine.Snapshot`.
  - Per-event stream/export field `requested_sleep_ns` (from sleep tracepoints).
- **Drop observability**: every generated handler counts a kernel-side event loss
  (`bpf_ringbuf_reserve` returning NULL, i.e. `event_map` full under userspace
  backpressure) in the per-CPU BPF map `ringbuf_drop_map` via
  `ior_count_ringbuf_drop()` (`internal/c/filter.c`). Userspace polls that map
  once per second (`ringbufDropMonitor`): a growing count raises a live warning
  (a TUI stream warning row, stderr in `-plain`/headless modes) and the run
  total is always printed in the end-of-run `Statistics:` block as
  `ring buffer drops: N (N/s, N% of events)`.
- **Comm resolution across `execve`**: most event payloads carry no command
  name, so it comes from `commResolver` (`internal/eventloop_comm.go`), an
  asynchronous `/proc/<tid>/comm` cache. Every lookup is bounded by
  `resolveCommTimeout` for real: `os.ReadFile` cannot be interrupted once
  inside the kernel, so the default resolver runs the blocking read in a
  helper goroutine and abandons it on expiry (`resolveCommWithinCtx`) - a
  `/proc` read stuck in the kernel (D-state task, frozen cgroup) can neither
  stall a worker nor hang the `workersWG.Wait()` that shutdown blocks on,
  and once shutdown begins the workers drain the queue without paying for
  the remaining reads. A tid survives `execve`, so a lookup
  that lands in the post-fork/pre-exec window would cache the *pre-exec* name
  and label the new program's first syscalls with it. The hand-written
  `sched:sched_process_exec` handler in `internal/c/exec.c` closes that race: it
  emits a `PROCESS_EXEC_EVENT` control record carrying `bpf_get_current_comm()`
  taken after the kernel installed the new name. It is not a syscall
  tracepoint, so it lives outside `probemanager` and is attached directly by
  `attachProcessExecProbe` — **before** the syscall tracepoints, and regardless
  of `-trace-*` selection. Control records never become rows; they only refresh
  the cache (`handleProcessExecEvent`), and because the ring buffer preserves
  reservation order and the event loop has a single consumer goroutine, the
  refresh lands before the new program's first syscall pair — **for every record
  that is actually delivered**. Two residual paths are handled explicitly:
  - *Lost record.* Under backpressure `bpf_ringbuf_reserve()` fails and the
    control record is never emitted (counted in `ringbuf_drop_map`). With
    `-comm X` active the usual self-healing path is closed too, because
    `matchRawOpenEvent` drops non-matching opens at enter so `handleOpenExit`
    never refreshes the cache from the kernel comm. A non-zero drop delta
    therefore flags the whole comm cache stale (`markAllStale`, requested by the
    drop monitor goroutine and applied by the event-loop goroutine in
    `applyPendingCommRefresh`). A stale entry keeps serving its current value
    and triggers one asynchronous procfs re-read on next use — that read happens
    after the exec, so it heals the label. Evicting instead would blank the comm
    column and, under `-comm`, drop the tid's events at the enter-side gate.
  - *Late lookup worker.* A resolver worker that read `/proc/<tid>/comm` before
    the exec could otherwise overwrite the authoritative post-exec name. Each
    cache entry carries an exec epoch, bumped by `handleProcessExecEvent`; a
    worker samples it before its procfs read and its result is discarded when
    the epoch moved on. Both writes are mutex-protected, so this is a logical
    race the race detector cannot see.

  A failed attach is non-fatal and simply degrades to the old procfs-only
  labelling. Correspondingly, `handleExecExit` deliberately does **not** cache
  the `sys_enter_execve` comm of a *successful* execve (that is the *calling*
  program's name); it does cache it for a **failed** one, where no
  `sched_process_exec` fires and the task keeps running under exactly that name.
  Kernel-sourced names — the control record, an open event's payload comm, a
  failed execve's payload comm — all go in through
  `commResolver.setCachedFromKernel`, which bumps the tid's rename generation
  and so retires any procfs lookup still in flight for it. A `markAllStale`
  sweep likewise bumps a resolver-wide sweep generation, so a lookup that was
  already in flight when the sweep ran lands *stale* rather than silently
  clearing the flag it never received.
- **Where the pair filter is enforced per kind**: *every* exit handler now ends
  in a full-strength checkpoint, so no kind escapes any filter dimension, and
  every handler performs its global-state mutations **before** that checkpoint.
  Those are two separate rules and both are load-bearing:
  - *State before the filter.* The fd table (`fdTracker`) and the comm cache are
    global, so a row this run does not want must still leave them correct for
    the rows it does want. `handleOpenExit` is the reference (registration plus
    `setCachedCommFromKernel` before `finishPair`, pinned by
    `TestDroppedOpenStillRegistersTheFd`), and the dup family now follows it:
    `handleFdExit` calls `applyFdTransferOp` (dup/dup2 `registerDup`,
    `pidfd_getfd`), `handleDup3Exit` calls `registerDup`, and `handleFcntlExit`
    calls `applyFcntlFdState` (F_SETFL, F_DUPFD, F_DUPFD_CLOEXEC) — all ahead of
    `finishPair`. Until then a `-path`/`-comm` run that dropped a dup row left
    the duplicated descriptor unregistered, so every later read/write/close on
    it lost its filename, or — when the target fd number was already tracked
    (`dup2(old, new)`) — kept reporting the file `new` used to point at, which
    is a *wrong* row rather than a missing one. Unlike the numeric dimensions
    this was CLI-reachable. Pinned by
    `TestDroppedDupStillRegistersTheDuplicatedFd` and
    `TestDroppedFcntlSetflStillUpdatesTheFdTable`
    (`internal/eventloop_dupfilter_test.go`). Eviction is the same rule from the
    other side — `applyFdCloseState` and `applyCloseRangeState` also run ahead of
    the checkpoint, because a *stale* entry mislabels the next syscall that
    reuses the descriptor number (`TestDroppedCloseStillEvictsTheFd` and
    `TestDroppedCloseRangeStillEvictsTheFds` respectively). Because these
    mutations now run on every pair rather than only surviving ones, the failure
    guards matter too: `registerDup` ignores a negative return
    (`TestFailedDupDoesNotRegisterAnFd`) and so does the `pidfd_getfd` branch
    (`TestFailedPidfdGetfdDoesNotRegisterAnFd`).

    Scope caveat: this rule is about the *pair-filter checkpoint*. Two earlier
    gates still drop events before any exit handler runs, so it does not make
    the fd table unconditionally correct under a filter. `matchRawOpenEvent`
    drops non-matching opens at enter, so under `-path X` an open of a different
    file never registers its fd at all (the one exception is an open whose
    payload filename is *empty* — see "Recovering a faulted open filename"
    below, where the path dimension is deferred to the exit checkpoint); and
    with `-comm` active
    `tracepointEntered` recycles a non-open/exec enter event for a tid whose
    comm is not cached yet — and comm resolution is asynchronous, so a brand-new
    tid's first syscall is exactly the exposed one. The `NewFdWithPid` procfs
    fallback covers both while the descriptor is still open.
  - *Filter input must be the reported value.* `pidfd_getfd` re-points `ep.File`
    at the transferred descriptor; while that happened after the checkpoint the
    pair was judged on the **source pidfd**, so `-path <transferred file>`
    dropped the very row that prints it and `-path pidfd` kept a row that
    printed something else. The assignment now precedes the filter
    (`TestPidfdGetfdIsFilteredOnTheFileItReports`). This is the hazard the
    `handleOpenExit` comment argues against, and the same reason
    `applyDerivedPairValues` runs before the handlers (below).
  - The name (rename-like) kinds end in the same `finishPairForTid` as every
    other kind. Their oldname-OR-newname rule is not a separate checkpoint any
    more: the file dimension of `Filter.Matches` is either-name-aware
    (`Candidate.OldFileValue` reports `Pair.Oldname` / `streamrow.Row.OldName`
    as the alternate value), mirroring the raw enter filter `MatchNameEvent`,
    which matches oldname-or-newname while `oldnameNewnameFile.Name()` reports
    only the newname. `MatchPairEitherName`/`MatchesEitherName` and
    `finishPairEitherName` used to exist as per-stage variants each caller had
    to remember to pick; they were deleted because picking the plain one was
    exactly how a `-path <oldname>` row counted in one stage went missing in
    another. Widening *only* the file dimension is what lets these kinds run
    the full pair filter at all.
  - The path kinds and `open_by_handle_at` run the full `finishPairForTid`; for
    `open_by_handle_at` that is the *only* filtering it gets, because its raw
    enter filter is `nil` (see `rawRuntimeEvents`).
  - `handleOpenExit` runs the full `finishPair`. Its raw enter filter
    (`MatchOpenEvent`) covers the comm and path dimensions only, so before this
    checkpoint existed `-syscall`/`-family`/`-fd`/`-ret`/`-latency`/`-bytes` and
    non-equality `-pid`/`-tid` reached open rows nowhere at all. Its fd
    registration and `setCachedCommFromKernel` stay *before* the filter: a row
    this run does not want must still leave the fd table and the comm cache
    correct for the rows it does want.
  - Every remaining kind ends in `finishPair`/`finishPairForTid`.

  Stated honestly, closing the open/name gap is **hardening, not an
  observable bug fix**: the dimensions it newly enforces are not reachable
  from the CLI at all. `flags.BuildTraceFilter` sets only comm/path/pid/tid,
  and the raw modes have no other filter source, so in `-plain`/`-flamegraph`/
  headless `-parquet` the only live dimensions are comm and path (already
  enforced at enter by `MatchOpenEvent`/`MatchNameEvent`) plus equality
  `-pid`/`-tid` (pushed kernel-side via `PID_FILTER`/`TID_FILTER` in
  `internal/c/filter.c`). The value is that a future raw-mode filter source
  cannot silently reintroduce the gap. The TUI reaches every dimension through
  its filter modal and filters in two further stages — `shouldIngestTracePair`
  (`internal/ior.go`, feeding the stats engine, flamegraph and parquet
  recorder) and the Stream tab's `applyFilter` plus its CSV export
  (`internal/tui/eventstream/`). Both call the same central predicate
  (`MatchPair`/`Matches`), whose file dimension carries the either-name rule,
  so the stages agree with the checkpoint by construction instead of by
  discipline; `TestAllFilterStagesAgreeOnRenameRows` is the fitness test that
  fails if a stage ever re-narrows on its own.
- **The fd table is keyed by (pid, fd), never by the bare fd number**: a
  descriptor is only meaningful inside the process that owns it, and fd 3 and
  fd 6 are near-universal, so the flat per-fd map `fdTracker.files` used to be
  made whichever process registered last own an entry - labelling every other
  process's rows with the wrong filename - and let one process's close evict
  another's still-open mapping. Both fdTracker maps now key on
  `fdKey(pid, fd)` (pid = the tgid the kernel stamps on every event), every
  fd-creating/evicting handler passes its enter event's `Pid` along, and
  `close`/`close_range` evict only the calling process's slice. Two
  reclamation paths keep the now-per-process key space bounded: the LRU cap
  `defaultMaxFdTableEntries` (the flat map had no cap at all; eviction is
  safe because `resolve` falls back to the procfs cache and then
  `/proc/<pid>/fd`), and a `sched:sched_process_exit` control record — the
  sibling of `sched_process_exec` in `internal/c/exec.c`, attached the same
  way in `internal/ior_bpfsetup.go` — whose `handleProcessExitEvent`
  (`internal/eventloop_processexit.go`) drops the exited tgid's entries from
  both maps. It fires per *task*, so a thread exit in a still-living
  multithreaded process evicts that process early: degraded, not wrong — the
  procfs fallback still answers and re-populates the table.
- **The pair filter runs on a fully derived Pair**: `tracepointExited` calls
  `applyDerivedPairValues` (bytes, address-space extent, requested sleep,
  latency and inter-syscall gap) *before* dispatching to the exit handler, i.e.
  before the checkpoint above. Computing them afterwards silently turned
  `-latency`/`-gap`/`-bytes` into "compare against 0" for **every** kind — a
  `-latency >= 50` filter dropped a row whose real latency was 100ns. Only the
  emission-side work stays after the handler (`finalizeTracepointPair`:
  advancing the per-tid previous-exit timestamp and `freezePairForEmission`).
  `freezePairForEmission` stays because it needs `ep.File`, which the handler
  assigns; advancing the timestamp stays for a different reason — so the gap
  keeps being measured from the previously *emitted* pair rather than from one
  the filter dropped. This ordering predates the per-kind checkpoints above and
  was wrong for every kind that already ran `MatchPair`, not just the ones
  added here.
- **Recovering a faulted open filename**: `bpf_probe_read_user_str()` is a
  *nofault* read — it runs with page faults disabled, so it returns `-EFAULT`
  and leaves the destination untouched when the user page is not resident. For
  the open family that is not a corner case: the path string usually lives in
  freshly mapped, never-touched memory (the classic case is the first `openat`
  a program makes through a library it has only just `mmap`'ed, the string
  sitting in that library's `.rodata`). Measured on this tree at 64dcac1,
  6153/41063 (14.98%) of the `openat` rows of a fork/exec workload and
  2107/10553 (19.97%) of a system-wide idle capture arrived with an empty
  filename. Such a row printed `E:name`, registered its descriptor under the
  empty string so every later read/write/close on it lost its path too, and
  could never match a `-path` pattern.

  Retrying at `sys_enter` cannot help (still nofault, still not resident), but
  by `sys_exit` the kernel's own `getname()` has faulted the page in, so the
  identical read succeeds. The generator therefore emits, **for the open kinds
  only** (`KindOpen`/`KindMqOpen`, flagged by `recoversFilename` in
  `internal/generate/kindregistry.go`; an exit handler learns what its enter
  captured through `GeneratedTracepoint.EnterKind`, since every `sys_exit_*`
  format is just `long ret` and so classifies as `KindRet`):
  - enter: `ior_stash_pending_filename(tid, ptr)` when the read fails, parking
    the user pointer in `syscall_enter_state.pending_filename`;
  - exit: `ior_take_pending_filename(tid, SYS_ENTER_X)` **before**
    `ior_on_syscall_exit`, which deletes the per-tid entry — guarded on
    `enter_trace_id` so a stale entry cannot graft a foreign path — then
    `ior_emit_open_name_fixup(...)`, which re-reads the string and publishes it
    as an `OPEN_NAME_FIXUP_EVENT` (48) control record **before** reserving the
    handler's own exit record. All three helpers live in `internal/c/filter.c`.

  The record reuses `struct open_event` (it carries exactly one thing: the enter
  payload's filename, read a second time), so it needs no Go type and no
  `fastdecode` entry of its own — only the generated constant and a
  `controlRaw` row in `rawRuntimeEvents`. `handleOpenNameFixupEvent`
  (`internal/eventloop_openfixup.go`) splices it into the still-pending enter
  event: the ring buffer preserves reservation order and the event loop has a
  single consumer goroutine, so the fixup always lands while the enter event is
  unpaired. It never overwrites a name the enter side captured itself, and it
  re-checks the enter trace ID so an `openat` fixup cannot be grafted onto a
  pending `open`. A still-failing re-read is discarded kernel-side rather than
  submitted; a fixup lost to backpressure simply never arrives and the row keeps
  its empty name, exactly as before.

  **The enter gate defers, it does not waive.** `matchRawOpenEvent` used to
  judge the path dimension on the payload filename, so an empty-name open was
  dropped before its fixup could arrive — which is why `-path` silently missed
  exactly these events. For an empty payload name the *file* dimension alone is
  now deferred (`Filter.MatchOpenEventComm`); the comm dimension still applies
  at enter, and the full pair filter applies at the exit checkpoint, where
  `handleOpenExit` ends in `finishPair` (see above). Nothing leaks: an
  unrecovered name reaches `finishPair` empty, and no non-empty `-path` pattern
  matches the empty string, so the row is dropped there instead of here.
  Evidence, identical 4s fork/exec workload: `E:name` rows 6153/41063 (14.98%)
  → 0/39617 (0.00%), and `-path locale-archive` — the path those opens were
  actually taking — went from 0 matched rows to 6211.

- **Control records in the statistics**: `numTracepoints` counts every non-empty
  ring-buffer record the event loop pulled off the ring. It is incremented
  before dispatch, so it counts records *seen*: undecodable records
  (`dropMalformedRawEvent`) and unhandled event types are included, and so are
  control records. Both the mismatch percentage and the `ring buffer drops: … %
  of events` denominator therefore cover the whole ring-buffer stream rather
  than syscall pairs alone. That is deliberate: `internal/c/exec.c` also counts
  a control record it fails to reserve in `ringbuf_drop_map`, so the drop share
  only stays arithmetically honest if the events side counts them too.

## Code Style

- Standard Go conventions with static linking (`-ldflags '-w -extldflags "-static"'`)
- Keep functions under 50 lines, refactor larger code to `/internal/` packages  
- Use generated types from `/internal/types/generated_types.go` for kernel-userspace communication
- BPF C code in `/internal/c/ior.bpf.c` should be minimal for verification
- Import style: `"ior/internal/packagename"` for internal packages
- Error handling: Return errors, don't panic except for setup validation
- Deliberately discarded errors are written as an explicit `_ =` (or
  `defer func() { _ = f.Close() }()`), never as a bare call with a
  `//nolint:errcheck` comment: the annotations were how these sites drifted
  apart in the first place — 24 of them had accumulated across `cmd/ioworkload`
  (16), `integrationtests` (7) and `audit/check` (1), of which 15 sat on one of
  the 160 otherwise-identical teardown calls and the rest did not. `//nolint` is banned outright and
  `internal/buildgate.TestNoNolintDirectives` enforces it, because the lint
  gate cannot: golangci-lint honours the directive by construction, so one
  comment removes a file from the gate while `mage lint` still reports
  "0 issues". Blanket exemptions live in `.golangci.yml` (see Linting above),
  stated once with their reasoning instead of re-litigated per call site.
  Inside `cmd/ioworkload` the covered teardown calls are written plainly, with
  no `_ =`, so all 160 look the same and the config is the single place the
  exemption is expressed.
- Compare errors with `errors.Is`, not `==`/`!=`, whenever the value is typed
  `error` (e.g. `errors.Is(err, syscall.EINTR)`). A bare `errno` returned by
  `syscall.RawSyscall` is a concrete `syscall.Errno` that cannot be wrapped, so
  `errno != 0` and `errno != syscall.EAGAIN` stay as direct comparisons.

## Rollback

If `v0.9.2-libbpf-1.5.1` stops working, roll the local checkout back to commit
`90dbffffbdab` (module version
`v0.6.0-libbpf-1.3.0.20240111220235-90dbffffbdab`), update `go.mod`/`go.sum`
accordingly, and rebuild:

```bash
git -C ../libbpfgo checkout 90dbffffbdab
git -C ../libbpfgo submodule update --init --recursive
make -C ../libbpfgo libbpfgo-static
```
