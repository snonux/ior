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
a pre-commit habit rather than something enforced for you.

**Where the gates are defined.** `Magefile.go` is behind `//go:build mage`, so
nothing can import it, and for several rounds every assertion about what `mage
lint` really runs had to be made against the *source text* of a function no
test could call. That lost repeatedly — a body that merely mentions the right
strings and runs nothing, a flag routed through a constant, a helper wrapping
the invocation, an early `return nil`. So the command lines live in
`internal/gatecmd` as ordinary data, and the Mage targets are thin wrappers
that supply the cgo environment and check the error. Change a gate's arguments
there, not in `Magefile.go`.

`internal/buildgate` pins the result, in three layers, weakest first:

1. *Argv.* Each `gatecmd` command line is compared against the reviewed one
   exactly — an allow-list, because blocklisting flags lost by one character
   twice (`--issues-exit-code` banned, `--issues-exit-code=0` walked past).
2. *Configuration.* Deny-by-default over the sections it walks — top level,
   `linters`, `linters.settings`, `linters.settings.staticcheck`,
   `linters.exclusions` and `issues` — because every way found to silence this
   gate was a different key from the one being watched: `linters.disable`
   beats `enable`, `exclusions.paths` and `.presets` beat `exclusions.rules`,
   `settings.errcheck.exclude-functions` exempts a function module-wide, and
   `run.issues-exit-code: 0` or `run.tests: false` work from a section none of
   those appear in. Adding a key means reading what it does and then adding it
   to the known set in `internal/buildgate/buildgate_test.go`.
3. *Behaviour — the layer that actually matters.* Pinning a configuration by
   its spelling is a losing game; five rounds of review each found another
   spelling. So `TestLintArgvRejectsAKnownDefect` runs the real lint argv with
   this repository's `.golangci.yml` against a throwaway module containing an
   unchecked error (in both a `.go` and a `_test.go` file) and two different
   staticcheck findings, and requires all of them to be reported — a config
   that is plausible key by key and collectively inert fails there.
   `TestMageLintFailsOnAPlantedDefect` goes one further and runs `mage lint`
   itself against a `git archive` of HEAD with an unchecked error added; it is
   the only test that sees the target as a whole, and the only one that catches
   an early-return guard clause or an error cleared before it is returned. It
   takes ~24s and is skipped under `-short`.

Two tree properties are pinned the same way — by asking the toolchain rather
than by matching text. `TestMageTagHidesNoFile` diffs `go list ./...` against
`go list -tags mage ./...`, because the single lint pass is sound only while no
file is excluded *by* that tag, and three rounds of regex plus one `//go:build`
parser each missed a spelling. `TestNoNestedModules` fails on any `go.mod`
below the root, since one would cut its subtree out of every `./...` at once.
`mage lint` also runs `golangci-lint config verify` before the run, because
`run` ignores keys it does not recognize and would otherwise report "0 issues"
from a config nobody reviewed.

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

**Opt-in stress signals**: `IOR_STRESS_TEST=1` turns on the two timing/throughput
signals that measure the *host* as much as the code, so neither gates
`mage test`. `internal/flamegraph.TestLiveTrieStressHighRateConcurrentSnapshot`
skips entirely without it; `internal/tui/flamegraph.TestStressHighEventRate`
always runs and always logs its render latency, but only asserts it against the
30fps frame budget when the variable is set. Run them on an otherwise idle box:

```bash
IOR_STRESS_TEST=1 go test -count=1 -run TestStressHighEventRate ./internal/tui/flamegraph/
```

Asserting that budget by default is what made `TestStressHighEventRate` flake:
peak render latency measured 11.6ms idle, 63.0ms under `-race` and 249.6ms
under 8x CPU oversubscription, so a loaded machine failed it deterministically and
`-failfast` then hid every package that had not yet run. What it gates on now
is load-independent instead — no event lost or double-counted by 10-way
concurrent ingest, every intermediate snapshot decoding and laying out inside
the viewport, snapshot totals never going backwards, an exact frame count for
the completed fixture trie, and a ceiling on the *allocations* one render pass
costs. The allocation *count* does not move with CPU pressure: across idle,
`-race` and 8x-16x oversubscription it varied by 0.14% (28917-28958), against a
33000 ceiling. The byte total takes more work to make load-independent — see
below.

The exact frame count is what gives the test grip on pruning. The bound it
replaced — frame count against the viewport's cell count — could not fail, and
with only that bound in place, raising `liveTrieMinFraction` from 0.001 to 0.05
dropped the flamegraph from 321 frames to 21 and the whole suite still passed.
Assert the *last* sample, never the peak: pruning is relative to the running
root total, so an early snapshot legitimately keeps more nodes, and how many
depends on where the render loop's ticks land (330 and 523 on two runs of the
same fixture). The completed trie is a property of the fixture alone.

Two tests make those bounds transfer to the TUI, and it takes both. The stress
test drives `SnapshotJSON` + decode; the flame tab drives `SnapshotTree()` and
skips the round-trip. `TestSnapshotTreeMatchesJSONRoundTrip` pins that the two
lay out to identical frames, and `TestFlameRefreshUsesTheTreeSnapshot` pins
that the tab's refresh paths really do call `SnapshotTree` and never the
round-trip. Neither alone is enough: the equivalence test never touches the
tab's code, so on its own it would keep passing if the tab stopped calling
`SnapshotTree` altogether.

Pin the *dispatched* path, not the helper underneath it. The dashboard refreshes
by calling `RefreshFromLiveTrieCmd()` and running the returned `tea.Cmd`; that
closure is its own call site, and an earlier version of this test called
`buildSnapshotMsg` directly, so rewriting only the closure to round-trip through
JSON passed the whole package. Same trap in the same test: `flameSnapshotReadyMsg`
is a struct value, so `msg == nil` after boxing into `tea.Msg` can never fire —
assert the message carries a snapshot and frames instead, or the test passes on
a refresh that renders nothing.

Be precise about what the equivalence test catches. `SnapshotJSON` is
`json.Marshal(SnapshotTree())` decoded back into the same struct, so marshal
and unmarshal stay self-consistent under any *rename* of a JSON tag — renaming
`SnapshotNode.HeightTotal`'s tag, or dropping the tag, does not fail it. Only a
field leaving serialization entirely (`json:"-"`) does.

### The byte ceiling is not load-independent for free

The allocation *count* is genuinely host-independent. The byte total is not:
`encoding/json` pools its `encodeState` buffers, GC drains that pool, so
bytes/pass rises with GC frequency and therefore with memory pressure. Left
alone it reached 1813350 under `-race` with `GOGC=1` and 16x load — a ceiling
that measures the machine, which is the defect the task existed to remove.

Three things fix it, and all are load-bearing. `measureStressRenderCost` pins
**both** GC triggers for the measurement window, restoring each on exit:
`debug.SetGCPercent(-1)` stops GOGC-driven and sysmon's periodic collections,
and `debug.SetMemoryLimit(math.MaxInt64)` stops the one `GOMEMLIMIT` forces
regardless — reachable in any memory-capped container, and worth 1699908 bytes
under `GOGC=1 GOMEMLIMIT=16MiB` with only the first pin in place. With both,
non-race holds to 0.45% (1466874-1473450 idle, 1491120 worst adversarial).
`stressByteCeilingPercent` (`stress_race_{enabled,disabled}_test.go`) then
scales the ceiling by 130% under `-race`, covering the residual no pin removes —
1550467-1589738, including a sample taken while the whole race suite ran
alongside.

Do not simply widen the byte ceiling instead. On the non-race build it is the
*only* assertion that catches an allocation regression staying under the count
ceiling: dropping the `childStates` preallocation in `livetrie.go` lands at
32560-32561 allocs (below the 33000 ceiling) and 1816954-1823520 bytes.

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
- **The trace-started signal is a promise, not a progress report**: in TUI mode
  `setupTraceInfra` closing the `started` channel is what makes
  `tuiTraceStarterFromRunTrace` report success, and from that moment nothing is
  selecting on its error channel any more. So `signalTraceStarted` is the last
  statement before the success return, after every fallible step - the filter
  validation, `setupBPFModule`, the event channel, profiling, and
  `newTraceEventLoop` (which exists to group `newEventLoop` and
  `newSyscallAggregateConsumer` so that ordering is visible in the shape of the
  function rather than resting on the reader noticing which calls can still
  fail). Signalling earlier is not a small bug: the dashboard leaves the
  "Attaching tracepoints" overlay and shows a live-looking, permanently empty
  session with no error anywhere - reachable on the next trace restart from a
  comm pattern as long as `MAX_PROGNAME_LENGTH`, or from a stale
  `IOR_BPF_OBJECT` lacking `syscall_aggregate_map`.
- **A filter the pipeline cannot honour is refused, not swapped in**: typing an
  over-long comm/path pattern into the filter modal takes the *live-swap* path,
  which restarts nothing - so `setupTraceInfra`'s validation above never runs on
  it. Until task l3 nothing else did either, and the swap succeeded into a
  running trace that could then match nothing at all: `matchString` looks for
  the pattern as a substring of a fixed-size kernel field, so a comm pattern
  that does not fit `MAX_PROGNAME_LENGTH` (or a path that does not fit
  `MAX_FILENAME_LENGTH`) cannot be found in anything the raw enter gates see,
  and the dashboard goes live-looking and permanently empty - the same symptom
  as the signalling bug above, reached without any restart. The limits are one
  byte below those constants, because the kernel NUL-terminates what it writes.
  "Cannot be found" is scoped to the kernel-field gates: a path resolved
  through the procfs fallback (`/proc/<pid>/fd`, getcwd) can be longer than the
  event field, so the check is conservative for those rows. `Model.refuseUnusableFilter`
  (`internal/tui/tui.go`) therefore runs `ValidateTracepointFields` at *both*
  entry points into the pipeline tail - `applyGlobalFilter` (modal apply,
  table drill-downs, undo-stack pushes) and `replaceGlobalFilter` (the `[`/`]`
  family re-scope) - **before** the stack push, the `setGlobal` and the filter
  epoch advance, so a refused filter leaves no half-applied state and no undo
  level behind.

  A refusal that says nothing is the same silence with an extra step, so the
  same function owns the user-visible half: it writes
  `dashboard.SetFilterNotice` with the reason on refusal and `""` on every
  accepted filter, so the notice cannot outlive the filter it describes (the
  undo path clears it for the same reason). The notice renders in the chrome's
  status row, ahead of the filter summary - the row is present on every tab and
  already answers "which filter am I running?", which is exactly the question a
  refusal changes the answer to. Two surfaces were rejected: `m.lastErr` is the
  full-screen terminal error (right for a trace that failed to start, a dead end
  for a typo in a modal while the trace is still running fine - still true after
  task z3 made that screen quittable, because the only way off it is *out*, and
  a typo in a modal must not cost the session), and a stream
  warning row is carried by `streamrow.NewWarning` with `Comm: "ior"`, so the
  *still-active* comm filter would filter the warning about it out of the
  stream tab. Because the notice lives in the status half of a shared row,
  `appendStatusText` now trims the static help text rather than the live status
  when the row cannot hold both. Pinned by
  `TestLiveFilterSwapRefusesAnOverLongCommPattern`,
  `TestLiveFilterSwapRefusesAnOverLongPathPattern`,
  `TestRefusedLiveFilterKeepsTheFilterStackUntouched`,
  `TestAcceptedLiveFilterSwapClearsTheRefusalNotice`,
  `TestFamilyCycleRefusesAnUnusableFilter`
  (`internal/tui/filterguard_test.go`) and
  `TestFilterNoticeIsVisibleOnANarrowDashboard`,
  `TestFilterNoticePrecedesTheFilterItKept`,
  `TestFilterNoticeClearsWhenUnset`
  (`internal/tui/dashboard/filternotice_test.go`).

  Validation measures the text the matcher compares, not what the user typed.
  `matchString` strips `^`/`$` before comparing and the filter modal advertises
  `^exact$`, so counting the anchors against the field size rejected `^` plus a
  15-character comm plus `$` - the documented way to exact-match the longest
  comm Linux allows, since `TASK_COMM_LEN` includes the NUL. That was harmless
  while the check only ran on a trace restart; guarding the swap path turned it
  into a refusal of a working, advertised filter, so both sites now share
  `trimAnchors` and cannot drift again (task m3;
  `TestValidateTracepointFieldsMeasuresTheMatchedTextNotTheAnchors`).

  Nothing after the signal can fail in TUI mode: `runTraceWithContext`'s only
  remaining error source is `finaliseTrace`'s `recorder.Write`, and the
  recorder is non-nil only for `-flamegraph`, which the mode registry makes
  mutually exclusive with the TUI. `reportLateTraceError` therefore never fires
  in TUI production today - it is there so that a post-signal failure added
  later is not dropped the way the original defect dropped setup failures.

  A stop that races a setup failure is silenced on *both* arms of the starter's
  select, on the context rather than on the error: the two are ready at once
  and Go picks between them at random, so gating one arm left about one run in
  a hundred reporting the old trace's failure against the next session -
  clearing its attach spinner, or writing into the stream buffer the TUI resets
  in place and hands to every run. Pinned by
  `TestSetupTraceInfraSignalsStartAfterEveryFallibleStep` (structural - the
  ordering itself cannot be reached behaviourally without root),
  `TestSetupTraceInfraRejectsAnUnusableFilterBeforeAnyBPFSetup`,
  `TestNewTraceEventLoop*`,
  `TestTuiTraceStarterSurfacesAFailureArrivingAfterStart`,
  `TestTuiTraceStarterKeepsACancelledStartSilent` and
  `TestTuiTraceStarterReportsAStopEvenWhenTheFailureIsReady`.
- **The full-screen error view is always quittable, and always says why**:
  `View` renders `m.lastErr` ahead of the help overlay, every modal and both
  screens, so once it is set nothing else on the model is on screen. Key
  handling now matches that precedence: `handleGlobalKeyPress` takes `q`,
  `ctrl+c` and `esc` (`isErrorScreenQuitKey`) straight to
  `quitFromErrorScreen` **before** the overlay and modal branches. Until task
  z3 every one of those keys was swallowed - `canHandleDashboardShortcut`
  gates on `lastErr == nil` and `shouldRouteQuitToEsc` needs a visible modal,
  so `handleQuitKeyPress` fell through to its "handled, do nothing" return -
  and there was no way out of the TUI from the keyboard. (bubbletea answers
  SIGTERM and SIGINT itself, so a signal from another terminal always worked -
  which is no help to someone sitting in front of it.)
  One case is a loss, not a gain: `esc` on the PID picker after a failed
  `recorderStop` used to clear the error and return to a working dashboard,
  and now leaves the session. That is the trade the rule forces - the screen
  the user is looking at answers its own keys - and it is the only escapable
  error the fix takes away. Seven of the eight sites that set `lastErr` are
  `recorderStop` failures where the trace is still healthy, so a recoverable
  variant is worth its own task; an unquittable screen was the worse of the
  two problems and is the one fixed here.

  The route needed no exotic setup: an over-long `-comm` on the CLI failed
  `setupTraceInfra`'s validation, arrived as `TracingErrorMsg` and set
  `lastErr` (that particular route is now also refused at parse time, below).
  Four details are load-bearing:
  - *Esc quits rather than dismisses.* Clearing `lastErr` and returning to the
    dashboard was the obvious alternative and is wrong for the common cause: a
    setup failure means nothing was wired up, so the dashboard behind the
    error would be live-looking and permanently empty - the symptom this file
    already calls worse than an error. Quitting is the honest action, and the
    trace has either not started or is being cancelled on the way out anyway.
  - *Cleanup is best effort.* `quitFromErrorScreen` runs the same two steps as
    the dashboard quit path - `recorderStop` and `tracer.stop()` (in that order, matching the dashboard quit; the recorder guards itself with a mutex and a stopOnce, so the order is for symmetry rather than safety) (a no-op
    when no trace ever started) - but discards the recorder error instead of
    routing it to `lastErr` and returning. The dashboard path does return
    without quitting on that error, which is precisely how a broken recorder
    lands the user on this screen; making the escape depend on the same call
    succeeding would swallow the key a second time.
  - *The view names its own way out.* `View` renders a `q / esc  quit` hint
    under the message; a screen that answers exactly one key and says nothing
    is what sent the reporter to another terminal in the first place
    (`TestErrorScreenAdvertisesTheWayOut`).
  - *The reason outlives the alt screen.* `RunWithTraceStarterConfig` and
    `RunTestFlamesWithTraceStarterConfig` go through `runProgram`, which
    returns the final model's `lastErr` (`finalModelError`). The terminal
    discards the alternate screen on exit, so before this the user quit the
    error view into a clean shell with no rows, no message and status 0;
    now `cmd/ior` prints `Failed to run: ...` and exits non-zero, as the raw
    modes always did for the same failure. Pinned by
    `TestErrorScreenQuitsOnEveryQuitKey`,
    `TestErrorScreenQuitOutranksAnOpenModal`,
    `TestErrorScreenQuitOutranksThePickerCancel`,
    `TestErrorScreenQuitOutranksTheHelpOverlay`,
    `TestRunProgramReportsTheFinalModelError`,
    `TestExportedEntryPointsReportTheError`, `TestErrorScreenQuitCancelsTheTrace`,
    `TestErrorScreenQuitStopsAnActiveRecording`,
    `TestErrorScreenQuitSurvivesARecorderThatCannotStop`,
    `TestOverLongCLICommFilterStaysQuittable`,
    `TestErrorScreenQuitReportsTheFailureToTheCaller` and
    `TestCleanExitReportsNoError` (`internal/tui/errorscreen_test.go`).

  Not fixed here, and still true: the "Attaching tracepoints..." overlay
  swallows the quit keys the same way. It is bounded by
  `defaultStartupTimeout` and resolves itself, so it is a wait rather than a
  dead end.
- **An unmatchable `-comm`/`-path` is rejected at parse time**: `validateConfig`
  (`internal/flags/flags.go`) ends in
  `BuildTraceFilter(cfg).ValidateTracepointFields()`, so a pattern longer than
  the fixed-size kernel field it is compared against is refused next to the
  `-pid`/`-tid` bounds checks and for the same reason - all of them otherwise
  produce a silently empty trace. `setupTraceInfra` still validates (it is the
  only gate for a filter that did not come from the CLI), but the CLI case no
  longer gets that far: the user reads `comm filter max size is 15 (got 20)` on
  stderr with exit status 2 instead of having a terminal taken over to show it
  (`TestParseRejectsUnmatchablePatternFilters`,
  `TestParseAcceptsTheLongestUsablePatternFilters`,
  `internal/flags/validation_test.go`).
- **Drop observability**: every generated handler counts a kernel-side event loss
  (`bpf_ringbuf_reserve` returning NULL, i.e. `event_map` full under userspace
  backpressure) in the per-CPU BPF map `ringbuf_drop_map` via
  `ior_count_ringbuf_drop()` (`internal/c/filter.c`). Userspace polls that map
  once per second (`ringbufDropMonitor`): a growing count raises a live warning
  (a TUI stream warning row, stderr in `-plain`/headless modes) and the run
  total is always printed in the end-of-run `Statistics:` block as
  `ring buffer drops: N (N/s, N% of events)`.

  That line is a statement of fact, which is why *both* of its inputs are
  guarded. **Every mode must hear about a failed reading**: only
  `makeTUIEventLoopConfigurer` wires `warningCb`, so a bare `notifyWarning` is a
  no-op in `-plain`/`-flamegraph`/headless `-parquet`. Warnings the user must
  see in any mode therefore go through `notifyWarningOrLog`
  (`internal/eventloop_output.go`), which falls back to stderr — the drop
  monitor's read-failure and drop-delta branches and the aggregate drainer all
  use it. And **an unknown figure is never printed as `0`**: if the last counter
  read failed, `numRingbufDrops` still holds the previous reading (`0` for a run
  whose first read already failed), so `ringbufDropStatLine` prints
  `ring buffer drops: unknown (drop counter unreadable[; N counted before the
  failure])` instead. The counter is cumulative, so one later successful read
  restores the total and the line goes back to reporting it (task 42;
  `TestEventLoopDropMonitorReadFailureReachesStderrWithoutWarningSink`,
  `TestStatsReportsUnknownRingbufDropsWhenTheCounterCannotBeRead`,
  `TestStatsKeepsTheLastKnownCountWhenTheCounterStopsBeingReadable`,
  `TestStatsReportsTheTotalAgainAfterTheCounterRecovers`). A binary whose BPF
  object has no `ringbuf_drop_map` leaves `dropSrc` nil, and that reports
  `unknown (drop counter unavailable)` for the same reason - nothing was
  measured, so there is nothing to state. The two causes are worded apart
  because they want different remedies, and `attachRingbufDropCounter`'s
  startup warning is not a substitute: a long run's summary is read hours later
  and on its own (`TestStatsReportsUnknownRingbufDropsWithoutADropCounter`).

  The corollary for tests: an `eventLoop` built without a `dropSrc` reports
  unknown, so a test asserting on a drop *figure* has to wire one - which is
  the honest precondition, not a nuisance.

  The flag and the total are published in the opposite order to the one
  `stats()` reads them in (total stored, then flag cleared; flag read, then
  total), so a reader that sees a cleared flag is guaranteed to see the total
  that cleared it. `startTraceShutdownWatcher` calls `stats()` on `ctx.Done()`
  while the monitor is still winding down on the same signal, so the two really
  do overlap; the other order leaves a window that prints the stale `0` as
  fact. The race detector cannot see it - both are atomics, so it is a logical
  ordering bug, not a data race - and nor can a test: what is pinned instead is
  the intermediate state
  (`TestStatsGatesTheDropTotalOnTheFailureFlagNotOnTheTotal`).
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

  **Tid recycling is a separate failure mode with the same symptom.** The two
  paths above are residuals of the exec record; this one is not about `execve`
  at all. The cache is keyed by tid and the kernel recycles tid numbers, so an
  entry outliving its owner labelled the *next* process handed that number with
  the dead one's name - until it exec'd (bumping the entry) or the entry fell
  off the 8192-entry LRU, neither of which is quick on a box churning
  short-lived processes. The `sched:sched_process_exit` control record already
  attached for the fd table (below) therefore also evicts the comm entry for
  its `ev.Tid` (`commResolver.evictTid`, called from `handleProcessExitEvent`).
  The record fires per *task* and this cache is keyed per task, so unlike the
  fd-table eviction this is precise rather than degraded: a thread exit drops
  only that thread's name. Eviction, not `markAllStale`, is right here because
  there is nothing left to serve - the value is not merely at risk of being
  outdated, its owner is gone; the recycled tid then behaves exactly like a
  never-before-seen one (async lookup, and under `-comm` its first
  non-open/exec syscall dropped at the enter-side gate).

  Retiring an in-flight lookup needs its own counter here: the entry's exec
  epoch cannot do it, because eviction *deletes* the entry, so a result landing
  afterwards would read epoch `0` back and match the `0` it sampled for a tid
  that had no entry either - reinstating the exact name the eviction removed.
  `commResolver.evictedLookups` is a per-tid counter bumped only when a lookup
  is actually in flight, sampled into `lookupState` and checked in
  `storeLookupResult`; it lives outside `comms` so it cannot be LRU-pruned out
  from under that lookup, and it is dropped together with the tid's pending
  flag, so it cannot leak. A lookup that samples the counter *after* the
  eviction is accepted - that read followed the exit, so it is the recycled
  tid's real name. Pinned by
  `TestRecycledTidDoesNotInheritTheDeadProcessComm`,
  `TestExitEvictionSurvivesAnInFlightLookup` and
  `TestProcessExitEvictsOnlyTheExitedTasksComm`
  (`internal/eventloop_processexit_comm_test.go`).

  **The same record evicts the tid's pair state and its pending handle**, for
  the same reason and with the same precision: `pairTracker.enters` and
  `pairTracker.prevTimes` (`pairTracker.evictTid`), and
  `pendingHandleTracker.paths`, are all tid-keyed too. Of the pair tracker's
  two, the parked enter is the sharper: a task killed *inside* a syscall never
  gets its `sys_exit`, so its enter stays parked, and the next task handed that
  tid number has its own
  exit consume it: the row is emitted with the dead task's filename and enter
  timestamp, i.e. a syscall that never happened with a latency as long as the
  gap between the two tasks. The trace-ID guard in `tracepointExited` cannot
  see it, because a recycled tid running the same syscall produces matching
  IDs. (Reaching it needs the new owner's own enter to be missing, which is
  routine: ring-buffer loss, or - under `-comm` - the enter-side gate dropping
  a brand-new tid's first non-open/exec syscall, which the comm eviction above
  guarantees is the recycled tid's state.) `prevTimes` is the milder half: it
  gave the new owner's first pair a `DurationToPrev` measured from the dead
  task's last syscall, which `-gap` filters on. The parked enter is *dropped*
  rather than emitted as a synthetic row - the syscall never returned, so it
  has no return value, bytes or latency, and the only timestamp available is
  the task's death, which would fabricate the very latency the eviction
  removes - and the drop is counted nowhere: `numTracepoints` already counted
  the enter record when it was seen, `numSyscalls` is only reached by a pair
  that found its enter, and `numTracepointMismatches` means *the tracker paired
  two records that do not belong together*, so putting ordinary
  kill-inside-syscall traffic there would mask a real pairing regression - and
  would cancel out a real gain: on a run tracing the `Process` family,
  `exit_group` emits an enter with no matching exit trace ID, so the enter
  parks forever and any exit that reaches it is necessarily a spurious
  mismatch. (Usually the recycled tid's own enter supersedes it first and
  nothing is counted - the mismatch needs that enter to be missing.) Pinned by
  `TestRecycledTidDoesNotPairWithTheDeadTasksEnter`,
  `TestRecycledTidDoesNotInheritTheDeadTasksGap` and
  `TestProcessExitEvictsOnlyTheExitedTasksPairState`
  (`internal/eventloop_processexit_pair_test.go`).

  `pendingHandleTracker` is the one with the longest reach.
  `name_to_handle_at` parks a pathname under the tid until the matching
  `open_by_handle_at` consumes it, and the two need not be the same task -
  passing the handle to another process is what the API is for - so an
  unconsumed pathname outliving its task is ordinary rather than exceptional.
  Left behind it does more damage than a parked enter: `handleOpenByHandleAtExit`
  labels the row with the dead task's path *and* registers that path in the fd
  table for the new process, so every later read, write and close on the
  descriptor reports it too. Both syscalls are FS-family, so a default run
  reaches it. Pinned by
  `TestRecycledTidDoesNotInheritTheDeadTasksPendingHandle`.

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
  both maps, and — keyed by tid rather than tgid — the exited task's cached
  comm, its pair state (parked enter plus gap baseline) and its unconsumed
  `name_to_handle_at` pathname (see "Comm resolution across `execve`"). It
  fires per *task*, so a thread exit in a still-living multithreaded process
  evicts that process early: degraded, not wrong — the procfs fallback still
  answers and re-populates the table. For the three tid-keyed structures the
  same record is precise rather than degraded, which is why one record serves
  all four.
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
  the 160 otherwise-identical teardown calls and the rest did not. `//nolint`
  is banned outright and `internal/buildgate.TestNoNolintDirectives` enforces
  it, because the lint
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
