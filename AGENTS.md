# AGENTS.md

This file provides guidance to AI coding assistants working with the I/O Riot NG (ior) codebase.

## Build/Test Commands

**Prerequisites**: Ensure `libbpfgo` is cloned at `../libbpfgo` relative to this repository (or set `LIBBPFGO`), pinned to `v0.9.2-libbpf-1.5.1`, and rebuilt with:

```bash
git -C ../libbpfgo checkout v0.9.2-libbpf-1.5.1
git -C ../libbpfgo submodule update --init --recursive
make -C ../libbpfgo libbpfgo-static
```

If builds/tests fail with missing libbpf headers (for example `bpf/bpf.h` not found), rerun the commands above and then retry the failed Mage target. Run `mage world` only on a host whose tracepoint set matches the committed generated artifacts; its generation diff gate stops on older kernels. Prefer Mage targets over raw `go test` for packages that import `libbpfgo`; Mage wires the required `CGO_CFLAGS`, `CGO_LDFLAGS`, and `LIBBPFGO` values.

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
the same `Fprintf` to a generic `io.Writer` is: `cmd/ior/main.go:59`
writes an unannotated `fmt.Fprintf(os.Stderr, …)`, while
`integrationtests/harness.go`'s `scanIorOutput` has to write `_, _ = fmt.Fprintln(w, line)`
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
concurrent ingest, a deterministically observed partial snapshot, every
production refresh laying out inside the viewport with a complete ancestry
index, snapshot totals never going backwards, an exact frame count for the
completed fixture trie, and ceilings on the allocations one dispatched and
applied refresh costs. Workers stop at their midpoint until the renderer
acknowledges a partial snapshot, so that coverage cannot disappear merely
because ingestion wins a scheduling race.

Direct `LiveTrie` tests now pin the 0.1% pruning rule below, exactly at and
above its boundary, plus the fact that it is evaluated against the running
root total: the same node can be visible in a partial snapshot and pruned from
the completed one. The stress test's exact completed-frame count remains as a
broader integration sentinel, but is no longer the only test with grip on the
rule. The bound it replaced — frame count against the viewport's cell count —
could not fail, and with only that bound in place, raising
`liveTrieMinFraction` from 0.001 to 0.05 dropped the then-current flamegraph
from 321 frames to 21 and the whole suite still passed. The completed fixture
now lays out 381 frames after gap-free child-span allocation. Assert the *last*
sample, never the peak: pruning is relative to the running root total, so an
early snapshot
legitimately keeps more nodes, and how many depends on where the render loop's
ticks land (330 and 523 on two runs of the same fixture). The completed trie
is a property of the fixture alone.

The terminal renderer has direct structural coverage as well: snapshot child
order stays stable and depth-first, rounding partitions a represented child
band without gaps, omitted pruned totals are redistributed over the retained
children, and a node's own value still reserves its proportional self-time
gap. A 16-level fixture rendered into four rows makes the viewport depth clamp
observable instead of relying on the shallower stress fixture. When every
child is narrower than one cell, the fallback stays inside that same
proportional child band and keeps exactly one cell visible when the band would
otherwise round to zero.

The cost and timing measurements execute `RefreshFromLiveTrieCmd()` and apply
its `flameSnapshotReadyMsg`, so they cover the production `SnapshotTree`, zoom,
layout, ancestry and update path. `TestFlameRefreshUsesTheTreeSnapshot`
independently pins that both refresh entry points call `SnapshotTree`, and
`TestFlameTickDispatchesAndAppliesFlamegraphRefresh` starts one level higher:
it advances the trie after `SetLiveTrie`, dispatches the dashboard's
`flameTickMsg`, executes the returned batch and requires the new version to be
applied. Without that outer test, deleting the refresh dispatch from
`handleFlameTick` freezes live updates while a direct command test stays green.

The refresh completion owns the `refreshInFlight` slot even if the user has
left the Flame tab before it arrives. The dashboard therefore offers every
completion to `flamegraph.Model.HandleRefreshCompletion`, including while
another tab is active. An off-tab completion releases the slot but discards its
snapshot: applying it with existing frames can start an animation, while the
inactive-tab route deliberately drops animation ticks, leaving animation stuck
and `lastVersion` current so no later snapshot is requested. The dashboard
regression starts with an existing rendered snapshot, dispatches a refresh,
switches away before delivering a current-viewport completion, requires no
command, version or rendered state to change, then returns to Flame and
requires a later refresh to dispatch and apply. A separate flamegraph test
makes a completion stale without starting a resize animation and pins that its
discard path releases the same in-flight slot.

Pin the *dispatched* path, not only the helper underneath it. The closure
returned by `RefreshFromLiveTrieCmd()` is its own call site, so an earlier test
that called `buildSnapshotMsg` directly missed a rewrite of the closure alone.
Same trap in the returned value: `flameSnapshotReadyMsg` is a struct, so
`msg == nil` after boxing it in `tea.Msg` can never fire. Assert that it carries
a snapshot, frames and ancestry, apply it, and assert the model reaches the new
version.

Be precise about what the equivalence test catches. Its oracle is
`json.Marshal(SnapshotTree())` decoded back into the same struct, so marshal
and unmarshal stay self-consistent under any *rename* of a JSON tag — renaming
`SnapshotNode.HeightTotal`'s tag, or dropping the tag, does not fail it. Only a
field leaving serialization entirely (`json:"-"`) does.

### A guessed terminal size must never override a real one

`initialWindowSizeCmd` (`internal/tui/tui.go`) guesses a viewport when the
terminal cannot be queried — `common.EffectiveViewport`'s 80x24 default, which
is what a test binary or a redirected stdout gets. bubbletea independently
sends a real `WindowSizeMsg`. Both are asynchronous and nothing orders them, so
whichever landed last used to win for the rest of the run.

That is not cosmetic: the dashboard's tab bar abbreviates below 90 columns, and
`syscallColumns` returns 9 columns below 140 and 12 at or above. Six
`TestTUIIntegration_Syscalls_*` tests were written against the 80-column layout
and passed only because the guess usually landed last; when it did not, they
failed — roughly one full `mage testRace` run in three, which is how this was
finally caught.

The guess is now a distinct `fallbackWindowSizeMsg` that `Update` applies only
when no real size has arrived, so the harness renders at the 160x48 it asks for
and the assertions are written against that width.
`TestFallbackWindowSizeNeverOverridesARealSize` pins all three load-bearing
parts: `initialWindowSizeCmd` emits the distinct fallback type, a guess after a
real size is ignored, and a guess before one still fills in the unknown.

### The cost ceiling measures the production path

Measuring the JSON round-trip was both indirect and noisier: it omitted
production-only work such as ancestry construction, while `encoding/json`'s
pooled buffers made the byte total depend on GC frequency. The test now measures
each real refresh between its own `runtime.ReadMemStats` pair, with the event
that advances the trie version outside the interval. No GC setting is changed.

Since `LiveTrie` snapshots prune before they build (task 1o2), the completed
fixture costs 3686 allocations / 439512 bytes per refresh in an idle non-race
run, 3686 / 439601 with `GOGC=1`, `GOMEMLIMIT=16MiB` and `GOMAXPROCS=128`, and
3686 / 446248 under `-race`. The ceilings are 4200 allocations and 500000
bytes (about 12-14% headroom). Both dimensions still matter: the former
full-walk snapshot, which cloned and sorted every trie node's children before
pruning, cost 26366 / 1479201 and trips both.

### LiveTrie snapshot cost and growth bound

`SnapshotTree` holds the trie's read lock, and every event's `AddRecord`
needs the write lock, so snapshot cost is ingest stall time. It is therefore
proportional to the *visible* nodes, not the recorded history:
`insertLiveTriePath` (the live trie's insert; the batch `insertTriePath` skips the
`topChildren` upkeep) maintains each node's subtree totals and its
`topChildren` (the 8 largest non-empty children) on every insert, and the
`snapshotBuilder` decides pruning from those before recursing — a pruned
subtree is never walked or allocated, and a wide fan-out's pruned tail is
usually not even scanned. The fallback set is exactly `topChildren`.
`TestLiveTrieSnapshotMatchesFullWalkReference` keeps the old full-walk
algorithm as an oracle and must stay exactly equal (its cases assert whether
the fallback fired, so they cannot silently stop exercising it).
On a shared, noisy dev box `BenchmarkLiveTrieSnapshotTree` measured 10k/100k
distinct paths at 0.4-1.1ms / 9-15ms per snapshot before and 0.09-0.12ms /
0.05-0.07ms after (549KB/4.9MB -> 16KB allocated), and a 100k-wide depth-one
fallback (`...WideFallback`) went from 10.7ms to about 1µs.
`IOR_STRESS_TEST=1` `TestLiveTrieStressHighRateConcurrentSnapshot` ingest went
from 584 to about 300000 events/s.

The trie is capped at `liveTrieMaxNodes` (2^18 nodes, ~210-290 B each, so
~55-75MB). Past it, `compactLocked` folds the lowest-ranked subtrees into a
per-parent `[other;]` bucket leaf (the `;` is deliberate: no frame contains
one, so a real comm or path component spelled `[other]` can never share the
bucket's name and path, which is all the TUI sorts and zooms by), only as many
as needed to get back to about half the cap. The rank is a node's *rate*, not
its all-time total: its total over the root events since its birth
(`trieNode.birthRootTotal`) plus one compaction window, maxed with its
children's ranks so a child never outranks its parent (ties go to the deeper
node, then walk order). Nodes the current snapshot shows (fallback children
included) are spared unless that cannot suffice, so the view only gains
buckets; buckets are identified by `trieNode.bucket`, not by name, and never
take part in the fallback decision.
Totals stay exact; only attribution of folded frames is lost. Pitfalls the
tests pin: a single threshold fold per cycle (the first version) kept
restarting late, steady frames from zero so they never became visible
(`TestLiveTrieCompactionKeepsAFrameThatAppearsLate`), overshot the target by
orders of magnitude and wiped zero-total tries into one root bucket; ranking
by all-time totals let more than cap/2 old idle frames starve a steady late
frame forever (`TestLiveTrieCompactionKeepsALateFrameOverOldIdleFrames`).

Compaction runs inside the `AddRecord` that crossed the cap, under the write
lock, and that is the event-loop goroutine (`internal/ior.go` print callback
-> `rt.liveTrie.Ingest`): for tens of ms at the default cap (measured 40-70ms
with `BenchmarkLiveTrieCompaction`; over 100ms on a heavily oversubscribed dev
box), plus GC of the folded nodes, no
events are consumed, so under a high rate of unique paths the BPF ring buffer
can back up and drop events. It happens at most once per cap/4 new nodes. A
lower cap shortens the pause proportionally; moving ingestion off the event
loop (a buffered hand-off) would hide it entirely. Tests lower
`LiveTrie.maxNodes` to exercise compaction.

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

`internal/generate/syscall_semantics_test.go` is the independent, reviewed
semantics oracle for the committed syscall handlers. Every `sys_enter_*`
handler must have exactly one literal row covering its kind, captured event
fields and source argument indices, exit return classification, and family.
Do not derive those expected rows from the generator tables. Rows awaiting a
known semantic fix keep the correct target in the ordinary fields and the
currently generated value in a `temporarySyscallSemantics` override labeled
with its task ID; the owning fix deletes that override when the artifact is
correct.

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
  `*Model` (the `eventstream` template). The small modal/screen models
  (`tracefilter.Model`, `probes.Model`, `export.Model`, `pidpicker.Model`,
  `tui.recordingModal`, and `eventstream`'s `SearchModal`/`ExportModal`) are
  **all-value-flow** instead: value receivers and every mutator returns the
  updated `Model`, matching their `Open`/`Close`/`Update` API. Do not mix
  receivers within a Model type: a value-receiver `Update` calling a
  pointer-receiver mutator only works while the value happens to be
  addressable, and a non-addressable or later-copied Model silently loses
  those mutations (tasks b2, fc).
- **`Init` is side-effect free**: every `Init` only reads its model and
  returns commands. Work that must change model state (starting a trace and
  storing its cancel func, arming a tick chain) is requested with a message
  that `Update` handles: `tui.Model.Init` emits `initialTraceStartMsg`
  (handled by `handleInitialTraceStart`, which drops the request after a quit
  or when a session is already running), and `dashboard.Model.Init` emits
  `tickChainsStartMsg` / `autoResetArmMsg`. Tests pin this per model
  (`TestInitDoesNotMutateModel` in `tui`, `pidpicker` and `flamegraph`,
  `TestInitDoesNotArmAutoReset` in `dashboard`; task fc).
- **Dashboard tabs**: `/internal/tui/dashboard/` contains tab renderers (flame/overview/syscalls/files/processes/latency+gaps/stream) and tab framework model.
- **Dashboard frame height budget** (task ls2; `layout.go`, `Model.View`): `View` never renders more lines than the terminal has rows, at any height from 1 up. `splitFrameRows` hands out the rows in priority order: the status block first (the help hint, or the expanded help bar with the filter/recording status on its last row; a too-short terminal keeps its tail, so the status line is always the last line), then the tab bar, then the body. `renderBody` clips the tab's output to its share (`clipLines`) as a last line of defence, and below the tab's minimum (`tabDescriptor.MinBodyRows`; the generic `minBodyRows` is 3, `altVizMinRows` for bubbles/treemap/icicle, and `overviewMinRows`/`latencyMinRows`/`flameMinRows` for the panel tabs, `streamTableMinRows` = 6, the stream panel alone, for the Stream tab) it shows a one-line "terminal too small" notice instead of a fragment cut mid-panel. Tables no longer keep a minimum row count: `tableRowBudget` is the body height minus the header and hint lines (it used to be `max(5, h-6)`, which overflowed below ~10 rows), and it is also the paging step's basis. A new tab or panel must honour its budget itself (it gets `height` rows and must not draw more) and declare the smallest height at which it is complete in `MinBodyRows`; that minimum must not depend on transient state (pause, a status message, an open modal), or the body flaps between the tab and the notice while the user acts, and a modal hidden behind the notice still takes the keys. The Stream tab therefore gets the standard content viewport (its real body rows) and fits everything beyond its panel itself: `eventstream.Model.View` appends the Row/Sel footer and then the status message only into rows the table leaves free (with a single free row a status message takes it in place of Row/Sel, since it is how "Export failed", "Open failed", "Invalid regex" or "No match" reach the user; `TestStatusMessageTakesTheOnlySpareRow`). Row/Sel follows the help bar while live (`footerShown`: help on or paused), the status message does not: with the help bar off and the stream live it used to be set but never drawn (e.g. a search error once space resumed the stream; task iz2), so `appendStreamFooter` draws it in every state, cut to the width, from a 7-row body up (at the 6-row minimum the panel fills the body and no message fits there, so `eventstream.Model.UndrawnStatusMessage` hands it to the dashboard, which shows it in the status line's badge slot that the Stream tab leaves free, `streamMessageBadges`: whole, then cut to 24 and 12 cells, dropped before the filter summary loses a cell; task 403); `TestStatusMessageMatrix` (heights 6..30, widths 20..200, help/pause/message on and off, five real messages incl. wide runes and escapes), `TestStreamStatusMessageReachesTheFrame` (the full frame contract at heights 1..30) and `TestStreamSearchErrorsStayShownWhenResumedWithHelpOff`. It draws the filter-stack line only while it fits besides the row a status message needs (`fittingFilterStack`: the message outranks the stack line, which the dashboard status line summarises, so a 7-row stream body on a 9-row terminal shows "Export failed" rather than the stack; `TestStatusMessageOutranksTheFilterStack`), and the search/export modals (`renderModal`, `eventstream/modalbox.go`) are capped at the view width (lines cut, not wrapped) and shed vertical padding, blank lines, label and title until they fit the height, keeping input, hint and a whole border down to 4-5 rows. Their key hint is fitted by whole " • " segments (`fitModalHint`, never "Esc cance"), and their text inputs are sized to the box (`SearchModal`/`ExportModal.Resize`, called from `SetViewport` and `View`; `fitModalInput`): bubbles' `textinput.SetWidth` only stores the width and its scroll window is recomputed only when the cursor leaves it, not after a width change nor after an insert, paste or delete inside it (with two-cell runes that window outgrew the box and the box cut the cursor off; with ASCII the cursor could sit over a blank mid-value), so the modals remember the window's start (`inputStart`) and after every `Update`, `Resize` and `View` `fitModalInput` keeps it while the cursor is drawn over its rune in it, moving it only as far as needed (`modalWindowStart`, which mirrors textinput's window arithmetic; a re-anchor around the cursor alone pinned the cursor to the left edge and hid text typed mid-value), then applies it through public cursor moves (end, window start, back to the cursor), keeping value and position (`TestStreamModalInputKeepsTheCursorInTheBox`; `TestStreamModalInputSurvivesMidValueEdits`: seeded random type/paste/backspace/delete/left/right/home/resize sequences on ASCII and wide-rune values at widths 8/9-80, checked after every step, a typed rune must stay drawn; `TestStreamModalInputScrollsMinimally`: Left/Right walks move the window by at most one/two runes, mid-value typing keeps the typed rune drawn). A bump of bubbles must keep `modalWindowStart` (`headWindowEnd`, `tailWindowStart`) in step with `textinput.handleOverflow`. The tests catch a drift on either side because they read the drawn window back (`scrollModal.windowStart`) and require it to start at the remembered `inputStart` after Open and every step, not only a correct-looking screen: a drifted `tailWindowStart` still drew right, since `CursorEnd` rebuilds textinput's own last screenful, while `inputStart` silently disagreed (`TestStreamModalInputRemembersTheDrawnWindow`: Open, Left, Right, Home, End and typing on both modals, ASCII and wide runes, every width 8/9-80; the random and scroll tests check it too). `renderBody` lays the tab out for `min(activeHeight, bodyRows)`, the body budget rather than the taller content viewport. `TestEveryTabFitsTheTerminalHeight` (`tabheight_test.go`) pins every tab in every visualization mode at heights 1..30, four widths (20 to 200 columns) and help on/off: `View().Content` must equal the tab bar (first line), the tab's own unclipped output or the notice, and the status tail (last line), so the clip has nothing to cut (it only protects the status line), and no line may be wider than the terminal; below 20 columns (`narrowBodyWidth`) the panels' own minimum widths (a bordered box is 5 cells, the overview panels 16-20) no longer fit, so `renderBody` also cuts each body line to the width (`cutBodyToWidth`, task qz2; `TestEveryTabFitsNarrowTerminals` sweeps every tab and mode over widths 1..19 and heights 1..30), measured by both `lipgloss.Width` and `ansi.StringWidth` (`assertFrameWidth`; the Flame placeholder panels such as "terminal too narrow" are cut to the width for this, the Syscalls/Files/Processes tables are fitted to it since task cz2, which removed their `knownWideTable` exemption). View's geometry never hands a tab more viewport than body budget, so `TestRenderBodyLaysTheTabOutForTheBudget` drives `renderBody` with smaller budgets to pin that cap. While the Flame body is the notice, `translateFlamegraphMsg(msg, bodyDrawn)` drops pointer events (`Model.activeBodyDrawn` false), so a click on the notice cannot select or zoom into an invisible frame. `TestStreamBodyKindSurvivesTransientState` pauses the stream, sets a status message and opens the search modal (alone and combined) at heights 1..20, widths 20-100 and help on/off, and requires the same body kind (table or notice) as the live stream plus the full frame contract; `TestStreamModalsFitTheirView` holds both modals to every view from 7x1 to 120x30. Not covered by this budget: the matrix does not open the FD-trace overlay (it fits from 6 rows by dropping its footer line, `TestFDTraceViewFitsItsHeight`), the line-count clip bounds height only (a line wider than the terminal soft-wraps past it, which is why every body must also fit the width), the export overlay composed in the top-level `tui.go` (`m.exporter`, not the stream modals) is drawn over this frame (bullet after next, task ns2). The Latency+Gaps panels fit the width as well (next bullet), and so do the Syscalls, Files and Processes tabs (**Dashboard table width**, the bullet after the export overlay).
- **Histogram panel width** (task ps2; `histogram.go`): a histogram panel never lays out a row wider than its inner width: the panel renders through `PanelStyle.Width`, so lipgloss would not draw a wider line but soft-wrap the row inside the panel, the panel would outgrow its row budget, `fitBlocks` would cut it mid-row (no bottom border) and the shown counts would stop adding up to `total=`. `planHistogramLayout` picks, per width, the full layout ("label | bar count" rows plus the scale legend, `histogramChromeRows` = 4) while a bar column of `histogramMinBarWidth` cells fits, else the compact one ("label | count", no legend, `histogramCompactChromeRows` = 3); the title falls back from "Latency Histogram" to the short "Latency" (`histogramSpec.shortTitle`) but always keeps "(total=N)". Columns are measured over every bucket and every label folding could produce (`histogramColumnWidths`: "[0,1us)" folds to the wider "[0,+inf)"), so the layout does not change with the height and a folded tail row always fits. Below the compact layout's width (`histogramMinWidth`: with the real buckets 20 columns plus the digits of the total for Latency, 19 plus them for Gaps, e.g. 24 at total=2259 and 27 at 1,000,000) the panel is a "Latency: terminal too narrow (need >= N columns)" notice, worded like Flame's and cut to the width by `common.RenderMessagePanel` (shared with the Flame placeholders; also used for the waiting-for-stats and no-data panels). The sparkline panel is drawn only when its labelled line fits the panel (`renderHistogramSparkline`: from 31 columns for Latency, 27 for Gaps). Tests: `TestLatencyTabFitsNarrowTerminals` sweeps `View` at widths 1..28, heights 1..30 and help on/off (frame contract, panels whole, a histogram drawn exactly from its minimum width and body rows), `TestHistogramSectionsFitNarrowWidths` sweeps the three renderers at widths 1..40 with labels folding widens and with the waiting-for-stats and no-data placeholders (also swept through `View` by `TestLatencyTabPlaceholdersFitNarrowTerminals`), `TestHistogramCountColumnFitsBucketsAheadOfTotal` holds the count column to a torn snapshot (taken mid-update) whose rendered folded tail row carries more digits than `total=` ("[100us,+inf) | 120003" under total=9999): every panel of the three renderers at widths 1..60 must be whole (bucket rows summing to the buckets' sum, bottom border, at most height rows) and drawn exactly from a hand-computed 25 columns, so a count column sized from `total=` alone fails on the soft-wrapped, cut panel in the Latency-only and Gaps-only renderers alike, and every Latency+Gaps cell of the height matrix runs `assertHistogramsWhole` (each drawn panel has rows, they sum to `total=`, and its bottom border is drawn). Below 20 columns `assertFrameFits` only checks that the last line is the status block's last line (the "filter:" text is cut there).
- **Export overlay over the dashboard** (task ns2; `internal/tui/exportoverlay.go`, `internal/tui/export/box.go`): the `e` export modal (`tuiexport.Model`) is drawn over the dashboard or PID picker, never above it. It used to be its full-screen `View` stacked on the whole base (`modal + "\n" + base`), about twice the terminal's height on every tab; `placeToViewport` does not help there, since `lipgloss.Place` only pads and returns taller or wider content unchanged. Now `overlayExportModal` composes `Model.Box` (the bare box) over the base on a `lipgloss.NewCanvas(width, height)`, so the frame is exactly the terminal's size by construction (base lines wider than the terminal are cut; wide runes and SGR runs split cleanly at the box's edges). `placeOverlayBox` puts the box where it covers neither the base's first line (tab bar) nor its last (status line): between them or in the blank rows below a short base (a table without data draws three rows), the larger region first; only when neither fits the compact box is it fitted to the whole frame (`fitOverlayBox`: height-2, then height-1 rows, so the status line outranks the tab bar as in `splitFrameRows`), ending above the last row. `Box` itself never outgrows its area: at most the view's width (from 7 columns), lines cut, the paused note and status message wrapped at whitespace only (`strings.Fields`: any Unicode white space, a tab or no-break space too, each run written as one plain space) and hard-wrapped inside a word longer than the line by `fitMessage`/`common.WrapAtSpaces` (`common/wrap.go`, moved out of `export` by task rz2 so the other modals share it; each line is then cut to the width, so a two-cell rune in a 7-column view's one-cell text area shows as a blank row instead of widening the box; lipgloss's own wrap let a long word widen a narrow box, and `ansi.Wordwrap`/`ansi.Wrap` also break after every '-', which split a fitting export path at "ior-" and left the note's " - " alone on a line; the dash now stays at the end of the line before when it fits, else opens the next, followed by "use"; alone only below five cells), and it sheds padding, blank lines, wrapping, title and then the paused note (`boxLayouts`) to fit the height, keeping the options, status and key hint (`fitHint`, whole " • " segments) in a whole border down to 5-6 rows. The other top-level modals (filter, record, probes) still replace the dashboard, but each now returns a frame exactly the terminal's width x height (task rz2): `lipgloss.Place` only pads, so their boxes used to come out 23-26 rows tall and wider than a small terminal and the terminal scrolled. They share `internal/tui/common` pieces: `ModalBoxWidth`/`RenderModalBox` (box at most the view width, bordered), `CutLine`, `FitSegments`/`FitHint` (whole " • " key-hint segments), `KeepRanked`/`PlaceModal` (a ladder of `ModalLayout`s from the roomy box down to the compact one, then a borderless `bare` fallback keeping the input, cursor and hint by rank), `WrapAtSpaces`/`FitWrapped`, and `FitTextInput`/`WindowStart`/`InputView` (the text input's scroll window, moved from `eventstream`'s modal logic so typed text stays drawn at any width; `tui.Model` calls the modals' `Resize(width)` on every window size and when they are rebuilt). They stay full-screen rather than overlays since the filter box takes 23 rows and the probes box 24 at 80x24. Pinned by `TestViewFitsEverySize` (tracefilter), `TestRecordingModalFitsEverySize`, `TestDashboardModalFramesFitTheTerminal`, `TestViewNeverExceedsTerminalHeight`/`Width` (probes) and `TestPlaceModalFitsEverySize`. Tests: `TestExportOverlayFitsTheTerminal` (every tab, help on/off, and the picker, heights 1..30, widths 1, 7, 30, 52 and 120 (`overlayWidths`): height and width bounds, modal text shown, tab bar and status line kept and not repeated), `TestPlaceOverlayBox`, `TestFitOverlayBoxReservesTwoRowsFirst`, `TestBoxFitsItsArea` (every modal state, wide-rune status messages included, 1x1 to 56x30 plus 80 and 120 columns), `TestBoxShedsInOrder`, `TestFitHintKeepsWholeSegments`, `TestBoxHintIsWholeSegments`, `TestWrapKeepsAHyphenatedPathWhole`, `TestWrapNeverLeavesTheNotesDashAlone`, `TestWrapShowsTheWholeMessage`, `TestWrapAtWhitespace`, `TestBoxShowsTheWholeStatus`, `TestViewIsClippedToItsHeight` (`Model.View`, the stand-alone rendering only tests call, cuts to its height), and the integration test `TestTUIIntegration_Export_SubmitWritesCSV`, which rejoins the wrapped status lines rather than matching a fragment of a temp path.
- **Dashboard table width** (task cz2; `tablefit.go`, `table.go`): the Syscalls, Files (plain and dir-grouped) and Processes tables never draw a line wider than the terminal, at any width from 1 up. Their fixed columns used to make 80-89-cell rows (and hint lines) at every width; bubbletea v2.0.1 does not soft-wrap such a line (its renderer draws `View` through `uv.StyledString` with `Wrap` false, i.e. clips at the terminal edge), so the height budget held, but the rightmost columns, the path and the hint were cut off mid-cell, and a renderer that wraps would break the budget. Each table is a `tableSpec`: its logical columns at their natural widths (the selected column index, "Col x/N", the sort keys of `syscallSortKeyForColumn`/`fileSortKeyForColumn`/... and Enter's filter dimension keep referring to them, so fitting never changes what a column means), one flex column (Syscall, Comm, Path/Directory) with a minimum (8 cells for names, `filePathMinWidth` = 10 for paths) and a cut rule (`truncatePathMiddle` keeps both ends of a path, `truncateText` the start of a comm; the rows carry the whole sanitised value and only the shown cells are cut, at their fitted width), and a drop order of the optional columns. `fitTableColumns` keeps the natural layout whenever it fits (so wide terminals render byte-identically: a differential of the pre-cz2 renderers against the fitted ones over widths 60-200, three data shapes and whole frames differed only where the old output overflowed), else drops optional columns in order until the rest fits beside the flex column, skipping the selected one (the cell the user navigated to stays on screen), gives the flex column the remaining width, and drops the selected column only when the flex column could not keep its minimum beside it. Drop orders: Syscalls p99, p95, Family, Bytes, Errors, Rate/s, Avg (required: name, Count; compact set below 140 columns, the full set always fits); Files Max Latency, Write, Read, Avg Latency (required: Accesses, Path); dir-grouped Max Latency, Write, Read, Files, Avg Latency; Processes Rate/s, Total Bytes, Avg Latency, Syscalls (required: PID, Comm). Below `tableSpec.minWidth` (required columns plus the flex minimum: 15 for Syscalls, 19 for the others) the table is the one-line "Files: terminal too narrow (need >= 19 columns)" notice, cut to the width. The "[Row x/N Col y/M] [...]" hint keeps whole segments from the left (`fitHintSegments`; the position segment is cut only when alone it does not fit), and the placeholders ("waiting for stats", "no data", the PID-filter note, `renderWaitingForStats` via `common.RenderMessagePanel`, and the bubble/treemap/icicle empty states via `fitPlaceholderLines`) are cut to the width. Tests (`tablefit_test.go`): `TestTablesFitTheTerminalWidth` (every table view at widths 1-100 and a spread to 200, data shapes with long names and paths, wide runes and keycap clusters, `MaxUint64` figures, an empty and a nil snapshot, dir rows with a remainder row: no line wider than the width by `lipgloss.Width` and `ansi.StringWidth`, notice exactly below the minimum, header and rows on the fitted columns, the row window the height allows), `TestFitTableColumnsPolicy` (natural layout kept when it fits, all of the width used otherwise, required and selected columns, drop order, monotone in the width), `TestTableFitPolicyPerTable`, `TestNarrowTableKeepsSelectionAndHint`, `TestTableTabsFitNarrowTerminals` (every view of the three tabs through `View` at widths 1-19 and around each table's natural width) and `TestTableTabPlaceholdersFitNarrowTerminals` (waiting and no-data states through `View` at widths 1-40). A new table must come with a `tableSpec` and be added to `tableRenderers`.
- **Chart rendering and bubble animation** (`internal/tui/dashboard/gridcell.go`, `bubbles.go`, `ticks.go`, `bubbleframe.go`; task yq2). The bubble, treemap and icicle views paint into a `[][]gridCell`; `renderGridRow` emits one styled run per stretch of same-style cells, with the per-palette-slot styles built once per frame and their escape sequences captured from a probe (`gridStyle`), instead of a `Style.Render` per cell (treemap 400x118 155ms -> 3.6ms). `TestRunRenderingMatchesLegacyOnRandomRows` compares it with the vendored pre-change renderer (`legacyRenderGridRow`); the one deliberate difference is an empty palette, where coloured cells now render uncoloured (selected ones bold-only) instead of panicking. **Animation is bounded, not frame-capped**: the 30fps bubble tick chain (`bubbleTickMsg`) re-arms only while `bubbleChart.Tick` reports motion. The ambient drift wobble runs for `bubbleDriftSeconds` (6s, fading over the last 2s) after the last *real* change - a bubble added or removed, or a bubble's anchor or radius moved by more than `bubbleRetargetEpsilon` (0.02 cells; smaller moves keep the old anchor and accumulate) - then the springs snap onto their targets and the chain ends, so a quiet workload costs nothing and an idle `View` is served from the exact-input frame cache (`bubbleFrameCache`). Every real change resets the wobble to the full 6s, so a workload whose counters reshuffle the bubbles on every 1s stats tick keeps the chain running at 30fps: only quiet workloads settle. What shrank there is the cost per frame (a tick plus re-render is about 0.4ms at 120x40 and 1.8ms at 300x80 instead of 10ms and 46ms), not the frame rate; capping the rate while data keeps changing was evaluated and left out (see `TestBubbleChainRunsWhileDataKeepsChangingThenSettles`). The chain is restarted (`tickScheduler.startBubble`, which supersedes the previous generation) by exactly these triggers, each pinned by a Model-level test in `bubblechain_test.go`: a stats tick that changes the active tab's bubbles (`handleStatsTick`), a resize (`handleWindowSize`), entering bubbles mode with `v` (`cycleVisualizationMode`), the `b` metric key (`toggleBubbleMetric`), switching into a bubbles-mode tab with the tab keys (`postKeyTransitionCmd` -> `tabEntryTickCmd`; `TestTabSwitchByKeyRestartsSettledBubbleChain`), and `Init`'s `tickChainsStartMsg` after a focus regain (`tabEntryTickCmd`). A blurred dashboard drops the ticks. The Files directory-grouping toggle needs no trigger: bubbles mode exists only while grouped and leaving grouped mode resets the tab to the table. Any new code path that changes what the bubble chart shows must call `startBubble` when the chart reports animation, or the picture freezes after the chain has ended.
- **Stats snapshots are built off the UI goroutine** (`internal/tui/dashboard/statstick.go`; task 8r2). `engine.Snapshot` costs up to ~22ms with stale latency reservoirs (2.9ms at 20 active syscalls, 8.9ms at 60, 22.5ms at 150; startup and after every auto-reset), and `Update` runs on the Bubble Tea loop, so the periodic refresh (`handleRefreshTick`), `SnapshotCmd` and the `r`/auto-reset baseline reset (`resetBaselineCmd`) only capture the engine and `statsGen` in `Update` and let a `tea.Cmd` call `Snapshot`; the result returns as a `StatsTickMsg` whose generation check (`handleStatsTick`) already drops a snapshot built before a reset. The baseline reset itself (engine clear plus generation bump) still happens synchronously in `Update`. `refreshStatsCmd` returns nil while the previous refresh build is running (an atomic flag the command clears when its build ends, not when the message is delivered, so an undelivered result cannot wedge refreshing): a skipped tick costs one refresh interval and builds never stack. `ResetStats` (the parent's probe toggles and filter swaps) deliberately stays synchronous so the fresh baseline is on screen when it returns; the engine was just cleared, so that build is cheap. Pinned by `TestRefreshTickBuildsTheSnapshotOffTheUpdatePath` (Update returns while `Snapshot` is held blocked), `TestRefreshStatsCmdSkipsWhileTheBuildIsRunning`, `TestRefreshBuiltBeforeAResetIsDropped` and `TestSnapshotCmdAndBaselineResetBuildWhenRun`. Any new `Update` path that needs fresh stats should use `statsTickCmd`, not `statsTick()` (the synchronous form exists for `ResetStats` and tests).
- **Export modal**: `/internal/tui/export/model.go` implements the centered modal used for CSV export flow in TUI mode.
- **libbpf log policy**: `internal/libbpflog.go` owns libbpf's process-global print callback in every mode. It is installed exactly once, in `init()` (`bpf.SetLoggerCbs` writes a plain libbpfgo variable that libbpf's threads read unsynchronised, so it must never be called again); `startTUITrace` only switches the mode via `setLibbpfLogging(true)`, which touches no routing. WARN lines are kept, INFO/DEBUG are dropped: libbpfgo's default logger printed ~23.5k DEBUG lines (2.6 MB) to stderr on every headless start. Headless keeps WARN on stderr, in full. TUI never writes stderr: during BPF load/attach `setupTraceInfraBPF` routes WARN lines into that session's setup-warning collector through a per-session `libbpfRoute`; `end` unhooks only the route it installed (TUI restarts overlap the cancelled session's setup, so a late `end` must not clear the newer session's routing, and `setupWarnings` is mutex-guarded because libbpf lines can arrive from the other session's goroutine). libbpf's callback carries no session identity, so during an overlap lines go to the newest route; a collector never receives a line after its own `end`. Routed rows are shaped for the dashboard: the per-tracepoint `failed to determine tracepoint ... perf event ID` lines are dropped (`bpfSetupLog` already reports skipped tracepoints through the probe manager), each row is shaped by `shortenWarning` (`internal/libbpflog_shorten.go`) to at most 512 bytes in all (the marker and `...` ellipses count; a single-line result within the bound and not ending in `\r` is returned unchanged, and every result is one, so shortening is idempotent at a given bound - a cut below 3 bytes has no ellipsis and could end on a mid-line `\r`, so the result's trailing `\r` is trimmed; `TestShortenWarningProperties` checks bound, single line, UTF-8 validity and idempotence over seeded random inputs at limits 0..40 and 512): a failed program load is ONE WARN holding the whole verifier log behind a `prog 'x': -- BEGIN PROG LOAD LOG --` banner, so its row becomes the banner's `libbpf: prog 'x':` prefix plus `verifier:` and the log's last three non-empty lines (offending instruction, the reason such as `R1 invalid mem access 'scalar'`, `processed N insns`) joined by ` | ` on ONE row, with a `... (N more lines)` marker counting the omitted non-blank log lines (`(1 more line)` for one; `splitMoreLinesMarker` recognises the singular with a count of 1 and the plural with any other run of digits - every form `moreLinesMarker` renders, plus counts it never renders such as `0` or `007`, which only a warning's own text could hold and which are kept whole either way). The prefix is capped at 96 bytes (`maxVerifierPrefixBytes`, ellipsis included) so a pathological program name cannot eat the row, and the kept lines share the rest by max-min fairness (`fairShares`: a short line keeps its length and lends the remainder to the long ones, so the reason line is not cut while the row has room). The log can be megabytes and is handled under the libbpf logger's mutex, so the kept lines are found by scanning backwards from the END marker and the omitted ones are only counted. A missing END marker, CRLF and blank lines are tolerated, a log without any text becomes `verifier: (empty log)`, and a message without the banner (or with nothing after the banner's line) falls back to the generic rule; any other multi-line warning is its first line plus the marker; at most 16 rows are routed per setup plus one summary row. `IOR_LIBBPF_DEBUG=1` restores the full output for headless modes (ignored in TUI mode; empty, `0`, `false`, `no` and `off`, case-insensitive, mean off); it is listed in the `-h` epilogue (`flags.setUsage`) and the README troubleshooting section. When setup fails the event loop never starts, so the collector is not replayed as rows: `setupTraceInfraWithEventLoop` (the wrapper around `runTraceSetup`, which owns the collector) returns the failure through `setupWarnings.explainFailure`, which appends the undelivered warnings to the error as a `Warnings logged during setup:` block (each row through the same `shortenWarning`, so verifier rows keep their reason lines and an already-routed row keeps its `(N more lines)` marker while only its content is cut, at most 512 bytes with marker and ellipses included (`maxFailureWarningBytes`, equal to the route bound, so a routed row passes byte for byte unchanged), escaped with `textsafe.Escape`, at most 8 listed plus a `... and N more warning(s)` row; `errors.Is`/`As` still reach the cause, and an error with no warnings is returned unchanged). The TUI's error screen shows that text, wrapped to the terminal width (`wrapErrorText`: `ansi.Wordwrap` then `ansi.Hardwrap` on the sanitised plain text before `ErrorStyle` styles each line, then every line re-measured with `ansi.StringWidth` and re-broken by `splitToWidth` through `common.TruncateRight`, because ansi's wrap and `Truncate` count a keycap such as `1\ufe0f\u20e3` as 1 cell where `StringWidth`, lipgloss and the terminal count 2; lipgloss's `Style.Width` wrap split a decomposed grapheme, putting a combining accent at the start of the next line), because the rows are far longer than a narrow terminal, and cut to the rows above the key hint with a `... (N more lines)` row (`errorScreenView`/`fitErrorBody`, `internal/tui/errorscreen.go`): 8 rows of 512 bytes wrap into 50+ lines at 80 columns, and `lipgloss.Place` pads short content but never shortens tall content, so the hint saying how to leave used to fall off the bottom. Its width is fitted too: the key hint (13 columns, 21 for the recoverable `esc  back  •  q  quit`) is cut to the terminal width with `common.TruncateRight` (`errorScreenHintText`), and `wrapErrorText` hard-wraps what word wrapping leaves too wide (a `  - ` indent or a word longer than the terminal, broken between graphemes) and drops only a grapheme wider than the whole terminal (a 2-cell rune or keycap at width 1; a grapheme that fits is never dropped with it, even where `TruncateRight` keeps nothing because ansi's `Truncate` counts an orphan combining mark plus a keycap as 1 cell at width 1 - the zero-width mark leads the next piece), so the hint's key line stays on screen and no line is wider than the terminal at any size from 1x1 up (`TestErrorScreenFitsNarrowTerminals`, widths 1..24; `TestErrorScreenFitsWithKeycapsAtEverySize`, widths 1..40 x heights 1..10, measured with `StringWidth` and `lipgloss.Width`). No grapheme is split except a space+combining-mark cluster at a word break (any space before a mark: `SanitizeLines` keeps a literal space and turns a tab or CR into one): the break drops the space and the zero-width mark leads the next line, still within the width. `cutBytes`/`shortenWarning` return "" for a limit of zero or less instead of indexing an empty string; a successful setup is untouched and still replays the warnings as rows.
- **Records left in the kernel ring at stop** (task us2; `internal/ringbuf_unread.go`, `eventLoop.countKernelRingLeftAtStop`): the libbpfgo poller feeds `rawCh` ahead of the decoder and blocks when it is full, so a consumer that lags until the stop leaves committed records in the kernel's BPF ring buffer, which `RingBuffer.Stop` abandons: they were in neither `tracepoints`, `ring buffer drops` (the kernel did not drop them) nor `records discarded at stop` (only what had reached `rawCh`, task tq2), so `drops: 0` overstated completeness. After the stop-time drain the loop reads the ring's own bookkeeping (`kernelRingUnread`: consumer page and producer page + doubled data area mapped read-only from the map fd; `countUnreadRingRecords` walks the 8-byte-aligned records between the two positions like libbpf's consumer, counts committed non-discard records and stops at a busy one) and reports `records left in the kernel ring buffer at stop: N` in the statistics plus a warning. Records the poller delivers to `rawCh` after the drain snapshot are not counted. The reader is wired next to the drop counter (`attachRingbufUnreadReader`, non-fatal) and maps/unmaps on the single call. Verified live with `-plain` into a pipe nobody reads for 9 s under a `dd bs=1` load (380831 records left). Pinned by the `countUnreadRingRecords` tests (committed, discarded, busy, consumer offset, wrap) and the accounting tests.
- **Text-input cursor stays on grapheme boundaries** (task pz2; `common.UpdateTextInput`/`snapCursorToGrapheme`): bubbles' textinput moves and edits by rune, so Left/Right could park the cursor between an emoji and its U+FE0F (or the two regional indicators of a flag), drawing it over a lone continuation rune that the terminal glues to the previous cell and that is measured one cell wider (the stream modals' input line outgrew its box). After every update through `UpdateTextInput` a cursor inside a cluster is moved to its edge in the direction it travelled (Left to the start, Right to the end), so one press crosses one grapheme; a cursor at a boundary, typing and deleting are untouched. The frame contract measures with `lipgloss.Width` and `ansi.StringWidth` (`TestStreamModalInputFitsWithMultiCodePointEmoji` sweeps flags, hearts and combining accents over widths 7..60); `uniseg.StringWidth` still counts some emoji sequences one cell wider than those two (a library disagreement, not ior's), which the sweep does not assert.
- **Ctrl+V in text inputs** (task uz2; `common.UpdateTextInput`/`isClipboardPaste`): bubbles' textinput answers Ctrl+V with a system-clipboard read whose result only the textinput can unwrap, and every host dropped that command, so the key did nothing. It is now swallowed in the one shared update path (no command, input unchanged); paste is the terminal's own (bracketed paste arrives as `tea.PasteMsg`, which works and is untouched). ior runs as root, often over SSH, where the clipboard is usually unreachable, so wiring the read up was not worth it. Pinned by `TestUpdateTextInputSwallowsTheClipboardPasteKey`, which also fails if bubbles stops answering Ctrl+V with a command.
- **Percentiles of aggregate-only syscalls** (task 003; `statsengine.SyscallSnapshot.NoPercentiles`/`NoPercentileData`): a syscall at sampling rate 0 (futex, clock_gettime by default in the TUI) is counted only by the kernel aggregate, which has a timed mean/min/max but no per-invocation samples, so the percentile reservoir stays empty and P50/P95/P99 are 0 placeholders. `NoPercentiles` (`!hasSamples`, a negative flag like `NoLatency` so literal fixtures keep their values) says so, and the Syscalls table (full and compact), bubble and treemap details render `-` for the percentile cells only; mean/min/max keep their numbers. A row with at least one streamed timed pair (rate N, or rate 1) has percentiles. Pinned by `TestSnapshotNoPercentilesMarksRowsWithoutSamples` and `TestSyscallRowsShowDashForNoPercentiles`.
- **Event-loop receive batching** (task 5s2; `consumeReadyRaw`, `internal/eventloop_runtime.go`): `processRawEvents` does one `select` (flush timer, `rawCh`, ctx) per wakeup and then drains up to `maxReadyBatch` (256) records already waiting in `rawCh` with plain non-blocking receives. A select per record cost ~17% (-flamegraph) / ~8% (-plain) of ior's CPU in `perf`; measured with 1.26M traced syscalls at ~190k/s (no drops, `-plain`): user CPU 2.38 s -> 1.90 s. The bound keeps the flush timer and a cancelled ctx waiting at most one batch. Not done: batched hand-over from the cgo callback (libbpfgo's per-record `C.GoBytes` + `chansend`), the rest of the cost.
- **Restart RSS** (task yr2; `internal/mallocarena.go`): each TUI trace restart loads and tears down a BPF module, and glibc kept libbpf's freed load allocations in per-thread arenas: anonymous RSS grew from 2 MB to ~155-175 MB over 12 load/close cycles (Go heap ~5 MB, fds and programs back at baseline), measured with a throwaway sudo loop over `setupBPFModule` + close. `MALLOC_ARENA_MAX=1` alone plateaus at ~35 MB, `malloc_trim` alone at 60-75 MB, both at ~25 MB. So a C constructor in the `internal` package calls `mallopt(M_ARENA_MAX, 1)` before the Go runtime starts threads (an explicit `MALLOC_ARENA_MAX` in the environment wins) and `closeTraceInfra` calls `releaseFreedHeap` (`malloc_trim(0)`) after the module's `Close`. Not covered by a unit test (it needs root and a BPF load); to re-measure, loop `setupBPFModule(ctx, flags.NewFlags(), nil, bpfSetupLog{})` + `mgr.Close()` + `release()` + `mod.Close()` as root and read `RssAnon` from `/proc/self/status`.
- **Cheap per-syscall BPF bookkeeping** (task 2s2; `internal/c/filter.c`, `internal/c/maps.h`, `internal/generate/bpfhandler.go`): every traced syscall used to cost ~280 ns (a `bs=1` dd ran 2.6x slower), mostly hash-map helper calls. Two changes cut a traced 6M-syscall dd from ~2.5 s to ~1.75 s (`dd bs=1 count=3000000` traced system-wide with a non-matching `-comm`, untraced 0.63 s). (1) `syscall_sampling_rate_map` is a `BPF_MAP_TYPE_ARRAY` indexed by the enter trace ID (an inlined lookup instead of a helper call; max_entries 4096, IDs top out near 1900); an array has no absent state, so a slot stores **rate + 1** and 0 means "not configured, rate 1" (`ior_sampling_rate` decodes, `encodeSamplingRate` in `internal/syscall_aggregate_consumer.go` encodes and saturates the largest rate so it cannot wrap to 0; an ID past the array's end also reads as the default). Anything writing that map must use the encoding. (2) At rate 1 `ior_on_syscall_enter` writes **no** `syscall_enter_state_map` entry: the entry only carries the sampling decision (always "emit" at rate 1) and the start time (only the kernel aggregate, which rate 1 never writes, uses it), so the exit takes the stateless path, `ior_stateless_exit_emits`, which is what a lost entry already did. The handlers that stash a pending filename onto the entry (the faulted-path recovery kinds and the output-path `getcwd` capture) need it at every rate, so the generator makes them call `ior_on_syscall_enter_stateful` (`handlerSpec.keepsEnterState`: decided by whether the kind body contains `ior_stash_pending_filename` or the syscall has an output-path argument, not by a kind table); other rates keep the entry everywhere. Pinned by the `enterstate_fallback_test.go` harness (`rate 1 elides the enter state`, `stateful enter keeps the rate-1 state` and three mutations), `TestGeneratedEnterHooksMatchTheirStash` (every committed handler: stash iff stateful hook) and `TestEncodeSamplingRateRoundTripsThroughTheBPFDecoder`. Not done: task-storage enter state (needs a pre-5.11 fallback for el8) and skipping the exit-side lookup at rate 1 (it also reaps a stale foreign entry).
- **Path-capturing exits do one enter-state lookup** (task 0t2; `internal/c/filter.c` `ior_on_syscall_exit_impl`, `internal/generate/bpfhandler.go` `renderTakingExitHook`): the faulted-path recovery used to take its pending pointer(s) with a separate `ior_take_pending_filename` (+ `ior_take_pending_filename2` for rename/link/move_mount) lookup ahead of the exit hook's own, i.e. 2-3 `syscall_enter_state_map` lookups per exit. The hook is now one function with two optional out pointers; `ior_on_syscall_exit` (no pointers), `ior_on_syscall_exit_take_filename` and `ior_on_syscall_exit_take_filenames` are thin wrappers (constant NULLs inline away). It zeroes the outputs, and copies `pending_filename`/`pending_filename2` out of the entry only after the `enter_trace_id` guard (a missing or foreign entry stays the stateless path with 0 pointers) and before the final delete; the generated exit declares the locals, reads the clock and calls the hook, and the fixup still follows a successful hook and precedes the handler's own reserve. Rate-1 non-stateful handlers are untouched (no entry, plain hook). Pinned by the `enterstate_fallback_test.go` harness (scenarios `exit hook ...`; the harness poisons deleted entries and presets the out pointers to garbage; mutations for not taking, leaking a foreign pointer, unset outputs, reading after the delete), `checkExitHookTakesPendingPointers` (source order inside the impl: one lookup, take after the guard and before the delete), `checkRecoveryOrdering` (generated handlers: decl, one taking hook, no plain hook or standalone take, emit between hook and reserve) and the getcwd oracle mutations in `syscall_semantics_test.go`. Measured: per-program `bpf_stats` times are too noisy on a laptop to resolve it (the unchanged `close` exit moved as much between runs), but the structure is deterministic: map-lookup call sites in the xlated programs `sys_exit_openat` 7 -> 6, `sys_exit_rename` 9 -> 7 (`close` unchanged at 5), and the kernel instructions of a 400k-iteration open+close+stat loop under `-comm nomatch` (`perf stat -e instructions:k`, 8 interleaved runs each) fell from a median 6.536G to 6.478G (-0.9%, min -0.65%, ~55-70 instructions saved per path exit).
- **Noreturn syscalls are rows at enter** (task pr2; `internal/eventloop_noreturn.go`, `internal/c/filter.c`, `internal/generate/typesgo.go`): `exit`, `exit_group` and `rt_sigreturn` never return (for `rt_sigreturn`, `restore_sigcontext` sets `orig_ax = -1`, so `ftrace_syscall_exit` skips it), so the generator emits no exit handler for them (`isNoreturnSyscall`) and their enter uses `ior_on_noreturn_syscall_enter`, which writes no `syscall_enter_state_map` entry (nothing would ever delete it). Userspace used to park their enters like any other, so selecting them produced no row at all. The same generator set is now emitted as `types.TraceId.NoReturn` (`noReturnTraceIds`, `writeTraceIdNoReturnSet`), and `syscallEntered` hands such an enter to `completeNoReturnEnter`, which builds the pair at once: a synthetic exit (`noReturnExit`: a `*types.NullEvent` at the enter's time and tid, trace ID enter-1, no `ret`) and `Pair.NoReturn`, then the normal exit path (`applyDerivedPairValues`, `handleTracepointExit` -> `finishPair`, `finalizeTracepointPair`, `sendPair`), so every filter dimension applies, `numSyscalls` counts it, and the tid's gap baseline advances (the next syscall after a signal handler measures its gap from the `rt_sigreturn`). It also recycles a stale enter still parked under the tid, as `pairTracker.set` would. Representation: `Duration` 0 and no return value; `-plain` leaves `ret` empty, Parquet and the stream CSV export write `ret = 0`, `latency_ns = 0` (non-nullable columns; documented in `docs/parquet-querying.md`), `streamrow.Row.NoReturn` makes the Stream tab show `-` for both, and the stats engine books the pair as untimed (global `totalUntimed`, per-syscall `untimedCount`, per-process `untimedCount`), so it never enters a latency mean, histogram, series or percentile reservoir. Views and filters treat the absent outcome as absent, not as 0 (review follow-up, task pr2): `statsengine.SyscallSnapshot.NoLatency` (`!syscallStats.hasTimed`, the flag rather than `count - untimedCount`, whose aggregate part may be one too high after a torn read) and `ProcessSnapshot.NoLatency` (timed count 0; exact, process rows get no aggregates) mark a row without any timed sample, and the dashboard renders its latency cells (`latencyCell`/`latencyCellUint`: Syscalls full/compact table, Processes table, bubble and treemap details) as `-` instead of `0ns`; it is a negative flag so literal snapshot fixtures keep their figures. `globalfilter.Candidate.NoReturnValue` (`pairCandidate`: `Pair.NoReturn`; `streamrow.Row`: `NoReturn`) makes `Filter.matchesOutcome` reject the row under every configured `LatencyNs`/`RetVal` predicate, whatever the operator (`ret == 0`, `latency < X` no longer list every `exit_group` as a fast success; errors-only already rejects it, `ErrorValue` is false), consistent with `aggregateIngestAllowedForFilter` dropping all aggregate rows, and so their untimed noreturn counts, under those filters; `NoReturnValue` is only called when an outcome predicate is set (lazy `Matches`). The paused Stream tab refuses Enter on the `-` Latency/Ret cells of such a row (`setNumericCellFilter`), like the File cell of a fileless row. Pinned by `internal/globalfilter/noreturn_test.go`, `TestNoReturnRowFailsOutcomeFilters` (streamrow), `TestPausedEnterOnNoReturnPlaceholderCellIsNotHandled`, `TestSnapshotNoLatencyMarksRowsWithoutTimedSamples` and `internal/tui/dashboard/nolatency_test.go`; user-facing in `docs/parquet-querying.md` ("Syscalls that never return") and the tutorial's Stream section. Kernel side, a noreturn enter the sampling rate suppresses is counted untimed in `syscall_aggregate_map` by the hook (it used to be counted nowhere, because the aggregate is otherwise written at `sys_exit`). Pinned by `internal/eventloop_noreturn_test.go`, `internal/statsengine/noreturn_test.go`, `TestNoReturnMarksExactlyTheNoreturnEnters` (committed artifact), `TestGenerateTypesGoNoReturnSet` and the integration tests `TestNoReturnSyscallsAreRows` (exactly one `exit_group` from the main thread, exactly one `exit` from the ended worker thread, `rt_sigreturn` per handled signal, `tgkill` as the paired control) and `TestAggregateOnlyNoReturnSyscallsAreCounted` (Parquet footer totals with `rt_sigreturn=0`), both on the `noreturn-syscalls` ioworkload scenario.
- **Kernel restart codes vs errors** (task aq2; `internal/event/return.go`, `internal/c/filter.c`, `docs/parquet-querying.md`): a signal that interrupts a blocked syscall leaves -512/-513/-514/-516 (`ERESTARTSYS`, `ERESTARTNOINTR`, `ERESTARTNOHAND`, `ERESTART_RESTARTBLOCK`) at `sys_exit`; user space never sees them. `event.IsErrnoRet` (-4095..-1) means "no result" and is what fd tracking and byte accounting use (the interrupted call created no descriptor and moved no bytes), so it deliberately includes the restart codes. Everything that counts or flags a *failure* (statsengine error counters, `streamrow` `is_error`/Parquet, the errors-only filter, the BPF aggregate's `ior_is_errno_ret`) uses `event.IsErrorRet` = `IsErrnoRet` minus `IsRestartRet`. `ret` keeps the raw value, so `ret == -512` still finds the rows. Nuance: the kernel (x86 `handle_signal`) restarts -513 always, -512 only with no handler or `SA_RESTART`, and -514/-516 only when no handler ran (-516 via `restart_syscall`); otherwise the program really gets `EINTR` (e.g. -512 without `SA_RESTART`, a relative `nanosleep` cut by a handled signal, -516), but `sys_exit` fires before that rewrite, so ior shows the restart code with `is_error=false`; only a literal -4 from the syscall itself is an error (pinned by `TestIsErrorRetExcludesRestartCodes` and the per-consumer tests). A -516 call resumed through `restart_syscall` is folded into one row (next bullet, task fs2); a call restarted by re-execution (`read` -512 then `read` n) stays two rows. The `signal-restart` ioworkload scenario (`cmd/ioworkload/scenario_restart.go`, `integrationtests/restart_codes_test.go`) produces them deterministically; its blocking calls use `syscall.Syscall`/`Syscall6`, not `RawSyscall`, so the runtime releases the P and the signal-sending goroutine still runs with `GOMAXPROCS=1` or one CPU.
- **restart_syscall folds into the call it resumes** (task fs2; `internal/eventloop_restart.go`, `restartTracker`): a call stopped without a handler (SIGSTOP/SIGCONT, ptrace or freezer stop) inside nanosleep, clock_nanosleep, poll or a timed futex wait exits -516 and is resumed by the kernel through `restart_syscall`, which used to give two or more rows (`clock_nanosleep ret=-516`, `restart_syscall ret=0` without the requested sleep). `tracepointExited` now holds a pair whose exit is a `*types.RetEvent` with -516 (`restartTracker.hold`, at most `maxHeldRestarts` = 4096 rows, beyond that unfolded) before its exit handler, derived values and pair filter run; `routeHeldRestart`, called by `rawRuntimeEventHandler` for every decoded record before anything else (so before the raw enter filter), then decides on the held tid's next record: its `restart_syscall` enter is consumed (resumed), the following `restart_syscall` exit is folded (its `Ret` and `Time` are written into the held exit, which keeps the original trace ID; a fold ending in -516 again is held again), and any other record of that tid - an enter, another exit, a control record such as its `sched_process_exit` or a `task_newtask` for the recycled tid - first completes the held row unchanged (`completeTracepointPair`, the old tail of `tracepointExited`). `processRawEvents` completes every row still held when it stops (`releaseAllHeldRestarts`, oldest exit first, before `run`'s `flushOutput`). The folded row is the original call: its enter, arguments, requested sleep and gap, the final `ret`, and a latency from the first enter to the final exit, stopped time included (the resumed sleep ends at the original deadline, so a short stop does not lengthen it); `numSyscalls` counts it once, and filters, stats engine, Parquet, CSV and flamegraph see one row. Only -516 is folded because only `restart_syscall` provably continues a call: -512/-513/-514 are restarted by re-executing the syscall, which ior cannot tell apart from a program that got `EINTR` and retried (it does not know whether a handler ran), so those stay two rows. Because a record may now release a held row before completing its own pair, the pair channel has two slots (`sendPair` still panics on a third). A held row is delayed until its tid's next record; released unchanged (handled signal, i.e. `EINTR`) that is the handler's first syscall. Kernel-side aggregates are per invocation and unfolded. Pinned by `internal/eventloop_restart_test.go` (fold, repeated stops, other tid, no held row, intervening syscall, cut-short continuation, rt_sigreturn release, thread-exit release, both stop paths, filters on the folded row, the bound), `TestRunSurvivesHandlerProducingThreePairs`, and the integration test `TestStoppedSleepIsOneRow` on the `stop-restart` ioworkload scenario (a child `sh` sends SIGSTOP/SIGCONT to the workload during a 600ms sleep; exactly one `clock_nanosleep` row with ret 0, the requested 600ms and latency >= 600ms, no `restart_syscall` on that thread).

## Integration-test output ownership

The integration harness has two complementary persisted outputs. Collapsed
`.ior.zst` records are the authoritative end-to-end surface for descriptor
flags; assert them with `ExpectedEvent.Flags` using access-mode plus required /
forbidden bit constraints so `O_RDONLY` (zero) is testable without pinning
unrelated kernel-added bits. Per-event syscall semantics live in Parquet;
`ExpectedRow` uses optional pointers so exact zero and `false` remain distinct
from "not asserted" for fd, return/error, epoll metadata, address-space bytes
and requested sleep duration.

Use `runParquetScenarioRows` for those row assertions. It reads through the
repo-local `internal/parquet.Record` schema and checks PID/comm ownership before
returning rows. A scenario should normally run in only one output mode: keep it
on collapsed output when flags are the semantic under test, and use Parquet for
the row-only fields. Dedicated deterministic ENOENT/EBADF scenarios assert both
the exact negative errno in `RetVal` and `IsError=true`; presence/count alone is
not sufficient.

Scenarios whose ior arguments depend on workload state use two harness hooks.
`TestHarness.IorArgsForPID` (`func(pid int) ([]string, error)`) returns extra
ior args from the workload PID (appended after the harness's own, so `-pid -1`
overrides its `-pid`), honoured by both `RunWithIorArgs` and
`RunParquetWithIorArgs`. The callback runs after the workload has started, so it
must report failure through its error result and never call `t.Fatal`/`Goexit`:
when it returns an error, the harness kills and reaps the workload before
failing the run, whereas an unwound goroutine would skip that cleanup and leave
the workload waiting 30s for its startup file as a zombie. On the workload side,
`scenarioPrestarts` (`cmd/ioworkload/scenario_threadexit.go`) runs a hook
*before* the PID is printed, i.e. before ior starts: `thread-exit-tid-worker`
and `exec-non-leader-thread-tid` use it (`startParkedWorker`) to park a worker
thread and write its TID to `$IOR_WORKLOAD_TID_FILE`, which the test's
`IorArgsForPID` reads to pass `-tid <worker>`. `TestHarness.IorEnv` adds
`KEY=VALUE` entries to ior's environment for every run built through
`iorCommand`, e.g. ior's `IOR_TEST_*` hooks (task wz2).

## TUI Behavior

- **Default mode** is TUI (`-plain` disables TUI and prints CSV rows to stdout).
- **Terminal-safe traced text** (`internal/textsafe`): comm names, paths, argv and frame names are attacker-controlled (a file named `"\x1b]8;;http://evil\a..."` plants an OSC 8 link). `textsafe.ClassAt`/`FirstUnsafe` is the single classification of unsafe runes (C0/DEL/C1 controls, invalid UTF-8 bytes, invisible/bidi format runes, blank-rendering space lookalikes (`textsafe.IsBlankLookalike`: every Unicode `Zs` space except U+0020, e.g. U+00A0 and U+3000, plus the pinned blank symbols U+2800, U+303F, U+FFFC, U+13441, U+13442, U+16FE4, U+1D159; the zero-width joiner marks such as U+2D7F are deliberately left alone, see `blank.go`; so legitimate names with a no-break or ideographic space show as `?`/`\u00a0` too, task ms2), a ZWJ outside an emoji sequence). The TUI replaces them with one-cell placeholders (`tui/common.Sanitize`); `-plain` (`event.Pair.AppendCSVRow`, `plainSink`) and `ior collapsed` (`CollapsedOptions.Escape`) rewrite them as `\x1b`/`\u202e`/`\U000e0041` via `textsafe.Escape`, selected by the shared `-escape=auto|always|never` flag (`textsafe.EscapeMode`, a `flag.Value`, so an invalid value is a parse error; `EscapeMode.Escaper` decides once per run). `auto` (default) escapes only when stdout is a terminal, so piped or redirected output stays byte-exact, but a pipe that ends in a terminal (`| less -R`, `| grep`, `| tee`) still shows raw bytes: that is what `always` is for; `never` keeps raw bytes on a terminal. The -plain default printCb (`plainStdoutSink.Print`) binds `os.Stdout` on the first pair, not at loop construction. It formats rows append-style into a reused buffer (`AppendCSVRow`, allocation-free for clean rows) and writes them in 64 KiB batches instead of one write(2) per row; a terminal stdout is written per row, and otherwise the event loop flushes within `plainFlushInterval` (20ms) of the first buffered row and when it stops (`eventLoop.flusher`, flushed by a defer in `run` that fires first on every exit, including a panic unwinding through it). `SetPrintCallback` drops the flusher (right for a callback that replaces the sink); a wrapper that still feeds the previous callback must use `WrapPrintCallback`, which keeps it, and `configureEventLoopOutput` must therefore use `WrapPrintCallback`, never `SetPrintCallback`, for the active-probe filter, or the 20ms timer and the shutdown flush silently vanish and rows leave only in 64 KiB chunks. Accepted trade-off: an exit that bypasses `run`'s defers (a crash in another goroutine, SIGQUIT, SIGKILL) can lose up to `plainFlushInterval` / 64 KiB of buffered rows, which the old unbuffered writer did not; SIGINT/SIGTERM, and SIGHUP in the headless modes unless the process inherited it as ignored (see **Headless signal handling**), cancel the context and flush normally. A failed write drops that batch, including the bytes of a partial write, and is recorded in `plainStdoutSink.Err()`; it is also reported through the sink's `onErr(err, droppedRows)`, which `newEventLoop` wires to `eventLoop.outputFailed` (the CSV header write reports the same way). The first failure warns on stderr (`notifyWarningOrLog`), stops the trace (`stopTrace`, wired to the trace's cancel func by `runTraceLoop`, so ior does not keep tracing into the void), adds the dropped rows to `rowsLost` (shown as `rows lost to stdout write errors: up to N` in the statistics, an upper bound because a partial write counts its whole batch), and `runTraceWithContext` joins `eventLoop.outputError()` into its result, so `ior -plain ... > /dev/full` exits 2 with `Failed to run: writing -plain output to stdout: ...` instead of 0. EPIPE takes the same path, but normally never gets there: `-plain` keeps die-on-SIGPIPE (see **Headless signal handling**), so the process ends from the signal first; the error path covers a parent that started ior with SIGPIPE ignored. Pinned by `TestPlainRunStopsOnFullDisk`, `TestPlainRunStopsOnUnwritableStdout` and `TestOutputFailedStopsTraceOnce`. The CSV header line is written directly to stdout by `run` before the first row and never goes through the sink, so it must stay ahead of every buffered row (`TestPlainRunHeaderPrecedesRows`). Escaping runs before CSV quoting and adds no delimiter, so rows stay valid CSV. Add new unsafe classes in `textsafe`, never in one renderer only. Independently of `-escape`, `WriteCollapsedStacks` always encodes LF/CR inside a frame as `\x0a`/`\x0d` (`encodeCollapsedFrame`, applied before aggregation) because they are structural in the line-based collapsed format; `;` never reaches a frame since `buildFrames` splits on it, and the weight is always the last token. A positive-weight record whose selected fields all render empty is counted under the `[unknown]` frame (`collapsedEmptyFrame`) so the total weight is preserved (the event count for the default `-count count`, the sum of that counter otherwise); it is not collision-free (a comm or relative path component named `[unknown]` merges into it, harmless), and zero-weight records are omitted.
- **The `-flamegraph` recorder is bounded** (`internal/flamegraph/recordcap.go`, task uq2): a `.ior.zst` record is one row per distinct `(path, tracepoint, comm, pid, tid, flags)` key (~250 B of heap each while recording; `Recorder.Write` adds only ~1-2 MB whatever the count, because `encodeRecords` streams the records message batch by batch, see the next bullet; `ior collapsed -fields` picks frames after the fact, so every field must be stored), which a fork- or thread-churning system-wide run grows by ~6000 keys/s, over 1 GB in the default 900s. `NewRecorder` therefore caps it at `DefaultMaxRecordKeys` (2^19 records, ~130 MB) and degrades in two stages, churning pid/tid first and the default collapsed fields (`comm,tracepoint,path`) last. Keys that already exist keep aggregating exactly; only a NEW key past the cap is folded. **Stage 1** folds it into the record of the same path, comm, tracepoint and flags with pid 0 and tid 0 (new stage-1 records may use a headroom of cap/8 beyond the cap, `stageOneHeadroom`; under pid/tid churn alone nothing the default fields show is lost). **Stage 2**, only when that stage-1 record would be new and the headroom is used up, folds it into a per-(tracepoint, flags) record with path and comm `[other]` and pid/tid 0. Totals (count, durations, bytes) are exact at every stage, the first keys seen win, and the memory bound is cap + cap/8 + one `[other]` record per (tracepoint, flags) seen. The fold is announced, not silent: the first event of each stage prints a one-time stderr notice during the run (the recording is only written at the end, up to 900s later), and `Recorder.Write` prints a summary after `Wrote <file>` with the number of events folded per stage (events, not keys: remembering keys would defeat the cap); a run under the cap prints neither. Only the live recorder is bounded: recordings loaded by `ior collapsed`/`LoadRecording`, `WriteRecordingFile` and test fixtures use `maxKeys == 0` (unbounded) and never fold. Same ambiguity class as `[unknown]` above: a real comm or path spelled `[other]` with pid/tid 0 shares a record with the stage-2 fold, and a real event with pid/tid 0 (idle task) shares its record with the stage-1 fold of its path and comm; frames of a recording are free-form text, so the labels cannot be made collision-free. The cap is configurable (task rs2): `-flamegraph-max-keys` (`flags.Config.FlamegraphMaxKeys`, default `DefaultMaxRecordKeys`) is passed by `maybePrependFlamegraphConfigure` to `NewRecorderWithMaxKeys`; `validateNumericLimits` rejects values outside `[1, MaxRecordKeysLimit]` (2^24 records, ~4 GB plus the cap/8 headroom; bigger is most likely a typo), and `NewRecorderWithMaxKeys` maps a non-positive cap from a hand-built `Config` to the default, so a live recorder is never unbounded. The flag is ignored without `-flamegraph` (the TUI's LiveTrie and the Parquet recorder have their own bounds), and the stage-1 notice names it so a user who hits the cap learns how to raise it. Pinned by `internal/flamegraph/recordcap_test.go` (both stages, both churn patterns, exact totals, flags kept apart at both stages, warn-once, a lowered and a raised cap, `BenchmarkAddDistinctKeysCapped` for the allocation-free at-cap path), `internal/flags/flamegraphkeys_test.go` (default, range, rejected values, help text including the save-time memory) and `internal/ior_flamegraph_maxkeys_test.go` (the flag reaches the recorder).
- **The records message of a `.ior.zst` is streamed** (`internal/flamegraph/recordsgob.go`, `gobwire.go`, task tz2): the format is unchanged (magic, gob header, ONE gob message holding the `map[recordKey]Counter`, decoded by a single `Decode`), but `encodeRecords` no longer calls `enc.Encode(records)`, which built the whole message in a buffer grown by append and handed it to zstd in one `Write` (answered with a CompressBound-sized copy): measured ~240-390 B/record peak extra heap (GOGC 10/100, 2^17 and 2^19 records), ~580-660 B/record allocated. `writeRecordsMessage` writes the same bytes from documented gob wire-format pieces: the stream's own encoder probes an empty map for the type definitions it still owes and the `int(typeID) 0x00` prefix, then `recordsBatchSize` (1024) records at a time are gob-encoded by a separate batch encoder as a `map[*recordKey]*Counter` (gob flattens pointers, so the key/elem pairs are identical, but reflect copies no struct per record, so encoding is allocation-free) and stripped of their framing; a sizing pass sums the pair bytes for the length prefix, the writing pass re-encodes and writes one batch per `Write` and fails (`errRecordsChanged`) if the bytes differ from the sized length. Measured after: ~1-2 MB peak extra heap whatever the record count (~10 B/record at 2^17, ~3 at 2^19), save ~10% slower (two encode passes; 2^19 records ~1.1 s vs ~1.0 s). A recording with at most one record is byte-identical to the old encoder's; with more, only the pair order differs (gob map order is random anyway). Pinned by `recordsgob_test.go` (byte identity incl. nil/empty/sampled, same-pairs-any-order and decode equality across batch boundaries with plain gob and `decodeRecords`, compressed file round trip, a failing writer at every byte offset, the size-mismatch check, and `TestEncodeCompressedHeapStaysBounded`: <= 16 B/record at 2^17, skipped with `-short` and under `-race`) and `gobwire_test.go` (uint encoding against gob itself). The libzstd compression context is C memory outside these figures and unchanged. A gob upgrade that changed the wire format would fail the probe/batch checks (an error, the temp file is discarded), not write a corrupt file.
- **Refreshing the emoji table** (`internal/textsafe/emojitable.go`): `isEmojiBase` is a generated range table (Extended_Pictographic + Emoji_Modifier_Base + Emoji_Modifier), never hand-edited (it carries a `Code generated ... DO NOT EDIT.` header naming the Unicode version and source file date). For a new Unicode version get its `emoji-data.txt` (Fedora `unicode-ucd`, or https://www.unicode.org/Public/<version>/ucd/emoji/emoji-data.txt), then run `go generate ./internal/textsafe` (reads `/usr/share/unicode/ucd/emoji/emoji-data.txt`) or `cd internal/textsafe && go run gen_emoji.go -in <path>/emoji-data.txt` (the generator is the build-ignored `gen_emoji.go`; output is sorted, merged and deterministic), review the diff, and run `go test ./internal/textsafe`. `TestEmojiBasesMatchEmojiData` compares the table against the installed `emoji-data.txt` and names the `go generate` command in its failure message when the table is stale; `TestEmojiZWJSequencesStaySafe` checks that every sequence in `emoji-zwj-sequences.txt` still classifies as Safe and prints no regenerate hint (a failure there means the context rules in `ClassAt` or the table need attention, not a regeneration). Both skip when no file is found; `IOR_EMOJI_DATA` (table test) and `IOR_EMOJI_ZWJ_SEQUENCES` (sequence test) point them at another Unicode version.
- **Headless signal handling** (`shutdownSignals`/`guardBrokenPipe` in `internal/ior.go`, task mq2): every headless mode (`-flamegraph`, `-parquet`, `-plain`) treats SIGINT, SIGTERM and SIGHUP as a graceful stop (context cancelled, recording finalised and published); the TUI has its own path (task rr2, `internal/tui/signals.go` and `signalwatch.go`): Bubble Tea turns SIGTERM/SIGINT into `QuitMsg`/`InterruptMsg` and returns from `Run` without calling `Update`, which used to skip the quit path and leave an active `R` recording as a 0-byte `ior-recording-*.parquet.tmp`, and it does not handle SIGHUP at all. Its handler is also one-shot (it returns and unregisters after the first signal), so a second signal could never end a hung shutdown. `newProgram` therefore disables it (`tea.WithoutSignalHandler`) and `watchTerminationSignals` owns SIGINT/SIGTERM/SIGHUP for the whole run with these semantics: the **first** signal sends `signalQuitMsg`, which `Model.handleSignalQuit` turns into the same cleanup as the `q` key (recording stopped and published, trace cancelled, BPF teardown awaited; a recorder Stop failure is kept in `lastErr` so the exit is reported and non-zero); a **second** signal arriving more than `repeatSignalWindow` (1s; SIGTERM+SIGHUP bursts from systemd or a closing terminal are one request) after the first while the shutdown is still running aborts it: `Program.Kill` restores the terminal, `Run` returns `errShutdownForced` and the safety net still publishes the recording (`cmd/ior/main.go` reports it as "Failed to run: ..." and exits with status 2); if `Run` does not return within `forceExitGrace` (5s; `Update` is wedged, e.g. a Stop stuck on a dead disk) `hardExit` ends the process with status 1. Exit codes of the TUI signal path: 0 after a clean shutdown, 2 for a forced exit (`errShutdownForced`), 1 for `hardExit`. Later signals are ignored. A forced exit publishes the recording itself first (`terminationWatcher.publishRecording`, straight through the recorder, bounded by `recordingStopWait`, never through the event loop), and a signal that arrives only after `Run` returned cleanly is a no-op (`finish`/`beginForce` under one lock; `stop` awaits a forced exit in progress and disarms `hardExit`), so a clean shutdown always exits 0. **Editor sessions**: the stream tab's "open in editor" runs the editor through `common.ExecProcess` (never bare `tea.ExecProcess`), which blocks Bubble Tea's event loop inside the child, so `Update` cannot run the quit path and a queued `signalQuitMsg` waits until the editor exits. While `common.ExecActive()`: SIGINT is ignored entirely (Ctrl+C in the cooked-mode editor reaches ior too but is the editor's key, exactly what Bubble Tea's own handler did via `ignoreSignals`; it does not count as the first signal); the first SIGTERM/SIGHUP (external kill, closing terminal) publishes the recording at once from the watcher goroutine and sends the editor SIGTERM, and the queued quit then runs the normal shutdown once the loop is free; a second one publishes again, SIGKILLs the editor and aborts as above. Known limitation: the editor is signalled directly (SIGTERM/SIGKILL to its pid) and shares ior's process group, so with a shell-wrapper `EDITOR` (`sh -c 'vim ...'`) killing the wrapper can leave the real editor running on the terminal after ior exits; a process-group kill would need `Setpgid` on the child plus a terminal hand-off (`tcsetpgrp`) so the editor still owns the tty, which is not done. Ctrl+C typed during the shutdown screen (`handleKeyWhileShuttingDown`) aborts the same way; every other key is ignored there. `signalQuitFilter` (`tea.WithFilter`) stays as a guard that converts a stray `QuitMsg`/`InterruptMsg` into `signalQuitMsg` while the model is not `quitting`. `runProgram` finalises a still-active recording after `Run` returns (`finaliseRecording`, a safety net for panics and aborted shutdowns; a Stop failure is joined onto the returned error), so a signal ends the TUI with exit 0 after a clean shutdown instead of "program was interrupted" (exit 2). SIGHUP is relayed only under the nohup rule below. **nohup rule**: SIGHUP is claimed only when `!signal.Ignored(syscall.SIGHUP)`, because `signal.Notify` installs a handler over an inherited SIG_IGN and would defeat `nohup ior -flamegraph -duration 3600 &` (or a `trap` that ignores HUP); the decision is `shutdownSignalsFor(cfg, sighupIgnored)`, tested without process state and end-to-end by `TestHeadlessRecordingKeepsInheritedSIGHUPIgnore`. SIGINT has the same ignore-override behaviour (Notify replaces an inherited ignore); that predates mq2 and was left alone. `-flamegraph`/`-parquet` also call `guardBrokenPipe` first thing in `Run`, so a closed stdout/stderr pipe yields EPIPE (status writes ignore errors) instead of SIGPIPE killing the run before the recording is written; `-plain` keeps die-on-SIGPIPE on purpose, its product is the stdout stream. The flamegraph `Wrote <file>` line goes to stderr (`flamegraph.statusOut`) after the file is published.
- **A headless `-pid` run ends with its target** (`eventLoop.endTraceOnTargetExit`, `internal/eventloop_targetexit.go`, task vr2): `-plain`, `-flamegraph` and `-parquet` with `-pid N` used to count the group-dead `sched_process_exit` record of N (`group-dead exits: 1`) and keep probing until `-duration` (900s by default), and once the kernel reused the pid the still-armed PID filter traced an unrelated process under the old filter. Like `strace -p`/`perf record -p`, `applyProcessDeath` now reaches `stopTrace` (the trace's cancel func, wired by `runTraceLoop`) through `endTraceOnTargetExit`/`targetExited` on the first, deduplicated group-dead record whose tgid equals `-pid`, after printing `Traced process N exited, stopping the trace` on stderr; the normal shutdown then drains, prints the statistics and publishes the recording, exit status 0. The ring buffer is ordered, so every row the target produced before dying has been handled. Only a *known* group-dead record of exactly that pid ends the run: a thread exit, a legacy 24-byte record (`IsGroupDeadKnown` false) and other processes' deaths do not, and neither does a run without `-pid`. It is armed only when `runTraceLoop` is called with `verbose` (every headless mode, `eventLoop.stopOnTargetExit`): the TUI keeps its session (and the last data) open after the target died. `-tid` is covered by the thread rule below (task os2); with both `-pid P -tid T` the run also still ends on P's group-dead record. **Liveness-watcher fallback**: one ring record is a fragile trigger (lost to ring-buffer backpressure, or never produced when the target dies during the ~5s probe attach, in which case wr2's startup check has already passed), so `runTraceWithContext` (and `runHeadlessParquetWith`, pinned by `TestTargetWatchOpensBeforeTheProbesAttach`) opens a `targetWatch` (`internal/ior_targetwatch.go`) *before* the probes attach (pidfd from `pidfd_open`, plus the start time, field 22 of `/proc/<pid>/stat`, so a recycled pid counts as dead; a zombie process leader with no other thread counts as gone, a zombie `-tid` thread always does; unknown stat errors count as alive) and `runTraceLoop` polls it every `targetWatchInterval` (500 ms, immediately first) in `watchTargetLiveness`; both triggers go through `eventLoop.targetExited`, whose atomic `targetExitSeen` makes the stop and the status line happen once. Only headless runs start it (`traceInfra.targetGone`). Test hook: `IOR_TEST_DISABLE_TARGET_EXIT_RECORD=1` (exactly `1`; any other value leaves them on) disables every record trigger, because it leaves `eventLoop.stopOnTargetExit` false, which `endTraceOnTargetExit` and (since task os2) `endTraceOnTargetThreadExit` both check, so `TestHeadlessPidRunEndsViaLivenessWatcherWithoutExitRecord` and the "liveness watcher only" `-tid` subtests prove the watcher alone ends a run, and the opposite hook `IOR_TEST_DISABLE_TARGET_WATCH=1` (exactly `1`, `targetWatchDisabled`) keeps `startTargetLivenessWatcher` from starting, so `TestHeadlessPidRunEndsWhenTargetExits` proves the record alone ends it: both triggers print the same status line and the watcher polls every 500 ms, so only switching the other one off proves a trigger works (unit: `ior_targetwatch_test.go`, incl. `TestTargetExitRecordHookIsExactlyOne`/`TestTargetWatchHookIsExactlyOne`). There is no opt-out flag. Pinned by `TestPidTargetGroupDeadExitStopsTheTrace`, `TestTargetExitIgnoresEveryOtherExit`, `TestHeadlessPidRunEndsWithItsTarget`, `TestInteractivePidRunSurvivesItsTarget` and the integration test `TestHeadlessPidRunEndsWhenTargetExits`. **`-tid` runs end with the traced thread** (task os2; `endTraceOnTargetThreadExit`, `traceTarget` in `internal/tracetarget.go`). `newTraceTarget(pid, tid)` picks what a headless run follows: the `-tid` thread when given (the narrower scope; with `-pid P -tid T` it follows T, whose exit precedes or equals P's death), else the `-pid` process. A `-tid`-only run used to idle to `-duration` after its thread (or process) died and then trace a recycled tid. The trigger is a `sched_process_exit` record whose *tid* equals `-tid`, whatever its `group_dead` flag (the legacy 24-byte record included), unless it is flagged `IOR_EXIT_TID_INHERITED` (the exec hand-over below): the record is the thread's own `do_exit`, and `filter()` already admits the traced tid. For a leader target (`-tid` = pid) a group-dead record whose *tgid* equals `-tid` ends the run too. Decided semantics: a non-leader thread ends the run when *it* exits while its process lives on; the thread-group *leader* (`-tid` = pid) ends it when the leader thread itself exits, even if siblings run on (its `do_exit` fires the record, it executes nothing more and stays a zombie; strace -p LEADER would wait for the whole group, ior does not); whole-process death ends it through the traced thread's own record (every thread runs `do_exit`) and, for a leader target, also through the group-dead record of its process that the `-tid` bypass forwards from another thread (`ior_process_exit_in_scope`: whichever task held the tid is gone, which covers an exec'ing thread killed inside `de_thread()` after the old leader's record was flagged); for a non-leader target no tgid equals the tid, so that record never matches (its own record precedes it anyway); exits of sibling threads, of other processes and the same exit in the TUI do nothing. The status line names the thread (`Traced thread N exited, stopping the trace`). Tid reuse: a matching record cannot be a recycled tid (a recycled tid exists only after the original task is gone, and that end already stopped the run through its own record, the group-dead record or the watch; a flagged record does not free the tid, the exec'ing task holds it, so skipping it opens no reuse window), and a death during the probe attach is caught by the liveness watch, whose start-time snapshot (field 22 of `/proc/<tid>/stat`, valid for any thread) tells a recycled tid from the original; for a thread the pidfd is opened with `PIDFD_THREAD` (Linux 6.9+, `pidfdThread`; readable as soon as the thread has exited, a zombie counts; older kernels answer EINVAL and the watch uses procfs alone). **An `execve` in a non-leader thread**: `de_thread()` kills the old leader, whose record carries the leader's tid (`group_dead` 0), then hands that tid and the leader's start time to the exec'ing thread, which runs on as the new program. Under `-tid <leader>` the BPF tid filter, a `PIDFD_THREAD` pidfd and `/proc/<tid>` all follow the new program (as `strace -p` does), so the run continues and ends when the new program exits: the BPF exit handler (`ior_exit_tid_inherited`, `internal/c/exec.c`) sets bit `IOR_EXIT_TID_INHERITED` of the record's `exit_flags` word (the former always-zero `reserved` word, so an older object reads "the tid is gone") when the exiting task is a leader and `signal->group_exec_task` (Linux 5.17+; `group_exit_task` on 5.16 and older, read through CO-RE flavors; that path compiles but has not been run on an old kernel yet, task gz2) is another thread (through 5.16 the core-dump code also set `group_exit_task` to the dumping thread, so there a `-tid <leader>` that exits on its own just as a sibling starts a core dump is flagged too and the run ends a little later, on the dumper's group-dead record or the watcher; see the comment in `exec.c`), and `endTraceOnTargetThreadExit` skips such a record (`ProcessExitEvent.TidInherited`, `types.ProcessExitTidInherited` is a hand-kept copy of the define). Under `-tid <non-leader>` the exec'ing thread loses its own tid without a record under it, and the BPF filter no longer matches the program: the watcher (the `/proc/<tid>` entry vanished, the pidfd turned readable) ends the run. The watcher trusts a thread target's exit (readable pidfd, zombie state) only when two consecutive polls see it (`targetWatch.exitSeen`, `confirmExit`), unless `/proc/<tid>` is gone or its start time changed (final at once): during `de_thread()` the old leader is briefly a zombie before the tid hand-over, while a leader that really exited stays a zombie and is confirmed one interval (500 ms) later; a process target's exit still counts at once. `-pid P -tid T` with T not a thread of P is wr2's startup error headless and a TUI warning, where nothing is armed. Pinned by `TestTidTargetExitStopsTheTrace`, `TestTidTargetExitIgnoresEveryOtherExit`, `TestTidLeaderSurvivesANonLeaderExec`, `TestTidTargetExitStopsOnce`, `TestHeadlessTidRunEndsWithItsThread`, `TestHeadlessTidRunSurvivesOtherExits`, `TestThreadWatchIgnoresTheExecHandoverZombie`, `TestTargetWatchRealThread` (asserts the `PIDFD_THREAD` pidfd opens on 6.9+ and that a pidfd-only watch, procfs faked alive, sees the exit), `TestNewProcessExitEventFastDecodesTidInherited`, `TestProcessExitTidInheritedMatchesTheBPFDefine` and the integration tests (`integrationtests/tid_target_exit_test.go`) `TestHeadlessTidRunEndsWhenItsThreadExits` and `TestHeadlessTidRunOutlivesSiblingExitsAndEndsWithTheLeader`, each with an "exit record only" (`IOR_TEST_DISABLE_TARGET_WATCH=1`) and a "liveness watcher only" (`IOR_TEST_DISABLE_TARGET_EXIT_RECORD=1`) subtest, and `TestHeadlessTidLeaderRunSurvivesANonLeaderExec` (ioworkload scenario `exec-non-leader-into-open`, with both triggers and with each alone; `signalTarget` in `signal_shutdown_test.go` points the shared run helper at another scenario and scope). Because the target's exit now ends the run, integration tests that need ior to outlive the target (signal/pipe shutdown in `integrationtests/signal_shutdown_test.go`) keep the `ioworkload` alive after its scenario through `IOR_WORKLOAD_HOLD_FILE` (it exits once that file exists) and release it with `signalRun.releaseTarget`.
- **Startup refuses scopes that can only trace nothing** (task wr2). A `-tps`/`-tpsExclude`/`-trace-*` selection that matches none of the traceable syscall tracepoints fails in `flags.validateTracepointSelection` (every mode, before any BPF work; the message adds a hint when the same `-tps` patterns with their leading `^` / trailing `$` stripped would attach at least one traceable tracepoint, judged with the real selector so `-trace-*` allowlists and `-tpsExclude` against the full `sys_enter_*`/`sys_exit_*` names suppress it; the message names the stripped patterns, shell-quoted when they contain metacharacters, and gives no hint for a pattern that strips to empty such as `^$`. It exists because `-tps '^openat$'` matches nothing: patterns match tracepoint names such as `sys_enter_openat`, so write `-tps openat`). `setupBPFModule` then checks the scope with `reportTraceTarget` (`internal/ior_targetcheck.go`): `-pid` must exist, `-tid` must exist and, together with `-pid`, be a thread of it; headless (`probes == nil`) that is a startup error, in the TUI a warning row (stream tab; `eventstream.filterRows` lets synthetic `IsWarning` rows bypass the user filter, so the active `-pid`/`-tid` predicates of exactly these scopes cannot hide the "trace will stay empty" explanation, task ur2; the other tabs point at these rows with the status-line warning badge, task ys2, next bullet but one). After the attach, `attachRequiredTraceProbes`/`requireAttachedProbes` treat zero attached syscall probes the same way (headless error with everything released; TUI warning pointing at the probes modal). The existence check stats `/proc/<pid>` in ior's own mount and PID namespace while the BPF filters compare host TGIDs, so ior inside a PID-namespaced container rejects a host pid (correct from the container's view: run ior in the host PID namespace), and under `hidepid=2` an unprivileged ior cannot see other users' pids (ior needs root for BPF anyway: run it as `sudo ./ior`). Only a definite ENOENT rejects; other stat errors fail open. Pinned by `internal/ior_targetcheck_test.go`, `internal/ior_bpfsetup_required_test.go` and `TestParseRejectsSelectionThatMatchesNoTracepoint`.
- **TUI startup honours `-tid`** (task ur2): `ior -pid P -tid T` puts both predicates in the first `TraceRequest`, and `ior -tid T` alone skips the PID picker and traces just that thread (PID predicate unset), like the headless modes. `resolveStartupPIDFilters` (`internal/tui/tui.go`) used to force tid to -1 whenever an attach pid existed, and `-tid` alone opened the picker whose `PidSelectedMsg` discards the tid, so the whole process was traced. Now an attach pid clears the tid only when it differs from the configured `-pid` (`NewModelWithConfig` with another target), and `initialScreen` treats a positive `tidFilter` as an attach target. The startup tid seeds only the first session: picking another process in the picker replaces it. `--testflames` shares the same resolution. Pinned by `internal/tui/startuptid_test.go`. `-pid P -tid T` with T not a thread of P is reachable this way: wr2's warning row is pushed to the stream buffer, and `filterRows` (`internal/tui/eventstream/model.go`, also used by the CSV export, which then drops the warning rows itself, so the file holds the filtered real rows only) always keeps `IsWarning` rows, so the Stream tab shows it instead of `total:1 filtered:0` (the status line's `filtered` counter therefore counts bypassed warning rows too: an intended trade-off, warning visibility over counter purity, pinned in the model-level test); pinned by `TestFilterRowsKeepsWarningRowsWhateverTheFilterSays` and `TestModelShowsStartupWarningBehindAnActivePidTidFilter`.
- **Stream warning badge** (task ys2; `streamrow.RingBuffer.WarningCount`, `eventstream.Model.WarningCount`, `internal/tui/dashboard/statusbadge.go`): setup/runtime warnings (wr2's wrong `-tid`, zero probes attached, libbpf warnings, drops) exist in the TUI only as synthetic `streamrow.NewWarning` rows in the Stream tab, so the dashboard's status line points at them from every other tab: `warnings: N (7:Stream)` in `ErrorStyle` (the warning rows' style). The count is kept exactly by the ring buffer under its mutex (`Push` adds a warning row and subtracts the warning row a wrap overwrites, `Reset` - the PID/TID reselect's stream clear - zeroes it), not by scanning a snapshot per frame; the eventstream model reads it from the live source through the optional exported `eventstream.WarningCounter` interface (a `Source` without it reports 0), because the model's own snapshot is frozen while paused and refreshed only while the Stream tab ticks. Every type the TUI publishes as the stream source must implement it: the raw `*streamrow.RingBuffer` (before the first trace, after `resetStreamBuffer`, and the `-tuiTestFlames` modes) and, during every real trace, the session's gated `tui.sessionEventSink` (`wireRuntimeBindings` publishes `bindings.StreamBuffer()`, and `handleTracingStarted` hands it to the dashboard), whose `WarningCount` forwards to the same ring buffer, so the count survives a trace restart. Both carry a compile-time assertion (`warnings.go`, `tracesession.go`); before the sink had the forward the badge read 0 from the moment a trace started. Pinned through the real session wiring by `internal/tui/sessionwarnings_test.go` (`beginSession` + `StreamBuffer` + `SetEventStreamSource` + `TracingStartedMsg`, the status line shows the badge; it persists across a restart and goes with the PID-change reset). Every counted row is in the Stream tab's buffer since warning rows bypass the stream filter (`filterRows`, ur2), but not necessarily on screen: a paused stream shows a frozen snapshot without later warnings, and in follow mode an early warning scrolls up out of view. The badge is still left out while the Stream tab is active: its job is to name the tab holding the rows, which is then the current one, and it would only take room from the filter summary (space resumes, `g` jumps to the oldest rows). `fitStatusRow` lays the status row out as `help | badge | summary` with the priority summary > badge > help: the summary is only ever cut to the width, the badge takes its longest rendering that fits beside it (`warnings: N (7:Stream)`, `warn: N (7)`, `!N`; `warningBadges`, tab number from the registry) and is dropped before the summary loses a cell, and the help text gets the rest. In the styled (>= 90 columns) row the text after the badge is re-rendered in the help bar's muted colour, since the badge's SGR reset would otherwise drop it. The help overlay's Dashboard Tabs section ends with a line explaining the badge (last, so an 80x24 overlay cuts it before the key hints). Tests: `internal/streamrow/ringbuffer_warnings_test.go` (insert, eviction on wrap, Reset, a seeded random mix over several laps against a scan, concurrent pushes under `-race`) and `internal/tui/dashboard/statusbadge_test.go` (row priorities at widths 1..200, unchanged row without warnings, badge on every tab but Stream, follows the ring through growth/wrap/reset, widths 1..200 x heights 1/3/24 x help on/off: height, status line last and within the width, the full frame contract from 20 columns, the badge shown exactly when it fits; ErrorStyle in both themes and readable with the colour stripped).
- **TUI trace flow** ingests events into the in-memory stats engine by default. It writes rows to Parquet only while the user has an `R` recording active.
- **One session gate per event row** (task yp2, `internal/tui/tracesession.go`, `internal/ior.go`): the print callback hands each row to a `runtime.RowEmitter` (`EmitRow(streamrow.Row)`), resolved once per event loop. The TUI's session view provides it through the optional `runtime.RowEmitterSource` on its bindings; `sessionRowEmitter.EmitRow` takes the session read lock once and does the stream push, the recorder `Record` and the recorder warning inside it, so `endSession` stays a barrier (task 5o2: once it returns no row of the retired session is in flight) at one lock round trip per event. Bindings without the capability (headless modes, fakes, bindings with no stream buffer) get `plainRowEmitter`, the old ungated push plus `recordRow`. The recorder and the filter epoch have one owner each: with an emitter the gate reads them from the live bindings on every event (the epoch inside the gate, as fresh as possible), and `wireRuntimeBindings` copies them into `tuiRuntime` only for the plain fallback. The row is passed **by value** on purpose: a `*streamrow.Row` through the interface makes the caller's per-event row escape (1 alloc, 224 B per event); the measured saving over the old two-gate path is only about 10-35 ns per event pair (most of the rest is the ring buffer's and the recorder's own locks), not the ~100 ns the task first estimated. Benchmarks: `BenchmarkSessionEmitRow*` and `BenchmarkSessionPushThenRecordWarning` in `internal/tui/tracesession_bench_test.go`; the epoch-in-gate stamp is pinned by `TestSessionEmitRowStampsTheEpochReadInsideTheGate`.
- **Parquet recorder overflow policy** (task 4s2, `internal/parquet/recorder.go`, `internal/ior_parquet_sink.go`): the recorder queue sits between the print callback (event-loop goroutine) and the writer goroutine, whose row-group flush compresses every column at once. The old 4096-slot queue covered ~5 ms at ~870k rows/s, so headless `-parquet` shed ~2% of rows the event loop had already processed (`Warning: N events were dropped (parquet recorder queue overflow)`). Two modes now, chosen by `RecorderConfig.BlockWhenFull`: **shed** (zero value, the TUI `R` recording, queue `defaultRecorderQueueCapacity` = 16384) never blocks the event loop, which also feeds the live views, and counts drops in `Status().RowsDropped`; **backpressure** (headless, `headlessRecorderConfig`, queue `HeadlessQueueCapacity` = 65536 slots, ~14 MiB of slot array at 224 bytes/slot) makes `Record` wait for room, so the file matches `syscalls after filter` and any overload surfaces as the kernel's counted `ring buffer drops`. Memory stays bounded by the queue in both modes, but the slot array is not all of it: a queued row also pins its heap strings (`FileName`, `OldName`, `Comm`). Kernel-captured names are capped at `MAX_FILENAME_LENGTH` = 256 bytes (`Comm` at 16) and a row carries at most two (rename/link rows: `FileName` + `OldName`) plus its `Comm`, so a completely full queue adds at most 65536 x (512 + 16) bytes, about 33 MiB, of kernel-sourced strings. That is a loose upper bound, typically a few MiB (one short path per row): fd-based rows share the name string cached in the fd table, while path-based rows (`openat`, `stat`, ...) convert their captured path into a fresh string each. Names the event loop resolves itself (`/proc/<pid>/fd` readlinks, dirfd-joined paths) can be longer, up to PATH_MAX = 4096 bytes, but only for distinct deep paths, which is not a realistic full-queue load. Which mode each call site uses is pinned by `TestRunHeadlessParquetBuildsABackpressuredRecorder` (headless, via the `newHeadlessRecorder` seam) and `TestRuntimeBindingsRecorderShedsInsteadOfBlocking` (TUI, via `Recorder.Config()`). Deadlock safety of the blocking send: a waiter holds `session.senders` (RLock) while it waits and gives up on `stopC`, which `Stop` and a dead writer (`abortSession`) both close, so it cannot wait on a gone consumer; `stopSession` takes the write lock (`awaitSenders`) before the final drain, so a row a waiter enqueued while stopping is drained, never stranded (pinned by `TestRecorderStopWaitsForRegisteredWaiter`, which fails on its first trial without the barrier: it waits with `parkwait` for the session goroutine to park in `awaitSenders` and fails if Stop returns first; `waiterRegisteredHook` is the test seam). A row accepted just as the writer dies is lost with the aborted recording, which Stop/Status report as the failure. Live check (host, whole-system trace plus `dd bs=1` 2.2M reads): the old build wrote 1718749 rows vs 1789693 `syscalls after filter` (70944 shed, warning); the new build wrote 2162764 rows = 2162764 after filter, no warning.
- **File output in TUI** has two explicit paths. `e` exports the current filtered stream snapshot to `ior-stream-<timestamp>.csv` in the current directory; its modal picks an option, and the filename is generated at submit time. `e` always snapshots the live ring, even while the stream is paused (`eventstream.Model.ExportInputs`); `x`/`X` write the paused rows. Because the frozen table and the live ring differ then, the `e` modal shows `export.PausedNote` while the stream tab is paused (`export.Model.OpenFor`, fed by `dashboard.Model.StreamPaused`); `T` (fd trace) and the stream footer note it raises (`FD trace: ...`, cleared by the next key) work on the paused snapshot (`m.allEvents`), never the live ring; the fd trace is bounded to the selected row's life of the descriptor number (`fdLifetimeEvents`: it stops at the successful `close` that ends that life and starts after the one that ended the previous, task cr2; a number reused without a close row in the snapshot still shares a trace). Enter in the Syscalls bubbles/treemap and the Files directory bubbles/treemap/icicle acts on the highlighted item (`selectedSyscallSnapshot`/`selectedDirSnapshot` resolve it by key like `selectedProcessSnapshot`; always by name in those Syscalls views, never by the table's family column; an icicle tile that is not a directory row selects nothing). The Stream tab's `X` modal prompts for a filename, which `resolveExportPath` (`internal/tui/eventstream/export.go`, task 9s2) honours as typed: a bare name lands in `exportDir` (`.`), a relative name with a directory part is resolved against it, an absolute one is used as is, `.csv` is appended to the last element. The directory part used to be dropped by `filepath.Base`, so `/tmp/x.csv` silently became `./x.csv`; it is not confined to `exportDir` because the user types it in their own TUI and the `R` prompt and `-parquet` take any path too (a symlink at the name is replaced, never written through, like every user-chosen name). Missing parents are not created. Empty and NUL-containing names, names that denote a directory (`.`, `..`, or ending in `/`, `/.` or `/..`; judged on the raw text, since `out/.` cleans to `out`) and a file name over `NAME_MAX` (the probe only creates a short temp name, so it would otherwise fail at the publish) are rejected in `resolveExportPath`, which cleans the path lexically, not the way the kernel resolves it (`lnk/../x` becomes `x` even when `lnk` is a symlink elsewhere); and `probeExportPath` (`atomicfile.ProbeReplace`, `Probe` for a generated name) turns a missing/unwritable directory or an existing directory at the name into one readable error that names the directory, never the internal `ior-<hex>.tmp` (publish-time errors too: `atomicfile.publishError` names the final path once with the bare errno, not the temp file or the doubled paths of an `*os.LinkError`). A refused name reopens the modal with the typed text, the cursor where it was and the error (`ExportModal.Reject`) instead of closing it; the error clears on the next edit keystroke (also the `filename is required` one), not on cursor movement, and Esc closes without saving; the generated-name test (`isDefaultStreamExportName`) looks at the file name only, so a default name typed with a directory part is still never replaced. Pinned by `TestResolveExportPath`, `TestExportRowsToCSV*` (`...UnwritableSysDirectory` also runs as root), `TestExportModal*`, `TestPublishErrorsDoNotNameTheTempFile` and `TestPausedExportModal*`. `R` starts or stops a Parquet recording, with a filename prompt when starting.
- **Export toggle flag**: `-tuiExport=true|false` (default `true`) enables or disables TUI stream CSV export at runtime, including the Stream tab's x/X/E shortcuts and their hints. It does not disable `R` Parquet recording.
- **Output file naming and publishing** (`internal/atomicfile`): every exporter writes to a unique `ior-<16hex>.tmp` sibling (`O_EXCL|O_NOFOLLOW`, fixed length so any valid final name fits `NAME_MAX`) and publishes by rename. Names ior generates (`.ior.zst` flamegraph, `ior-stream-*.csv`, `ior-recording-*.parquet`) use `Publish`/`WriteFile`: `renameat2(RENAME_NOREPLACE)` and a `-N` suffix on collision, and the actual path must be reported (flamegraph prints it, the Stream tab shows `Exported: <path>`, the recorder's `Status().Path` and the `rec: saved as` status/headless log line follow it). Names the user chose (`-parquet <path>`, names typed into the `X`/`R` prompts) use `PublishReplace`/`ReplaceFile` and keep the historical replace-in-place semantics (the replaced file's permission bits and, best effort, owner are carried over to the new file; a symlink at the name is replaced, never written through); the TUI tells them apart with the strict `atomicfile.IsGeneratedName` (exact zero-padded layout incl. extension, judged on the name as typed, so a missing `.csv`/`.parquet` counts as user-chosen for both exporters; `isDefaultStreamExportName`, `isDefaultParquetRecordingName`). A `-N` suffix truncates the stem (rune-safe) to stay within `NAME_MAX`. Crashed runs leave orphan `*.tmp` files; `mage mrproper` removes them, there is no automatic sweep. **Outputs are checked at startup, not at the end** (task oq2): a trace can run for `-duration` (900s default) and the recording is written only afterwards, so every `-flamegraph`/`-parquet` output problem must fail before BPF setup. `-name` is a base name (`flamegraph.ValidateName` rejects `/`, both in the `-flamegraph` mode handler's `validate` and again in `Recorder.Prepare`); the file always lands in the working directory. `Recorder.Prepare` (called first in `runTraceWithContext`) also rejects a final name over `NAME_MAX`, probes the directory with a real temp file (`atomicfile.Probe`: unwritable dir, NFS root_squash, read-only mount, vanished cwd) and probes the characters the name really contains that vfat/exFAT/SMB refuse (`atomicfile.RiskyNameChars` -> `atomicfile.ProbeNameChars`: the time of day's `:`, any `? * " < > | \` or control byte in `-name`, then its non-ASCII runes and invalid-UTF-8 bytes, each once, capped at 64 bytes - Linux takes arbitrary bytes but vfat `iocharset`, ZFS `utf8only` and casefolded ext4 answer EINVAL/EILSEQ); only EINVAL/EILSEQ (`atomicfile.IsNameRejected`) count as a naming rule, any other probe error (ENOSPC, EIO, ...) is returned. A rejection cured by the colon-free `2006-01-02_15-04-05` layout switches to it with a status note; the note names only the time-of-day `:` (probed alone, not the combined set); if the `-name` itself carries a refused character, startup fails. `ProbeReplace`'s name probe is pinned by a NUL in the name (real EINVAL on every filesystem, `TestProbeReplaceProbesNameCharsAgainstARealRejection`); EILSEQ is only reachable through the flamegraph `probeNameChars` hook. Probe errors name the absolute directory and the bare errno, never the internal temp name. `-parquet` runs `parquet.CheckOutputPath` (`atomicfile.ProbeReplace`: missing/unwritable directory, final name is a real directory - an `Lstat` check, since a symlink to a directory is replaced by the rename, not followed - and special characters in the file name) before `setup`; the real temp file is still created by the recorder's `Start`, so the probe is an early rejection, not a reservation.
- **Stream CSV export columns** (task rq2/ts2, `internal/tui/eventstream/export.go`; user-facing list in `docs/parquet-querying.md`): `writeStreamCSV` writes the header `streamCSVHeader` and then one `streamCSVRecord` per row: the 22 columns `seq, time_ns, gap_ns, latency_ns, comm, pid, tid, syscall, fd, ret, bytes, file, error, family, requested_sleep_ns, nfds, timeout_ns, address_space_bytes, old_file, epoll_op, epoll_target_fd, epoll_events`, i.e. the full per-event Parquet schema under the same names, except that `error` is Parquet's `is_error` and the recorder-internal `filter_epoch` is not exported. The first 17 columns are a positional contract that must never move; new columns are only appended. Synthetic warning rows (`Row.IsWarning`: UI notes with a wall-clock `time_ns` and placeholder pid/ret) are skipped, never exported. `comm`, `file` and `old_file` go through `textsafe.SanitizeComm`/`SanitizePath`, the same functions `parquet.RecordFromStream` uses, so the CSV gets the same UTF-8 repair as the recording (next entry) and strict readers such as DuckDB `read_csv` accept it; the other cells are written directly from the row. The package deliberately does not call `RecordFromStream` (only its tests import `internal/parquet`): that import pulled the Parquet library into its build, 341 instead of 140 packages in `go list -deps ./internal/tui/eventstream` (task 4z2). Two tests in `export_schema_test.go` guard drift against Parquet. `TestStreamCSVHeaderMatchesParquetSchema` ties `streamCSVHeader` to the `parquet.Record` `parquet:"..."` tags by reflection (negative cases in `TestColumnDriftDetectsAddedAndRemovedColumns`), so adding or removing a column on one side without the other fails. `TestStreamCSVCellsMatchParquetRecord` is the cell-level half: it writes one row in which every field has a distinct non-zero value (`distinctRow`) and compares every CSV cell to the `parquet.Record` field of the same column name (`RecordFromStream` output), so a swapped, missing or hard-coded cell fails by column name; the test also fails if `distinctRow` leaves a non-bool field zero or repeats a value. A new Parquet column therefore needs a `streamCSVHeader` entry, a `streamCSVRecord` cell and a value in `distinctRow`, or an entry in the test's `notExported`.
- **Parquet strings are always valid UTF-8** (`internal/parquet/schema.go`, repair in `internal/textsafe/utf8repair.go`): `comm`, `file` and `old_file` are STRING columns, and DuckDB/Arrow reject every query touching a column with an invalid byte. `RecordFromStream` is the single row-to-Record conversion point; it calls `textsafe.SanitizeComm`/`textsafe.SanitizePath` (moved out of `internal/parquet` in task 4z2 so the CSV writers share them without importing the Parquet library; tests in `internal/textsafe/utf8repair_test.go`, plus `TestRecordFromStreamUsesTextsafeRepair` pinning that the recording equals them), which call `textsafe.TrimPartialRune` to drop a multi-byte rune cut at the 15-byte comm limit or, for file/old_file, at the 255-byte BPF path capture limit (only paths of exactly that length, plus the getcwd `...` form; shorter paths are never trimmed). Names resolved against a dirfd are trimmed earlier, in `resolveDirfdPath` (`trimCutPathname`), before the join makes them longer than the limit; that also drops the garbage half-rune from TUI/plain output, and `textsafe.SanitizeUTF8` rewrites any other invalid byte as `\xHH` via `textsafe.Escape` (lossy by design: a literal `\xff` in a name is indistinguishable, no exact-bytes column; independent of `-escape`). **No-file rows** (task pq2): `event.NoFileName` (`N:file`) is display text. Data files never store it: `RecordFromStream` and the stream CSV export (`streamCSVRecord`, which calls `ev.FileValue()` itself and repairs it with `textsafe.SanitizePath`, not through `RecordFromStream`) write `streamrow.Row.FileValue()` (empty when `Row.NoFile`), the `.ior.zst` flamegraph record stores `event.Pair.FileValue()` (empty path when `Pair.File == nil`, shown as `[unknown]` by `ior collapsed -fields path`; the live trie drops the empty frame), only the `-plain` stdout CSV still prints the placeholder (`appendCSVFile`, pinned by `pair_test.go`), and the descriptor column is `-1` (`streamrow.UnknownFD`) when there is none, because 0 is a real fd; a real file literally named `N:file` is stored under that name. `.ior.zst` recordings made before this change (and Parquet files, see `docs/parquet-querying.md`) still hold `N:file` as a real path frame; there is no format version bump, `ior collapsed` prints them as written. The live TUI flame view drops the empty path frame (fileless events only add to the root self value) whereas `collapsed` shows `[unknown]`. Build Parquet `Record`s through `RecordFromStream`, never by hand; the one exception among the `streamrow.Row` writers is the stream CSV export, which builds its cells by hand with `textsafe` to keep the Parquet library out of `internal/tui/eventstream` (see above), guarded by `TestWriteStreamCSVRepairsInvalidUTF8LikeParquet` (repaired text equals `RecordFromStream`'s) and the ts2 tests `TestStreamCSVHeaderMatchesParquetSchema`/`TestStreamCSVCellsMatchParquetRecord` (columns and cells). Document new free-form string columns in `docs/parquet-querying.md`. The other persisted data is not built from a `streamrow.Row` and so never goes through `RecordFromStream`: the `.ior.zst` flamegraph record (built from `event.Pair`; its text is not UTF-8-repaired). (The dashboard snapshot CSV, `internal/export`, `ior-snapshot-*.csv`, task 3z2, was removed in task jz2: since task 364 the stream export replaced it and nothing called it.) Piped `-plain` stdout is deliberately not repaired: it stays byte-exact under `-escape=auto`.
- **Runtime family toggle**: the probes modal (`o`/`O`) has a Syscalls and a Families view (`tab` switches); in Families, `space`/`enter` attaches or detaches a whole family with progress (`probemanager.AttachFamily`/`DetachFamily`). The modal only requests a batch (`probes.FamilyBatchRequestMsg`); `tui.Model` owns the run (`startFamilyBatch`: one at a time, numbered, survives modal rebuilds) and records the batch's intended attached set before it starts, so a restart during the batch still attaches it; the batch runs on the trace session's context (`traceLifecycle.sessionContext`; `AttachFamily`/`DetachFamily` take a ctx and stop between probes once it is cancelled), so it is cancelled when the session ends, and `familyBatchRunning()` blocks (one at a time, Syscalls-view refusal) only while the run's session is still current - a new session can start a family batch immediately; a stale run's progress is not replayed into the modal, and a stale result keeps the recorded intent instead of reading back the new manager and reports a "batch cancelled" note when the cancellation was what stopped it (not as an error). Single toggles are tagged the same way (`ProbeToggledMsg.Session`/`Intent`, set via `probes.Model.WithSession`): a stale single-toggle result applies only its delta (adds or removes its syscall) to the recorded selection, so it cannot clobber a batch intent recorded since; a nil selection stays absolute. **`a`/`n` (all on/off) are model-owned exactly like family batches** (task wp2): the modal only emits `probes.SetAllRequestMsg`, and `startSetAll` records the intent (every registered syscall, or none) as the selection at the key press, then runs `probes.SetAllCmd` on `sessionContext()` (it stops between probes once the session ends) with results tagged by the session; a stale result records nothing (the intent counts from the key press, not from the seconds-later result, so a restart during the walk starts the next session with it and a late result can never re-apply it over newer changes). One walk runs per session (`bulkRunState`, `bulkRunning()`), refusing another `a`/`n` and a family batch meanwhile, and while it runs `rememberProbeSelection` records its intent instead of the half-done read-back. The modal refuses `space`/`enter`/`a`/`n` with a notice while the walk runs, like during a family batch: the model tells it (`probes.Model.SetBulkRunning`: set when the walk starts, cleared by the walk's own result - never by a stale session's - and re-derived for every rebuilt or rebound modal), so a single toggle cannot race the walk on the same manager. A stale single or bulk result is also never shown in the modal (`handleProbeToggledMsg` checks the session before forwarding), because its error ("probe manager is closed") describes a manager that is gone. A probes modal left open across a session change follows it (`beginTraceCmd` -> `rebindProbeModal` / `probes.Model.Rebind`, again when `handleTracingStarted` publishes the new manager): it would otherwise keep the old manager and session tag, so its toggles would fail against a closed manager and their outcome would be dropped as stale; between the restart and the new manager it lists no probes, and the cursor and the info line (a family batch's "trace restarted" outcome) are kept while an old-session error or refusal is dropped (`Rebind` clears `lastErr`). While a family batch runs, the Syscalls view refuses `space`/`enter`/`a`/`n` with a notice (the running batch is replayed into every rebuilt modal, so the guard survives reopening it); `a`/`n` read `States()` fresh and use `Attach`/`Detach`, so they touch only probes not yet in the requested state and are idempotent. After any current runtime probe change the TUI stores the live attached set on the trace lifecycle (`rememberProbeSelection`, `internal/tui/probeselection.go`) - with a running family batch's intent applied on top, so a toggle mid-batch cannot drop the rest of the family. The carried set can therefore be an intent: probes in it that cannot attach are retried and skipped (logged) at each session start until the next change reads the truth back. Every later `TraceRequest` carries the selection as `AttachSyscalls`, so restarts (PID/TID reselect, filter changes) keep it and it replaces the startup `-trace-*` selection (nil = keep the flags, empty = attach nothing). `[`/`]` only re-scope the view; onto a family with no attached probe (but some registered) the status line shows `<Family> not traced: press O, tab, space to attach`, and `O` opens the modal with the Families cursor on the scoped family so those keys attach exactly it (`O`, not `o`: the Flame tab, the default, consumes lowercase `o` as its frame-order key, so `o` cannot open the modal there; the probes binding matches both and is labelled `o/O`).
- **Tab navigation** supports `tab/shift+tab` and numeric keys `1..7` only. `left/right` and `h/l` navigate table columns (and the flame graph); they do not switch tabs.
- **Family visibility**: the Syscalls tab shows a per-syscall Family column classified via `TraceId.Family()`; there is no dedicated Non-IO tab.
- **Dashboard row filters select what the row counts** (`internal/tui/dashboard/rowfilter.go`). Enter on a table row pushes a global filter built from the row's value, never a plain substring of it:
  - Syscall and file rows use `globalfilter.ExactPattern` (`^value$`), so Enter on `read` does not also admit `readv`/`pread64`, and `/tmp/a` does not also admit `/tmp/ab`. Because `trimAnchors` strips exactly one anchor per end and blanks are trimmed only outside the anchors, the wrapper also keeps a value's leading/trailing blanks and a literal edge `^`/`$` intact (`^x$$` is exactly `x$`).
  - Dir-grouped Files rows count only the files **directly** in their directory, so they use `globalfilter.DirPattern`, the directory-children pattern `^dir/*` (the root is `^/*`; `^//*` parses to the root too; a dir already ending in `/` still gets `/*` appended, so `a/` from `a//b` is `^a//*`). The matcher (`internal/globalfilter/dirchildren.go`) defines `^dir/*` as "`globalfilter.LiteralDir(value) == dir`", and the stats engine groups rows by `statsengine.DirOf`, which is `LiteralDir` (or the `.` no-dir group) - the literal text before the path's last `/`, not `filepath.Dir` - so the filter selects exactly the files the row counts: never a subdirectory's files (they have their own rows) and, for the `/` row, only top-level entries. `./src/x`, `//usr/lib/x`, `a/../b/c` stay under their literal dirs. Like a shell glob, `*` never crosses a `/`. `^dir/*$` stays the exact path `dir/*`; the text `^dir/*` no longer means the literal prefix `dir/*` (no row filter produced it). The `.` group (names with no `/`, and `./`-relative ones) has no pattern selecting exactly that mix: Enter on it pushes no filter and sets a filter notice instead.
  - **Directory rows come from the engine, not from the top-64 files** (`internal/statsengine/dirrank.go`). The Files tab's directory view (table, bubbles, treemap, icicle) reads `Snapshot.Dirs()`/`DirsOther()`, which the engine's `dirRanker` fills on every ingested file pair: it aggregates per `DirOf` directory regardless of whether any single file made the top-N, so a directory of 10,000 once-read files ranks by its total (`TestDirRankerCountsDirectoriesOfFilesOutsideTheTopN`, `TestDirViewsShowTheDominantDirectoryOutsideTheTopFiles`). `Snapshot.Files()` still holds only the top-N files; a snapshot built without engine rows (`NewSnapshot` in tests/exporters) falls back to `AggregateFilesByDir(Files())`. Rows beyond the top-N directories are folded into one remainder row (`DirSnapshot.IsRemainder`, label `(other: N dirs)`) that every sort pins last and whose identity is not a path: it has no filter, so Enter on it sets `otherDirsNotice` instead of pushing a filter (like the `.` group's `noDirGroupNotice`), and its selection key is NUL-based so it cannot collide with a real path. Memory is bounded: once more than `32*topN` directories are tracked, compaction keeps the best `max(topN, maxSeen/2)` by accesses (`dirRankKeep`; the margin was measured to keep all true top-64 directories exact on a 20,000-directory Zipf workload, where keeping only `topN` lost 4-6 of them) and folds the rest into the remainder, so accesses/bytes/latency stay exact in total. Eviction trade-off (documented on `dirRanker`, pinned by `TestDirRankerEvictedDirectoryRestartsButTotalsStayExact` and `TestDirRankerCompactionKeepsAMarginBelowTheTopN`): a dropped directory that reappears restarts its own row from zero (its earlier counts stay in the remainder), a real top directory that trailed more than `maxSeen/2` others at some compaction is under-ranked the same way, and the remainder's `FileCount` counts a returning directory's files twice (once from before eviction, once in its own row). The per-directory `FileCount` is a k-minimum-values sketch (`filesketch.go`, k=256): exact below 256 files, about 6.3% standard error and unbiased beyond (`TestFileSketchIsUnbiasedWithTheDocumentedError` averages 400 fixed seeds; `TestFileSketchEstimatorFormula` pins the formula). The path hash is an injectable field (`dirRanker.hash`, a randomly seeded maphash in production so file names cannot skew a sketch); tests inject `seededPathHash` to be deterministic.
  - Family rows (Family column of the Syscalls tab) keep the bare family name: families are a closed set in which no name contains another, and the `[`/`]` family cycle (`internal/tui/familycycle.go`) reads the current family back by its bare name.
  - The Processes tab's Comm cell pushes the *trimmed substring* comm, not an exact pattern: the row aggregates every thread of the PID while the comm filter matches each thread's own comm, and thread names commonly extend the process's (`chrome` -> `Chrome_ChildIOT`). A comm starting with `^` or ending with `$` cannot be a literal substring pattern, so that row falls back to the PID filter (`commSubstringUsable`), as does every other Processes column.
  - Case rule (`globalfilter.matchString`, one rule for typed and row filters): substring, `^prefix` and `suffix$` patterns are case-insensitive; the fully anchored `^exact$` form is **case-sensitive**, because anchoring both ends means "exactly this value" and Linux paths/comms are case-sensitive (`^/tmp/a$` does not select `/tmp/A`). The rule lives in the pattern text, not in a flag on `StringFilter`, so a row filter round-trips unchanged through the filter modal and a user typing `^foo$` gets the same exact semantics. The directory-children form `^dir/*` is **case-sensitive** as well: it is derived from exact row values, so the `/tmp/A` row does not admit `/tmp/a/x`. The exact and directory-children forms are plain string comparisons (zero-alloc for any input); the other modes keep the zero-alloc ASCII fold path (`fold.go`). `ValidateTracepointFields` measures an exact pattern by its raw length only (its lowered form is no witness), `^dir/*` by its shortest witness `dir/` (`/` for the root), other patterns by the shorter of raw and lowered. The filter modal's help line documents `^dir/*`. Pinned by `TestStringFilterCaseSensitivityByAnchorMode`, `TestMatchStringASCIIFoldAgreesWithLowering`, `TestMatchStringASCIIDoesNotAllocate` and `TestValidateTracepointFields*` (`internal/globalfilter`).
  - The Stream tab's paused Enter-on-cell (`requestGlobalFilterFromSelectedCell` / `setStringCellFilter` in `internal/tui/eventstream/model.go`) follows the same rule: its Comm, Syscall and File cells push `globalfilter.ExactPattern`, and a blank string cell pushes nothing. Unlike the Processes tab's Comm cell, the Stream Comm cell is exact because a Stream row is one event showing that event's own thread comm. Numeric cells keep equality (`pid=`, `tid=`, `fd=`, `ret=`, `bytes=`); Gap/Latency push a `>=` lower bound.
  - Pinned by `TestEnterRowFilterSelectsExactlyTheRow`, `TestEnterDirRowFilterSelectsExactlyTheFilesItCounts`, `TestEnterOnNoDirGroupShowsNotice`, `TestEnterFamilyFilterStaysBare` (`internal/tui/dashboard/filteraction_test.go`), `TestPausedEnterStringCellFilterIsExact` (`internal/tui/eventstream/model_test.go`), `TestExactPatternMatchesOnlyTheValue`, `TestDirPatternMatchesDirectChildrenOnly`, `TestDirChildrenPatternIsCaseSensitive` (`internal/globalfilter/filter_test.go`), `TestValidateTracepointFieldsDirChildrenPattern` (`internal/globalfilter/trace_test.go`), `TestDirOf` (`internal/statsengine/dirrank_test.go`, the grouping key) and `TestModelRoundTripsExactRowPatterns` (`internal/tui/tracefilter/model_test.go`).
- **When export is disabled**, export key hints are hidden from dashboard help and `e` and the Stream tab's x/X/E shortcuts do not open the export modal or write CSV files.
- **Fast-refresh cadence**: `-tui-fast-refresh` (default `250ms`) controls the high-frequency tick interval for the flamegraph and stream tabs; set to `0` to fall back to the built-in 200ms flame/stream tick constants (high-frequency refresh never fully stops — it does not fall back to the slower standard dashboard cadence).
- **Attach-time tracepoint selection**: with no `-trace-*`/`-no-trace-*` flags the default allowlist is the **FS family only** — the other 11 families (`Network`, `Memory`, `Signals`, `Sched`, `IPC`, `Time`, `Process`, `Security`, `Polling`, `AIO`, `Misc`) are opt-in via `-trace-families`/`-trace-kinds`/`-trace-syscalls`. Only the full opt-in set reaches the ~300+ syscalls the generator classifies; the default attaches a subset of them.
- **Sampling / aggregate-only mode**:
  - `-syscall-sampling-families` and `-syscall-sampling-syscalls` control per-family/per-syscall sampling (`0` = aggregate-only, `1` = all events, `N` = 1-in-N).
  - Current defaults include aggregate-only (`0`) for `futex`, `futex_wait`, `futex_wake`, `futex_requeue`, `futex_waitv`, and `clock_gettime`.
  - Precedence, lowest to highest: built-in per-syscall default < `-syscall-sampling-families` rate < explicit `-syscall-sampling-syscalls` rate. The defaults live in `Config.DefaultSyscallSamplingRates`, separate from the user-explicit `Config.SyscallSamplingRates`, so e.g. `-syscall-sampling-families Time=100` reaches `clock_gettime` and `IPC=1` reaches the futex variants (`buildSyscallSamplingRates` in `internal/syscall_aggregate_consumer.go`). Test this through `flags.ParseArgs`, not `flags.NewFlags()` (whose default map is empty).
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
  - **Gap statistics are between traced calls.** Aggregate rows carry no
    inter-syscall gap, and a pair's `DurationToPrev` runs from the previous
    *emitted* pair of its TID, so under sampling or aggregate-only rates it
    spans the untraced calls. `Snapshot.GapMeanNs`, the gap histogram and the
    gap sparkline all use the traced pairs that have a previous pair
    (`event.Pair.FirstOnTID` excludes a thread's first); the Overview labels
    the mean `Traced gap`. Dividing by all counted calls instead would be
    diluted by threads that make only aggregate-only calls (parked futex
    waiters).
  - The partition also holds without a per-tid enter state
    (`syscall_enter_state_map` full, clone/fork child exits, syscalls in
    flight at attach, and the two non-leader exec exits that stay stateless:
    `-tid <leader>` filtered the caller's enter, or the enter-state move
    failed; see *Non-leader exec* below): a failed enter-state write is
    counted *untimed* into the aggregate at sys_enter unless the rate
    is `1`, and a stateless or mismatched sys_exit is emitted only at rate `1`
    and never counted (see "Enter state and its two fallbacks" in
    `internal/c/filter.c`). Untimed counts bump `count` only; userspace reports
    them as `SyscallAggregate.UntimedCount` and keeps them out of min/max,
    the latency means and the latency sparkline. The kernel stores `count`
    last, and the consumer tolerates torn per-CPU reads (histogram ahead of
    count counts as timed; a slot's first timed sample read before its
    min/max landed is deferred to the next drain instead of seeding a 0
    minimum; a baseline only advances with a new count). This relies on the
    copy reading `count` first, so `count` must stay the first field of
    `struct syscall_aggregate` in `maps.h`. Completed invocations are recorded
    as at least 1ns, so a settled slot's min/max are never 0; the consumer
    relies on that to tell a settled slot from one still being written. The
    accounting functions of `filter.c` are compiled and exercised on the host
    by `internal/generate/enterstate_fallback_test.go`.
  - **Raw-mode outputs of a sampling run say so and keep the exact totals**
    (task qq2; `internal/sampling`, `internal/sampling_tally.go`). A raw mode
    (`-plain`, `-flamegraph`, headless `-parquet`) has no stats engine, so a run
    with an explicit rate other than 1 (`rawModeSamplingRates`; the promoted
    defaults sample nothing) used to write its 1-in-N rows with no marker and
    never read the kernel counts of the other invocations. Now `newEventLoop`
    gives such a run a `samplingTally` as its aggregate sink, so the drain loop
    runs (headless Parquet wires the aggregate source only in this case; an
    unsampled run pays nothing): `traced` is counted where the loop emits a pair
    (`drainPairs`), `counted` is the drained aggregate rows, and their sum is
    the exact per-syscall population (the two sources are disjoint, see above).
    The totals are withheld, not guessed, when they cannot be trusted: a filter
    the syscall-keyed kernel rows cannot answer (`aggregateIngestAllowedForFilter`,
    e.g. `-comm`) or a last drain that failed gives `Unavailable` with the
    reason, rates still reported. Lost rows make them inexact, not
    unavailable: a dropped event is an emitted row that is in neither `traced`
    nor the kernel aggregate, so `samplingResult` marks the `Summary` with
    `AtLeast()` (`LowerBound`) whenever `numRingbufDrops > 0`, the drop
    counter could not be read, or `numDiscardedAtStop > 0` (records discarded
    by the stop-time drain are emitted rows that never reached decoding, so
    they are in neither `traced` nor the kernel aggregate either; pinned by the
    "records were discarded at stop" case of
    `TestSamplingTotalsAreALowerBoundUnderRingbufDrops` and the parquet footer
    twin); the stats block says "at least", the footer JSON
    carries `"lower_bound":true` per element. The report is compact:
    `sampling.New` folds syscalls that run at a `-syscall-sampling-families`
    rate into `Summary.Families` (`FS=10`, once) and keeps an `Entry` only for
    those with a nonzero total plus the explicit per-syscall rates, so neither
    the startup line, the stats, the footer/header nor `ior collapsed` list a
    family's 100+ syscalls. `Entry.Family` is set when the effective rate equals
    the family's rate. The rates are intersected with the probes that really
    attached (`restrictSamplingToActive`, called from
    `setupTraceInfraWithEventLoop` with `Manager.IsActive`), so a syscall that
    was never traced gets no "0 calls" line. `openAggregateSource` is the seam
    that lets `TestHeadlessParquetLoopWiresTheKernelCountsIntoTheFooter` drive
    the real `newHeadlessParquetEventLoop` without a BPF module. `traced` counts
    pairs at `drainPairs`, before the Parquet queue and the active-probe filter,
    so it can exceed the file's row count (`RowsDropped`, inactive probes).
    Surfaces: startup line on stderr
    (`announceSampling`), a block in the end-of-run statistics
    (`samplingStatLines`, incl. "syscalls including kernel-counted only"),
    Parquet footer keys `ior.sampling` (rates, written at start) and
    `ior.sampling.totals` (JSON or `unavailable`, added by
    `Recorder.SetSamplingTotals` just before the footer is written; neither key
    exists in an unsampled file, so the key is the marker), and the `.ior.zst`
    header's `Sampling` field, which writes format version 2 (version 1 stays
    for unsampled runs; a pre-qq2 reader refuses version 2 rather than show
    sampled counts as complete). `ior collapsed` prints the sampling to stderr
    (`CollapsedOptions.Notice`) and `flamegraph.LoadRecording` returns it.
    `-plain` stdout stays the fixed CSV: its marker is the stderr lines only.
    TUI `R` recordings are marked too (task qs2, next item). The first
    version was verified with stubs only; the fix round checked the
    1000-read scenario, a ring-buffer-drop run (`-mapSize 4096`, 3M reads)
    and a family rate live.
  - **TUI `R` recordings carry the same footer keys** (task qs2;
    `internal/recording_sampling.go`, `internal/tui/recordingsampling.go`,
    `sampling.Tally`, `internal/parquet/recorder_sampling.go`). The TUI's
    sampled list always holds the aggregate-only futex*/clock_gettime
    defaults, but `ior.sampling` lists only sampled syscalls attached at Start
    (`Tally.Plan`), and the default `-trace-families` attaches FS only: a
    default R file is unmarked (live-checked); with `-trace-families
    FS,IPC,Time` (or the probes modal) it is marked
    `clock_gettime=0,futex=0,...`. The totals do NOT come from the stats
    engine: it is reset by the auto-reset timer, `r` and every live filter
    swap and replaced per session, while a recording spans all of that.
    Instead each recording gets a fresh `sampling.Tally`
    (`parquet.StartOptions.SamplingTally`): `traced` is counted by the
    recorder where it writes a row (writer goroutine, so it equals the file's
    rows; shed rows make it a lower bound), `counted_only` arrives from the
    TUI event loop's aggregate drain (`forwardAggregatesToRecording` ->
    session-gated `sessionRecorder.CountKernelOnly` ->
    `Recorder.CountKernelOnly`, a no-op without an active recording). Window
    exactness: the session publishes a `runtime.RecordingSampling` (sampled
    syscalls + `FlushCounters`, via `aggregateDrainer.Flush` and
    `ringbufDropMonitor.Flush`: the drop monitor polls only every 1s, so its
    edge reads put the last second's drops into the stopping recording and
    baseline the pre-start drops away), and the TUI flushes before `Start`,
    before `Stop` (also at quit and from the signal watcher, pinned by
    `TestSignalWatcherFlushesTheCountersIntoTheRecording`) and before a
    session retires while recording (`runtimeBindings.endSession`), so
    consecutive recordings get disjoint deltas. A failed drain at the start
    flush reaches no recording, so `FlushCounters` returns false and
    `beginRecordingSampling` marks the new tally unavailable (its undrained
    deltas would leak pre-start counts in). A session retired mid-recording
    while its loop may still run (live-filter setter still registered: set
    before the loop, removed after it returned) marks a lower bound: its
    undelivered rows are dropped by the gate and the restart does not wait
    (`flushSessionForRecording`). Rates: those attached at Start
    (`ior.sampling`); rates never change at runtime (flags only), but a
    sampled probe attached mid-recording still appears in the totals once
    invoked. Lower bound: ring-buffer drops or an unreadable drop counter
    during the recording (`handleRingbufDropResult`), shed rows, a retired
    live session. Unavailable: a drain failure (incl. the start flush), or
    counts withheld by a filter the kernel rows cannot answer
    (`aggregateDrainResult.withheld`). The sampled-syscall list outlives its
    session (`runtimeBindings.sampledSyscalls`) so an R pressed while the next
    session attaches is still marked; the flush does not.
  - What stays sampled for rate `N` syscalls: per-event detail only — stream
    rows, file/process attribution, byte totals, gaps, and latency percentiles
    come from the ~1/N emitted pairs (kernel aggregate rows carry no bytes,
    gaps, files or processes). Counts/errors/latency-sums/histograms are full.
  - The runtime filter applies to aggregate rows per row where a
    syscall-keyed row can answer it (`aggregateDrainer.filterRowsForIngest`):
    `Syscall` and `Family` via `Filter.MatchesSyscallRow`, so `-syscall futex`
    still counts an aggregate-only futex and `-family FS` keeps other
    families' aggregate rows out of the dashboard totals. A `PID`/`TID`
    equality is honoured only when it equals the kernel-enforced
    `PID_FILTER`/`TID_FILTER` scope the program was loaded with
    (`kernelProcessScope`). Any other dimension (comm, file, fd,
    latency, gap, bytes, retval, errors-only, or a PID/TID the kernel does not
    enforce) gates aggregate ingestion off entirely
    (`aggregateIngestAllowedForFilter`), so aggregate-only syscalls disappear
    and sampled syscalls fall back to their 1-in-N counts until the filter is
    cleared.
  - A live filter swap (`eventLoop.SetFilter` while the drain loop runs) goes
    through `aggregateDrainer.SwapFilter`: it drains and ingests the map under
    the *outgoing* filter before installing the new one, serialised with the
    poll ticks. The counts pending at swap time therefore land in the pre-swap
    baseline the TUI resets right after (`resetAggregatesAfterLiveSwap`)
    instead of inflating the first post-swap interval.
    The drain loop's stop retires the drainer under its lock during the final
    drain (clearing its handle and source), so a SetFilter that races the stop
    swaps the filter without draining the possibly closed map.
- **Additional metric dimensions**:
  - Address-space extent accumulator: `TotalAddressSpaceBytes` and `AddressSpaceBytesPerSec` in `statsengine.Snapshot`. What feeds it (task hq2, `internal/eventloop_addrspace.go`): successful `mmap`/`munmap`/`mremap` (larger of old/new size) and `brk`, each rounded up to the host page size because the kernel maps whole pages (`mmap(len=1)` maps 4096 bytes). `brk` is the movement of the per-process break since the previous `brk` (`brkTracker`, evicted on exec and group-dead exit; the first sighting and `brk(0)` only baseline). `msync`/`mprotect`/`madvise`/`mlock*` leave the extent unchanged and report 0. Huge-page mappings stay at base-page granularity. Accepted approximation: `brkTracker` keys by tgid, not by address space, so a `CLONE_VM`/vfork child (own tgid, shared mm) baselines its first `brk` to 0 and the parent's stale baseline later attributes the shared heap's movement to itself; exec clears the baseline, which covers the common vfork-then-exec case.
  - Per-event stream/export field `requested_sleep_ns` (from sleep tracepoints): `-1` when unknown (null/unreadable or kernel-invalid timespec, absolute `TIMER_ABSTIME` sleeps); valid requests whose nanoseconds are unrepresentable in `__s64` saturate to `S64_MAX` (`generateExtraSleep`). The kernel similarly clamps to `KTIME_MAX`, but from `tv_sec >= KTIME_SEC_MAX` regardless of `tv_nsec`, so values within ~1s of the boundary may differ.
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
  through the procfs fallback (`/proc/<pid>/fd`) can be longer than the event
  field, and a getcwd row whose cwd did not fit the captured field reports its
  `MAX_FILENAME_LENGTH - 1`-byte prefix plus a `...` suffix, so the check is
  conservative for those rows. `Model.refuseUnusableFilter`
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
  the status row (`fitStatusRow`, `internal/tui/dashboard/statusbadge.go`; it
  was `appendStatusText`) trims the static help text rather than the live status
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
- **The full-screen error view owns its keys, and distinguishes fatal from
  recoverable failures**: `View` renders `m.lastErr` ahead of the help overlay,
  every modal and both screens. `handleGlobalKeyPress` therefore dispatches its
  advertised keys through `handleErrorScreenKeyPress` before any invisible
  overlay, modal or picker can consume them. Before task z3, `q`, `ctrl+c` and
  `esc` all fell through to a handled/no-op path and the TUI had no keyboard
  exit (bubbletea still answered a signal from another terminal).

  `Model.errorKind` makes the exit decision explicit at the source. A
  `TracingErrorMsg` is fatal: startup failed, so `esc`, `q` and `ctrl+c` all
  quit rather than reveal a live-looking dashboard wired to nothing. Each of
  the seven `recorderStop` failure sites marks the error recoverable: the trace
  is still usable, so `esc` clears the error and returns, while `q` and
  `ctrl+c` still quit. Fatal is the zero value, so an accidentally unclassified
  error fails closed instead of exposing a broken session.

  A recoverable error can cover a re-selection picker whose return bookmark is
  still pending. The error-screen branch still owns `esc`; its deliberate
  recovery tail then resumes `cancelPickerToDashboard`, restoring the saved
  PID/TID and trace-start routing cleanly. This is not permission for the
  invisible picker to answer the key. The same precedence makes `q`/`ctrl+c`
  quit from that state rather than behave as picker Back.

  Quit cleanup remains best effort: `quitFromErrorScreen` calls
  `recorderStop` and then `tracer.stop()`, but ignores a repeated recorder
  failure so the same broken finalisation cannot swallow the exit again.
  `lastErr` stays set, and `runProgram` returns it from the final model so
  `cmd/ior` can print the reason after the alternate screen disappears. The
  hints match the classification: fatal shows `q / esc  quit`; recoverable
  shows `esc  back  •  q  quit`.

  The sensitive coverage reaches a real recorder rename failure through the
  `R` shortcut and pins trace-preserving Esc, q/ctrl+c cleanup and reporting,
  fatal startup handling, both hints, and error-screen precedence over modal,
  help and picker routing. See `TestRecorderStopErrorEscReturnsToDashboard`,
  `TestRecorderStopErrorQuitKeysStillQuit`,
  `TestRecoverableErrorScreenEscOutranksAndResumesPickerCancel`,
  `TestRecoverableErrorScreenQuitOutranksPickerCancel`,
  `TestErrorScreenQuitsOnEveryQuitKey`,
  `TestErrorScreenQuitOutranksAnOpenModal`,
  `TestErrorScreenQuitOutranksTheHelpOverlay` and the reporting/cleanup tests in
  `internal/tui/errorscreen_test.go`.

  The startup PID picker follows the same visible-screen rule, with one
  addition (the next paragraph): once its filter input is blurred (Up/Down) and
  there is no pending dashboard return, `q` quits with best-effort cleanup;
  during a re-selection `q` is Back, like `esc`. `ctrl+c` always quits and `esc`
  always leaves the picker, even mid-typing
  (`TestStartupPIDPickerQuitsOnQOnceTheInputIsBlurred`,
  `TestStartupPIDPickerCtrlCStillQuitsWhileTyping`,
  `TestStartupPIDPickerEscStillQuitsWhileTyping`,
  `TestStartupPIDPickerQuitsOnQuitKeys`,
  `TestQuitKeysOnReselectPIDPickerReturnToDashboardLikeEsc`). The bounded
  "Attaching tracepoints..." overlay does not swallow quit keys:
  `handleQuitKeyPress` calls `quitWithBestEffortCleanup` while
  `attachingOnDashboard()` is true
  (`TestQuitWhileDashboardIsAttachingWaitsForBlockedStarterCleanup`).

  **A focused text input owns printable keys** (task xq2). In
  `handleGlobalKeyPress`, after the error screen and the help overlay but before
  picker-cancel, quit, `H` help and the dashboard shortcuts, a key whose
  `msg.Key().Text != ""` is passed on untouched (`return m, nil, false`) when
  `Model.textInputFocused` says the screen or modal receiving keys has a
  focused input. Otherwise typing `mysql` in the startup picker quit ior at the
  `q`, `Hypr` opened help, and a `q` in the filter modal's Comm field applied a
  truncated filter. Keys without text (`ctrl+c`, `esc`, arrows, alt/ctrl
  chords) never count as typing, so they keep their global meaning and are not
  inserted as characters. A visible modal decides before the active screen, and
  the attaching overlay reports no focus so `q` still leaves it. Each input
  reports focus through a `TextInputFocused` predicate: the PID/TID picker
  filter (focused by default, blurred by Up/Down, re-focused by the next
  printable key), the trace-filter modal (only while a field is being edited,
  not while navigating), the record modal path, the probes modal search line,
  and on the dashboard (aggregated by `dashboard.Model.TextInputFocused` via
  `tabDescriptor.TextInputFocused`) the flame `/` search and the stream search
  and export-filename modals. A new text input must add its predicate there or
  `q`/`H` will again be eaten as commands. Because plain `r` is filter text
  while the picker input is focused, the picker footer and help show
  `ctrl+r refresh` in that state and `r refresh` once the input is blurred.
  Pinned by `internal/tui/textinput_keys_test.go` (one test per input, each
  asserting both "no quit/help" and "the typed text reached the input",
  the TID picker, modified-key negatives, ctrl+r and the attaching guard) and
  `TestFooterAdvertisesTheRefreshKeyThatWorksInEachFocusState`.

  **A bracketed paste reaches every text input** (task 4r2). bubbletea v2
  enables bracketed paste by default, so a terminal paste is one `tea.PasteMsg`,
  not a run of key presses, and every layer between `Model.Update` and the
  `textinput` has to forward it or it vanishes without a trace (pasting
  `/var/log/messages` into the filter File field applied nothing). The routes:
  the filter modal's `Update` (only while a field is being edited), the probes
  modal's `Update` (only while the search line is open), the flamegraph's
  `Update` (only while `/` search is active), `dashboard.Model.handlePaste` ->
  `tabDescriptor.HandlePaste` (gated by `TextInputFocused`) -> the flame model or
  `eventstream.Model.HandlePaste` (the stream's keys are key *names*, so the
  search/export modals get a separate entry point), and the PID/TID picker,
  where a paste focuses a blurred input like a printable key. With no input open
  a paste is dropped, never replayed as commands (`c`, `q`, `7`, `/` would
  otherwise clear filters, quit or switch tabs). `Model.Update` also drops it
  while the shutdown/attaching screen, the error view or the help overlay covers
  the screens (`textlessViewCovers`, the non-modal half of `overlayCoversScreen`), so a modal hidden underneath cannot be filled
  unseen, and `updateDashboardForModal` does not hand a paste to the dashboard
  behind a modal (`TestPasteWhileModalCoversFocusedDashboardInputIsNotForwarded`;
  `textlessViewCovers` and `modalVisible` are the two halves of
  `overlayCoversScreen`, pinned by `TestOverlayPredicatesCoverEveryOverlayState`).
  Known cosmetic limit: while a text input is being edited it shows a pasted
  bidi override (U+202E), zero-width character or blank-rendering space
  lookalike (NBSP, U+3000, U+2800, ...) as is. Bubbles v2.0.0
  `internal/runeutil` (what `textinput` uses on typed and pasted runes) drops
  exactly the runes `unicode.IsControl` reports and U+FFFD (`utf8.RuneError`),
  and replaces each tab, CR and LF with one space (`textinput` configures
  `ReplaceTabs(" ")` and `ReplaceNewlines(" ")`); everything else, including
  Cf format runes (bidi, zero-width) and Zs spaces, is kept. Every editing view
  renders `textinput.View()` unsanitised (PID picker, filter modal while a field is edited, flamegraph `/`
  search bar, probes search, stream search/export modals, recording modal), so
  that is the documented limit. Once the text is committed and shown somewhere
  else it is rendered through `common.Sanitize`: the filter modal's fields, the
  flamegraph toolbar, status-bar `filter:` query and the `Filter "..."` status
  line / no-match placeholder (`%q` alone prints U+2800 and U+FFFC raw), the
  stream search status and filter summary, and the probes modal's `Filter:`
  header (task ms2). The stored value stays raw for matching and only the
  display is made safe.
  A new text input must accept `tea.PasteMsg` as well as keys.
  Pinned by `internal/tui/paste_test.go` and the per-package `*Paste*` tests.

  **Every textinput is fed through `common.UpdateTextInput`** (task kz2,
  `internal/tui/common/textinput.go`), never `textinput.Model.Update`
  directly. bubbles' `textinput.deleteWordForward` (v2.0.0, still in v2.2.1,
  so a version bump does not help) steps past the last rune and reads one
  past the value: Alt+D / Alt+Delete with the cursor on the last rune
  panicked the whole TUI in the PID picker, flame search, probes search,
  record modal, filter modal and (until 9z2) the stream search/export
  modals. `UpdateTextInput` turns exactly that press into a plain Delete,
  which removes the same rune (also for masked inputs, where bubbles
  deletes after the cursor); every other cursor position and message passes
  through. Pinned by `common/textinput_test.go` (values, wide runes, masked,
  negative controls, and `TestBubblesDeleteWordForwardStillPanicsOnTheLastRune`,
  which fails once an upgraded bubbles fixes the bug so the guard can go),
  `internal/tui/textinput_deleteword_test.go` (every host end to end through
  `Model.Update`) and `common/textinput_hosts_test.go`, a type-checked scan
  of `internal/tui` (each package type-checked from source against the
  export data of `go list -export`) that fails when a non-test file uses
  the `Update` method of `textinput.Model` outside the allow-list
  (`common/textinput.go` only). It resolves the method itself, so any
  expression of type `textinput.Model` or `*textinput.Model` is caught:
  fields, pointer fields, parameters, locals and copies, slice/map
  elements, getter results, embedded fields, method values and method
  expressions. Only dynamic dispatch (an interface value holding the
  input, reflection) gets past it.

  **The stream search/export modals get the real key press** (task 9z2).
  `eventstream.Model.HandleTeaKey` hands an open modal the `tea.KeyPressMsg`
  itself instead of round-tripping it through its name, and the `textinput`
  types only the press's `Text`. The old route went through `HandleKey(name)`,
  whose `keyMsgFromString` knew six names and made every other one a press
  with `Text` set to the name. Bound names (Ctrl+A/E/B/F/H/D/K/U/W, Home/End,
  Alt+B/F/D/Backspace/Delete, Ctrl+V) still acted as keys that way, because
  bubbles' `key.Matches` compares `msg.String()`, which returns the `Text`.
  What changed: unbound keys (Ctrl+X, Alt+X, Insert, PgUp, Shift+Tab) are no
  longer typed as their names, and Ctrl/Alt+Left/Right now move by word
  (`HandleTeaKey`'s switch used to send them to `HandleKey("left"/"right")`,
  dropping the modifier). `HandleKey(name)` stays for name-driven callers and
  tests: `keyMsgFromString` (`modalkeys.go`) maps the fifteen named keys the
  stream uses plus the `pgdn`/`pagedown`/`pageup` aliases, with modifier
  prefixes, and reports anything else (`f13`, which it leaves out, or `abc`)
  as no key, which an open modal consumes and ignores. Alt+D/Alt+Delete on the
  last rune already panicked in both modals before task 9z2 (bubbles v2.0.0
  `deleteWordForward` indexes past the value); their `Update` now turns it
  into Delete there (`common.UpdateTextInput`, which since task kz2 guards
  every textinput, see above). Pinned by `eventstream/modalkeys_test.go`
  (both modals, both entry points; comments mark which cases pin changed
  behaviour) and
  `dashboard/streammodalkeys_test.go` (end to end through `dashboard.Update`
  with presses built as Bubble Tea delivers them).
- **The stream's FD-trace overlay (`T`) owns the keyboard like its two modals** (task 3r2).
  `eventstream.Model.FDTraceVisible` joins `ExportModalVisible`/`SearchModalVisible` in the
  Stream tab's `BlocksGlobalShortcut`, so `q` (and `ctrl+c`) is re-routed as Esc and closes
  the overlay instead of starting the shutdown, and the `tui.go` dashboard shortcuts
  (`f`, `R`, `o`, ...) stay inert behind it. `handleFDTraceKey` consumes every key for the same
  reason: an unhandled key used to fall through to the dashboard's tab/view/reset shortcuts.
  The overlay has no text input, so a paste is dropped. Any new stream overlay must add its
  predicate there. Pinned by `TestQClosesTheFDTraceOverlayInsteadOfQuitting`,
  `TestFDTraceOverlayBlocksGlobalShortcuts` (`internal/tui/textinput_keys_test.go`) and
  `TestFDTraceOverlayConsumesEveryKey` (`internal/tui/eventstream/model_test.go`).
- **The PID/TID picker selection follows the process, not the row number**
  (`pidpicker.Model.applyFilter` -> `relocateSelection`): a rescan or a typed
  filter reorders rows, so the selected pid (tid in TID mode) is looked up again
  in the rebuilt list. If it vanished (exited, or no longer matches the filter)
  the PID picker enters `noSelection`: no row is highlighted, a one-line notice
  (`pid 30 exited - pick a process`) is shown and Enter is a no-op, because the
  fallback All row means a system-wide trace (`selectedPIDFilter(0) == -1`) and a
  reflexive Enter must not start one unexplained. The state is sticky across
  rescans and edits until Up/Down moves the selection (either key lands on the
  All row, so tracing everything stays one deliberate keypress away). The TID
  picker keeps the plain fallback to "All TIDs", which stays inside the process.
  Pinned by `internal/tui/pidpicker/selection_test.go`.
  A selection the user has not made is derived from the filter instead (task
  hs2, `selection.go`: `Model.implicit`, `followFilter`): no filter text selects
  the All row (a bare Enter still means all PIDs), a filter with matches selects
  the first match, so typing `mysql` and pressing Enter picks that process
  rather than the whole system, and a filter without a match selects nothing
  (the `noSelection` state with a "no process matches the filter" notice,
  "thread" in the TID picker; Enter is a no-op in both). That notice stays
  hidden while an empty list does not mean "no match": before the first scan
  result is in (it only means "not loaded yet") and after a failed scan (the
  scan error line explains it). The derived state is recomputed on every edit of
  the text and every rescan, so backspacing to an empty filter returns to All. A
  derived process row keeps its pid across a rescan (`applyScan`,
  `keepDerivedProcess`): a new process sorting ahead does not take over, and if
  the highlighted first match left the list the next match is selected with a
  notice that names both and the reason (`pid 30 exited - selected pid 40
  instead`, or `pid 30 no longer matches the filter - ...` when the process
  still runs; `tid` in the TID picker) instead of silently. A failed scan
  empties the list, and what that does depends on the selection
  (`TestFailedScanOutcomeDependsOnTheSelection`). A selection derived from a
  non-empty filter ends up with nothing selected (`followFilter`'s no-match
  branch, Enter a no-op, only the scan error shown, no notice), and a derived
  pid is held (`heldPid`) for the next successful scan, which keeps it or
  announces the move the same way; a real edit of the filter text drops the held
  pid. A derived All row (empty filter) and an All row the user moved onto stay
  highlighted, so Enter still traces all PIDs (all TIDs of the process in the
  TID picker); a thread the user picked in the TID picker falls back to All
  TIDs, and a process the user picked in the PID picker is lost like one that
  exited (`noSelection` with the lost-selection notice). Up/Down hands the
  selection to the user (a process row then follows the process as above); a
  user who moved back onto the All row and then edits the filter text gets it
  handed back to the filter, so typing a filter with a match highlights that
  match even after Up. Enter right after typing still means All in two cases: a
  whitespace-only filter, which trims to an empty query and so derives the All
  row (`TestWhitespaceOnlyFilterKeepsAllRow`), and, in the TID picker, a thread
  the user moved onto that the typed character hides, which falls back to the
  user-owned All TIDs row (it stays within the process). Only a change of the
  text counts (`editFilter` compares the value and rebuilds nothing otherwise):
  cursor keys, an empty paste or any other message that reaches the focused
  input leave the selection alone, so a derived pid tracked across a rescan is
  not reset to row 1 by an unrelated key. The same keeps the All TIDs row of
  that TID fallback (it is not swapped for another thread; the next real edit
  hands it to the filter). Startup is unaffected: `-pid`/`-tid` skip the picker
  (task ur2), and the picker's `PidSelectedMsg` still replaces any startup tid.
  Pinned by `internal/tui/pidpicker/filterselect_test.go` and, as a seeded
  randomized comparison with an independent reference model in both PID and TID
  mode (Enter emits exactly the highlighted row's message, the All message only
  for the All row, nothing without a selection; the notice line matches word for
  word), `internal/tui/pidpicker/selection_model_test.go`.
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
  `ring buffer drops: N (N/s, N% of events)`. The same block also reports
  `group-dead exits: N` (whole-process `sched_process_exit` records, counted
  once per process death: repeats of a pid within 100ms are suppressed, see the
  fd-table notes below); the thread-exit integration tests assert both lines
  through the harness's `OutputCapture`, the drop line being `0`.

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
  of `-trace-*` selection. Control records never become rows themselves (the
  exec record may complete an untraced-exit execve pair, see *Non-leader
  exec*); they refresh the cache (`handleProcessExecEvent`), and because the
  ring buffer preserves reservation order and the event loop has a single
  consumer goroutine, the refresh lands before the new program's first syscall
  pair — **for every record that is actually delivered**. Two residual paths are handled explicitly:
  - *Lost record.* Under backpressure `bpf_ringbuf_reserve()` fails and the
    control record is never emitted (counted in `ringbuf_drop_map`). The
    payload comm of an open or exec enter heals a tid that opens or execs
    (`seedCommFromEnterPayload`, applied before the raw `-comm` gate so even a
    dropped open refreshes the cache), but a tid that only reads and writes has
    no such record to heal it. A non-zero drop delta
    therefore flags the whole comm cache stale (`markAllStale`, requested by the
    drop monitor goroutine and applied by the event-loop goroutine in
    `applyPendingCommRefresh`). A stale entry keeps serving its current value
    and triggers one asynchronous procfs re-read on next use — that read happens
    after the exec, so it heals the label. Evicting instead would blank the comm
    column and, under `-comm`, drop the tid's rows at the exit-side comm check.
  - *Non-leader exec.* An `execve` by a thread other than the leader enters
    under the caller's tid but returns under the leader's (`de_thread`). The
    record carries the pre-exec tid (`old_tid`); the BPF handler moves the
    in-flight `syscall_enter_state_map` entry to the new tid
    (`ior_on_exec_tid_change` in `filter.c`), and userspace re-keys the parked
    execve enter and its gap baseline the same way (`rekeyExecCaller`, gap
    baselines are keyed by the exit's tid), so the execve row is emitted with
    the caller's tid and nothing leaks under the vanished one. If the record
    is lost after the BPF move, a successful execve exit under `tid == pid`
    with no enter of its own adopts the process's parked non-leader exec
    enter (`adoptLostExecCaller`, via the pair tracker's per-pid
    `execCallers` index). Integration test: `TestNonLeaderExecIsPaired`
    (scenario `exec-non-leader-thread`).
    Under `-tid <that non-leader>` the post-exec (leader) tid is filtered, so
    the execve's exit never reaches userspace. The exec record is still
    emitted for the traced caller (`ior_exec_record_scope` in `exec.c`:
    `old_pid == TID_FILTER`, `PID_FILTER` still applies, ior excluded) and
    flagged `exit_untraced`; userspace evicts the FD_CLOEXEC descriptors and
    completes the parked enter from the record (`completeUntracedExec`: ret
    0, duration ending at `sched_process_exec`). **`-tid` tracing of that
    thread ends at the exec**: `TID_FILTER` is a load-time constant and
    following the renumbered task would cost a map lookup in `filter()` for
    every rejected event. Residual gap: if that flagged record is lost to
    ring-buffer backpressure, the BPF enter state is already gone and no exit
    ever arrives, so `adoptLostExecCaller` has nothing to adopt from and the
    execve row (at rate `N` also its count) is lost; only `ringbuf_drop_map`
    shows it, and the parked enter ages out of the LRU. Integration test:
    `TestNonLeaderExecUnderTidFilterIsCompleted` (scenario
    `exec-non-leader-thread-tid`, which parks the exec thread in a prestart
    hook so its tid is known before ior starts).
  - *Late lookup worker.* A resolver worker that read `/proc/<tid>/comm` before
    the exec could otherwise overwrite the authoritative post-exec name. Each
    cache entry carries an exec epoch, bumped by `handleProcessExecEvent`; a
    worker samples it before its procfs read and its result is discarded when
    the epoch moved on. Both writes are mutex-protected, so this is a logical
    race the race detector cannot see.

  **A new task is named by a record, not looked up (task fr2).** The exec
  record renames an existing tid; nothing named a *new* one, so its comm came
  from the same asynchronous procfs read and lost the race against short-lived
  tasks: a thread that exited before the lookup ran has no `/proc/<tid>` and
  every row it produced carried an empty comm, the first rows of a thread that
  lives on did too, and under `-comm` a tid with no cached comm has an empty
  comm at the exit-side filter, which matches no ordinary pattern (only `^$`,
  `^` and `$` match an empty comm), so those rows were dropped silently (0 of
  200 in the report). The hand-written `task:task_newtask` handler in `internal/c/exec.c` (`handle_task_newtask`, attached by
  `attachTaskNewtaskProbe` next to the exec and exit probes, before the syscall
  tracepoints, regardless of `-trace-*`) emits a 56-byte `TASK_NEWTASK_EVENT`
  control record from the creator's context, before the child is first woken:
  child tgid, child tid, the inherited comm, the raw `clone_flags` and the
  creator's tgid (`creator_pid`; a legacy 48-byte record of an older
  `IOR_BPF_OBJECT` decodes with `CreatorPid` 0 = unknown).
  `handleTaskNewtaskEvent` (`internal/eventloop_newtask.go`) seeds the comm in
  ring-buffer order before the child's first pair, as a *provisional* name
  (`setCachedProvisional`): the inherited name is the creator's, and a new
  thread often renames itself at once (`prctl(PR_SET_NAME)`,
  `pthread_setname_np`: tokio, Java, Chrome, Bun pools), which the
  `task:task_rename` record (task lr2, below) reports. A provisional entry does
  not bump the tid's rename epoch and is flagged stale (unless rename records are
  trusted, task xr2 below), so the first use of the
  tid queues exactly one
  `/proc/<tid>/comm` read whose result replaces it (a read of an already-gone
  thread comes back empty and leaves the seed). Seeding as authoritative
  (`setCachedCommFromKernel`, which bumps the epoch and so discards later procfs
  results) pinned the parent's name on renamed threads for good and hid their
  rows from `-comm <renamed>`; exec and open records are still authoritative
  and outrank an in-flight read. Rows emitted before that read lands carry the
  inherited name (and are matched against it under `-comm`), as the first rows
  did before any name was known (the `task_rename` record normally makes even
  those rows right). The record also retires the per-tid state of a dead
  previous owner whose exit record was lost (`retireRecycledTid`: cached comm
  and in-flight lookup, parked enter, `-gap` baseline, pending
  name_to_handle_at path), the same set the exit record clears. The child's
  tgid is derived (`CLONE_THREAD` -> the creator's tgid, else the child's tid)
  rather than read from the task struct, and the record is scoped like
  `filter()` but applied to the *child* (`ior_task_in_scope`): a thread of a
  `-pid` target is in scope, its `fork()` child is not, ior's own threads are
  excluded. A fork that execs is renamed by the exec record that follows. A lost
  record (`ringbuf_drop_map`), a failed attach or an older `IOR_BPF_OBJECT`
  without the program degrade to the old procfs lookup.

  **The corrective read is skipped when renames are reported (task xr2).**
  Under thread churn that one read per new thread was nearly all of the
  resolver's work (300 threads/s: 4375 `/proc/<tid>/comm` reads in 15s, 99%
  ENOENT because the thread had exited, each followed by a `/proc/<tid>/exe`
  readlink failing the same way). The seed is now flagged stale only when a
  rename could go unreported (`eventLoop.provisionalSeedNeedsRecheck`): when
  the `task_rename` probe attached *and* the drop counter is monitored
  (`dropSrc`), a rename normally arrives as a record or its loss shows up as a
  drop whose `markAllStale` sweep flags the seed. Trace setup learns the attach
  through `bpfSetupLog.attached` (`attachHandProbe` announces every sched probe
  that attached; `renameAttachRecorder` keeps only `task_rename`) and hands it
  to `eventLoop.trustRenameRecords` after the event-loop factory (which wires
  `dropSrc`) and before the start signal
  (`TestRunTraceSetupTrustsRenameRecordsBeforeTheStart`,
  `TestRenameAttachRecorderNotesOnlyTheRenameProbe`,
  `TestTraceSetupCarriesTheRenameAttachToTheLoop`). Two cases keep the read
  anyway. While the drop counter's latest read failed (`ringbufDropReadFailed`)
  a lost rename would not show up as a drop, so trust is suspended until a read
  succeeds (a one-off failure is harmless: the counter is cumulative, so the
  next poll still reports and stamps the drops). And the sweep reaches only
  entries that exist when the loop applies it, but the loop consumes a backlog,
  so a newtask record reserved before a reported drop can be seeded *after* the
  sweep while the lost record was a rename of that thread.
  `requestCommSweepAfterDrop` therefore stamps `lastDropSeenBootNs`
  (CLOCK_BOOTTIME, the clock of `bpf_ktime_get_boot_ns`, read after the
  counter) *before* raising `commRefreshPending`
  (`TestDropStampIsStoredBeforeTheSweepIsRequested`; the other order lets the
  loop sweep and then seed such a record against the old stamp), and a seed
  whose record time is not newer keeps its read. **Not covered** (each wrong
  name stays until the thread execs, renames again or makes an open/exec
  syscall whose payload comm contradicts the cache): two microsecond-wide windows in
  `copy_process` - a third thread writing the child's `/proc/<tid>/comm`
  between `attach_pid` and `trace_task_newtask` (its rename record precedes the
  newtask record, whose seed then overwrites the newer name with the
  creator's), or a sibling renaming the creator between `dup_task_struct` and
  the tracepoint (the record carries a name the child never had). A rename record `handle_task_rename` cannot read the name of is counted as a ring-buffer drop (task mz2), so the drop sweep covers it. Kernel-sourced comm writes (rename and exec records, open/exec enter payloads) from a record no newer than the last drop stamp (`lastDropSeenBootNs`) leave the entry stale (`setCachedCommFromKernel`, `seedCommFromEnterPayload`, task lz2): such a record was reserved before the drop but consumed from the backlog after the sweep, which only flagged the entries that existed then, so without the flag the record the drop lost could never be healed. Before xr2
  the corrective read healed both windows. `resolveCommFromProcWithError`
  returns at once on ENOENT/ESRCH instead of trying the exe fallback
  (`TestResolveCommOfAGoneTaskSkipsTheExeFallback`, over a fake procfs root
  through `resolveCommFromProcRoot`). Negative-caching ENOENT per tid was
  measured and not needed: no tid was looked up twice. Benchmarks:
  `BenchmarkThreadChurnCommLookups` (~16.5k -> ~6.1k CPU ns and 1 -> 0 lookups
  per thread) and `BenchmarkResolveCommOfGoneTid`
  (`internal/eventloop_commchurn_bench_test.go`); tests in
  `internal/eventloop_newtask_recheck_test.go` and
  `internal/eventloop_newtask_trust_test.go`.

  **A rename is reported by a record too (task lr2).** Nothing reported a task
  changing its own name: `prctl(PR_SET_NAME)` and `pthread_setname_np` (a write to
  `/proc/self/task/<tid>/comm`, also possible from a sibling thread) change
  `task->comm` with no syscall record, exec record or open payload to say so, so
  the cache kept serving the old name until an `openat` of that thread happened to
  heal it. Every later row carried the wrong comm and `-comm` inverted:
  `-comm <new>` dropped the renamed thread's rows, `-comm <old>` kept admitting
  them, and an `openat` dropped at the enter-side gate could not heal the cache
  either (the next `close` row was `E:name`). The hand-written
  `task_rename` handler in `internal/c/exec.c` (`handle_task_rename`, attached by
  `attachTaskRenameProbe` with the other sched probes, regardless of `-trace-*`)
  emits a 40-byte `TASK_RENAME_EVENT` control record (renamed task's tgid and
  tid, the new comm) for every `__set_task_comm()` - including the exec's own
  rename, which merely repeats the exec record's name. `handleTaskRenameEvent`
  (`internal/eventloop_taskrename.go`) writes it through
  `setCachedCommFromKernel`: authoritative, so an in-flight procfs lookup that
  read the old name cannot undo it, and it settles a provisional newtask seed
  (the corrective `/proc` read becomes unnecessary). The record is ordered with
  the task's syscall records, but a row is labelled when it is *paired*, so what
  it carries depends on the kind. Most kinds take the label at the syscall's
  exit (`e.comm(tid)`): a syscall that entered before a sibling's rename and
  exits after it is labelled with the NEW name (the `prctl` row itself pairs
  after the record and carries the new one too). The open kinds and `execve`
  carry the kernel comm of their ENTER record (`ep.Comm = openEv.Comm`), so an
  `open` that entered before the rename keeps the old name on its own row even
  when it exits after it. The *cache* is always the newest name in ring order:
  the payload comm of an open/exec enter is applied when the enter is consumed
  (`seedCommFromEnterPayload`, before the raw `-comm` gate), not at the exit,
  because an exit-time write restored the pre-rename payload over a rename that
  landed in between (a thread blocked in `open(fifo)` renamed by a sibling, task
  lr2 review: its later `pwrite64`/`close` rows kept the old name). That write
  (`commResolver.setCachedFromEnterPayload`) is authoritative like the others
  (it bumps the epoch), but it leaves the entry stale, so the tid's next use
  queues one `/proc/<tid>/comm` re-read, in two cases. An *exec* enter names the
  program that is about to be replaced: the `task_rename`/exec records that
  follow clear the flag again, and without them (probes not attached, an older
  `IOR_BPF_OBJECT`, both records lost) the re-read is the only thing that learns
  the new program's name; clearing the flag there turned a fork child's
  provisional parent name final when its first syscall was `execve` (a failed
  `execve` pays one redundant read). A payload that *contradicts* the cached
  name is re-checked too: usually the cache was wrong (a lost record), but it
  also mitigates a narrow sibling-rename race. `__set_task_comm()` fires
  `task_rename` *before* it stores the new name, so a sibling's
  `/proc/<tid>/comm` write (`pthread_setname_np`) racing with the renamed
  thread's `openat` enter on another CPU can put the old name in a payload
  behind the rename record; the re-read heals it on the next use instead of the
  old name sticking until the next open or rename (the row labelled in between
  still carries the old name; a self-rename via `prctl` cannot race this way;
  documented next to `handle_task_rename` in `exec.c`). A matching payload, the
  common case, costs nothing, and so does an open payload for a tid with no
  cached entry, which contradicts nothing
  (`TestOpenPayloadWithoutACachedEntryQueuesNoRead`). A rename *to the same
  name* just rewrites the same cache entry (and bumps its epoch, discarding an
  in-flight procfs read); an empty name (`prctl(PR_SET_NAME, "")` stores an
  empty comm) is ignored and keeps the cached name, because an empty label is
  indistinguishable from "not resolved yet".
  Two details differ from the other hand-written handlers. It is a **raw**
  tracepoint (`SEC("raw_tracepoint/task_rename")`, attached through
  `probemanager.RawTracepointProgram`, a separate interface so the syscall probe
  manager's `Program` stays small): the classic tracepoint's context holds the new
  name in a `char newcomm[16]` member, and copying a context array needs the ctx
  pointer arithmetic the 4.18/5.14 verifiers reject (one rejected program fails
  the whole object, as for `task_newtask`); the raw arguments (task, comm
  pointer) are plain u64 loads at offsets 0 and 8, and the name is read from the
  kernel buffer with `bpf_probe_read_kernel_str`. It cannot use
  `bpf_get_current_comm` instead: the tracepoint fires *before* the kernel stores
  the name, and the renamed task need not be the current one. Scope is therefore
  judged on the renamed task's own tgid and tid (read from the task struct),
  with the same predicate as the newtask handler (`ior_task_in_scope`). A failed
  name read drops the record (`bpf_ringbuf_discard`) rather than sending an
  unterminated string. A lost record (`ringbuf_drop_map`), a failed attach or an
  older `IOR_BPF_OBJECT` degrade to the old behaviour (stale name until another
  record corrects it). Pinned by the `TestTaskRename*`,
  `TestRenamedTaskWithoutARecord*` and `TestMalformedTaskRenameRecord*` tests
  (`internal/eventloop_taskrename_test.go`, with the negative fixture without a
  record), `TestSameNameRenameKeepsTheLabelAndQueuesNoRead` and the
  enter/rename/exit ordering tests of
  `internal/eventloop_taskrename_race_test.go` (`TestOpenPayloadComm*`,
  `TestFailedExecComm*`, `TestFilteredOutOpenStillSeedsTheCache`, each with its
  no-rename control), the stale-payload tests
  `TestExecEnterKeepsTheInheritedSeedCorrectable` and
  `TestContradictingOpenPayloadIsRecheckedAgainstProcfs` (with their no-read
  controls `TestExecRecordsMakeTheExecEnterRecheckUnnecessary` and
  `TestMatchingOpenPayloadQueuesNoRead`), the attach tests in
  `internal/ior_bpfsetup_execprobe_test.go`, the
  decoder layout test, the buildgate test that the handler has no ctx
  relocation, `TestTaskRenameHandlerChecksTheScopeBeforeEmitting` (the compiled
  handler reads `IOR_PID_FILTER`/`PID_FILTER`/`TID_FILTER` before it reserves
  ring-buffer space: `if (0)` in place of `ior_task_in_scope` fails it), and end
  to end by `TestRenamedTasksAreRelabelledByTheRenameRecord` and the two `-comm`
  tests in `integrationtests/taskrename_test.go` (scenario
  `thread-comm-late-rename`: the main thread and workers renamed by
  `prctl`, by a write to their own procfs comm and by a write from another
  thread) and `TestRenameBetweenOpenEnterAndExitIsNotUndone` (scenario
  `thread-comm-rename-in-open`: a worker blocked in `open(fifo)` renamed by a
  sibling; its later `pwrite64` and `close` rows must carry the new name).

  **A forked child inherits its creator's fd-table entries (task gr2).** The fd
  table is keyed by tgid and nothing modelled fork, so a new process started
  with no entries and every descriptor it inherited fell back to
  `/proc/<pid>/fd`, which renames it (`pipe:0:3:4` -> `pipe:[N]`,
  `memfd:name` -> `/memfd:name (deleted)`, `eventfd:0` ->
  `anon_inode:[eventfd]`) and, once the child was gone before the lazy read, to
  `E:name`; a child's `dup2` of an inherited fd then copied a procfs answer.
  `handleTaskNewtaskEvent` now calls `inheritFdTable`
  (`internal/eventloop_newtask.go`) from the record's flags: `CLONE_THREAD`
  does nothing (the thread already uses the creator's tgid entries);
  a new process without `CLONE_FILES` (fork, vfork, posix_spawn, plain clone)
  gets a copy of the creator's fd-table entries *and* procfs-cache entries
  (`fdTracker.inherit`: one `FdFile.Dup` per descriptor, so FD_CLOEXEC stays per
  table while the status word is shared with the parent's entry through the
  open-file-description object, as the kernel's fork shares it (task nr2, below);
  the copy is a snapshot of the table, what the parent closes or reopens after
  the fork does not reach the child). **The copy is bounded**: a parent tracking more than
  `maxInheritedEntries` (128) fd-table plus cache entries passes none on, and a
  copy that would not fit in ior's own tracker maps (`filesLimit`/`cacheLimit`,
  `inheritFits`; not the traced process's fd table) is skipped too (the child
  then resolves through procfs, as before gr2; `fdTracker.inheritSkipped`
  counts them, together with the same skip when an exec or
  `CLOSE_RANGE_UNSHARE` leaves a shared table (`copyTable`), and a non-zero
  count is printed in the end-of-run `Statistics:` block as `fd-table copies
  skipped: N (source table over 128 entries or no room in ior's fd tracker;
  descriptors resolved through procfs)`, hidden at 0 like `rows lost`/`records
  discarded at stop` (task ss2, `eventLoop.fdCopySkipStatLine`,
  `internal/eventloop_fdcopyskip_stats_test.go`); it explains rows of a child
  that show the procfs spelling of an inherited descriptor). Reason: the copy
  is O(entries) per fork on
  the one event-loop goroutine plus the same again at the child's exit
  (`BenchmarkForkStorm`: 1.2 us for 8 entries, 11 us for 64, 28 us for 128, and
  0.27 ms for 1024, 3.7-7.8 ms for 8192 before the cap, i.e. half a core for a
  1000-fd parent forking 1000/s), and unbounded copies of live children filled
  the 32768-entry table and evicted the parent's own entries. A fork never
  prunes the LRU (it skips instead of overflowing the cap) and the copies are
  stamped with age 0, the oldest: they are the first to go when any later
  insertion prunes, and the child's own lookups stamp what it really uses. A lazy
  per-fd copy was rejected: O(1) per fork, but keeping the snapshot semantic
  when the parent closes or reopens a descriptor after the fork needs
  copy-on-write on the parent's side, which is unbounded again.
  A `CLONE_FILES` process gets *no* snapshot but the creator's very table
  (task hr2, below): a copy would go stale on the first open/close of either
  side. In every non-thread case the entries under the child's tgid are dropped
  first: a new process's tgid is fresh, so they belong to a previous owner whose
  exit record was lost. A fork+exec child then loses the close-on-exec entries
  through the ordinary exec record (`dropOnExec`). A record without a creator
  (legacy object), a lost record or a fork child out of scope (`-pid`
  children) leave the child's table empty as before. The inherited copy is only as good as the
  creator's table: entries the trace never saw (a `-path`/`-comm` run drops
  non-matching opens at enter) stay on the procfs path. Pinned by
  `internal/eventloop_newtask_fdinherit_test.go` (including a real child process
  against real procfs) and end to end by
  `TestForkedChildReadsInheritedPipeUnderItsTracedName` (scenario
  `fork-inherit-fds`, a raw `fork(2)` child reading an inherited pipe end: the
  row says `pipe:<flags>:<r>:<w>`, the pre-fix procfs spelling was `pipe:[N]`).
  The fork child is out of scope under `-pid`, so that test uses
  `TestHarness.RunSystemWideWithIorArgs` (no `-pid`, narrowed by `-comm`; ior
  then lasts the full `-duration`, so pass a short one). A system-wide run also
  sees other `ioworkload` processes (a parallel test), so the assertion only
  counts rows of this test's own child: the scenario writes the child's pid to
  `$IOR_WORKLOAD_CHILD_PID_FILE`.

  **Duplicated descriptors share one open file description (task nr2).** The
  kernel keeps the status word (access mode, `O_APPEND`, `O_NONBLOCK`, ...) in
  the open file description that `dup`, `dup2`, `dup3`,
  `fcntl(F_DUPFD*)` and `fork` share between descriptors, and `FD_CLOEXEC` in the
  descriptor itself; a second `open()` of the same path is a new description.
  The model's shared word is that status word *as `open()` reported it* and
  `F_SETFL` updated it since: it still carries `O_CREAT`/`O_TRUNC`/`O_EXCL`/
  `O_NOCTTY` from `open()`'s arguments, which the kernel drops from `f_flags`
  (its `F_GETFL` returns e.g. `0106001`, without `O_CREAT|O_TRUNC`), until an
  `F_GETFL` replaces the whole word with the kernel's, for every duplicate.
  `FdFile` mirrors that split (`internal/file/fdfile_desc.go`): the status word
  is a `*openFileDesc` (no `O_CLOEXEC` bit in it), `closeOnExec`/`closeOnExecKnown`
  and the number and name are per `FdFile`, and `Flags()` folds the descriptor's
  `FD_CLOEXEC` into the shared word for display. `FdFile.Dup` creates a second
  descriptor on the *same* description (used by `registerDup`, the fork copy and
  `copyTable`); `FdFile.Detach` makes an independent snapshot that shares
  nothing (used by `freezePairForEmission` for every emitted row and by
  `snapshotExecTarget`, because a row must keep the flags of its moment while the
  live table entry moves on). Before nr2 `Dup` copied the flag word, so an
  `fcntl(dup, F_SETFL, O_APPEND|O_NONBLOCK)` updated one table entry and the
  original kept reporting `O_WRONLY|O_CREAT|O_TRUNC` (open()'s word; the kernel's
  `F_GETFL`: `0106001`), and a
  later `dup(orig)` started from the stale word even after `F_GETFL` refreshed
  the original. Rule for new code: change a status flag through
  `SetStatusFlags`/`MergeFlags`/`AddFlags` on the descriptor the syscall named
  (the change is then seen by every duplicate); never copy a flag word between
  `FdFile`s by hand and never hold a live table entry on an emitted pair. A
  `Dup` or `Detach` is one allocation (`FdFile` and its description share an
  object, pinned by `TestFdFileDetachAndConstructorsAllocateOnce`). Not modelled:
  descriptors that share a description through a transfer ior does not
  model as a dup (`SCM_RIGHTS`, `pidfd_getfd`, which registers nothing) are
  resolved per descriptor through procfs, so each carries its own word until
  procfs or `F_GETFL` re-reads it. Pinned by
  `internal/eventloop_ofdshare_test.go` (every dup variant, both directions, dup
  of a dup, cleared flags, `F_GETFL` refresh incl. later dups, independent opens
  and `FD_CLOEXEC` per descriptor as negative controls, close of one leaves the
  other, emitted rows keep their moment, fork), by
  `internal/eventloop_ofdshare_boundary_test.go` (a fork-inherited
  *procfs-cache-only* descriptor shares its word with the child's copy, with an
  independent description as negative control; and a `-race` test that an emitted
  row's `File` can be read and `Dup`ed from another goroutine while the loop
  does `F_SETFL`/`F_SETFD`/`dup` on the live table, which fails with a DATA RACE
  if `freezePairForEmission` stops calling `Detach`) and the `TestFdFile*` tests
  in `internal/file/file_test.go`.

  **`CLONE_FILES` processes share one fd table (task hr2).** The kernel gives two
  processes that `clone(CLONE_FILES)` a single descriptor table, so what one
  closes, opens or `dup2()`s changes what the other's numbers mean; a per-tgid
  table kept answering with the old name (a read of fd 3 labelled
  `/etc/hostname` while the kernel had pointed it at `/etc/os-release`).
  `fdTracker` now translates every pid to a *table id* first (`tableID`,
  `internal/eventloop_fdshare.go`; the map is empty for an ordinary trace, so
  the cost is one length check per lookup): an in-scope `CLONE_FILES` child is
  pointed at its creator's table by `shareTable`, so both tgids read and write
  the same entries (they count once toward the table caps); procfs reads still
  use the real pid. A member leaves the sharing by `exec` (the kernel copies the
  table before closing close-on-exec descriptors: `dropOnExec` calls
  `detachShared`, which hands the exec'ing process a bounded private copy,
  `copyTable`), by `close_range(CLOSE_RANGE_UNSHARE)` (`unshareFiles`, same copy, before the range
  is applied; **only for a thread-group leader**: the kernel privatises just the
  calling *thread's* table, so a worker thread's call leaves the tgid's table
  exactly as it is - no detach, no range applied, no un-blind - and a leader is
  taken to be alone, which the event stream cannot prove) and by exit (`deletePid`: a table others still share outlives its
  holder and is re-keyed onto the smallest sharer, `handOverTable`, so no table
  id dangles on a tgid the kernel may reuse). **A `CLONE_FILES` child that is out
  of scope** (`-pid`/`-tid` names the creator): the filter hides every syscall
  of the child, so nothing says what it does to the creator's table. The BPF
  handler therefore emits the one record an out-of-scope task ever produces, for
  a `CLONE_FILES` *process* child of an in-scope creator, flagged by
  `IOR_NEWTASK_CHILD_OUT_OF_SCOPE` in the record's `scope_flags` word (formerly
  the always-zero reserved word, so an older object reads "in scope";
  `TaskNewtaskEvent.ChildOutOfScope`). Userspace marks the creator's table
  *blind* (`markBlind`): its entries are dropped and no new ones are stored,
  every lookup reads `/proc/<pid>/fd`, the live shared table, until the table
  dies or its holder execs (an exec is exact: `de_thread` killed every other
  thread, so nobody invisible shares the new table; `CLOSE_RANGE_UNSHARE` never
  un-blinds, because the caller may have sibling threads still sharing the old
  table with the invisible process, so an unsharing leader stays blind with an
  empty private table - names stay right, only the speed-up is lost). The price:
  one successful procfs resolution (`NewFdWithPid`, 6 to 13 us measured, depending on
  host and descriptor type; the 4.5 us figure is only a *failing* `readlink`) per event of that process and
  procfs spellings for anonymous descriptors (`pipe:[N]`) instead of the traced
  ones - the state before gr2. The out-of-scope child's exit is filtered out
  too, so nothing ever says the invisible sharer is gone: **a blind table stays
  blind for the life of its holder** (until exec, or exit). The record changes
  nothing else: no comm seed, no tid retirement.
  **Documented limitations** (no signal names them): (1) a *thread* that makes
  its own table private with `unshare(CLONE_FILES)` or
  `close_range(CLOSE_RANGE_UNSHARE)` stays mapped to its process's table - the
  tracker is keyed by tgid and has no per-thread table (the main thread's reads
  of a number the thread reused keep showing the old name; a worker's
  `close_range(UNSHARE)` is deliberately ignored altogether, see above); (2) under
  `-tid`, a sibling thread's close/reopen of a shared descriptor is filtered out
  in the kernel and invisible. A hidden `CLONE_THREAD` sibling cannot be flagged
  like the `CLONE_FILES` process child: the filter hides it by design and there is
  no tgid of its own to blind. (1) and (2) keep the pre-hr2 behaviour: stale names
  until the number is re-registered or the table is dropped. (3) **Not the
  pre-hr2 behaviour:** a `CLONE_FILES` child *process* that calls
  `unshare(CLONE_FILES)` stays aliased to its creator's table, because `unshare`
  is a null-kind record that carries no flags (the argument is not captured, so
  the call cannot be told from `unshare(CLONE_NEWNS)`); the kernel gave the child
  a copy, but its later close/open of a shared number overwrites the creator's
  entry here, a wrong-name mode that did not exist while each tgid had its own
  table (`close_range(CLOSE_RANGE_UNSHARE)` by such a child *is* handled).
  Recognising it would need the syscall's flags in the BPF record and was left
  out. (4) A `-pid` target that was itself created with `CLONE_FILES` by a
  creator the trace never saw (records exist only for children of in-scope
  creators) is aliased by nobody and blinded by nobody: a sibling's writes to its
  table go unnoticed (as before hr2, so (4) is no regression). (5) **Also not the pre-hr2 behaviour,
  like (3):** a leader that calls `close_range(CLOSE_RANGE_UNSHARE)`
  while sibling threads still share the old table is treated as alone: it leaves
  the sharing (a blind table stays blind), and the siblings' later rows on those
  numbers keep the leader's view. Pinned by
  `internal/eventloop_fdshare_test.go` (sharing both ways, exit/hand-over,
  exec and `CLOSE_RANGE_UNSHARE` detach (leader) / no-op (worker thread) / stays
  blind (also a blind leader with sharers that unshares), a recycled tgid that was a stale sharer or holder, blind table, a plain fork that stays
  independent, an unshared trace that keeps the fast path, bookkeeping
  invariants incl. the blind-set properties: a blind id is a table id and tracks nothing) and `TestNewTaskNewtaskEventFastScopeFlags`
  and `TestTaskNewtaskChildOutOfScopeMatchesTheBPFDefine` (the Go constant is a
  hand-kept copy of the define in `internal/c/exec.c`; the latter parses the C
  source) in `internal/types/fastdecode_test.go`.

  Old-kernel portability (RHEL/Rocky 8 and 9, 4.18/5.14): the handler takes
  `void *` and reads `pid`/`clone_flags` through the local CO-RE flavor
  `trace_event_raw_task_newtask___ior`, so the object compiles against a
  `vmlinux.h` without the struct, and it takes the comm from
  `bpf_get_current_comm()` (the handler runs in the creator's context) because
  copying the tracepoint's `char comm[16]` out of the context compiles to
  context pointer arithmetic that old verifiers reject ("dereference of modified
  ctx ptr"), which fails the load of the whole object. Pinned by the buildgate
  tests `TestBPFObjectCompilesWithoutTaskNewtaskStruct` and
  `TestTaskNewtaskHandlerHasNoContextPointerArithmetic` (llvm-objdump of the
  compiled handler). Not yet run on a real RHEL 8/9 kernel (the rocky VM was
  unreachable when this was written). Pinned by `TestTaskNewtask*`
  (`internal/eventloop_newtask_test.go`, `internal/eventloop_newtask_rename_test.go`,
  including the negative fixtures without a record) and end to end by
  `TestNewThreadsAreNamedWithoutAFilter` / `TestNewThreadsSurviveACommFilter`
  (scenario `thread-comm-short-lived`) and `TestRenamedThreadsKeepTheirNewName` /
  `TestRenamedThreadsSurviveTheRenamedCommFilter` (scenario
  `thread-comm-renamed`), all in `integrationtests/newtask_test.go`; the
  scenarios' threads must be created after ior attached - they skip goroutines
  that land on pre-existing Go runtime threads, for which no record can exist.

  **Tid recycling is a separate failure mode with the same symptom.** The two
  paths above are residuals of the exec record; this one is not about `execve`
  at all. The cache is keyed by tid and the kernel recycles tid numbers, so an
  entry outliving its owner labelled the *next* process handed that number with
  the dead one's name - until it exec'd (bumping the entry) or the entry fell
  off the 8192-entry LRU, neither of which is quick on a box churning
  short-lived processes. The `sched:sched_process_exit` control record already
  attached for the fd table (below) therefore also evicts the comm entry for
  its `ev.Tid` (`commResolver.evictTid`, called from `handleProcessExitEvent`).
  The record fires per *task* and this cache is keyed per task, so this runs
  on every exit record and is precise: a thread exit drops only that thread's
  name (the fd-table eviction, keyed by tgid, waits for the group-dead
  record). Eviction, not `markAllStale`, is right here because there is nothing
  left to serve - the value is not merely at risk of being outdated, its owner
  is gone; the recycled tid then behaves exactly like a never-before-seen one
  (async lookup, and under `-comm` its rows dropped at the exit-side comm check
  until the name is known).

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
  routine: ring-buffer loss. Before task dr2 the `-comm` enter-side gate
  also dropped a brand-new tid's first non-open/exec syscall, which the comm
  eviction above guaranteed was the recycled tid's state; that gate is gone.)
  `prevTimes` is the milder half: it gave the new owner's first pair a
  `DurationToPrev` measured from the dead task's last syscall, which `-gap`
  filters on. The parked enter is *dropped*
  rather than emitted as a synthetic row - the syscall never returned, so it
  has no return value, bytes or latency, and the only timestamp available is
  the task's death, which would fabricate the very latency the eviction
  removes - and the drop is counted nowhere: `numTracepoints` already counted
  the enter record when it was seen, `numSyscalls` is only reached by a pair
  that found its enter, and `numTracepointMismatches` means *the tracker paired
  two records that do not belong together*, so putting ordinary
  kill-inside-syscall traffic there would mask a real pairing regression - and
  would cancel out a real gain: a killed task's surviving enter is consumed by
  the recycled tid's exit of a different syscall whenever that tid's own enter
  was lost, which is a spurious mismatch. (The noreturn syscalls used to be the
  common source of such forever-parked enters; since task pr2 they are rows at
  enter and never park, see "Noreturn syscalls are rows at enter". That row is
  not the synthetic row refused here: a noreturn call is complete at enter and
  its row carries the enter's own time and no latency.) Pinned by
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
  labelling. Correspondingly, the `sys_enter_execve` comm is the *calling*
  program's name: it is cached when the enter record is consumed
  (`seedCommFromEnterPayload`), so a *successful* execve's own records (the
  `task_rename` of `begin_new_exec` and the exec record) replace it in ring
  order, and a **failed** one, where no `sched_process_exec` fires, leaves the
  task under exactly that name. Neither exit handler writes the cache.
  Kernel-sourced names all bump the tid's rename generation and so retire any
  procfs lookup still in flight for it: the exec and rename control records go
  in through `commResolver.setCachedFromKernel`, the payload comm of an open or
  exec enter through `commResolver.setCachedFromEnterPayload`, which shares
  that epoch-bumping write but leaves the entry stale for an exec enter or a
  contradicting open payload (see the lr2 paragraph above). The bump matters
  for the exec enter too: a pre-exec read queued by a fork child's dup2/close
  would otherwise land after it, store the parent's name and clear the flag
  (`TestExecEnterRetiresAPreExecReadInFlight`). A `markAllStale`
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
    `TestDroppedCloseRangeStillEvictsTheFds` respectively). Linux `close(2)`
    releases the descriptor even when it returns errors such as `EINTR` or
    `EIO`; only `EBADF` means there was no open descriptor to release, so
    `applyFdCloseState` evicts on every return except `-EBADF`
    (`TestApplyFdCloseStateFollowsLinuxCloseSemantics`). Because these
    mutations now run on every pair rather than only surviving ones, the failure
    guards matter too: `registerDup` ignores a negative return
    (`TestFailedDupDoesNotRegisterAnFd`) and so does the `pidfd_getfd` branch
    (`TestFailedPidfdGetfdDoesNotRegisterAnFd`).

    Scope caveat: this rule is about the *pair-filter checkpoint*. One earlier
    gate still drops events before any exit handler runs, so it does not make
    the fd table unconditionally correct under a filter. `matchRawOpenEvent`
    drops non-matching opens at enter, so under `-path X` (or `-comm X`) an
    open of a different file (or program) never registers its fd at all (the
    one exception is an open whose payload filename is *empty* — see
    "Recovering a faulted open filename" below, where the path dimension is
    deferred to the exit checkpoint). The `NewFdWithPid` procfs fallback covers
    it while the descriptor is still open. There used to be a second gate: with
    `-comm` active `tracepointEntered` recycled a non-open/exec enter for a tid
    whose comm was not cached yet, and comm resolution is asynchronous, so a
    brand-new thread's close/dup2/dup3/close_range/fcntl never reached the
    table and rows the run *did* want kept a closed file's name (task dr2).
    `tracepointEntered` now parks every enter; an uncached tid has an empty comm
    at the checkpoint, which matches no ordinary `-comm` pattern, so its own row
    is dropped there after the state work ran (the patterns `^$`, `^` and `$` do
    match an empty comm and select such a row; the TUI's exact-pattern helper
    emits `^$` for a row with an empty comm cell, so that is intended)
    (`TestUncachedThreadFdChangesReachTheFdTableUnderCommFilter`). The
    `task:task_newtask` record still matters: it names the tid before its first
    syscall so that thread's *own* rows can match `-comm`.
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
    enter filter is `nil` (see `rawRuntimeEvents`). A *failed*
    `open_by_handle_at` (EPERM, EBADF, ESTALE, ...) reaches that checkpoint
    too, as a descriptor-less pathname row like a failed open: named after
    the thread's stashed `name_to_handle_at` path (consumed; there is no fd to
    verify it against, so with several pending handles it may be another
    handle's path) or empty without one (`failedHandleFile`,
    `internal/eventloop_handle.go`). It used to be recycled in
    `handleOpenByHandleAtExit`, so failed calls produced no row, no error and
    no "syscalls after filter" count (task eq2). Pinned by
    `internal/eventloop_handle_fail_test.go` and the integration test
    `TestOpenByHandleAtFailuresAreErrorRows` (scenario
    `open-by-handle-at-fail`). A *successful* call is named by
    `openedHandleFile`: the stash is one slot per tid (the thread's last
    `name_to_handle_at`), so it is checked against the returned descriptor
    through `/proc/<pid>/fd/<fd>` (inode, then link text) and a contradicted
    stash is left alone while procfs names the row. The link-text rule
    (`compareHandleLinkText`) accepts three things. The link minus one
    trailing ` (deleted)`: a file unlinked after its handle was taken (clean
    stash, row shows the clean path). The link as it stands: a stash that was
    itself read from a `/proc` link, which is what `name_to_handle_at(fd, "",
    AT_EMPTY_PATH)` stashes for a descriptor that is *not* in ior's fd table
    (`fdTracker.resolve` falls back to procfs) - a pidfd, a namespace, a file
    already unlinked at that point, an untracked memfd (`/memfd:x (deleted)`;
    the row keeps the suffix, as every procfs-named unlinked file does). And
    the link form of a traced name (`tracedHandleLink`): the same call on a
    memfd or pidfd ior saw being created is answered from the fd table, so
    the stash is `memfd:x` or `pidfd:0`, which is translated to
    `/memfd:x (deleted)` or `anon_inode:[pidfd]` for the comparison while the
    row keeps the traced name, like every other row on that descriptor. It
    is translated from the name rather than read from the source's `/proc`
    link when the stash is taken: the fd table is in event order, procfs is
    not, and the source number is often reused by then. Without the last two
    such a stash contradicted its own descriptor: the row was named from
    procfs, but the stash stayed in the slot and named the thread's next
    `open_by_handle_at` whenever procfs could not answer for it (task l03).
    The stash is never stripped: `<path> (deleted)` against a live `<path>`
    is a new file at the old path, and a name literally ending in
    ` (deleted)` must still match its `... (deleted) (deleted)` link. Equal
    text is not the same file: any pidfd matches a pidfd stash, and two
    unlinked files that lived at one path, or two memfds of one name, read
    the same link, so the stash of one is spent on the open of the other
    (the row's name is still that descriptor's). Still unmatched, stash left
    behind: a traced memfd whose name BPF could not read (`memfd:<flags>`)
    and every relative stash. Pinned by
    `internal/eventloop_handle_deleted_test.go` and
    `internal/eventloop_handle_traced_test.go`. The `/proc/<pid>/fd/<fd>`
    probe that check rests on is taken when the loop handles the exit, not
    when the syscall returned, so a task that closed the descriptor and
    opened something else under the same number makes procfs describe the
    newer file (task j03: `TestOpenByHandleAt` failed 10 of 40 runs because
    `os.RemoveAll`'s directory open reused the number, and the row and its
    `close` were named after the directory).
    A contradicting descriptor is therefore believed only when
    `confirmedHandleFd` finds it still there (link read, fdinfo readable) with
    the fixed open flags the call asked for (`sameFixedFlags`: `O_ACCMODE`,
    `O_DIRECTORY`, `O_NOFOLLOW`, `O_PATH` - a chosen subset of the flags
    neither `F_SETFL` nor `F_SETFD` can change; `O_SYNC`/`O_DSYNC` are as
    immutable and deliberately left out); otherwise the number is most likely
    changing hands and the stash names the row and is consumed, as in the
    unverifiable case. The access mode counts only for a descriptor whose link
    is an absolute path (`fixedFlagsMask`): pidfs forces it (a pidfd handle
    opened `O_RDONLY` shows `O_RDWR` in fdinfo), so for a non-path target
    that a handle can open (`anon_inode:[pidfd]`, nsfs links such as
    `net:[N]`) only `O_DIRECTORY`/`O_NOFOLLOW`/`O_PATH` are compared -
    otherwise a pidfd row took an unrelated stash. A non-path target that no
    handle can open is never believed (`reachableByHandle`, a deny list:
    `socket:[`, `pipe:[`, and `anon_inode:` other than `anon_inode:[pidfd]`):
    sockfs, pipefs and the generic anon-inode fs have no export operations
    (kernel knowledge; on 7.2.5 `name_to_handle_at(fd, "", AT_EMPTY_PATH)`
    answers `EOPNOTSUPP` for socket, pipe, eventfd, epoll, timerfd, signalfd
    and inotify descriptors and succeeds for a pidfd and every
    `/proc/self/ns/*`), so such a link under the returned number proves the
    number was reused - without it an `O_RDONLY` call whose number went to an
    `O_RDWR` socket/eventfd/epoll descriptor was named after that descriptor,
    because the kind mask does not look at the access mode. What the kind
    mask still costs: a number reused by a pidfd or a namespace descriptor is
    believed unless the request carried a kind flag. "Most likely" is meant
    literally, and there is a losing case: the vanished descriptor can be the
    call's *own*, closed between the probe's reads. If the stash then belongs
    to another handle (stale, or a daemon that calls `name_to_handle_at` only
    for mount IDs and opens handles obtained elsewhere), the row carries the
    wrong stash where it used to get the correct procfs name (readlink ok,
    fdinfo gone) or no name (stat ok, readlink failed), and the stash is
    spent. Accepted because the common pattern - take a handle and open it on
    the same thread - is strictly better off. Both halves are needed:
    with the flag comparison alone the test still failed 22 of 100 runs,
    because the directory descriptor lives for microseconds: closed again
    between the probe's readlink and the fdinfo read, it left a name but no
    flags to compare. The
    evidence is one-sided: a number reused with the *same* fixed flags and
    still open - by a path, or under the kind mask by a pidfd or namespace
    descriptor - is taken for the opened handle and names the row; only handle
    bytes in the BPF events could close that (task k03). The integration
    test is exposed to exactly that residual and passes thanks to the
    workload's fd numbering (see the comment in `openByHandleAt`,
    `cmd/ioworkload/scenario_open.go`). Pinned by
    `TestOpenByHandleAtIgnoresAReusedDescriptorNumber`,
    `TestConfirmedHandleFdRejectsAVanishedDescriptor`,
    `TestOpenByHandleAtDirectoryHandleStillNamedFromProcfs`,
    `TestOpenByHandleAtPidfdHandleIsNamedFromProcfs`,
    `TestOpenByHandleAtIgnoresANumberReusedByAHandleLessDescriptor`,
    `TestOpenByHandleAtPidfdStashMatchesAPidfd`, `TestReachableByHandle`,
    `TestOpenByHandleAtOtherAccessModeOnAPathIsAReusedNumber`,
    `TestFixedFlagsMask` and `TestSameFixedFlags`
    (`internal/eventloop_handle_test.go`).
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
  way in `internal/ior_bpfsetup.go` — handled by `handleProcessExitEvent`
  (`internal/eventloop_processexit.go`). The record fires per *task* and
  carries a `group_dead` flag (`ProcessExitEvent.IsGroupDead`), set by
  `ior_exit_group_dead` in `exec.c` from the tracepoint's own `group_dead`
  field when the kernel has it (CO-RE `bpf_core_field_exists`), else from
  `task->signal->live == 0` (runtime-verified only on kernels with the
  field). The field is read through a local CO-RE flavor type,
  `struct trace_event_raw_sched_process_exit___ior` (libbpf ignores the `___ior`
  suffix and matches the kernel's type by name), and the `exec.c` exit handlers
  take `void *ctx`: the build host's `vmlinux.h` may lack
  `struct trace_event_raw_sched_process_exit` altogether (RHEL/Rocky 8 and 9
  kernels define the tracepoint from a shared template), so naming the kernel
  type would fail the compile there (`internal/buildgate` compiles the object
  against a `vmlinux.h` with that struct stripped). The `signal->live`
  fallback can report `group_dead` on several threads of one `exit_group`, so
  userspace de-duplicates per pid (`groupDeadDedup` in
  `internal/eventloop_groupdead_dedup.go`: a repeat of the same pid within a
  100ms window of boot-clock time is dropped, a FIFO queue expires entries from
  the front, so a recycled pid dying later still counts). The cleanup is split by key: every record drops the exited task's
  tid-keyed state — cached comm, pair state (parked enter plus gap baseline)
  and unconsumed `name_to_handle_at` pathname (see "Comm resolution across
  `execve`") — while the tgid's entries in both fd maps are dropped only on
  the group-dead record. Evicting them on a mere thread exit pushed the
  surviving threads' descriptors through the `/proc/<pid>/fd` fallback,
  which renames them (`pipe:0:3:4` → `pipe:[N]`), loses already-closed ones,
  and under lag can resolve a reused fd number to the wrong file
  (`TestThreadExitKeepsFdName` covers it end to end). A group-dead exit
  bypasses `-tid` in BPF, because the thread that ends the group is usually
  not the traced one; the bypass is scoped to the traced thread's process via
  the `TID_FILTER_TGID` global (`tidFilterTgid` in `internal/bpfsetup.go`).
  An object that predates the global (every one that emits the legacy exit
  record) does not define it: `setTidFilterTgid` treats libbpfgo's "symbol not
  found" (`isMissingSymbol`) as non-fatal - silent without `-tid`, one setup
  warning with it saying the object cannot scope the process-exit forwarding
  to the `-tid` target (depending on its age it forwards every group-dead exit
  or none; the warning claims no mechanism) - so such an `IOR_BPF_OBJECT`
  still loads. Any other setter error stays fatal
  (`TestSetTidFilterTgidClassifiesSetterErrors`, injected setter), a missing
  `TID_FILTER` stays fatal, and `TestLibbpfgoReportsAMissingGlobalAsSymbolNotFound`
  guards libbpfgo's error text unprivileged: the tests open the real object
  through `NewModuleFromFileArgs{SkipMemlockBump: true}` (the buffer variant
  always bumps RLIMIT_MEMLOCK and needs root).
  Every group-dead record that reaches userspace and is not a per-pid
  duplicate is counted (`numGroupDeadExits`) and printed in the end-of-run `Statistics:` block as
  `group-dead exits: N`; `TestTidFilterForwardsGroupDeadExitOfUntracedThread`
  parses that exact line to prove the bypass forwards the group-dead exit of an
  untraced thread under `-tid <worker>` (it reads 0 with the bypass disabled),
  so keep its format stable. That test runs ior with both target-exit
  triggers off (`IOR_TEST_DISABLE_TARGET_EXIT_RECORD=1`,
  `IOR_TEST_DISABLE_TARGET_WATCH=1`, through the harness's `IorEnv`), so the
  run lasts until `-duration` (task wz2): since os2 a headless `-tid <worker>`
  run ends on the worker's own exit record, before the process exits, and the
  stop drain only decodes the backlog present at the stop (the trace window
  ends there, by design), so the later group-dead record was counted only when
  it happened to be buffered already. Bisected to `15f7ecd` (20 runs each:
  `15f7ecd^` 20/20 pass, `15f7ecd` 11/20; 1/10 on `d97df48`); with the
  triggers off it passed 20/20 idle and 20/20 under 2x-nproc CPU load. It also
  fails on any "exited, stopping the trace" line, so a renamed hook cannot
  bring the race back silently. In a real headless `-tid <non-leader>` run the
  bypassed record therefore normally arrives after the stop; it matters to the
  TUI, which outlives its target, and to a leader target, whose process's
  group-dead record is a stop trigger (`endTraceOnTargetThreadExit`).
  Both control records keep a pre-change `IOR_BPF_OBJECT` override
  compatible (`NewProcessExitEventFast`/`NewProcessExecEventFast` in
  `internal/types/fastdecode.go`). The legacy 24-byte exit record predates
  `group_dead`, so it decodes as "group-dead unknown"
  (`IsGroupDeadKnown` false, `IsGroupDead` false; the marker is an all-ones
  `GroupDead` the kernel never writes, because the generated struct cannot
  carry a Go-only field). `applyProcessDeath` still evicts the tgid's fd
  entries on such a record, as every exit did before the flag existed —
  a thread exit costs the survivors a `/proc/<pid>/fd` fallback, whereas
  never evicting would keep a dead process's descriptors — but neither counts
  it in `group-dead exits` nor retires the stats row, which would split a
  live multi-threaded process into one row per exited thread. The current
  32-byte exit record's last word is `exit_flags` (task os2; it used to be an
  always-zero `reserved` pad): bit `IOR_EXIT_TID_INHERITED` marks a
  thread-group leader killed by a sibling's `execve`, whose tid lives on in
  the new program (see "`-tid` runs end with the traced thread"). An older
  object writes 0 there and the legacy record decodes with `ExitFlags` 0,
  both reading "the tid is gone", i.e. the pre-os2 behaviour. The legacy
  40-byte exec record predates `old_tid`/`exit_untraced` and decodes with
  both 0 ("tid kept", exit still coming): an old object never re-keys a
  non-leader exec's enter or suppresses an execve exit. Payloads longer than
  the current layout decode its prefix (forward compatible with appended
  fields); every other shorter size is rejected rather than decoded at the
  wrong offsets. Dropping the legacy sizes instead flooded the TUI with a
  malformed-event warning per task exec/exit.
- **Procfs cache hygiene (task ir2)**: `fdTracker.resolve` caches only a *successful*
  procfs lookup (non-empty name). A failed readlink is returned for that row but
  never stored, so a number that later names a descriptor created by an untraced
  syscall (pipe/socketpair) is re-read instead of staying nameless with O_NONE.
  The price is one failing readlink (~3-4 us, 7 allocs) per event on a number
  procfs cannot answer, so EBADF, the hot shape of that (close loops, the
  `fcntl(F_GETFD)` closefrom sweep over ~1000 numbers), never reaches procfs:
  every fd-resolving exit handler (read/write family, fcntl/ioctl, dup3, mmap,
  two-fd, epoll_ctl, poll, accept, inotify/fanotify, io_uring) calls
  `eventLoop.resolveOnExit`, which on an EBADF exit evicts the procfs-cache
  entry and uses the fd-table entry if present, else an unnamed file with
  unknown flags, with no procfs read (`TestEveryFdResolveGoesThroughTheEBADFHelper`
  parses the package's non-test sources and fails on any function outside its
  explicit allowlist that mentions a `resolve` selector, so aliasing the tracker
  does not bypass it and comments do not trip it). The fd table itself is left
  alone on EBADF: traced syscalls own it and a reordered exit must not erase a
  correct name. The guard is per function, not per call site: a new direct
  resolve inside an already-allowlisted function would pass. Known gaps: an
  fd-table entry whose close event was lost stays stale after EBADF; a syscall
  whose EBADF can concern a descriptor other than the labelled one (epoll_ctl's
  target fd, dup2/dup3's out-of-range new fd, the source of
  sendfile/splice/tee/copy_file_range which are labelled by the destination,
  pidfd_getfd's targetfd, fanotify_mark's dirfd, and read/write on an open fd
  of the wrong access mode) leaves its row unnamed when the labelled fd is
  valid but has no table entry (the next non-EBADF event resolves it;
  close_range never returns EBADF). fanotify_mark is the exception to
  "unnamed": `handleFdPathExit` names the row from the captured pathname, so
  only its flags are unknown (-1);
  dirfd-relative path resolution (`resolveDirfdPath`) has no exit record and is
  not shortened; and successful events of an already-exited pid or an fd closed
  before the event was processed still cost one failing readlink each (no
  per-pid "dead" marker: a failing readlink cannot tell dead pid from closed fd).
- **Close rows never read procfs (task jr2, `internal/eventloop_procfs_close.go`)**:
  `resolveOnExit` routes close and close_range (not `CLOSE_RANGE_CLOEXEC`,
  and not a close_range that failed, e.g. EINVAL: both close nothing, so their
  rows keep the ordinary resolution, procfs included; `closesDescriptor`) to
  `fdTracker.resolveClosing`: the fd-table entry, else
  a procfs-cache entry whose read time (`fdTracker.procFdReadAt`, CLOCK_BOOTTIME
  stamped by `resolve` after the readlink returned, the clock of the BPF record
  timestamps) is earlier than the close's enter time, else an unnamed row with
  unknown flags. Reading `/proc/<pid>/fd` for a close row happens after the
  close, so it named nothing or the file that reused the number (`close(3);
  pipe()` reported the new pipe). Doing the readlink when the *enter* record is
  processed is no better: user space consumes it after the kernel finished the
  close (prototype, 200 pre-attach fds closed and each reused by a pipe, 3 runs:
  exit-time 0/600 correct names, 181 reuser's pipe; enter-time 0/600 correct, 29
  pipe). Only BPF could name the file before the close (no `bpf_d_path` in
  tracepoints; a dentry walk per close), not done. The read time is needed
  because the cache itself lags: a write processed after its fd's close and
  reuse caches the reuser. It lives in a side map, not in `file.FdFile`, so
  per-row files keep their size; `copyTable`/`rekeyTable` carry it along and
  `deleteCacheKey` drops it, and `setProcFdCache` (no time) makes an entry a
  close row ignores. A close of an untracked fd no longer costs a procfs read
  (`BenchmarkCloseUntrackedOpenFd`: ~22 allocs and 33-79 us to 2 allocs and
  ~4-6 us on a busy host). A blind table (`markBlind`, a CLONE_FILES sharer
  the trace cannot see) keeps no entries and no cache answers, so every close
  row there is unnamed, even for fds ior saw opened (before jr2: procfs after
  the close, empty or wrong). The stamp comparison, like
  `provisionalSeedNeedsRecheck`, assumes ior runs in no time namespace with a
  boottime offset (user-space CLOCK_BOOTTIME includes it, BPF stamps do not;
  see `bootClockNs`). Integration: `TestCloseUntrackedNeverNamesTheReusingFile`
  (scenario `close-untracked`: 64 fds opened in a prestart hook, before ior
  attaches; pre-fix 58-62 of 64 close rows named after the pipe; the other 63 files are
  also written right before their close, so the lagging write caches the pipe
  and the test fails without the read-time check: 62 of 63 pipe-named closes,
  5/5 runs).
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
  identical read succeeds. The generator therefore emits, for every kind that
  captures a path — the open kinds
  (`KindOpen`/`KindMqOpen`/`KindOpenTree`), the named eventfd creators
  memfd_create/fsopen, and the pathname, fd-pathname, name and two-fd-names
  kinds (`KindPathname`/`KindFdPathname`/`KindName`/`KindTwoFdNames`: stat,
  access, unlink, mkdir, inotify_add_watch, rename, link, move_mount, ...),
  flagged by `recoversFilename` in `internal/generate/kindregistry.go`. A
  second flag, `recoversSecondFilename` (set for the two-path kinds: `KindName`,
  the rename/link family, and `KindTwoFdNames`, move_mount), makes the exit
  handler also recover the second path (newname, to_pathname) through its own
  stash and fixup slot, because either read can fault independently of the
  other; it implies `recoversFilename`
  and is what `bpfhandler.go` keys the exit handler's second-slot take/emit
  calls on. An exit handler learns what its enter captured through
  `GeneratedTracepoint.EnterKind`, since every `sys_exit_*` format is just
  `long ret` and so classifies as `KindRet`:
  - enter: `ior_stash_pending_filename(tid, ptr)` when the read fails, parking
    the user pointer in `syscall_enter_state.pending_filename`;
  - exit: `ior_on_syscall_exit_take_filename(tid, SYS_ENTER_X, ctx->ret, now,
    &pending_filename)` (`_take_filenames` with both out pointers for the
    two-path kinds): the exit hook itself copies the stashed pointer(s) out of
    the enter-state entry it looks up anyway, **before** it deletes that entry —
    guarded on `enter_trace_id` so a stale entry cannot graft a foreign path
    (the outputs stay 0 for a missing or foreign entry) — then
    `ior_emit_open_name_fixup(...)`, which re-reads the string and publishes it
    as an `OPEN_NAME_FIXUP_EVENT` (48) control record **before** reserving the
    handler's own exit record. The helpers live in `internal/c/filter.c`.

  **Stat, access, unlink and the other path kinds were the same bug** (task
  fq2). Only the open kinds used to recover, so a `stat`/`access`/`unlinkat`/
  `rename` whose path string sat on a never-touched page kept an empty file:
  `-path` could not match the row and the Files tab attributed it to `''`.
  Reproduced with every path argument on a freshly `mmap`'ed untouched file
  page: `access`, `newfstatat` (x2), `unlinkat`, `rename`, `link` and `symlink`
  rows all had an empty file before the change and all named their path after
  it, and `-path no-such-unlink` went from 0 matched rows to 1. The mechanism
  is the same shared one; two details are specific to the new kinds:
  - **Two names, two slots.** rename/link/symlink carry two paths, and so
    does move_mount (from_pathname/to_pathname, carried as the
    `two_fd_names_event` oldname/newname), and either, both or neither read
    can fault. The second name has its own stash
    (`syscall_enter_state.pending_filename2`, `ior_stash_pending_filename2`, read back
    by `ior_on_syscall_exit_take_filenames`) and its own fixup call
    (`ior_emit_second_name_fixup`), and the record says which name it is for:
    `open_name_fixup_event.slot` (`OPEN_NAME_FIXUP_SLOT_FIRST` = filename,
    pathname or oldname/from_pathname; `_SECOND` = newname/to_pathname).
    Without the slot a recovered newname would land on a still-empty oldname. `ior_emit_open_name_fixup`
    and `ior_emit_second_name_fixup` are thin wrappers over
    `ior_emit_name_fixup(tid, id, ptr, slot)`.
  - **Gap kept on purpose.** `exec` does not retry (a successful exec
    replaces the address space the pointer belonged to). `move_mount`
    (`KindTwoFdNames`) used to be a second gap and recovers both paths since
    task vs2; its enter has no raw-enter gate (`enterRaw(..., nil)`), so
    nothing judges a faulted name before the fixup lands, and
    `applyRecoveredTwoFdNames` splices into the `types.TwoFdEvent` that
    `decodeTwoFdNamesEvent` builds. Verified with
    `integrationtests/faultedpath_test.go` (`path-faulted-move-mount`: every
    combination of a faulted from/to path; on the previous BPF object every
    faulted path came out empty).

  **getcwd reuses the same three helpers for an output buffer.** Its path only
  exists once the call has returned, so `outputPathSyscalls`
  (`internal/generate/classify.go`, currently just `getcwd`) makes the enter
  handler stash `args[0]` *unconditionally* right after `ior_on_syscall_enter_stateful`
  (only emitted enters get this far) while the enter stays a header-only
  `null_event`; the exit handler takes it before `ior_on_syscall_exit` and
  emits the fixup only under `if (ctx->ret > 0)`, since a failed call wrote
  nothing into the buffer. Userspace does not splice it into the enter event:
  `applyCapturedOutputPath` (`internal/eventloop_getcwd.go`, keyed on
  `capturedOutputPathEnters`, which a test pins to
  `generate.OutputPathSyscalls()`) puts the path on the pending pair and
  `handleNullExit` validates it with `finishGetcwdPath` against `ret` (the byte
  count including the NUL): no path on failure or when the record was lost, a
  `...` suffix when the cwd was longer than the field, a cut to `ret - 1`
  bytes otherwise. This replaced a `/proc/<tid>/cwd` readlink at processing
  time, which reported the wrong directory when the loop lagged behind a
  `chdir`, nothing once the tracee had exited, and cost a syscall per getcwd
  on the event loop.

  The record uses a dedicated `struct open_name_fixup_event` carrying only the
  enter trace ID, tid, filename and path slot alongside its event type: 272
  bytes instead of the 304-byte `struct open_event`, with no unused comm
  lookup, timestamp or pid. The slot trails the string so the 268-byte prefix
  older readers decode (tid at 8, filename at 12) did not move. Its generated
  `OpenNameFixupEvent` and dedicated `fastdecode` entry travel through the
  narrow control-record dispatch contract rather than claiming the PID/time
  semantics of a syscall `event.Event`. The decoder also accepts the pre-slot
  268-byte record (read as slot FIRST, the only thing it ever carried) and the
  former 300/304-byte `open_event` layouts so a pre-change `IOR_BPF_OBJECT`
  override remains compatible; every other size is rejected rather than
  decoded at the wrong offsets.
  `handleOpenNameFixupEvent`
  (`internal/eventloop_openfixup.go`) splices it into the still-pending enter
  event (`spliceRecoveredPath`, per kind and slot: open/eventfd filename,
  path/fd-path pathname, name oldname or newname): the ring buffer preserves
  reservation order and the event loop has a single consumer goroutine, so the
  fixup always lands while the enter event is unpaired. It never overwrites a
  name the enter side captured itself, and it re-checks the enter trace ID so
  an `openat` fixup cannot be grafted onto a pending `open`. A status other
  than `PATH_READ_FAILED` (a NULL pointer, a read that succeeded) is never
  promoted, and a slot that does not exist for the kind (a `SECOND` record for a
  single-path kind, or a raw value that is neither slot) is ignored, as is a
  record whose tid has no pending enter. A still-failing re-read is discarded
  kernel-side rather than submitted; a fixup lost to backpressure simply never
  arrives and the row keeps its empty name, exactly as before.

  Cost note: the take used to be a separate `ior_take_pending_filename` lookup
  (two for the rename/link family and move_mount) on top of the hook's own;
  task 0t2 folded it into the hook (`ior_on_syscall_exit_impl`), so a
  path-capturing exit does one `syscall_enter_state_map` lookup like any other.

  **The enter gate defers, it does not waive.** `matchRawOpenEvent` used to
  judge the path dimension on the payload filename, so an empty-name open was
  dropped before its fixup could arrive — which is why `-path` silently missed
  exactly these events. For an empty payload name the *file* dimension alone is
  now deferred (`Filter.MatchOpenEventComm`); the comm dimension still applies
  at enter, and the full pair filter applies at the exit checkpoint, where
  `handleOpenExit` ends in `finishPair` (see above). `matchRawPathEvent` and
  `matchRawNameEvent` defer the same way for a `PATH_READ_FAILED` name (the
  fd-pathname and two-fd-names kinds have no enter gate; their pairs are
  filtered at exit). Nothing leaks: an unrecovered name reaches `finishPair`
  empty, and no non-empty `-path` pattern matches the empty string, so the row
  is dropped there instead of here.
  Evidence, identical 4s fork/exec workload: `E:name` rows 6153/41063 (14.98%)
  → 0/39617 (0.00%), and `-path locale-archive` — the path those opens were
  actually taking — went from 0 matched rows to 6211.

- **Stop-time drain** (task tq2; `internal/eventloop_stopdrain.go`): the BPF
  ring buffer's poller (libbpfgo) fills `rawCh` (4096 records) ahead of the
  decoder, and `RingBuffer.Stop` discards what is left in it, so returning at
  `ctx.Done()` alone lost the tail of the trace window whenever the consumer
  lagged - in neither `tracepoints` nor `ring buffer drops`, so `drops: 0`
  overstated completeness. `drainBacklogAtStop` therefore decodes, on the
  event-loop goroutine, the snapshot of `len(rawCh)` taken at the stop (not
  what the still-attached probes add meanwhile: the window ends at the stop and
  chasing a saturated producer would never finish). It is capped at 1 s
  (`defaultStopDrainBudget`, `stopDrainBudget` in tests) so a stalled stdout
  pipe or saturated TUI cannot hang the stop, and it is skipped when a `-plain`
  output write already failed (`outputErr`; the rows have nowhere to go).
  Whatever it could not decode is added to `numDiscardedAtStop`, raised as a
  warning through `notifyWarningOrLog` (every mode), and printed as the
  conditional stats line `records discarded at stop: N (delivered but not
  decoded; ...)` (`discardedAtStopStatLine`, absent when the backlog was
  drained, like `outputLossStatLine`). A nonzero count also marks sampling
  totals as lower bounds (see the sampling notes). This is the userspace half
  of loss observability: records the kernel could not reserve stay in `ring
  buffer drops`, and the loss that remains in the kernel ring buffer itself at
  stop is tracked separately (task us2). Pinned by
  `internal/eventloop_stopdrain_test.go` and `TestRunStopsPromptlyAfterCancel`
  (nothing is emitted after `run` returned).

- **Control records in the statistics**: `numTracepoints` counts every non-empty
  ring-buffer record the event loop pulled off the ring. It is incremented
  before dispatch, so it counts records *seen*: undecodable records
  (`dropMalformedRawEvent`) and unhandled event types are included, and so are
  control records. The `ring buffer drops: … % of events` denominator
  therefore covers the whole ring-buffer stream rather than syscall pairs
  alone. That is deliberate: `internal/c/exec.c` also counts a control record
  it fails to reserve in `ringbuf_drop_map`, so the drop share only stays
  arithmetically honest if the events side counts them too. The mismatch
  percentage is the opposite case: `numTracepointMismatches` is counted once
  per enter/exit *pair*, so it is shown on the `syscalls:` line as a share of
  `numSyscalls` (the pairs formed, incremented just before the trace-ID
  check). Dividing pairs by ring-buffer records mixed units and capped the
  figure near 50% even if every pair mismatched (task sq2).

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
- Tests that must wait until a goroutine is parked on a lock (to change
  shared state only once it provably waits) use `internal/parkwait`, never a
  sleep: take `parkwait.Count` as the baseline, start the goroutine, then
  `parkwait.Await{...}.Run(t)`, which polls `runtime.Stack` until the
  goroutine's dump header shows the wait reason inside the given frame. It
  matches by function name, filtered to goroutines started by the calling
  test goroutine, so start the goroutine and call Count/Run from the test
  goroutine itself. Test-only: never import it from production code.
- Event-loop test fixtures that model a made-up process use pids/tids of the
  form `absentPidBase + n` (`internal/eventloop_absentpid_test.go`;
  `defaultPid`, `execCommPid`, `forkChildPid` are built that way), never a
  plain small literal. Every descriptor or comm the loop has not seen traced
  falls back to the real `/proc/<pid>/...`, so a fixture pid that happens to
  be alive on the host answers with that process's files: plain pid 7100 made
  the fork negative control read `anon_inode:[eventfd]` (task zs2).
  `absentPidBase` is `PID_MAX_LIMIT` (2^22); the kernel never allocates a pid
  at or above it, and `TestAbsentPidsCannotExistOnThisHost` checks that
  premise. A test that needs a live process uses its own pid or a child it
  starts; one that needs specific procfs contents takes a fake root
  (`resolveCommFromProcRoot`, `checkTraceTarget`).

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
