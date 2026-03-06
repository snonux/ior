# TUI Flamegraph Tab - Full Design Plan

## Overview

Add a **7th dashboard tab** (`7:Flame`) that renders a live, interactive flamegraph
directly in the terminal using lipgloss for layout/styling and **Charm Harmonica**
for smooth spring-based animations on both zoom transitions and live data refresh.
The tab consumes data from an embedded `LiveTrie` and
provides interactive flamegraph navigation directly in-terminal.

## Architecture

```
BPF events -> eventLoop.printCb
                |
                +-> statsengine.Ingest()    (existing tabs 1-5)
                +-> eventstream.Push()      (existing tab 6)
                +-> LiveTrie.Ingest()       (NEW: tab 7)
```

The `LiveTrie` is instantiated in the TUI startup path and published via
`runtimeBindings`, similar to how `SnapshotSource` and `RingBuffer` are already
wired.

## New Files and Packages

| File/Package | Purpose |
|---|---|
| `internal/tui/flamegraph/model.go` | Bubble Tea sub-model: state, Update, View |
| `internal/tui/flamegraph/renderer.go` | Converts LiveTrie snapshot -> terminal frame layout, renders with lipgloss |
| `internal/tui/flamegraph/animation.go` | Harmonica spring state for frame width interpolation and zoom transitions |
| `internal/tui/flamegraph/search.go` | Search/highlight: text input bubble, match filtering, highlight styling |
| `internal/tui/flamegraph/zoom.go` | Zoom stack management (zoom into subtree, undo zoom, reset zoom) |
| `internal/tui/flamegraph/controls.go` | Toolbar rendering (status line, field order, keybindings help) |

## Detailed Design

### 1. Data Wiring

**Changes to existing files:**

- `internal/tui/tui.go` -- Add `SetLiveTrie(*flamegraph.LiveTrie)` to
  `TraceRuntimeBindings` interface and `runtimeBindings` struct. The trace starter
  publishes the `LiveTrie` the same way it publishes the stats engine.
- `internal/ior.go` / trace setup -- When running in TUI mode, create a `LiveTrie`
  alongside the stats engine. In the `eventLoop.printCb`, call
  `liveTrie.Ingest(ep)` in addition to existing stats/stream ingestion. Publish via
  `bindings.SetLiveTrie(lt)`.
- `internal/tui/dashboard/model.go` -- Add `liveTrie *flamegraph.LiveTrie` field,
  `flamegraphModel flamegraphtui.Model` child model. Wire refresh tick to poll
  `LiveTrie.Version()`.

### 2. Tab Integration

**Changes to `internal/tui/dashboard/tabs.go`:**

```go
const (
    // ... existing tabs ...
    TabFlame   // new 7th tab
)

var allTabs = []Tab{..., TabFlame}
```

Tab label: `"Flame"` (short: `"Flm"`). Key binding: `7`.

**Changes to `internal/tui/dashboard/model.go`:**

- Add `flamegraphModel` field of type `flamegraphtui.Model`
- In `Update()`, on `refreshTickMsg` or a dedicated `flameTickMsg` (200ms like
  stream), poll `LiveTrie.Version()` and push snapshot data into the flamegraph
  model
- In `handleKey()`, add `key.Matches(msg, m.keys.Seven)` -> `TabFlame`
- In `renderActiveTab()`, delegate to `flamegraphModel.View(width, height)`
- On `WindowSizeMsg`, propagate dimensions to `flamegraphModel.SetViewport(w, h)`
  -- this triggers re-layout of all frames to fit new terminal size

### 3. Flamegraph TUI Model (`internal/tui/flamegraph/model.go`)

```go
type Model struct {
    // Data
    liveTrie      *flamegraph.LiveTrie
    lastVersion   uint64
    snapshot      *flamegraph.trieSnapshot  // latest parsed snapshot

    // Layout
    frames        []tuiFrame              // current rendered frames
    targetFrames  []tuiFrame              // target frames (for animation lerp)
    width, height int

    // Interaction
    selectedIdx   int                     // cursor/selected frame index
    zoomStack     []zoomState             // zoom history for undo
    zoomRoot      *flamegraph.trieSnapshot // current zoom root (nil = full view)

    // Search
    searchActive  bool
    searchInput   textinput.Model         // from bubbles/textinput
    searchQuery   string
    matchIndices  map[int]bool            // frame indices matching search

    // Field ordering
    fieldPresets  [][]string
    fieldIndex    int

    // Animation
    springs       []frameSpring           // per-frame Harmonica spring state
    animTicker    bool                    // whether animation tick is running

    // Flags
    paused        bool
    isDark        bool
}

type tuiFrame struct {
    Name    string
    Col     int     // column position (0-based, in terminal cells)
    Row     int     // row from bottom
    Width   int     // width in terminal cells
    Total   uint64
    Percent float64
    Fill    lipgloss.Color
    Depth   int
    Path    string  // full path for zoom identification
}
```

### 4. Rendering Strategy (`internal/tui/flamegraph/renderer.go`)

Terminal flamegraphs use a **cell-based layout** rather than pixel coordinates:

1. **BuildTerminalLayout(snapshot, width, height, zoomRoot)** converts trie snapshot
   to `[]tuiFrame`:
   - Width is terminal columns (not 1200px). Each frame width =
     `floor(termWidth * (node.total / rootTotal))`.
   - Height is terminal rows. Each frame is exactly **1 row tall** (not 16px).
   - Rows grow bottom-to-top: root at the bottom, leaves at the top (classic
     flamegraph orientation). If tree depth exceeds available rows, only show the
     deepest `height-2` levels (toolbar + status take 2 rows).
   - Frames narrower than 1 cell are culled (terminal equivalent of `minWidthPx`).

2. **Frame rendering**: Each frame is a **colored block** of text:
   - Use lipgloss background color fill with the existing `frameColor()` warm palette
   - Frame text = truncated function/path name that fits within the frame width
   - Selected frame gets a distinct border/highlight style (e.g., bold + inverted)
   - Search-matched frames get a different highlight color (e.g., red background)

3. **Compositing**: Use `lipgloss.Place()` or the new lipgloss v2 compositor/canvas
   to layer frames at their (col, row) positions. Each row of the flamegraph is
   assembled by joining frame cells horizontally with background fill for gaps.

4. **Auto-resize**: On `WindowSizeMsg`, re-run `BuildTerminalLayout` with new
   dimensions. All frame widths and row counts recalculate. Harmonica springs
   animate from old positions/widths to new ones.

### 5. Subtree Highlighting

When the user selects (navigates to) a frame, the **entire subtree rooted at that
frame** is visually highlighted so the user can see exactly what would be zoomed
into on `enter`.

**Visual states for any frame:**

| State | Visual Treatment |
|---|---|
| **Selected frame** | Bold text + bright border/underline + slightly lightened background |
| **Selected subtree** (ancestors + descendants) | Full saturation, normal brightness -- "active" look |
| **Not in subtree** | **Dimmed**: reduced saturation / lower contrast background, muted text |
| **Search match** | Red/magenta background overlay (overrides dim but not selection) |

Dimming the *non-subtree* frames makes the selected subtree "pop" naturally.

**Ancestor vs Descendant Distinction:**

| Relationship | Visual |
|---|---|
| **Selected frame** | Bold, inverted/bright border |
| **Descendants** | Full color, normal weight |
| **Ancestors** | Full color with subtle left-border indicator (breadcrumb trail) |
| **Unrelated** | Dimmed (lower contrast background, gray text) |

**Subtree membership** computed via `Path` field (the `\x1f`-delimited ancestor
chain). A frame is in the subtree if:
- Its path is a **prefix** of the selected frame's path (ancestor), OR
- The selected frame's path is a **prefix** of its path (descendant), OR
- It **is** the selected frame

O(n) scan over frames, recomputed each time selection moves.

**Interaction with search**: Search matches outside subtree shown dimmed in match
color; inside subtree shown bright. Selected frame matching search uses selection
style.

### 6. Animation with Harmonica (`internal/tui/flamegraph/animation.go`)

```go
type frameSpring struct {
    widthSpring  harmonica.Spring
    colSpring    harmonica.Spring
    currentW     float64
    currentCol   float64
    velocityW    float64
    velocityCol  float64
}
```

**Two animation scenarios:**

1. **Data refresh**: When `LiveTrie` version changes and new frame widths differ
   from current, set new target widths. On each animation tick (~30fps =
   `tea.Tick(33ms)`), call `spring.Update(current, velocity, target)` for each
   frame's width and column. Render at interpolated values. Stop animation tick
   when all frames reach target within epsilon.

2. **Zoom transition**: When user zooms into a subtree, the target layout changes
   (zoomed subtree expands to fill full width). Springs animate column positions
   and widths from pre-zoom to post-zoom. Undo-zoom reverses this.

**Spring configuration**: `harmonica.NewSpring(harmonica.FPS(30), 6.0, 1.0)` --
critically damped for snappy transitions without oscillation.

### 7. Keybindings

| Key(s) | Action |
|---|---|
| `j` / `down` / `arrow-down` | Move selection to frame below (shallower depth) |
| `k` / `up` / `arrow-up` | Move selection to frame above (deeper / toward leaves) |
| `h` / `left` / `arrow-left` | Move selection to previous sibling at same depth |
| `l` / `right` / `arrow-right` | Move selection to next sibling at same depth |
| `enter` | Zoom into selected frame's subtree |
| `backspace` / `u` | Undo zoom (pop zoom stack) |
| `escape` (when zoomed) | Reset zoom to root |
| `/` | Open search input |
| `escape` (when searching) | Close search, clear highlights |
| `n` | Jump to next search match |
| `N` (shift+n) | Jump to previous search match |
| `p` | Toggle pause |
| `r` | Reset baseline |
| `o` | Cycle field order preset |
| `?` | Toggle flame-specific help overlay |

Both vim-style (j/k/h/l) and regular cursor keys (arrow keys) are bound to the
same actions via `key.NewBinding(key.WithKeys("j", "down"))`.

### 8. Search (`internal/tui/flamegraph/search.go`)

- Uses `bubbles/textinput` for inline search input at the bottom of flame view
- On submit, iterate frames and mark matching indices (case-insensitive substring
  match on frame name)
- Matching frames rendered with highlight color; non-matching frames dimmed
- `n`/`N` moves selection to next/previous match
- Show match count in status line (e.g. `3/12 matches`)

### 8.1 Color Coding (Implemented)

Flame frames now use semantic colors first, with hash-based fallback for unknown labels:

| Category | Match rule | Color (RGBA / hex) |
|---|---|---|
| Read I/O | name contains `read`/`pread` | `78,132,201` (`#4E84C9`) |
| Write I/O | name contains `write`/`pwrite` | `222,122,58` (`#DE7A3A`) |
| Metadata I/O | name contains `open`, `close`, `stat`, `rename`, `link` | `196,168,72` (`#C4A848`) |
| Path-oriented nodes | starts with `/`, contains `/`, or `path:` | `88,156,84` (`#589C54`) |
| Process/thread labels | contains `pid` or `tid` | `67,151,149` (`#439795`) |
| Other syscall buckets | starts with `sys_` | `191,99,74` (`#BF634A`) |
| Fallback | anything else | deterministic hash palette |

This keeps common I/O classes visually stable across refreshes while preserving
distinct colors for uncategorized frames.

### 9. Zoom (`internal/tui/flamegraph/zoom.go`)

- `zoomStack []zoomState` where `zoomState` holds the `path` string of the zoomed
  node and the previous `selectedIdx`
- On zoom-in: push current state, find subtree node matching selected frame's path,
  set as `zoomRoot`, rebuild layout with subtree as root
- On undo: pop stack, restore previous root
- On reset: clear stack, set `zoomRoot = nil`

### 10. Field Order Cycling

Preset cycle:
```go
fieldPresets = [][]string{
    {"comm", "path", "tracepoint"},
    {"path", "tracepoint", "comm"},
    {"tracepoint", "comm", "path"},
    {"pid", "path", "tracepoint"},
}
```

Pressing `o` calls `LiveTrie.Reconfigure(nextPreset)` which resets the trie and
starts fresh accumulation.

### 11. Toolbar / Status Line (`internal/tui/flamegraph/controls.go`)

Rendered as a single line above the flamegraph area:

```
[LIVE] | o:order(comm>path>tp) | /:search | enter:zoom | u:undo | r:reset | p:pause
```

When paused: `[PAUSED]` in red. When searching: shows search input and match count.

Selected frame info line at the bottom:
```
sys_read (1,234 calls, 45.2%) - /usr/bin/myapp > /dev/sda > sys_enter_read
```

### 12. Dependencies to Add

- `github.com/charmbracelet/harmonica` -- spring animation
- `charm.land/bubbles/v2/textinput` -- search input (already transitive via bubbles v2)

### 13. Changes to Existing Files (Summary)

| File | Change |
|---|---|
| `internal/tui/dashboard/tabs.go` | Add `TabFlame`, update `allTabs`, `String()`, `tabLabel()` |
| `internal/tui/dashboard/model.go` | Add `flamegraphModel` field, wire refresh, handle key `7`, render in `renderActiveTab()` |
| `internal/tui/tui.go` | Add `SetLiveTrie()` to bindings interface, propagate to dashboard |
| `internal/tui/common/keys.go` | Add `Seven` key binding for tab 7 |
| `internal/ior.go` | Create `LiveTrie` in TUI mode, wire into eventLoop callback, publish via bindings |
| `internal/flags/flags.go` | Add `-fields` default propagation to TUI mode |
| `go.mod` | Add `github.com/charmbracelet/harmonica` dependency |

### 14. Risks and Mitigations

1. **Performance at high event rates**: The `LiveTrie.Ingest()` call adds overhead
   to the hot path. Mitigation: TUI render is decoupled via version polling.

2. **Terminal width too narrow**: Flamegraphs with many shallow frames may not
   render meaningfully in 80-column terminals. Mitigation: cull frames below 1 cell,
   show "terminal too narrow" message below ~60 columns.

3. **Animation frame budget**: 30fps animation ticks in a terminal could cause
   flicker on slow terminals. Mitigation: only run animation tick when springs are
   active, stop when settled.

4. **Color support**: Not all terminals support 24-bit color. Mitigation: lipgloss
   v2 auto-downgrades. The warm flamegraph palette degrades gracefully to 256-color.

---

## Benchmarking & Profiling Plan

### Goals

1. Quantify render performance at various terminal sizes and trie depths
2. Measure animation overhead of Harmonica spring ticks at 30fps with N springs
3. Detect regressions via baseline benchmarks running in CI alongside `mage bench`
4. Profile hot paths to identify allocations and CPU bottlenecks

### Benchmark Suite

New file: `internal/tui/flamegraph/bench_test.go`

| Benchmark | What it measures |
|---|---|
| `BenchmarkBuildTerminalLayout` | trieSnapshot -> []tuiFrame at widths 80/120/200/300 and depths 10/50/100 |
| `BenchmarkRenderFrame` | Full View() render at 80x24, 120x40, 200x60 |
| `BenchmarkComputeSubtreeSet` | Subtree membership with 100/1000/5000 frames |
| `BenchmarkSearchHighlight` | Search match computation across N frames |
| `BenchmarkSpringUpdate` | harmonica spring.Update() across 100/500/2000 springs |
| `BenchmarkAnimationTick` | Full tick: update springs + rebuild render output |
| `BenchmarkZoomTransition` | Layout rebuild on zoom-in |
| `BenchmarkLiveTrieIngestAndSnapshot` | End-to-end: ingest N events + snapshot + layout |
| `BenchmarkResizeRelayout` | Layout rebuild at new terminal dimensions |

### Benchmark Fixtures

Synthetic trie generators in `internal/tui/flamegraph/testdata_test.go`:

| Label | Depth | Breadth | Approximate frame count |
|---|---|---|---|
| `small` | 5 | 3 | ~120 |
| `medium` | 10 | 5 | ~2,500 |
| `large` | 15 | 8 | ~10,000+ |
| `deep` | 50 | 2 | ~100 (narrow but deep) |
| `wide` | 3 | 50 | ~5,000 (shallow but very wide) |

### Performance Targets

| Operation | Target | Rationale |
|---|---|---|
| `BuildTerminalLayout` (medium, 120-col) | < 500us | Well within one tick interval |
| `View()` full render (medium, 120x40) | < 2ms | 30fps = 33ms budget |
| `ComputeSubtreeSet` (1000 frames) | < 100us | Runs on every selection move |
| Single animation tick (500 springs) | < 1ms | 16ms frame budget headroom |
| `LiveTrie.Ingest` + `SnapshotJSON` | < 200us | Hot path performance |

### Profiling Integration

#### Built-in profiling flag

When `-pprof` is set in TUI mode:
- Write `ior-tui-cpu.prof` during session
- Write `ior-tui-mem.prof` on quit
- Write `ior-tui-trace.out` for first 10 seconds

#### Mage Targets

| Target | Command |
|---|---|
| `mage benchFlame` | `go test ./internal/tui/flamegraph/ -bench=. -benchmem -count=5` |
| `mage benchFlameProf` | Same + `-cpuprofile` + `-memprofile` |
| `mage benchFlameCmp` | Compare against saved baseline via `benchstat` |

### Allocation Targets

| Hot path | Strategy |
|---|---|
| `BuildTerminalLayout` | Pre-allocate []tuiFrame, reuse across refreshes |
| `View()` render | strings.Builder with pre-estimated capacity, cache styles |
| `computeSubtreeSet` | Reuse map[int]bool (clear + repopulate) |
| Spring updates | Fixed-size []frameSpring, no per-tick allocs |

Target: **zero allocs** in animation tick, **< 5 allocs/op** in full render.

### Stress Tests

New file: `internal/tui/flamegraph/stress_test.go`

- **TestStressHighEventRate**: 100k events from 10 goroutines + concurrent render
- **TestStressRapidResize**: 100 WindowSizeMsg with random dimensions
- **TestStressZoomDuringRefresh**: Interleaved zoom/undo with data refresh ticks

All run with `-race`.

### Profiling Workflow (Manual)

```bash
# Run TUI with profiling
sudo ior -pprof -pid 1234

# Analyze CPU profile
go tool pprof -http=:8080 ior-tui-cpu.prof

# Analyze allocations
go tool pprof -http=:8080 -alloc_space ior-tui-mem.prof

# Analyze execution trace
go tool trace ior-tui-trace.out

# Benchmark-specific profiling
mage benchFlameProf
go tool pprof -http=:8080 flame-cpu.prof
```
