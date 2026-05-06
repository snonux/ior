# TUI Reference

## TUI Flamegraphs

Flamegraphs are available only inside the TUI dashboard.
Use `-fields` to change the stack order and `-count` to choose the metric.
The default stack order is `comm,path,tracepoint` (bottom to top).

## Recording Modes

`ior` has four distinct output flows:

| Mode | How to use it | What it writes | Filter behavior |
| --- | --- | --- | --- |
| TUI dashboard | default startup | nothing continuously; data stays in memory unless you export | current TUI/global filters drive what you see |
| TUI CSV snapshot export | press `e` in the dashboard | one `ior-stream-<timestamp>.csv` snapshot of the current filtered stream view | exports only the currently filtered in-memory rows |
| Headless `.ior.zst` export | start with `-flamegraph -name <name>` | one aggregated native trace artifact written at shutdown | no TUI filter stack; this is the native trace/integration workflow |
| Parquet recording | press `R` in the TUI, or start with `-parquet <file>` | a streaming Parquet file of traced syscall rows | TUI mode records rows that pass the active TUI filter; headless `-parquet` records all traced rows |

Important distinction:

- `.ior.zst` output is an aggregated native artifact, not a row-by-row event log.
- CSV export is a point-in-time snapshot of the ring buffer.
- Parquet recording is a streaming capture from start to stop.
- The ring buffer is capped, so CSV export is not a replacement for Parquet recording or `.ior.zst` output.

### Headless Native `.ior.zst` Output

Use `-flamegraph` when you want the native `ior` trace artifact instead of a streaming row log:

```shell
sudo ./ior -flamegraph -name trace-run -duration 60
```

Native `.ior.zst` behavior:

- writes one `*.ior.zst` file when the run ends
- stores aggregated counters for repeated syscall/path/process combinations
- is intended for `ior`'s native flamegraph and integration-style workflows
- does not preserve one output row per traced syscall

### TUI Parquet Recording

Start a recording from the dashboard with `R`.

- First `R`: open a filename prompt (`ior-recording-<timestamp>.parquet` by default).
- `Enter`: start recording to that file.
- Second `R`: stop and finalize the active Parquet file.
- Recording stops automatically when you quit the TUI or reselect PID/TID/session scope.

Lifecycle details:

- TUI recording uses the active TUI global filter at emission time.
- If a filter change restarts tracing, the recorder stays alive and continues writing matching rows after the restart.
- The dashboard footer shows the active recording path or the last recording error.

### Headless Parquet Recording

Use `-parquet` to skip the TUI and stream traced syscall rows directly to a Parquet file:

```shell
sudo ./ior -parquet trace.parquet -duration 60
```

Headless Parquet mode behavior:

- skips the TUI completely
- records all traced rows
- rejects content filters such as `-comm`, `-path`, `-pid`, and `-tid`
- cannot be combined with `-plain`, `-flamegraph`, `--testflames`, or `--testliveflames`

Use headless mode when you want a full recording, and TUI mode when you want interactive filtering plus optional start/stop recording from the dashboard.

### Choosing Between `.ior.zst` and Parquet

| Question | Native `.ior.zst` | Parquet |
| --- | --- | --- |
| Data shape | aggregated counters | one row per traced syscall |
| Write pattern | collect in memory, write one compressed artifact at the end | stream rows continuously while recording |
| Best for | `ior`-native trace artifacts, flamegraph workflows, integration assertions | offline analysis in other tools, long captures, preserving per-event detail |
| Relative write cost | usually lower because repeated events are folded together before file write | usually higher because each traced row is serialized |
| Detail retained | loses original row order and per-event granularity | keeps per-event timing and syscall fields |

Rule of thumb:

- choose `.ior.zst` when you want the native `ior` artifact and do not need every traced syscall row preserved
- choose Parquet when you want a full event stream for downstream analysis outside `ior`

## TUI Navigation

The TUI has an in-screen help panel (toggle with **H**) that lists all available
keys. Use it to discover shortcuts without consulting this document.

Dashboard tabs:

- **tab** / **shift+tab** — next / previous tab
- **1** — Overview
- **2** — Syscalls
- **3** — Files
- **4** — Processes
- **5** — Latency+Gaps
- **6** — Stream

The TUI has two key scopes:

- Global hotkeys: available from any dashboard screen.
- Dashboard hotkeys: behavior that depends on the active tab (especially `6:Stream`).

### Global Hotkeys

- `tab` / `shift+tab`: cycle tabs.
- `1`–`6`: jump to tab by number (`7` is an alias for `6`).
- `e`: export filtered stream rows to CSV (`ior-stream-<timestamp>.csv`).
- `R`: start or stop Parquet recording.
- `p`: re-open process selector (PID selection flow).
- `t`: open TID selector flow.
- `o`: open probe selection/toggling dialog.
- `r`: refresh dashboard snapshot.
- `H`: toggle bottom help sections on/off.
- `q` or `ctrl+c`: quit.

### Dashboard / Tab-Specific Hotkeys

- `d` in `3:Files`: toggle directory-grouped files view.
- `s` in sortable tabs (`2:Syscalls`, `3:Files`, `4:Processes`): sort by selected column.
- `S` in sortable tabs: reverse-sort by selected column.
- `j/k` or `up/down` in list tabs: scroll list.

`left/right` and `h/l` do not switch tabs. In `6:Stream` paused mode they move the selected column.

### 6:Stream Hotkeys and Behavior

`6:Stream` has two modes:

- Live mode (`paused=false`): rows update continuously.
- Pause mode (`paused=true`): selection/cell/filter/search/export workflows are enabled.

Core controls:

- `space`: toggle live/pause.
- `g`/`G`: jump to top/tail.
- `c`: clear stream filters.
- `f`: open advanced filter modal.
- `j/k` or `up/down`: move selected row (pause) or scroll (live).
- `left/right` or `h/l`: move selected column in pause mode.

#### Enter-Based Filter Stack (Pause Mode)

In pause mode, `enter` on the selected cell pushes a filter onto a stack and
immediately re-filters the current ring buffer snapshot. Filters are stackable.

- String columns use case-insensitive substring match:
  - `Comm` → `comm~<value>`
  - `Syscall` → `syscall~<value>`
  - `File` → `file~<value>`
- Numeric exact match: `PID`, `TID`, `FD`, `Ret`, `Bytes`
- Numeric threshold (`>=`): `Latency` → `latency>=selected_value`, `Gap` → `gap>=selected_value`

`esc` in pause mode pops the most recent filter (LIFO); repeated `esc` undoes
all stacked filters.

#### Regex Search (Pause Mode)

- `/`: search forward; `?`: search backward.
- Search checks all stream columns and wraps around the ring buffer.
- `n` / `N`: next / previous match.

#### Stream CSV Export (Pause Mode)

- `x`: quick export filtered stream rows to CSV.
- `X`: export with filename prompt.
- `E`: open last stream-exported CSV in foreground editor (`EDITOR` → `VISUAL` → `SUDO_EDITOR` → `hx` → `vi`).

`e` (global) exports a fresh filtered snapshot even outside paused mode; `x`/`X`
export the exact paused view.
