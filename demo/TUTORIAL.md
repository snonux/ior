# I/O Riot NG: a guided tour

This tutorial walks through every major surface of `ior` — the dashboard tabs, the live stream, recording, headless modes, and the in-TUI flamegraph — using short animated GIFs so you can *see* what the keys actually do.

Every GIF in this document is regenerated from a [VHS](https://github.com/charmbracelet/vhs) tape under [`demo/tapes/`](./tapes). To rebuild them all, run `sudo -v && mage demo` (see [Regenerating the demo](#regenerating-the-demo)).

## Contents

1. [Installing ior](#installing-ior)
2. [First launch: the PID picker](#first-launch-the-pid-picker)
3. [Touring the dashboard tabs](#touring-the-dashboard-tabs)
   - [1 · Flamegraph (default landing tab)](#1--flamegraph-default-landing-tab)
   - [2 · Overview](#2--overview)
   - [3 · Syscalls](#3--syscalls)
   - [4 · Files](#4--files)
   - [5 · Processes](#5--processes)
   - [6 · Latency + Gaps](#6--latency--gaps)
   - [7 · Stream](#7--stream)
4. [Mastering the Stream tab](#mastering-the-stream-tab)
   - [Pause + stacked filters](#pause--stacked-filters)
   - [Regex search](#regex-search)
   - [CSV export](#csv-export)
5. [Choosing what to trace](#choosing-what-to-trace)
6. [Recording for offline analysis](#recording-for-offline-analysis)
   - [TUI Parquet recording](#tui-parquet-recording)
   - [Headless modes](#headless-modes)
7. [Regenerating the demo](#regenerating-the-demo)

## Installing ior

See the [main README](../README.md) for full install steps. In short:

```shell
git clone https://codeberg.org/snonux/ior ~/git/ior
git clone https://github.com/aquasecurity/libbpfgo ~/git/libbpfgo
sudo dnf install -y golang clang bpftool elfutils-libelf-devel zlib-static glibc-static libzstd-static
git -C ~/git/libbpfgo checkout v0.9.2-libbpf-1.5.1
git -C ~/git/libbpfgo submodule update --init --recursive
make -C ~/git/libbpfgo libbpfgo-static
cd ~/git/ior
env GOTOOLCHAIN=auto mage all
```

ior needs `CAP_BPF`, so every invocation below uses `sudo`.

The build dance only has to happen once: the resulting `ior` binary is fully statically linked (libbpf, libelf, libzstd, zlib are baked in) **and** the embedded BPF object uses CO-RE, so libbpf relocates field offsets against the target kernel's BTF at load time. Build it on one box, then `scp ior` to any other Linux host with a BTF-enabled kernel and run it there. See the [Compile once, run everywhere](../README.md#compile-once-run-everywhere) section in the main README for details.

## First launch: the PID picker

`sudo ./ior` starts with the **PID picker**. The cursor is on **All PIDs**, so pressing `Enter` traces the whole system. Type into the filter box to narrow the list by PID, comm, or cmdline; arrow keys move the selection.

![Cold start: PID picker, then the dashboard appears](./assets/01-launch.gif)

The same picker can be re-opened later from the dashboard with `p`.

![PID picker default state](./assets/screenshot-pidpicker.png)

## Touring the dashboard tabs

The dashboard has seven tabs, addressable by number key. The default landing tab is **Flamegraph**. `tab` / `shift+tab` step forward / back.

| Key | Tab               | What it shows                                                            |
|-----|-------------------|--------------------------------------------------------------------------|
| `1` | Flamegraph (`Flm`)| Live FlameGraph of the configured stack (`comm`/`path`/`tracepoint`)     |
| `2` | Overview (`Ovr`)  | Sparkline + top syscalls + top paths summary                             |
| `3` | Syscalls (`Sys`)  | Sortable per-syscall counters, latency, byte volume                      |
| `4` | Files (`Fil`)     | Per-path counters; `d` toggles directory grouping                        |
| `5` | Processes (`Pro`) | Per-process / per-comm counters                                          |
| `6` | Latency (`Lat`)   | Latency + inter-syscall gap histograms                                   |
| `7` | Stream (`Str`)    | Live tail of individual traced events                                    |

### 1 · Flamegraph (default landing tab)

The first thing you see after dismissing the PID picker is the **live flamegraph**. Bars grow as new events come in. `o` cycles the stack ordering (e.g. `comm/path/tracepoint` ↔ `comm/tracepoint/path`); `b` toggles the size metric (event count vs. duration vs. gap).

![Live flamegraph rebuilding from real workload](./assets/13-tui-flamegraph.gif)

### 2 · Overview

Press `2`. The Overview tab is the at-a-glance view: a sparkline of recent event volume, the top syscalls, and the top paths.

![Overview tab populating](./assets/02-overview-tab.gif)

### 3 · Syscalls

Press `3`. A sortable table of every traced syscall (count, average latency, total bytes). `j` / `k` (or arrow keys) scroll the rows; `←` / `→` move the selected column; `s` sorts by the selected column using its default direction; `S` reverses.

![Syscalls table with sort + reverse-sort](./assets/03-syscalls-tab.gif)

### 4 · Files

Press `4`. Per-path counters. The most useful key here is `d`, which toggles **directory grouping** — paths roll up into their parent directory, which is essential when one process touches thousands of files in `/usr/share/...`.

![Files tab toggling directory grouping](./assets/04-files-tab.gif)

### 5 · Processes

Press `5`. Per-process / per-comm view. `S` reverse-sorts; combine with `←` / `→` to pick a column.

![Processes tab](./assets/05-processes-tab.gif)

### 6 · Latency + Gaps

Press `6`. Two histograms: syscall **latency** (how long the syscall ran) and the inter-syscall **gap** (idle time on the same thread between syscalls). The big-write workload running in the background spreads the latency distribution noticeably.

![Latency + gap histograms](./assets/06-latency-gaps-tab.gif)

### 7 · Stream

Press `7`. A live tail of every traced event row — comm, PID, TID, syscall, file, FD, return value, bytes, latency, gap. This is the workhorse view; the next section explores it in depth.

![Stream tab live-tailing rows](./assets/07-stream-live.gif)

## Mastering the Stream tab

Stream has two modes: **Live** (rows scroll past) and **Pause** (`space` toggles). Almost everything interesting happens in pause mode.

### Pause + stacked filters

In pause mode, navigate with `j`/`k` (rows) and `←` / `→` (columns). Pressing `Enter` on the selected cell **pushes a new filter onto a stack** and immediately re-filters the ring buffer. Filters are stackable, so you can drill down — first by `Comm`, then by `Syscall`, then by `File`. `Esc` pops the most recent filter (LIFO); keep hitting `Esc` to undo all the way back.

![Pause, push two filters, undo with Esc](./assets/08-stream-pause-filter.gif)

The filter is reflected in the bottom status line, and matches the same syntax you'd type by hand: `comm~bash`, `syscall~openat`, `latency>=100000`, etc.

### Regex search

`/` opens a forward regex prompt; `?` opens a backward one. `n` jumps to the next match in the same direction; `N` reverses. The search runs against every column on every row in the ring buffer and wraps at the end.

![Regex search with /, n, n, then ?](./assets/09-stream-regex-search.gif)

### CSV export

Three keys, three flavours:

- `e` — quick export of the **current TUI-filter snapshot** to `ior-stream-<timestamp>.csv` in the current working directory. Works from any tab, not just Stream.
- `x` — quick export of the **paused stream view** specifically (preserves your filter stack).
- `X` — same as `x`, but prompts for a filename first.
- `E` — open the most recent stream-exported CSV in your `$EDITOR` (`hx` / `vi` fallback).

![Press 'e', then ls the resulting CSV](./assets/10-stream-csv-export.gif)

If you don't want CSV export at all, start ior with `-tuiExport=false`; the help footer hides the export keys and `e` becomes a no-op.

## Choosing what to trace

Three modal pickers reshape what the rest of the TUI sees:

- `p` — **PID picker** (re-opens the launch picker).
- `t` — **TID picker** for thread-level focus.
- `o` — **Probes** dialog: enable / disable individual syscall tracepoints.

![PID, TID, and probe pickers](./assets/11-pid-tid-probe.gif)

Restricting to a single PID is also exposed as a CLI flag (`-pid <n>`), as is comm/path filtering (`-comm`, `-path`). Tracepoint subsetting on the command line uses `-tps <regex>` / `-tpsExclude <regex>`.

## Recording for offline analysis

ior has three persistence flows; each solves a different problem.

| Flow                   | How                                          | What you get                                            |
|------------------------|----------------------------------------------|---------------------------------------------------------|
| TUI Parquet recording  | `R` from the dashboard                       | streaming Parquet of every row that passes your filter  |
| Headless `.ior.zst`    | `sudo ./ior -flamegraph -name <name>`        | one aggregated native trace artifact (bandwidth-cheap)  |
| Headless Parquet       | `sudo ./ior -parquet trace.parquet`          | streaming Parquet, full firehose, no TUI                |
| Plain CSV              | `sudo ./ior -plain`                          | one CSV row per event on stdout                         |

### TUI Parquet recording

Press `R` in the dashboard, accept the default filename (`ior-recording-<timestamp>.parquet`) with `Enter`, and rows start streaming to disk. The footer shows the active recording path (or the last error). Press `R` again to stop.

![Start, run, and stop a parquet recording](./assets/12-parquet-recording.gif)

The recorder follows your *current* TUI global filter — narrow with `p`/`t`/`o` first if you want a focused capture.

### Headless modes

For unattended captures or scripting, skip the TUI entirely. The demo runs all three back-to-back, capped with `-duration` so each terminates on its own.

![Three headless flows in one tape](./assets/14-headless-modes.gif)

`-flamegraph` writes one aggregated `.ior.zst` artifact at shutdown — ideal for `ior`'s native flamegraph and integration workflows. `-parquet` streams every row, so the file grows continuously. `-plain` is the lightest weight: CSV to stdout you can pipe into anything.

## Regenerating the demo

The whole asset pipeline is reproducible:

```shell
mage installDemoTools          # one-time: VHS via go install + ttyd via dnf
sudo -v                        # warm the sudo timestamp once
mage demo                      # regen all 14 GIFs + screenshots (~10 min)
```

Or rebuild a single tape after editing it:

```shell
TAPE=07-stream-live mage demoOne
```

Tapes live in [`demo/tapes/`](./tapes), the background workload that drives them is [`demo/scripts/workload.sh`](./scripts/workload.sh), and the resulting assets land in [`demo/assets/`](./assets). VHS records headlessly under `ttyd` + Chromium — no real terminal window opens, so `mage demo` is safe to run in the background while you keep working.
