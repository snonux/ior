# I/O Riot NG: a guided tour

This tour shows the dashboard, stream, recording and headless modes with short GIFs captured
from the program.

Every GIF in this document is regenerated from a [VHS](https://github.com/charmbracelet/vhs)
tape under [`tapes/`](./tapes). To rebuild them all, run `sudo -v && mage demo` (see
[Regenerating the demo](#regenerating-the-demo)).

## Contents

1. [Installing ior](#installing-ior)
2. [First launch: the PID picker](#first-launch-the-pid-picker)
3. [Touring the dashboard tabs](#touring-the-dashboard-tabs)
   - [1 · Flamegraph](#1--flamegraph-default-landing-tab)
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
   - [Changing probes while tracing](#changing-probes-while-tracing)
   - [Syscall families on the command line](#syscall-families-on-the-command-line)
   - [Sampling](#sampling)
   - [Other filters](#other-filters)
6. [Recording for offline analysis](#recording-for-offline-analysis)
   - [TUI Parquet recording](#tui-parquet-recording)
   - [Headless modes](#headless-modes)
7. [When something looks wrong](#when-something-looks-wrong)
8. [Regenerating the demo](#regenerating-the-demo)

## Installing ior

See the [main README](../../README.md) for build requirements. On a Docker-capable Linux
host with BTF and tracefs:

```shell
git clone https://codeberg.org/snonux/ior ~/git/ior
cd ~/git/ior
./scripts/build-with-docker.sh
```

For a native build, set up libbpfgo as described in the
[Rocky build guide](../build-rocky-linux-9.md):

```shell
mage all
```

The tracing examples use `sudo` because attaching BPF tracepoints needs elevated access on
the usual host setup.

The built binary embeds a CO-RE BPF object. It can be copied to compatible Linux/amd64 hosts
with BTF; missing tracepoints are skipped. See [the build notes](../../README.md#build).

## First launch: the PID picker

`sudo ./ior` starts with the **PID picker**. The cursor is on **All PIDs**, so pressing
`Enter` traces the whole system. Type into the filter box to narrow the list by PID, comm,
or cmdline; arrow keys move the selection.

![Cold start: PID picker, then the dashboard appears](./assets/01-launch.gif)

The same picker can be re-opened later from the dashboard with `p`.

![PID picker default state](./assets/screenshot-pidpicker.png)

## Touring the dashboard tabs

The dashboard has seven tabs. The default landing tab is **Flamegraph**. Use the number keys
or `tab` / `shift+tab` to move between them. With no selection flags, ior attaches only the
FS syscall family.

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

The first thing you see after dismissing the PID picker is the **live flamegraph**. Bars
grow as new events come in. `o` cycles the stack ordering (e.g. `comm/path/tracepoint` ↔
`comm/tracepoint/path`); `b` toggles the size metric (event count vs. bytes).

![Live flamegraph rebuilding from real workload](./assets/13-tui-flamegraph.gif)

### 2 · Overview

Press `2` for a sparkline of recent event volume, top syscalls and top paths.

![Overview tab populating](./assets/02-overview-tab.gif)

### 3 · Syscalls

Press `3`. A sortable table of every traced syscall (family, count, average latency, total
bytes). Each row carries a **Family** column that groups the syscall into a broad class (FS,
Network, Memory, Polling, …). `j` / `k` (or arrow keys) scroll the rows; `←` / `→` move the
selected column; `s` sorts by the selected column using its default direction; `S` reverses.

![Syscalls table with sort + reverse-sort](./assets/03-syscalls-tab.gif)

### 4 · Files

Press `4` for per-path counters. `d` toggles **directory grouping**, which rolls paths up to
their parent directory. A directory row counts only the files directly in that directory
(subdirectories get rows of their own), and `Enter` on it filters on exactly those files with
the pattern `^dir/*` (case-sensitive; like a shell glob, `*` does not cross a `/`), so the `/`
row selects only top-level entries such as `/etc`, not all of `/etc/passwd`'s tree. You can
type the same `^dir/*` form in the filter modal (`f`).

![Files tab toggling directory grouping](./assets/04-files-tab.gif)

### 5 · Processes

Press `5`. Per-process / per-comm view. `S` reverse-sorts; combine with `←` / `→` to pick a
column.

![Processes tab](./assets/05-processes-tab.gif)

### 6 · Latency + Gaps

Press `6`. Two histograms: syscall **latency** (how long the syscall ran) and the
inter-syscall **gap** (idle time on the same thread between syscalls). The big-write
workload running in the background spreads the latency distribution noticeably.
The gap is measured between consecutive *traced* calls on a thread: with syscall sampling
(`-syscall-sampling-*` rate N), or for syscalls only counted in kernel aggregates (such as
futex), it spans the untraced calls in between. The Overview tab's `Traced gap` mean uses
the same samples.

![Latency + gap histograms](./assets/06-latency-gaps-tab.gif)

### 7 · Stream

Press `7` for a live tail of event rows: comm, PID, TID, syscall, file, FD, return value,
bytes, latency and gap.

![Stream tab live-tailing rows](./assets/07-stream-live.gif)

Setup and runtime warnings (no probe attached, dropped events, libbpf warnings) show up as
rows in the stream too. While there are any, the other tabs show `warnings: N (7:Stream)`
in the status line. Pause, select a warning row and press `Enter` to read all of it.

## Mastering the Stream tab

Stream has **Live** and **Pause** modes; `space` switches between them. Pause lets you
select cells and build filters.

### Pause + stacked filters

In pause mode, navigate with `j` / `k` (rows) and `←` / `→` (columns). Pressing `Enter` on
the selected cell **pushes a new filter onto a stack** and immediately re-filters the ring
buffer. A `Comm`, `Syscall` or `File` cell filters on exactly that value (`^value$`, case-sensitive), so
`read` does not also select `readv` or `READ`, and `/tmp/a` not `/tmp/ab`; numeric cells filter on
equality, and `Gap`/`Latency` on "at least this long". Filters are stackable, so you can
drill down: first by `Comm`, then by `Syscall`, then by `File`. `Esc` pops the most
recent filter (LIFO); keep hitting `Esc` to undo all the way back. The `-` Latency and Ret
cells of `exit`, `exit_group` and `rt_sigreturn` rows push no filter: these syscalls never
return, so they have no latency or return value, and a `latency` or `ret` filter never selects
them (see `docs/parquet-querying.md`, "Syscalls that never return").

![Pause, push two filters, undo with Esc](./assets/08-stream-pause-filter.gif)

The filter is reflected in the bottom status line, and matches the same syntax you'd type by
hand: `comm~bash`, `syscall~openat`, `latency>=100000`, etc.

### Regex search

`/` opens a forward regex prompt; `?` opens a backward one. `n` jumps to the next match in
the same direction; `N` reverses. The search runs against every column on every row in the
ring buffer and wraps at the end.

![Regex search with /, n, n, then ?](./assets/09-stream-regex-search.gif)

### CSV export

Four export keys are available:

- `e`: open the dashboard export picker, then write the **current TUI-filter snapshot** to `ior-stream-<timestamp>.csv` in the current working directory. Works from any tab.
- `x`: quick export of the **paused stream view** specifically (preserves your filter stack).
- `X`: same as `x`, but prompts for a filename first.
- `E`: open the most recent stream-exported CSV in your `$EDITOR` (`hx` / `vi` fallback).

![Press 'e', then ls the resulting CSV](./assets/10-stream-csv-export.gif)

`-tuiExport=false` hides and disables those CSV export keys. It does not disable the `R`
Parquet recorder.

## Choosing what to trace

Three modal pickers reshape what the rest of the TUI sees:

- `p`: **PID picker** (re-opens the launch picker).
- `t`: **TID picker** for thread-level focus.
- `o` / `O`: **Probes** dialog (on the Flame tab, the default, `o` cycles the frame order, so use `O` there): enable / disable individual syscall tracepoints. Press `tab` inside
  the dialog to switch between the **Syscalls** view (single probes: `space`/`enter` toggles,
  `a` all on, `n` all off, `/` search) and the **Families** view.

![PID, TID, and probe pickers](./assets/11-pid-tid-probe.gif)

The **Families** view lists all 12 syscall families with attached/total probe counts
(`[x]` all attached, `[~]` some, `[ ]` none). `space` or `enter` detaches a family that has
any attached probe and attaches it otherwise. Failed attachments are reported without
aborting the rest; the counts depend on the tracepoints available on your kernel.

### Changing probes while tracing

Start with the default FS set:

```shell
sudo ./ior
```

1. Press `Enter` on **All PIDs** in the launch picker. Wait for the dashboard to appear,
   then press `O` to open **Probes**. Capital `O` works on every tab; lowercase `o` also
   opens it on the other tabs. On Flame, lowercase `o` changes the frame order.
2. Press `tab` for **Families**. Move to **Network** with `j` / `k` or the arrow keys,
   then press `space`. Watch the `attaching Network...` progress line and wait for the
   result. On this host it finished with `Network: attached 22 of 22 probes`.
3. Keep Network selected and press `space` again. Wait for the detach to finish; its
   row returns to `[ ]` with zero attached probes. FS stays attached.
4. Press `tab` to return to **Syscalls**. Press `/`, type `openat`, then press `Enter`
   to leave the search prompt. Both `openat` and `openat2` match: search is a case-insensitive
   substring filter. Select `openat` and press `space` to detach just that syscall;
   press it again to attach it. `a` attaches **all registered syscalls**, and `n` detaches
   them all, even with a search active. Try `a`, wait for it to finish, then `n` and wait
   again. To restore FS, press `tab`, select **FS** and press `space`.
5. Press `Esc` to close the dialog. Press `]` to scope the dashboard to **Network**;
   `[` goes back to the unscoped view. With Network detached, the status line shows
   `Network not traced: press O, tab, space to attach`. These keys change what the
   dashboard shows; they do not attach probes.
6. Follow that hint: press `O`, `tab`, `space`. The Families cursor is already on
   Network. Wait for attachment to finish, then press `Esc` to return to the scoped
   dashboard. Press `[` to show all attached families again, or `q` to quit.

Your probe selection survives PID/TID reselects (`p` / `t`) and filter changes (`f`),
including ones that restart the trace. Only quitting and restarting `ior` restores the
`-trace-*` startup set (FS when no selection flags were given). Detaching everything
therefore leaves later trace sessions with no probes until you attach some again.
Newly attached syscalls use the sampling rates set at startup. If a trace restarts during
a probe change, ior keeps the requested selection; probes that cannot attach are retried
and skipped with a log line until your next probe change.

![Attach and detach Network, then follow the untraced-family hint](./assets/16-probes-families.gif)

### Syscall families on the command line

Every syscall belongs to one of 12 families (FS, Network, Memory, Signals, Sched, IPC,
Time, Process, Security, Polling, AIO, Misc) and has a kind that describes its arguments
(`open`, `fd`, `socket`, `sleep`, ...). With no selection flags, only FS is attached.
The positive `-trace-families`, `-trace-kinds` and `-trace-syscalls` selections are added
together; any matching `-no-trace-*` exclusion wins. For example, `-trace-families Time
-trace-syscalls openat` selects Time **and** openat.

`./ior -help` lists all valid families and kinds, and
[Syscall tracing](../syscalls.md) shows which syscall is in which. A tracepoint missing
on the host is skipped with a warning; selecting its family does not make that syscall
available on an older kernel.

The recipes below use one local Python 3 workload: Unix sockets, `/dev/null`, anonymous
memory, POSIX timers and a 100 ms sleep. Start it in the same shell where you will run
ior, then use `$recipe_pid` as the process to trace (replace it with your application's
PID for a real investigation):

```shell
python3 - <<'PYTHON' &
import ctypes
import mmap
import os
import socket
import time

libc = ctypes.CDLL(None, use_errno=True)
timer = ctypes.c_void_p()
while True:
    left, right = socket.socketpair()
    left.send(b"hello")
    right.recv(5)
    left.getsockname()
    left.close()
    right.close()
    fd = os.open("/dev/null", os.O_WRONLY)
    os.write(fd, b"hello")
    os.close(fd)
    with mmap.mmap(-1, 4096) as page:
        page[0] = 1
    if libc.timer_create(1, None, ctypes.byref(timer)) != 0:
        raise OSError(ctypes.get_errno(), "timer_create")
    if libc.timer_delete(timer) != 0:
        raise OSError(ctypes.get_errno(), "timer_delete")
    time.sleep(0.1)
PYTHON
recipe_pid=$!
```

Each command stops after three seconds. The CSV excerpts are rows from real runs;
PIDs, timings, addresses and descriptor names will vary. Status and warnings go to
stderr.

![CLI selectors for Time, memory mappings, and individual file syscalls](./assets/15-cli-families.gif)

#### Network calls from one process

Use this when a client or server's socket activity is getting lost among file calls:

```shell
sudo ./ior -pid "$recipe_pid" -trace-families Network -plain -duration 3
```

```csv
durationToPrevNs,durationNs,comm,pid.tid,name,ret,file
00000000,00025946,python3,2267829.2267829,socketpair,0,"socket:1:1:0%(4,O_RDWR|O_CLOEXEC)"
00006176,00003496,python3,2267829.2267829,sendto,5,"socket:1:1:0%(4,O_RDWR|O_CLOEXEC)"
00003237,00002001,python3,2267829.2267829,recvfrom,5,"socket:1:1:0%(5,O_RDWR|O_CLOEXEC)"
```

`close` belongs to FS, so a Network-only trace does not include it; add
`-trace-syscalls close` if you need socket closes too.

#### Sleeps and timers

Use the Time family to see sleeps alongside POSIX timer creation and deletion:

```shell
sudo ./ior -pid "$recipe_pid" -trace-families Time -plain -duration 3
```

```csv
durationToPrevNs,durationNs,comm,pid.tid,name,ret,file
00000000,00002604,python3,2267829.2267829,timer_create,0,N:file
00005102,00001539,python3,2267829.2267829,timer_delete,0,N:file
00003200,100058941,python3,2267829.2267829,clock_nanosleep,0,N:file
```

For a thread that spends its time sleeping, select just the `sleep` kind:

```shell
sudo ./ior -pid "$recipe_pid" -trace-kinds sleep -plain -duration 3
```

```csv
durationToPrevNs,durationNs,comm,pid.tid,name,ret,file
00000000,100053122,python3,2267829.2267829,clock_nanosleep,0,N:file
```

`timerfd_create` and the other timerfd calls belong to IPC; add that family if your
application uses file-descriptor timers.

#### Memory mapping

Use the Memory family when investigating mapping, protection or allocation syscalls:

```shell
sudo ./ior -pid "$recipe_pid" -trace-families Memory -plain -duration 3
```

```csv
durationToPrevNs,durationNs,comm,pid.tid,name,ret,file
00000000,00020318,python3,2267829.2267829,mmap,139691959808000,anon
00011642,00006288,python3,2267829.2267829,munmap,0,N:file
```

For the mapping and address-range argument kinds, choose `mmap,mem` instead:

```shell
sudo ./ior -pid "$recipe_pid" -trace-kinds mmap,mem -plain -duration 3
```

```csv
durationToPrevNs,durationNs,comm,pid.tid,name,ret,file
00000000,00015790,python3,2267829.2267829,mmap,139691959808000,anon
00010338,00007150,python3,2267829.2267829,munmap,0,N:file
```

These are syscall traces: writing a byte to an already mapped page is not another row.

#### Combine families and remove noisy calls

Keep file, socket and timer activity while dropping file reads/writes and every syscall
of the `sleep` kind:

```shell
sudo ./ior -pid "$recipe_pid" -trace-families FS,Network,Time \
  -no-trace-syscalls read,write -no-trace-kinds sleep -plain -duration 3
```

```csv
durationToPrevNs,durationNs,comm,pid.tid,name,ret,file
00004285,00010884,python3,2269761.2269761,openat,4,"/dev/null%(4,O_WRONLY|O_CLOEXEC)"
100091377,00029219,python3,2269761.2269761,socketpair,0,"socket:1:1:0%(4,O_RDWR|O_CLOEXEC)"
00088894,00006270,python3,2269761.2269761,timer_create,0,N:file
```

Network `sendto`/`recvfrom` remain selected: excluding `read,write` names those two
syscalls, rather than every operation that moves data.

#### Individual syscalls

Use an explicit syscall list to follow file opens and closes without read/write rows:

```shell
sudo ./ior -pid "$recipe_pid" -trace-syscalls openat,close -plain -duration 3
```

```csv
durationToPrevNs,durationNs,comm,pid.tid,name,ret,file
00005027,00015792,python3,2267829.2267829,openat,4,"/dev/null%(4,O_WRONLY|O_CLOEXEC)"
00005410,00001010,python3,2267829.2267829,close,0,"/dev/null%(4,O_WRONLY|O_CLOEXEC)"
```

This selects exactly `openat` and `close`; it does not add the default FS family.

#### Narrow a family selection with tracepoint regexes

Use `-tps` to narrow the selected families and `-tpsExclude` to remove matches from
that result:

```shell
sudo ./ior -pid "$recipe_pid" -trace-families FS,Network \
  -tps 'sys_(enter|exit)_(openat|close|socketpair)$' -tpsExclude 'close$' \
  -plain -duration 3
```

```csv
durationToPrevNs,durationNs,comm,pid.tid,name,ret,file
00000000,00027074,python3,2267829.2267829,socketpair,0,"socket:1:1:0%(4,O_RDWR|O_CLOEXEC)"
00058486,00008414,python3,2267829.2267829,openat,4,"/dev/null%(4,O_WRONLY|O_CLOEXEC)"
```

Here the family set and `-tps` must **both** match, then `-tpsExclude` removes close.
The regexes match tracepoint names such as `sys_enter_openat`, not bare syscall names;
use `openat` or `sys_(enter|exit)_openat$`, rather than `^openat$`. Match both enter and
exit so ior can pair a completed call into a row.

With `-tps` alone and no `-trace-*` or `-no-trace-*` selectors, the regex replaces the
FS default. Use this to select socketpair directly even though it is outside FS:

```shell
sudo ./ior -pid "$recipe_pid" -tps 'sys_(enter|exit)_socketpair$' -plain -duration 3
```

```csv
durationToPrevNs,durationNs,comm,pid.tid,name,ret,file
00000000,00028008,python3,2267829.2267829,socketpair,0,"socket:1:1:0%(4,O_RDWR|O_CLOEXEC)"
```

Adding even a negative dimension selector restores dimension gating: with no positive
`-trace-*` selector, that starts from FS. `-tpsExclude` alone also subtracts from FS.

When finished with the recipes, stop the background workload:

```shell
kill "$recipe_pid"
wait "$recipe_pid" 2>/dev/null
```

### Sampling

Busy syscalls can be sampled per family or per syscall: `1` emits every call, `N` emits
about one in N, and `0` only counts calls in the kernel (aggregate-only). A sampling flag
sets rates for the probes you attach; it does not attach a family itself. This dashboard
run samples Time at 1-in-100, only counts Misc, and samples `read` at 1-in-10:

```shell
sudo ./ior -trace-families FS,Time,Misc \
  -syscall-sampling-families Time=100,Misc=0 \
  -syscall-sampling-syscalls read=10
```

Select **All PIDs** in the picker. Per-syscall settings override family settings, which
in turn override the built-in defaults. In the TUI, the futex variants (`futex`,
`futex_wait`, `futex_wake`, `futex_requeue`, `futex_waitv`) and `clock_gettime` are
aggregate-only by default. They belong to IPC and Time, so the default FS-only trace
never sees them. To get individual `futex` rows in Stream, attach IPC and override its rate:

```shell
sudo ./ior -trace-families IPC -syscall-sampling-syscalls futex=1
```

The other futex variants keep their defaults. A family setting such as `IPC=1` overrides
the defaults for the whole family.

Press `6` in the first run to see the effect on **Latency + Gaps**. The latency histogram
and syscall counts include the calls counted only in the kernel. The gap histogram has
samples only between consecutive *emitted* calls on a thread: with `read=10`, a gap can
span several reads, including their execution time. Aggregate-only calls also lie inside
those gaps. A larger gap therefore need not mean the thread spent more time idle. The
Overview tab calls the same mean `Traced gap`.

Raw modes (`-plain`, `-flamegraph`, headless `-parquet`) promote the built-in rate-0
defaults and any **family** rate of `0` to `1`. In this raw version, Misc emits every call;
Time still runs at 1-in-100:

```shell
sudo ./ior -plain -trace-families Time,Misc \
  -syscall-sampling-families Time=100,Misc=0 -duration 2 > sampled.csv
```

An explicit per-syscall `0` is preserved even in raw modes: it gives that syscall no
output rows, but its kernel counts appear in the end totals. CSV keeps its fixed schema;
the sampling notice and totals go to stderr.

For a sampled Parquet capture:

```shell
sudo ./ior -parquet sampled.parquet -trace-syscalls read \
  -syscall-sampling-syscalls read=10 -duration 2
```

One run printed this startup notice and these end-of-run lines on stderr (your counts
will differ):

```text
Sampling active (read=10): output rows are a sample of these syscalls; exact totals are reported at the end
sampled syscalls (read 1-in-10): rows are a sample; the counts below are exact kernel totals
  read: 9874 calls (1-in-10: 957 traced, 8917 counted only)
syscalls including kernel-counted only: 9874
```

Read the two footer keys in DuckDB:

```sql
SELECT decode(key) AS key, decode(value) AS value
FROM parquet_kv_metadata('sampled.parquet')
WHERE decode(key) IN ('ior.sampling', 'ior.sampling.totals')
ORDER BY key;
```

That file had 957 rows and these footer values:

```text
ior.sampling = read=10
ior.sampling.totals = [{"syscall":"read","rate":10,"traced":957,"counted_only":8917,"total":9874}]
```

Use `total` for the population; row counts, bytes, paths and per-row latency analysis stay
sampled. TUI `R` recordings carry the same keys when a sampled probe is attached, including
aggregate-only defaults. Lost events make totals lower bounds (`"lower_bound":true`);
filters the kernel counters cannot apply can make them `unavailable`. See
[Sampled recordings](../parquet-querying.md#sampled-recordings) for those details.

The native recording carries sampling in its header and uses **format version 2**
(unsampled recordings use version 1). Capture one, then pass the filename printed by
`Wrote` to `ior collapsed`; this glob works when there is just one matching recording:

```shell
sudo ./ior -flamegraph -name sampled -trace-syscalls read \
  -syscall-sampling-syscalls read=10 -duration 2
./ior collapsed ./*-sampled-*.ior.zst > sampled.collapsed
```

`ior collapsed` reports the sampling on stderr. For example, a separate native capture
printed:

```text
ior collapsed: sampled syscalls (read 1-in-10): rows are a sample; the counts below are exact kernel totals
ior collapsed:   read: 9058 calls (1-in-10: 935 traced, 8123 counted only)
```

The collapsed weights describe the emitted sample. See [Output files](../output.md#sampling)
for the recording formats.

![Sampling rates, syscall counts, and the Latency + Gaps view](./assets/17-sampling.gif)

### Other filters

Restricting to a single PID is also exposed as a CLI flag (`-pid <n>`), as is comm/path
filtering (`-comm`, `-path`). Tracepoint subsetting on the command line uses `-tps <regex>`
or `-tpsExclude <regex>`. Both take a comma-separated list of regexes; whitespace around
each regex and empty entries (for example a trailing comma) are ignored, and because the
comma is the separator a regex cannot itself contain one.

## Recording for offline analysis

Choose an output according to the detail you need:

| Flow                   | How                                          | What you get                                            |
|------------------------|----------------------------------------------|---------------------------------------------------------|
| TUI Parquet recording  | `R` from the dashboard                       | streaming Parquet of every row that passes your filter  |
| Headless `.ior.zst`    | `sudo ./ior -flamegraph -name <name>`        | one aggregated native recording at shutdown            |
| Headless Parquet       | `sudo ./ior -parquet trace.parquet`          | per-event Parquet rows written during the run          |
| Plain CSV              | `sudo ./ior -plain`                          | one CSV row per event on stdout (status lines on stderr) |

### TUI Parquet recording

Press `R` in the dashboard, accept the default filename
(`ior-recording-<timestamp>.parquet`) with `Enter`, and rows start streaming to disk. The
footer shows the active recording path (or the last error). Press `R` again to stop.

![Start, run, and stop a parquet recording](./assets/12-parquet-recording.gif)

The recorder follows your *current* TUI global filter. Narrow with `p`, `t` or `o` first if
you want a focused capture.

### Headless modes

For unattended captures or scripting, skip the TUI entirely. The demo runs all three
back-to-back, capped with `-duration` so each terminates on its own.

![Three headless flows in one tape](./assets/14-headless-modes.gif)

`-plain` writes CSV to stdout; status lines and statistics go to stderr. `-parquet`
streams per-event rows to disk. `-flamegraph` writes an aggregated `.ior.zst` recording
at shutdown; convert it to an SVG with external FlameGraph tools.

The examples below run from the repository root in Bash. Define a short workload that
writes five bytes every 100 ms for about eight seconds:

```shell
headless_workload() {
  bash -c 'for ((i=0; i<80; i++)); do
    printf hello > "$1"
    sleep 0.1
  done' ior-headless "${1:-/dev/null}" &
  workload_pid=$!
}
```

#### Stop when a process exits

Start the workload, then select the newest Bash process with `pgrep`:

```shell
headless_workload
sudo ./ior -plain -pid "$(pgrep -n bash)" -duration 15
wait "$workload_pid"
```

On a busy host, use `-pid "$workload_pid"` to select this exact instance instead.
The loop's `printf` is a Bash builtin, so its writes belong to that process. Its
`sleep` children are separate processes: `-pid` does not follow forks.

The trace stops when the Bash process exits, before the 15-second cap. This run printed
on stderr:

```text
Traced process 2328116 exited, stopping the trace
```

The PID will differ on your host. Statistics follow, and ior exits successfully.

#### Stop when a worker thread exits

This Python process starts one worker, then keeps the main thread alive for 12 seconds:

```shell
python3 - <<'PY' &
import threading
import time

def worker():
    for _ in range(80):
        with open("/dev/null", "wb") as output:
            output.write(b"hello")
        time.sleep(0.1)

thread = threading.Thread(target=worker)
thread.start()
time.sleep(12)
thread.join()
PY
thread_pid=$!

# Wait for the worker to appear, then select its TID rather than the main thread.
for _ in {1..40}; do
  worker_tid=$(ls "/proc/$thread_pid/task" |
    awk -v pid="$thread_pid" '$0 != pid {print; exit}')
  [ -n "$worker_tid" ] && break
  sleep 0.05
done
test -n "$worker_tid"
ls "/proc/$thread_pid/task"
sudo ./ior -plain -tid "$worker_tid" -duration 15
kill -0 "$thread_pid"             # The process is still alive after ior stops.
wait "$thread_pid"
```

This run listed main-thread TID `2332120` and worker TID `2332125`, then printed:

```text
Traced thread 2332125 exited, stopping the trace
```

The trace follows that thread's lifetime, even while its process keeps running. `-pid`
and `-tid` can also be combined when you want to name both.

#### Record, then choose the flamegraph weight

Start a fresh workload and save a recording named `run`:

```shell
headless_workload
sudo ./ior -flamegraph -name run -pid "$workload_pid" -duration 15
wait "$workload_pid"
```

This run stopped when the process exited and reported:

```text
Wrote earth-run-2026-10-05_11:29:39.ior.zst
```

The hostname and timestamp vary. Set `record` to the path printed by your run. With
[`flamegraph.pl`](https://github.com/brendangregg/FlameGraph) on your `PATH`:

```shell
record=earth-run-2026-10-05_11:29:39.ior.zst
./ior collapsed "$record" | flamegraph.pl > flame.svg
./ior collapsed -fields comm,path -count bytes "$record" |
  flamegraph.pl --countname bytes > bytes.svg
```

The first SVG counts events and uses the default `comm,tracepoint,path` frames. The
second groups by command and path, with width proportional to bytes transferred.
`--countname bytes` labels that weight in the SVG. The same recording can be collapsed
again with `-count duration` or `-count durationToPrev` for syscall time or the gap
between traced calls; both weights are nanoseconds.

#### Escaping on a terminal and through a pager

Make a file whose name contains a real ESC followed by the red-colour sequence:

```shell
escape_dir=$(mktemp -d /tmp/ior-escape.XXXXXX)
escape_file="$escape_dir/"$'a\x1b[31mred'
touch "$escape_file"
```

Run this loop directly in a terminal:

```shell
for mode in auto always never; do
  headless_workload "$escape_file"
  sudo ./ior -plain -pid "$workload_pid" -trace-syscalls openat \
    -duration 1 -escape="$mode"
  wait "$workload_pid"
done
```

Now send the same rows through `less -R` (press `q` after each trace has finished):

```shell
for mode in auto always never; do
  headless_workload "$escape_file"
  sudo ./ior -plain -pid "$workload_pid" -trace-syscalls openat \
    -duration 1 -escape="$mode" | less -R
  wait "$workload_pid"
done
rm -- "$escape_file"
rmdir -- "$escape_dir"
```

The filename behaved as follows in these runs:

| Mode | Direct terminal | Pipe to `less -R` |
|------|-----------------|------------------|
| `auto` (default) | Literal `a\x1b[31mred` | Raw ESC; `red` appears red |
| `always` | Literal `a\x1b[31mred` | Literal `a\x1b[31mred` |
| `never` | Raw ESC; `red` appears red | Raw ESC; `red` appears red |

`auto` checks ior's stdout, so a pipe gets raw bytes even when the pager displays on a
terminal. Use `always` for a readable escaped pipeline. `ior collapsed` accepts the
same `-escape` modes; see [Terminal escaping](../output.md#terminal-escaping).

#### Plain CSV schema

`-plain` prints the header `durationToPrevNs,durationNs,comm,pid.tid,name,ret,file` once,
then one RFC 4180 CSV row per event. It is a reduced schema: there is no timestamp, byte
count, `requested_sleep_ns`, `nfds`, or `timeout_ns` column, and pid/tid share one
dot-separated column. Fields that may contain commas (process names, file paths) are
CSV-quoted, so parse the rows with any CSV reader rather than a naive comma split. For the
full per-event schema (with `seq`, `time_ns`, `bytes`, `error`, `family`,
`requested_sleep_ns`, `nfds`, `timeout_ns`, `address_space_bytes`, `old_file`, `epoll_*`) use the TUI stream CSV export (`e` in
the dashboard, writes `ior-stream-<timestamp>.csv`) or headless Parquet instead.

## When something looks wrong

For the full limitation list and explanations, see [Troubleshooting](../troubleshooting.md).

To see a setup warning, deliberately choose a thread that cannot belong to the selected
process. In a shell on the host, `$$` is your shell's PID/TID, not a thread of PID 1:

```shell
sudo ./ior -pid 1 -tid $$ -duration 15
```

The Flame tab's status line shows `warnings: 1 (7:Stream)`. Press `7`, `space` to pause,
`g` to select the oldest row, then `Enter` to read the whole warning. This run showed
the following (your shell's TID will differ):

```text
ior: -tid 2263035: not a thread of -pid 1 (the pid and tid filters are ANDed, so nothing could ever match): the trace will stay empty
```

`Esc` closes the warning; `p` lets you choose another process, and `q` quits.

![Warning badge, Stream warning row, and its full message](./assets/18-stream-warnings.gif)

To see what event loss looks like, use a tiny ring buffer and a burst of one-byte reads
and writes. This runs the tracer in the background, gives it two seconds to attach,
and keeps CSV off the terminal while saving warnings and statistics:

```shell
sudo -v
sudo ./ior -plain -trace-syscalls read,write -comm dd -mapSize 4096 -duration 5 > /dev/null 2> drops.log &
tracer=$!
sleep 2
dd if=/dev/zero of=/dev/null bs=1 count=1000000 status=none
wait "$tracer"
cat drops.log
```

An excerpt from the end-of-run statistics on this host:

```text
Statistics:
    ring buffer drops: 2882319 (576473.22/s, 71.66% of events)
    probe runs skipped by the kernel: 0
```

Drop counts are host-wide, even with `-comm dd`, and vary with workload and host load.
Nonzero drops mean the trace is incomplete. For normal captures, omit `-mapSize` to use
the default 16 MiB, or raise it to absorb longer consumer stalls.

For libbpf's full load diagnostics, capture stderr from a headless run:

```shell
sudo IOR_LIBBPF_DEBUG=1 ./ior -plain -duration 5 2> libbpf.log > /dev/null
```

The log includes lines such as `libbpf: loading object 'ior.bpf.o' from buffer`.
Use the same trace options as the failing run and read `libbpf.log` for the load or
verifier error. The TUI ignores this variable because it owns the terminal screen.

## Regenerating the demo

The whole asset pipeline is reproducible:

```shell
mage installDemoTools          # one-time: VHS via go install + ttyd via dnf
sudo -v                        # warm the sudo timestamp once
mage demo                      # regen all 18 GIFs + screenshots
```

Or rebuild a single tape after editing it:

```shell
TAPE=07-stream-live mage demoOne
```

Tapes live in [`tapes/`](./tapes), the background workload that drives them is
[`scripts/workload.sh`](./scripts/workload.sh), and the resulting assets land in
[`assets/`](./assets). VHS records headlessly under `ttyd` + Chromium, so no real terminal
window opens; `mage demo` is safe to run in the background while you keep working.

## Hotkey Quick Reference

### Global keys

| Key | Action |
|-----|--------|
| `tab` / `shift+tab` | next / previous tab |
| `1`–`7` | jump to tab by number (1=Flame, 2=Overview, 3=Syscalls, 4=Files, 5=Processes, 6=Latency+Gaps, 7=Stream) |
| `H` | toggle global help overlay |
| `F1` | toggle bottom dashboard help bar |
| `e` | export filtered stream snapshot to CSV |
| `R` | start / stop Parquet recording |
| `p` | re-open PID picker |
| `t` | open TID picker |
| `o` / `O` | open probe selection dialog (`O` on the Flame tab, where `o` cycles the frame order; `tab` there: Syscalls / Families view; `space`/`enter` toggles a whole family) |
| `[` / `]` | scope the view to the previous / next syscall family |
| `r` | refresh dashboard snapshot |
| `q` / `ctrl+c` | quit |

### Tab-specific keys (`3:Syscalls`, `4:Files`, `5:Processes`)

| Key | Action |
|-----|--------|
| `s` | sort by selected column (default direction) |
| `S` | reverse-sort by selected column |
| `j`/`k` or `↑`/`↓` | scroll list |
| `d` (Files only) | toggle directory grouping |

### Stream tab (`7:Stream`)

| Key | Action |
|-----|--------|
| `space` | toggle live / pause mode |
| `g` / `G` | jump to top / tail |
| `j`/`k` or `↑`/`↓` | move row (pause) / scroll (live) |
| `←`/`→` or `h`/`l` | move selected column (pause only) |
| `enter` | push cell value as exact filter (pause); on a warning row, show its whole message (`esc`/`enter` close) |
| `esc` | pop most recent filter (LIFO) |
| `c` | clear all stream filters |
| `f` | open advanced filter modal |
| `/` / `?` | regex search forward / backward |
| `n` / `N` | next / previous search match |
| `x` | quick CSV export of paused view |
| `X` | CSV export with filename prompt |
| `E` | open last CSV export in `$EDITOR` |
