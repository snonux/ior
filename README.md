> **🚧 PRE-ALPHA SOFTWARE:** This project is in a pre-alpha state and is intended for my own personal use only. Use at your own risk.

# I/O Riot NG (aka ior)

<img src=assets/ior-small.png />

I/O Riot NG is an experiments with BPF. This program traces for synchronous I/O syscalls and then analyses the time taken for each of those syscalls. This is especially useful for drawing FlameGraphs like these:

<img src=assets/screenshot-flames.png />

Maybe this is a spiritual successor of one of my previous projects, I/O Riot https://codeberg.org/snonux/ioriot, the latter was based on SystemTap and C. The NG is based on Go, C and BPF (via libbpfgo).

This works only on Linux!

## Demo

A short guided tour with animated GIFs of every major surface lives in [`demo/TUTORIAL.md`](./demo/TUTORIAL.md). Two teasers:

<img src=demo/assets/01-launch.gif width=720 alt="Cold start: PID picker, then the dashboard appears" />

<img src=demo/assets/13-tui-flamegraph.gif width=720 alt="Live in-TUI flamegraph rebuilding from real workload" />

The demo is fully reproducible: `mage installDemoTools` once, then `sudo -v && mage demo` regenerates every GIF and screenshot. See the [tutorial](./demo/TUTORIAL.md) for the full walkthrough.

## Requirements

- Go 1.26 or newer (ior relies on cgo via libbpfgo).

## Local libbpfgo Toolchain

`ior` links against a locally built `libbpfgo` checkout. By default
`Magefile.go` expects that checkout at `../libbpfgo` relative to this repo; set
`LIBBPFGO=/absolute/path/to/libbpfgo` if you keep it elsewhere.

Pin that checkout to `v0.9.2-libbpf-1.5.1` and rebuild the static artifacts
before running `mage` targets:

```shell
git -C ../libbpfgo checkout v0.9.2-libbpf-1.5.1
git -C ../libbpfgo submodule update --init --recursive
make -C ../libbpfgo libbpfgo-static
```

Validated commands for this pin:

```shell
env GOTOOLCHAIN=auto mage world
env GOTOOLCHAIN=auto mage integrationTest
```

Troubleshooting and rollback:

- If builds fail with `bpf/bpf.h` missing, re-run the checkout, submodule sync,
  and `make libbpfgo-static` commands above, then retry `env GOTOOLCHAIN=auto mage world`.
- Prefer Mage targets over raw `go test` for packages that import `libbpfgo`;
  Mage injects the required `CGO_CFLAGS`, `CGO_LDFLAGS`, and `LIBBPFGO` values.
- To roll back to the previous wrapper state, repin `go.mod` to
  `github.com/aquasecurity/libbpfgo v0.6.0-libbpf-1.3.0.20240111220235-90dbffffbdab`,
  then reset the sibling checkout and rebuild:

```shell
git -C ../libbpfgo checkout 90dbffffbdab
git -C ../libbpfgo submodule update --init --recursive
make -C ../libbpfgo libbpfgo-static
```

## Timing Semantics

Each reported event pair has two timing counters:

- `durationNs`: syscall runtime on the same thread (`exit(current) - enter(current)`).
- `durationToPrevNs`: inter-syscall gap on the same thread (`enter(current) - exit(previous)`).

Important details:

- `durationToPrevNs` is tracked per `tid` (thread), not globally across all threads.
- The first observed syscall pair for a thread has `durationToPrevNs = 0` because there is no prior exit timestamp.
- `durationToPrevNs` is attributed to the current syscall pair (the one whose `enter` closes the gap).
- There is no separate "idle" pseudo-event bucket; use the `durationToPrev` count field when aggregated flamegraph output should emphasize inter-syscall time.

## Rocky Linux 9

Verified on a fresh Rocky Linux 9.7 install (e.g. kernel `5.14.0-611.5.1.el9_7`,
exact stamp not required). Runs on the **stock RHEL 9 kernel** — no kernel
upgrade needed. One build-time caveat:

- Rocky 9 ships neither `libelf.a` nor `libzstd.a` (no `*-static` packages). Both have
  to be built from source — the elfutils dance is the same as the Fedora section above;
  `libzstd.a` needs an extra `make` from the upstream tarball.

> Historical note. Earlier versions of `ior` typed BPF tracepoint context as
> `struct trace_event_raw_sys_enter`/`_exit` (the BTF-emitted alias). RHEL 9
> backports an `rt`-tree patch that adds `preempt_lazy_count` to `struct
> trace_entry`, which widens those aliases by 8 bytes and shifts the `args`/`ret`
> offsets — but the actual context the kernel hands the program is still
> `struct syscall_trace_enter`/`_exit`, where the offsets did not move. The
> verifier saw the program reading past `max_ctx_offset` and rejected the
> attach with `EACCES`. `ior` now uses `syscall_trace_*` directly (matching
> the [bcc fix](https://github.com/iovisor/bcc/pull/4920) and inspektor-gadget),
> so the stock kernel works with no workaround.

```shell
# 1) Enable repos and install build dependencies (CRB ships static libs).
sudo dnf config-manager --set-enabled crb
sudo dnf install -y epel-release
sudo dnf install -y gcc clang bpftool elfutils-libelf-devel zlib-static \
    glibc-static libzstd-devel git make cmake wget rpmdevtools strace bpftrace
sudo dnf builddep -y elfutils

# 2) Install Go 1.26 from go.dev (Rocky 9 ships only Go 1.25; ior needs 1.26+).
cd /tmp
wget -q https://go.dev/dl/go1.26.2.linux-amd64.tar.gz
sudo tar -C /usr/local -xf go1.26.2.linux-amd64.tar.gz
echo 'export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH' | sudo tee /etc/profile.d/go.sh
source /etc/profile.d/go.sh

# 3) Build libelf.a from elfutils source (same trick as the Fedora section).
mkdir -p ~/src && cd ~
dnf download --source elfutils-libelf
rpm -ivh elfutils-*.src.rpm
tar -C ~/src -xjf rpmbuild/SOURCES/elfutils-*.tar.bz2
cd ~/src/elfutils-*
./configure --enable-deterministic-archives --disable-debuginfod --disable-libdebuginfod
make -C lib -j$(nproc)
make -C libelf -j$(nproc)
sudo cp -v libelf/libelf.a /usr/lib64/

# 4) Build libzstd.a from upstream (libzstd-devel does not ship the static archive).
cd /tmp
wget -q https://github.com/facebook/zstd/releases/download/v1.5.5/zstd-1.5.5.tar.gz
tar xzf zstd-1.5.5.tar.gz
make -C zstd-1.5.5/lib -j$(nproc) libzstd.a
sudo cp -v zstd-1.5.5/lib/libzstd.a /usr/lib64/

# 5) Clone ior + libbpfgo, pin libbpfgo, build the static archive, install mage.
mkdir -p ~/git
git clone https://codeberg.org/snonux/ior ~/git/ior
git clone https://github.com/aquasecurity/libbpfgo ~/git/libbpfgo
git -C ~/git/libbpfgo checkout v0.9.2-libbpf-1.5.1
git -C ~/git/libbpfgo submodule update --init --recursive
make -C ~/git/libbpfgo libbpfgo-static
go install github.com/magefile/mage@latest

# 6) Generate against the live kernel (the syscall-coverage audit is
# kernel-specific; IOR_FORCE_GENERATE skips the strict diff against the
# committed audit which was generated on a different kernel build).
cd ~/git/ior
env IOR_FORCE_GENERATE=1 GOTOOLCHAIN=auto mage generate
env GOTOOLCHAIN=auto mage all

# 7) Smoke test.
sudo ./ior -plain -duration 5
```

If `./ior -plain -duration 5` prints `Probing for 5s` and a stream of CSV rows,
the install is good.

## Compile once, run everywhere

The full build dance above only has to happen on **one** machine. The resulting
`ior` binary is portable across Linux hosts: `scp ior other-host:/usr/local/bin/`
and run it there. Two reasons it works:

- The Go binary is compiled with `-extldflags "-static"` and links libbpf,
  libelf, libzstd, and zlib as static archives. There is no runtime dependency
  on the build host's library versions (a couple of glibc resolver functions —
  `getpwnam_r` and friends — fall back to the target's libc, which is fine on
  any reasonable distro).
- The BPF object inside the binary is built with libbpf's CO-RE
  (Compile-Once, Run-Everywhere) machinery. Field offsets are not baked into
  the bytecode; libbpf reads the target kernel's BTF
  (`/sys/kernel/btf/vmlinux`) at load time and patches the program for that
  kernel. As long as the target ships BTF — true on every Debian, Ubuntu,
  Fedora, Arch, RHEL, and now ElRepo `kernel-ml` build at the time of
  writing — the same `ior` binary runs without recompilation.

So in practice: pick one Rocky 9 / Fedora box, do the build dance once, then
distribute the 23 MB binary to wherever you want to trace. The build host needs
all the dev tooling; the trace hosts need only a BTF-enabled kernel and `sudo`.

For the eBPF + CO-RE explanation, see Part 2 of the I/O Riot NG blog series:
[Unveiling I/O Riot NG — Part 2: under the hood](https://foo.zone/gemfeed/unveiling-ior-ng-part-2.html).

## TUI Flamegraphs

Flamegraphs are available only inside the TUI dashboard.
Use `-fields` to change the stack order and `-count` to choose the metric.
The default stack order is `comm,path,tracepoint` (bottom to top).

## Recording Modes

`ior` has four distinct output flows. They are intentionally different:

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

Both formats are useful, but they solve different problems:

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

The TUI interface provides an in‑screen help panel (toggle with **H**) that lists all available keys. Use this help screen to discover navigation shortcuts.

You can move between dashboard tabs:

- **tab** – next dashboard tab
- **shift+tab** – previous dashboard tab
- **1** – Overview
- **2** – Syscalls
- **3** – Files
- **4** – Processes
- **5** – Latency+Gaps
- **6** – Stream

The bottom hint shows `press H for help` when the help is hidden.



The TUI has two key scopes:

- Global hotkeys: available from dashboard screens.
- Dashboard hotkeys: behavior that depends on the active dashboard tab (especially `6:Stream`).

Help visibility:

- `H`: toggle bottom help sections on/off.
- By default, help is hidden and the bottom hint shows `press H for help`.

### Global Hotkeys

- `tab`: next dashboard tab.
- `shift+tab`: previous dashboard tab.
- `1`: `Overview` tab.
- `2`: `Syscalls` tab.
- `3`: `Files` tab.
- `4`: `Processes` tab.
- `5`: `Latency+Gaps` tab.
- `6`: `Stream` tab.
- `7`: `Stream` tab (alias).
- `e`: export filtered stream rows to CSV (`ior-stream-<timestamp>.csv`) in current working directory.
- `R`: start or stop Parquet recording from the TUI dashboard.
- `p`: re-open process selector (PID selection flow).
- `t`: open TID selector flow.
- `o`: open probe selection/toggling dialog.
- `r`: refresh dashboard snapshot.
- `q` or `ctrl+c`: quit.

### Dashboard / Tab-Specific Hotkeys

- `d` in `3:Files`: toggle directory-grouped files view.
- `s` in sortable table tabs (`2:Syscalls`, `3:Files`, `4:Processes`): sort by the selected column using that table's default direction.
- `S` in sortable table tabs (`2:Syscalls`, `3:Files`, `4:Processes`): reverse-sort by the selected column.
- `j/k` or `up/down` in list-like tabs (`2:Syscalls`, `3:Files`, `4:Processes`): scroll list.

`left/right` and `h/l` do not switch tabs. In `6:Stream` paused mode they move selected column.

### 6:Stream Hotkeys and Behavior

`6:Stream` has two modes:

- Live mode (`paused=false`): rows update continuously.
- Pause mode (`paused=true`): selection/cell/filter/search/export workflows are enabled.

Core controls:

- `space`: toggle live/pause.
- `g`/`G`: jump to top/tail.
- `c`: clear stream filters.
- `f`: open advanced filter modal.
- `j/k` or `up/down`: move selected row in pause mode; scroll in live mode.
- `left/right` or `h/l`: move selected column in pause mode.

#### Enter-Based Filter Stack (Pause Mode)

In pause mode, `enter` on the selected cell pushes a new filter onto a stack and immediately re-filters the current ring buffer snapshot. Filters are stackable.

- String columns use case-insensitive substring match:
- `Comm` -> `comm~<value>`
- `Syscall` -> `syscall~<value>`
- `File` -> `file~<value>`
- Numeric exact match:
- `PID`, `TID`, `FD`, `Ret`, `Bytes`
- Numeric threshold (`>=`):
- `Latency` -> `latency>=selected_value`
- `Gap` -> `gap>=selected_value`

Undo:

- `esc` in pause mode pops the most recent filter from the stack (LIFO).
- Repeated `esc` keeps undoing until no stacked filters remain.

#### Regex Search (Pause Mode)

- `/`: open regex prompt and search forward.
- `?`: open regex prompt and search backward.
- Search checks all stream columns/fields and wraps around ring-buffer rows.
- `n`: next match in the same direction as last `/` or `?`.
- `N`: previous match (opposite direction).

#### Stream CSV Export (Pause Mode)

- `x`: quick export filtered stream rows to CSV (`ior-stream-<timestamp>.csv`).
- `X`: export filtered stream rows to CSV with filename prompt.
- `E`: open last stream-exported CSV in foreground editor (`EDITOR` -> `VISUAL` -> `SUDO_EDITOR` -> fallback `hx`, else `vi`).

Export behavior:

- `e` exports a fresh filtered stream snapshot using the current shared TUI filter, even outside paused mode.
- `x`/`X` export the currently paused stream rows, preserving the stream tab's exact paused view.
