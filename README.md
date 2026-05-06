# I/O Riot NG (aka ior)

<img src=assets/ior-small.png />

I/O Riot NG is an experiments with BPF. This program traces for synchronous I/O syscalls and then analyses the time taken for each of those syscalls. This is especially useful for drawing FlameGraphs like these:

<img src=assets/screenshot-flames.png />

Maybe this is a spiritual successor of one of my previous projects, I/O Riot https://codeberg.org/snonux/ioriot, the latter was based on SystemTap and C. The NG is based on Go, C and BPF (via libbpfgo).

This works only on Linux!

## Demo

A short guided tour with animated GIFs of every major surface lives in [`docs/tutorial/tutorial.md`](./docs/tutorial/tutorial.md). Two teasers:

**Startup — the PID picker:** `sudo ./ior` opens a searchable process list. Navigate with arrow keys, filter by typing, and press `Enter` to start tracing. The dashboard appears immediately after.

<img src=docs/tutorial/assets/01-launch.gif width=720 alt="Cold start: PID picker, then the dashboard appears" />

**Live flamegraph tab:** Once tracing, tab `1` shows a live flamegraph that rebuilds in real time as I/O events arrive. Bars grow and shift with the workload — this is the default landing tab.

<img src=docs/tutorial/assets/13-tui-flamegraph.gif width=720 alt="Live in-TUI flamegraph rebuilding from real workload" />

The demo is fully reproducible: `mage installDemoTools` once, then `sudo -v && mage demo` regenerates every GIF and screenshot. See the [tutorial](./docs/tutorial/tutorial.md) for the full walkthrough.

> **Note:** `mage installDemoTools` uses `dnf` to install `ttyd` and is only supported on Fedora / RHEL / Rocky / Alma Linux. On other distros install `ttyd` manually (binary releases are on its GitHub page) and then `go install github.com/charmbracelet/vhs@latest` for VHS; `mage demo` will find them on `PATH`.

## Requirements

- Docker and a Linux host with a BTF-enabled kernel (`/sys/kernel/btf/vmlinux` present).

## Build

Builds a fully static `ior` binary inside a Rocky Linux 9 container and writes
it to the repo root — no local Go, clang, or libbpfgo setup required:

```shell
mage buildDocker
```

First run takes ~15–20 minutes to build the image; subsequent runs reuse the
cached image and finish in under a minute. To skip the image rebuild:

```shell
./scripts/build-with-docker.sh --run
```

For contributors who need a native build (Fedora / Rocky Linux 9), see
[docs/build-rocky-linux-9.md](./docs/build-rocky-linux-9.md) and
[AGENTS.md](./AGENTS.md).

## Compile once, run everywhere

Build on one machine, then `scp ior other-host:/usr/local/bin/` and run it
anywhere. The binary is fully statically linked and uses libbpf CO-RE
(Compile-Once, Run-Everywhere) to adapt field offsets to the target kernel's
BTF at load time — no recompile per host or kernel version needed.

See [docs/build-rocky-linux-9.md](./docs/build-rocky-linux-9.md) for the full
explanation.

## TUI

Press **H** inside the dashboard to toggle the built-in help panel. Tabs are
reachable with **tab/shift+tab** or number keys **1–7**. For the full hotkey
reference, recording modes, and the `.ior.zst` vs Parquet trade-off see the
[tutorial](./docs/tutorial/tutorial.md).
