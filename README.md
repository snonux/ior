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

## Requirements

- Docker (for the official build) **or** a Linux host with Go 1.26+, clang, and libbpfgo for native development builds.
- Linux with a BTF-enabled kernel (`/sys/kernel/btf/vmlinux` present) to run `ior`.

## Build

The officially supported build method is Docker — no local Go, clang, or libbpfgo setup needed. Native builds are supported for contributors who want to iterate quickly without Docker.

### Docker build (official)

Builds a fully static `ior` binary inside a Rocky Linux 9 container and writes
it to the repo root:

```shell
mage buildDocker
```

First run takes ~15–20 minutes to build the image; subsequent runs reuse the
cached image and finish in under a minute. To skip the image rebuild:

```shell
./scripts/build-with-docker.sh --run
```

### Native build (development)

For local development, `ior` links against a locally built `libbpfgo`. Clone it
as a sibling of this repo and build the static archive once:

```shell
git clone https://github.com/aquasecurity/libbpfgo ../libbpfgo
git -C ../libbpfgo checkout v0.9.2-libbpf-1.5.1
git -C ../libbpfgo submodule update --init --recursive
make -C ../libbpfgo libbpfgo-static
mage world
```

For Rocky Linux 9 specific steps (building static libelf/libzstd, installing Go
1.26) see [docs/build-rocky-linux-9.md](./docs/build-rocky-linux-9.md).

## Compile once, run everywhere

Build on one machine, then `scp ior other-host:/usr/local/bin/` and run it
anywhere. The binary is fully statically linked and uses libbpf CO-RE
(Compile-Once, Run-Everywhere) to adapt field offsets to the target kernel's
BTF at load time — no recompile per host or kernel version needed.

See [docs/build-rocky-linux-9.md](./docs/build-rocky-linux-9.md) for the full
explanation.

## TUI

Press **H** inside the dashboard to toggle the built-in help panel. Tabs are
reachable with **tab/shift+tab** or number keys **1–7**. Full hotkey reference:
[docs/tutorial/tutorial.md](./docs/tutorial/tutorial.md#hotkey-quick-reference).

## Recording Modes

`ior` has four distinct output flows:

| Mode | How to use it | What it writes |
| --- | --- | --- |
| TUI dashboard | default startup | nothing — data stays in memory until export |
| TUI CSV snapshot | press `e` | `ior-stream-<timestamp>.csv` of filtered stream |
| Headless `.ior.zst` | `-flamegraph -name <name>` | aggregated native trace artifact |
| Parquet recording | press `R` in TUI, or `-parquet <file>` | streaming Parquet file |

Full details and the `.ior.zst` vs Parquet trade-off:
[docs/tutorial/tutorial.md](./docs/tutorial/tutorial.md#recording-for-offline-analysis).
