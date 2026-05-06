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
- Linux with a BTF-enabled kernel (`/sys/kernel/btf/vmlinux` present).

## Build

### Docker build (recommended — no toolchain setup required)

Builds the static `ior` binary inside a Rocky Linux 9 container and writes it
to the repo root. Requires only Docker and a Linux host with tracefs and BTF:

```shell
mage buildDocker
```

On first run this takes ~15–20 minutes to build the image. Subsequent runs
reuse the cached image and finish in under a minute. To skip the image build:

```shell
./scripts/build-with-docker.sh --run
```

### Native build

`ior` links against a locally built `libbpfgo`. Clone it as a sibling of this
repo and build the static archive once:

```shell
git clone https://github.com/aquasecurity/libbpfgo ../libbpfgo
git -C ../libbpfgo checkout v0.9.2-libbpf-1.5.1
git -C ../libbpfgo submodule update --init --recursive
make -C ../libbpfgo libbpfgo-static
```

Then build everything:

```shell
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
reachable with **tab/shift+tab** or number keys **1–6**. Full hotkey reference:
[docs/tui-reference.md](./docs/tui-reference.md).

## Recording Modes

`ior` has four distinct output flows:

| Mode | How to use it | What it writes |
| --- | --- | --- |
| TUI dashboard | default startup | nothing — data stays in memory until export |
| TUI CSV snapshot | press `e` | `ior-stream-<timestamp>.csv` of filtered stream |
| Headless `.ior.zst` | `-flamegraph -name <name>` | aggregated native trace artifact |
| Parquet recording | press `R` in TUI, or `-parquet <file>` | streaming Parquet file |

Full details and the `.ior.zst` vs Parquet trade-off:
[docs/tui-reference.md](./docs/tui-reference.md).
