# I/O Riot NG (`ior`)

<img src="assets/ior-small.png" alt="ior logo" />

`ior` traces Linux syscalls with eBPF and shows what processes are doing: timings, counts,
file paths, all in a terminal dashboard with a live flamegraph. It can also record to
Parquet, CSV or its own `.ior.zst` format for later.

It's the Go/C/eBPF rewrite of [I/O Riot](https://codeberg.org/snonux/ioriot), which used
SystemTap. The [blog series](https://foo.zone/gemfeed/2026-05-08-unveiling-ior-ng-part-1.html)
has the backstory.

<img src="assets/screenshot-flames.png" alt="ior flamegraph" />

## Build

You need Linux/amd64 and a kernel with BTF (`/sys/kernel/btf/vmlinux`). The easiest way is
Docker:

```sh
./scripts/build-with-docker.sh        # writes ./ior
./scripts/build-with-docker.sh --run  # rebuild, reusing the image
```

With [Mage](https://magefile.org), `mage buildDocker` does the same, and `mage buildDockerEl8`
builds `ior.el8` for RHEL/Rocky/Alma 8. For a native build see the
[Rocky Linux 9 guide](./docs/build-rocky-linux-9.md) and [AGENTS.md](./AGENTS.md).

The build reads the build host's tracepoints, so build on a kernel that has the syscalls you
care about. The binary is static and embeds a CO-RE BPF object, so you can copy it to other
hosts with BTF. Tracepoints missing there are skipped.

## Run

```sh
sudo ./ior
```

Pick a process (or **All PIDs**) and you land on the flamegraph. `tab`, `shift+tab` or `1`-`7`
switch tabs, `H` shows the help. The [tutorial](./docs/tutorial/tutorial.md) walks through
every tab.

![PID picker](./docs/tutorial/assets/01-launch.gif)

By default only filesystem syscalls (the **FS** family) are traced. To trace more:

```sh
sudo ./ior -trace-families Time,Polling
sudo ./ior -trace-kinds fd,open -no-trace-syscalls read
sudo ./ior -trace-syscalls openat,recvmsg,nanosleep -no-trace-kinds null
```

`./ior -help` lists the valid values. In the TUI, `O` opens the probes dialog where you can
attach or detach families and single syscalls while it runs.

## Save output

| What | How | Result |
|---|---|---|
| CSV snapshot | `e` in the TUI | `ior-stream-<timestamp>.csv` |
| Parquet recording | `R` in the TUI to start/stop | `ior-recording-<timestamp>.parquet` |
| Flamegraph record | `sudo ./ior -flamegraph -name run` | `<host>-run-<timestamp>.ior.zst` at exit |
| Headless Parquet | `sudo ./ior -parquet trace.parquet` | one row per event |
| Plain CSV | `sudo ./ior -plain -duration 5 > events.csv` | one row per event on stdout |

Turn a `.ior.zst` record into an SVG with the usual FlameGraph tools:

```sh
ior collapsed run.ior.zst | flamegraph.pl > flame.svg
```

Headless runs with `-pid` or `-tid` stop when the traced process or thread exits.

## Docs

- [Tutorial](./docs/tutorial/tutorial.md): the TUI tab by tab
- [Output files and recordings](./docs/output.md): file naming, sampling, CSV schemas, memory limits, escaping
- [Querying Parquet](./docs/parquet-querying.md)
- [Troubleshooting and known limitations](./docs/troubleshooting.md): warnings, libbpf logs, io_uring, seccomp and other blind spots
- [Syscall tracing](./docs/syscall-tracing-plan.md): families, kinds, sampling, byte counting
- [Building on Rocky Linux 9](./docs/build-rocky-linux-9.md)
