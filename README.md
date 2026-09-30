# I/O Riot NG (`ior`)

<img src="assets/ior-small.png" alt="ior logo" />

`ior` traces Linux syscalls with eBPF and shows their timing, counts, paths and processes in
a terminal dashboard. It can also write a collapsed `.ior.zst` recording, Parquet rows or
plain CSV. By default it attaches only filesystem syscalls; other families are opt-in.

This is the Go, C and eBPF successor to [I/O Riot](https://codeberg.org/snonux/ioriot),
which used SystemTap. The
[blog series](https://foo.zone/gemfeed/2026-05-08-unveiling-ior-ng-part-1.html) covers the
project history.

<img src="assets/screenshot-flames.png" alt="ior flamegraph" />

## Build

`ior` runs on Linux/amd64 and needs a host kernel with BTF at `/sys/kernel/btf/vmlinux`.
The Docker build also reads the host's tracepoints, so build it on a Linux host with the
syscalls you want to include. Tracepoints absent on a target host are skipped when `ior`
attaches.

With Docker, build directly from the checkout:

```sh
./scripts/build-with-docker.sh
```

That writes `./ior`. Later builds can reuse the image with
`./scripts/build-with-docker.sh --run`. If you have [Mage](https://magefile.org) installed,
`mage buildDocker` runs the same container build. `mage buildDockerEl8` writes `ior.el8` for
RHEL/Rocky/Alma 8 hosts.

For native builds, install the Go version in `go.mod`, place `libbpfgo` at `../libbpfgo`
(or set `LIBBPFGO`), and follow
[the Rocky Linux 9 build guide](./docs/build-rocky-linux-9.md). [AGENTS.md](./AGENTS.md)
lists the build and test targets.

The binary statically links its userspace libraries and embeds a CO-RE BPF object. CO-RE
adjusts supported kernel field offsets using the target's BTF; it does not add syscalls or
BPF features to an older kernel.

## Run

```sh
sudo ./ior
```

The PID picker opens first. Choose a process, or press `Enter` on **All PIDs**. The
dashboard starts on the live flamegraph tab. Use `tab` / `shift+tab` or `1`–`7` to change
tabs; press `H` for help.

![PID picker](./docs/tutorial/assets/01-launch.gif)

![Live flamegraph](./docs/tutorial/assets/13-tui-flamegraph.gif)

The [tutorial](./docs/tutorial/tutorial.md) shows all seven tabs and their keys. Its GIFs
come from VHS tapes; `mage demo` rebuilds them after `mage installDemoTools` and `sudo -v`
on a Fedora/RHEL-family host.

### Choose syscalls

Without selection flags, only the **FS** family is attached. Choose families, kinds or names
explicitly when you need more:

```sh
sudo ./ior -trace-families Time,Polling
sudo ./ior -trace-kinds fd,open -no-trace-syscalls read
sudo ./ior -trace-syscalls openat,recvmsg,nanosleep -no-trace-kinds null
```

`./ior -help` lists the valid values. [Syscall tracing](./docs/syscall-tracing-plan.md)
explains classification and sampling.

In the TUI you can change the traced set at runtime: press `o` for the probes modal, `tab`
to switch to the Families view (attached/total probes per family), and `space` to attach
the selected family, or detach it if any of its probes is attached. The Syscalls view
toggles single probes. Runtime changes survive trace restarts (PID/TID reselect, filter
changes), and newly attached syscalls get the same sampling rates as at startup. The carried
set is what you asked for: normally exactly what is attached, but a change that finishes
after the trace restarted keeps its intended set, whose unattachable probes are retried and
skipped with a log line until your next probe change. Detaching everything makes later
sessions attach nothing; only restarting `ior` returns to the `-trace-*` startup selection. `[`/`]`
only scope the view to a family; on a family with no attached probe the status line says
how to attach it.

### Save output

| Mode | Command or key | Output |
|---|---|---|
| TUI CSV snapshot | `e` | Current filtered stream snapshot in `ior-stream-<timestamp>.csv` |
| TUI Parquet recording | `R` to start and stop | Rows captured while recording |
| Native aggregate | `sudo ./ior -flamegraph -name run` | `<host>-run-<timestamp>.ior.zst` at shutdown |
| Headless Parquet | `sudo ./ior -parquet trace.parquet` | Per-event rows written during the run |
| Plain CSV | `sudo ./ior -plain -duration 5 > events.csv` | Per-event CSV on stdout; status on stderr |

The TUI keeps its statistics in memory until you export or start a recording.
`-tuiExport=false` disables CSV export shortcuts; it does not disable `R` recording. The
plain CSV schema is deliberately small:
`durationToPrevNs,durationNs,comm,pid.tid,name,ret,file`. Use TUI CSV export or Parquet for
timestamps, byte counts and other per-event fields.

`-flamegraph` writes an aggregated native record, not an SVG. To render it with external
FlameGraph tools, run `ior collapsed <file>.ior.zst | flamegraph.pl > flame.svg`.

Traced comm names and paths come from other users and may contain terminal escape
sequences. When `-plain` or `ior collapsed` writes to a terminal, control characters
(ESC, BEL, C1, line breaks), invalid UTF-8 bytes and invisible or bidi format characters
are shown in Go escape notation such as `\x1b` or `\u202e`; the CSV stays valid.
Backslashes are not doubled, so this display is for reading only. When stdout is piped or
redirected, both commands write the exact traced bytes for machine consumers.

That terminal check is `-escape=auto`, the default. It cannot see a terminal at the end
of a pipe, so `ior -plain | grep`, `| tee` or `| less -R` (and `ior collapsed ... | less -R`)
still show raw bytes. Use `-escape=always` for such pipelines, or `-escape=never` to keep
raw bytes on a terminal. Both `-plain` and `ior collapsed` accept the flag, and any other
value is an error.

## Bytes Classification

Throughput bytes come from positive return values of these syscalls only:

- `ReadClassified`: `fgetxattr`, `flistxattr`, `getcwd`, `getdents`,
  `getdents64`, `getrandom`, `getxattr`, `getxattrat`, `lgetxattr`,
  `listxattr`, `listxattrat`, `llistxattr`, `mq_timedreceive`, `msgrcv`,
  `pread64`, `preadv`, `preadv2`, `process_vm_readv`, `read`, `readlink`,
  `readlinkat`, `readv`, `recvfrom`, `recvmsg`, `sched_getaffinity`
- `WriteClassified`: `process_vm_writev`, `pwrite64`, `pwritev`, `pwritev2`,
  `sendmsg`, `sendto`, `write`, `writev`
- `TransferClassified`: `copy_file_range`, `sendfile64`, `splice`, `tee`,
  `vmsplice` (counted as both read and write bytes)
- Non-bytes: all remaining traced syscalls

[Syscall tracing](./docs/syscall-tracing-plan.md) lists every traced syscall by family and
kind and covers the exceptions, such as xattr size probes.
