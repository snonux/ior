# Syscall tracing

`ior` groups generated syscall tracepoints by family and kind. The full syscall lists are
generated from the kernel used for the committed artifacts; copying them into a prose page
would go stale. Read `syscallFamilies` and `syscallKinds` in
[`internal/tracepoints/generated_tracepoints.go`](../internal/tracepoints/generated_tracepoints.go)
for the committed set, and run `./ior -help` for selector values accepted by the current
binary. A target kernel may lack some of those tracepoints; attachment skips them with a
warning.

## What attaches

With no trace selection flags, `ior` attaches the **FS** family only. The other families
(Network, Memory, Signals, Sched, IPC, Time, Process, Security, Polling, AIO and Misc)
require an explicit selector.

```sh
sudo ./ior -trace-families Time,Polling
sudo ./ior -trace-kinds fd,open -no-trace-syscalls read
sudo ./ior -trace-syscalls openat,recvmsg,nanosleep -no-trace-kinds null
```

`-trace-families`, `-trace-kinds` and `-trace-syscalls` add matching syscalls to the attach
set. `-no-trace-families`, `-no-trace-kinds` and `-no-trace-syscalls` remove matches. The
generated registry, not this page, is the authority for each syscall's family and kind.

The selector kind describes a syscall's role. It is separate from the BPF record type. For
example, fd xattr calls still select as `fd` even though their requested size now travels in
a dedicated `fd_size_event`; `memfd_create` still selects as `eventfd`, and `move_mount`
as `two-fd`. This wire split reduced ordinary ring-buffer records without changing selector
behavior.

## Counts and sampled detail

`-syscall-sampling-families` and `-syscall-sampling-syscalls` accept `name=rate`: `0` keeps
aggregate counts only, `1` emits every event, and `N` emits about one in N events. Futex
variants and `clock_gettime` default to aggregate-only in the TUI.

The kernel aggregates the invocations it does not emit. Aggregate rows plus emitted rows
therefore give exact TUI counts, errors, latency sums and histograms for sampled syscalls.
Stream rows, file/process attribution, bytes, gaps and latency percentiles still come only
from emitted events. A runtime filter with an unsupported aggregate dimension temporarily
gates aggregate ingestion off.

Headless `-plain`, `-flamegraph` and `-parquet` modes have no TUI aggregate sink. They
promote aggregate-only defaults and explicit family rate `0` to `1`; explicit per-syscall
rate `0` remains the caller's choice and produces no rows for that syscall.

## Byte and argument semantics

[`internal/generate/classify.go`](../internal/generate/classify.go) assigns return-value
classifications. Positive results from read-like calls such as `read`, `recvmsg` and
`getxattr` count as read bytes; write-like calls such as `write` and `sendto` count as write
bytes. Transfers such as `copy_file_range`, `sendfile64` and `splice` contribute to both
totals. Other return values do not count as throughput bytes. Address-space extent from
memory syscalls is a separate metric.

A `getxattr*` or `listxattr*` call with a zero output-buffer size asks for the required
capacity. Its positive return is kept in the row, but its throughput byte count is zero.
`syslog` is also non-bytes because the meaning of its return depends on the action.

For a transfer with two descriptors, the file row names one endpoint: the destination fd for
`sendfile64`, `copy_file_range`, `splice` and `tee`. `vmsplice` uses its single pipe fd.
Aggregate transfer bytes still contribute to both read and write totals.

`openat2` reads the flags word from the user-provided `open_how` struct. NULL or unreadable
pointers keep an unknown sentinel distinct from `O_RDONLY` (zero). Open-family handlers
retry a filename read at syscall exit when the enter-side nofault read failed; the
`OPEN_NAME_FIXUP_EVENT` control record repairs the pending enter event. Other pathname, name
and exec handlers do not yet have that retry.

Polling records preserve `nfds` (or `maxevents` for epoll waits), timeout and the epoll
instance descriptor where applicable. `timeout_ns = -1` means an infinite wait; `-2` means
unreadable, invalid or unrepresentable. Non-negative values are captured nanoseconds.

## Dashboard

The dashboard has seven tabs: Flamegraph, Overview, Syscalls, Files, Processes, Latency +
Gaps and Stream. Syscalls shows each call's family in a column; there is no separate Non-IO
tab. Use `tab` / `shift+tab` or `1`–`7` to navigate. The [tutorial](./tutorial/tutorial.md)
covers the keys and output modes.
