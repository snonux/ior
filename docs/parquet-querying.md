# Query Parquet recordings with ClickHouse

Press `R` in the TUI to record rows while tracing, or run
`sudo ./ior -parquet trace.parquet` for headless output. The TUI recorder follows the active
global filter. Headless `-parquet` is a raw output mode and does not run the TUI.

The examples use `clickhouse local` from the `clickhouse/clickhouse-server` Docker image.
Mount the directory containing the recording read-only:

```sh
recording_dir=$(pwd)
recording_file=trace.parquet
docker run --rm -v "$recording_dir:/data:ro" clickhouse/clickhouse-server:latest \
  clickhouse local -q "SELECT count(*) FROM file('/data/$recording_file', Parquet)"
```

Use an absolute `recording_dir` if the file is elsewhere. The file schema comes from
[`internal/parquet/schema.go`](../internal/parquet/schema.go):

| Column | Type | Meaning |
|---|---|---|
| `seq` | UInt64 | Event sequence number |
| `time_ns` | UInt64 | Timestamp in nanoseconds since boot |
| `gap_ns` | UInt64 | Gap since the previous traced syscall on the same thread |
| `latency_ns` | UInt64 | Syscall duration (for a call [stopped and resumed](#a-stopped-sleep-is-one-row), the whole call); `0` for the [syscalls that never return](#syscalls-that-never-return) |
| `comm`, `syscall`, `family` | String | Process name, syscall name and family |
| `pid`, `tid` | UInt32 | Process and thread IDs |
| `fd` | Int32 | File descriptor; `-1` when the syscall has none (not `0`, which is a real descriptor) |
| `ret` | Int64 | Return value as seen at `sys_exit`; negative values are errno results, except the kernel-internal restart codes -512, -513, -514 and -516, which are interruptions rather than errors (see the `is_error` rule below); `0` for the [syscalls that never return](#syscalls-that-never-return) |
| `bytes` | UInt64 | Classified payload bytes |
| `address_space_bytes` | UInt64 | Virtual address space added, removed or moved by `mmap`, `munmap`, `mremap` (the larger of old and new size) and `brk` (how far the program break moved since the process's previous `brk`; the first `brk` seen for a process and `brk(0)` queries report 0), rounded up to whole host pages. `msync`, `mprotect`, `madvise` and `mlock*` do not change the address space and report 0. `brk` is tracked per process, not per address space: a `vfork`/`CLONE_VM` child shares its parent's heap, so its first `brk` reports 0 and the parent's next `brk` may absorb heap movement the child caused (exec resets the baseline) |
| `requested_sleep_ns` | Int64 | Requested relative sleep duration; `-1` unknown (null/invalid timespec, `TIMER_ABSTIME`), `9223372036854775807` for requests too large for Int64 (e.g. `sleep infinity`) |
| `nfds` | Int32 | Poll/select count or epoll `maxevents` |
| `timeout_ns` | Int64 | Polling timeout; `-1` infinite, `-2` unknown |
| `file`, `old_file` | String | Resolved path and source path for rename/link calls |
| `is_error` | Bool | Whether the return is a negative errno the program can observe (-1 to -4095, except -512, -513, -514 and -516). See [Restart codes and `is_error`](#restart-codes-and-is_error) |
| `filter_epoch` | UInt64 | Filter generation at capture time |
| `epoll_op` | String | `epoll_ctl` ADD, MOD or DEL |
| `epoll_target_fd` | Int32 | Target descriptor of `epoll_ctl` |
| `epoll_events` | UInt32 | Requested epoll event mask |
| `restarts` | UInt8 | How many kernel restarts ior folded into the row: `0` for an ordinary call, `1` or more for a call that was [stopped and resumed](#a-stopped-sleep-is-one-row) or [re-executed](#a-re-executed-call-is-one-row) after a signal. See [Finding the calls that were interrupted](#finding-the-calls-that-were-interrupted) |

Fields that do not apply to a row use zero or an empty string, except `fd` (`-1`) and
`timeout_ns` (`-1`/`-2`), where zero is a real value. In particular, `file` is the
new path for rename and link calls, and `old_file` is the source path.

A row whose syscall has no file (for example `sync`) has an empty `file` and
`fd = -1`. The terminal views and `-plain` show such rows with the placeholder `N:file`, but the
placeholder is display text only and is never written to a Parquet recording, to the stream CSV
export of the `e` key (both use an empty `file` and `fd = -1`) or to the `.ior.zst` flamegraph
record (an empty path, which `ior collapsed -fields path` shows as `[unknown]`). Only the
`-plain` stdout CSV prints `N:file`, because it is a display stream. `WHERE file != ''`
therefore selects exactly the rows that have a file, and a file really named `N:file` is stored
under that name. To count descriptor-carrying rows use `fd >= 0`. Recordings made before
this change hold `N:file` and `fd = -1` in those rows; filter them with
`file NOT IN ('', 'N:file')`.

### Stream CSV export columns

The TUI stream CSV export (`e`, and `x`/`X` on the paused Stream tab; `E` only opens the last
export in an editor) carries the same per-event fields as the recording, in this order:
`seq, time_ns, gap_ns, latency_ns, comm, pid, tid, syscall, fd, ret, bytes, file, error, family,
requested_sleep_ns, nfds, timeout_ns, address_space_bytes, old_file, epoll_op, epoll_target_fd,
epoll_events, restarts`. The names match the Parquet columns above, except that `error` is the Parquet
`is_error`; `filter_epoch` exists only in recordings. New columns are only ever appended, so a
script that indexes by position keeps working. `old_file` (rename/link source, `file` being the
destination), `address_space_bytes` and the `epoll_*` columns follow the same zero/empty rules
as in the recording. The synthetic warning lines the Stream tab shows (`Trace stopped: ...`,
recorder failures) are UI notes with a wall-clock time and placeholder pid/ret, so they are not
exported; like a recording, the CSV holds only traced syscalls with their boot-clock `time_ns`.
Like the recording, the CSV repairs invalid UTF-8 in `comm`, `file` and `old_file` (the same
code, so both hold identical text for a row), which lets strict readers such as DuckDB's
`read_csv` accept the file: a name cut mid-rune at the capture limit loses the partial rune and
any other invalid byte becomes a literal `\xHH` escape. Valid text is written unchanged.

### Restart codes and `is_error`

When a signal interrupts a blocked syscall, the kernel leaves an internal restart code in the
return register: -512 (`ERESTARTSYS`), -513 (`ERESTARTNOINTR`), -514 (`ERESTARTNOHAND`) or
-516 (`ERESTART_RESTARTBLOCK`). The `sys_exit` tracepoint, which ior reads, fires before the
signal-delivery path decides what user space gets, so these raw values are what `ret` holds.
ior keeps them visible in `ret` but sets `is_error` to `false` and does not count them as
errors (error counters, the errors-only filter, `is_error`). The filter `ret == -512` still
matches, so the rows can be found on purpose.

What the program experiences depends on the restart code and on whether a signal handler ran
(Linux x86, `arch/x86/kernel/signal.c`; see also signal(7), "Interruption of system calls and
library functions by signal handlers"):

- The call is transparently restarted, and the program never saw a failure, when either no
  handler ran (`SIGSTOP`/`SIGCONT`, a ptrace attach, cgroup freezer, a signal whose action is
  ignore or default-continue), or a handler ran and the code allows a restart after it:
  - -513 (`ERESTARTNOINTR`) is always restarted, with or without a handler.
  - -512 (`ERESTARTSYS`) is restarted when no handler ran, or when the handler was installed with
    `SA_RESTART`.
  - -514 (`ERESTARTNOHAND`) is restarted only when no handler ran.
  - -516 (`ERESTART_RESTARTBLOCK`) is resumed via `restart_syscall` only when no handler ran.
  A transparently restarted call is one row with the value it finally returned, so the restart
  code does not appear at all; see the two sections below.
- The program gets a real `EINTR` when a handler ran and the code does not allow a restart:
  -512 without `SA_RESTART`, -514 (`ERESTARTNOHAND`, for example `pause` or `sigsuspend`) and
  -516 (a relative `clock_nanosleep`/`nanosleep` interrupted by a handled signal) always. ior
  still shows the restart code with `is_error=false` in that case, because
  the rewrite to -4 happens after `sys_exit`. If the program then calls the syscall again, that
  retry is a call of its own and a second row (for example `read ret=-512`, then `read ret=1`).

So a row whose `ret` is a restart code is a call the kernel did not carry on as far as ior
could prove: the program got `EINTR`, or the proof was not available (see "When a restart is
not folded" below).
- A call that itself returns `-EINTR` (-4), for example `epoll_wait` when a signal is
  pending, is a genuine result: `ret=-4`, `is_error=true`. Only the four restart codes are
  excluded. `-515` (`ENOIOCTLCMD`) is not a restart code and stays an error.

#### A stopped sleep is one row

A `nanosleep`, `clock_nanosleep`, `poll` or timed futex wait that is stopped without a handler
(`kill -STOP`/`-CONT`, Ctrl-Z and `fg`, a debugger attaching, a cgroup freeze) exits with -516
and is then resumed by the kernel through `restart_syscall`, possibly several times. ior folds
the `restart_syscall` continuation into the interrupted call, so the recording holds a single
row for it:

- `syscall` and the arguments (`requested_sleep_ns`, `nfds`, `timeout_ns`, ...) are the
  original call's, `ret` is what the call finally returned (`0` for a completed sleep), and
  `is_error` follows that value.
- `latency_ns` spans the whole call, from its enter to the final return, including the time
  the process was stopped. A resumed relative sleep still ends at its original deadline, so a
  stop shorter than the sleep does not lengthen it: `latency_ns` is about `requested_sleep_ns`.
- `gap_ns` is the gap before the original call. The call is counted once, and filters (for
  example `-latency`, `-ret`, `-syscall`) judge the folded row.
- `restarts` counts the `restart_syscall` continuations folded into the row: `1` for a call
  stopped once, `2` for one stopped again while it was being resumed, and so on. The -516 is no
  longer in `ret`, so this is what tells the row from a sleep nobody stopped.

ior does not go by the order of the rows for this. `restart_syscall` resumes nothing but a
-516 call, but the `restart_syscall` that follows a -516 row in a recording need not be that
call's: after a handled signal the call has none (the program got `EINTR`), and a later call
of the thread that the recording does not show may be stopped and resumed in turn. So ior
decides in the kernel, as it does for re-executed calls (next section). A thread whose
recorded call exits with -516 is marked; a signal handler delivered to it removes the mark,
and the row is complete as it is; and the `restart_syscall` that a still-marked thread enters
is announced, with its timestamp. Only an announced `restart_syscall` is folded, and only into
the row it was announced for. Neither `rt_sigreturn` nor the later call has to be traced for
that.

A -516 row therefore stays as it is when a handler ran and the program got `EINTR`, when the
trace ended (or the thread exited) while the call was stopped, and when `restart_syscall` is not
traced. In that last case a headless run (`-parquet`, `-plain`, `-flamegraph`) writes the -516
row when the call is interrupted: its syscalls are fixed for the whole run, so ior knows that
nothing will continue the row. In the TUI, where syscalls can be switched on and off while
tracing, the row is also late: nothing ior records marks the moment the call is resumed, so the
-516 row appears only with the thread's next traced syscall or its exit, which can be seconds
after the stop (typically the rest of the sleep). The row itself is correct; only its place in
the output and the time it shows up are affected. Trace `restart_syscall` along with the
sleeping syscalls to get one row per sleep, and in the TUI to avoid the delay. A
`restart_syscall` row whose interrupted call was not traced (the trace started while the process
was stopped, or the original syscall is not traced) also stays. And when some other record of
the thread arrives between the `restart_syscall` enter and its exit (another thread wrote this
thread's `comm` through `/proc/<pid>/task/<tid>/comm`), ior no longer treats what follows as the
continuation: the -516 row stays as it is and is followed directly by a `restart_syscall` row
with the final return value.

The kernel-side decision needs two probes, on `signal:signal_deliver` and
`sched:sched_process_exit`. When either cannot be attached (ior warns at startup), no stopped
sleep is folded: each is its -516 row, followed by a `restart_syscall` row. The same holds,
without a warning, when ior runs with a BPF object built before this kernel-side decision
existed (an `IOR_BPF_OBJECT` override): such an object never announces a `restart_syscall`,
so a sleep stopped twice is three correct rows: the sleep and a `restart_syscall`, both with
`ret` -516, and a `restart_syscall` with the final return value.

The same two rows are what you get under record loss. When the kernel drops records
(ring-buffer backpressure, see the drop counter), the announced `restart_syscall` that
arrives next may resume a later stopped call of the thread, with everything in between lost.
So ior folds a stopped sleep only when it can rule out that any record, of any process, was
dropped between the interruption and the `restart_syscall` (it checks when the
`restart_syscall` is announced and again when it returns, by the rule described under "When a
restart is not folded"). Otherwise the -516 row stays and `restart_syscall` is a row of its
own with the return value it had; no row is lost and both are counted. A sleep stopped
several times is checked stop by stop, so it may be folded up to one of its stops: a row with
`ret` -516 whose `latency_ns` runs to that stop, followed by a `restart_syscall` row.

One exception: when the kernel's drop counter is not available at all (ior warns at startup
and the end-of-run statistics say "ring buffer drops: unknown (drop counter unavailable)"),
stopped sleeps are still folded, without this check. In such a run a burst of lost records
can, rarely, leave one row that starts with one stopped sleep and ends with the result of a
later one of the same thread.

Sampling is not record loss, and the drop counter says nothing about it. By default every
`restart_syscall` is recorded and the above holds. If you sample `restart_syscall` itself
(`-syscall-sampling-syscalls restart_syscall=N`, or a rate for its family,
`-syscall-sampling-families Process=N`; any effective rate other than 1), no stopped sleep of
that run is folded: every -516 row stays as it is, and each `restart_syscall` that is sampled in
is a row of its own. A stopped call's own `restart_syscall` is then recorded only some of the
time, so only some stopped sleeps could be folded at all, and waiting for it would hold every
other -516 row back until the thread's next syscall or its exit; ior keeps the rows of such a
run separate throughout and writes each -516 row when the call is interrupted. Sampling the
interrupted syscall alone (`clock_nanosleep=N`) does not turn the fold off: the sleeps that are
recorded are still one row each. Leave `restart_syscall` at rate 1 when stopped calls matter in
a sampled recording. (An explicit `restart_syscall=1` wins over a family rate.)

#### A re-executed call is one row

A blocked `read`, `accept`, `wait4`, `futex` wait, ... that a signal interrupts exits with
-512, -513 or -514, and the kernel restarts it by running the very same syscall again: at once
when no handler runs (a stop and continue, an ignored signal, a signal another thread took),
or after the handler returns when the code survives a handler (-513 always, -512 with
`SA_RESTART`). ior folds that re-execution into the interrupted call, so the recording holds a
single row for it, shaped exactly like the stopped sleep above:

- `syscall`, the arguments and `gap_ns` are the original call's, `ret` (and `bytes`, `file`,
  `is_error`) is what the call finally returned, and `latency_ns` spans the whole call from
  its first enter to the final return, including the time stopped or spent in the handler.
- The call is counted once, and filters judge the folded row.
- `restarts` counts the re-executions folded into the row, `1` for a call interrupted once.
- The syscalls a signal handler makes before the call is re-executed (its `rt_sigreturn`
  included, when traced) are rows of their own. They complete before the call they
  interrupted, so they are listed before its row; their `gap_ns` is measured from the
  interruption.

A program's own retry after `EINTR` looks the same to the syscall tracepoints (an exit with
the restart code, then an enter of the same syscall), and it is never folded: it is a second
call. ior tells the two apart in the kernel. A BPF probe on `signal:signal_deliver` sees every
handler delivered to a thread with an interrupted call pending and applies the rules listed
above; only when they say the kernel re-executes the call - and, after a handler, only once
that handler has returned through `rt_sigreturn` - is the thread's next syscall enter marked
as the re-execution. The mark carries that enter's timestamp, and only the enter with exactly
that timestamp is accepted for it. Without the mark, or without its enter, nothing is folded.

#### Finding the calls that were interrupted

A folded row holds the call's final return, so `ret` no longer shows that a signal interrupted
it. The `restarts` column does: it is the number of continuations ior folded into the row, of
either kind (a `restart_syscall` after -516, a re-execution after -512/-513/-514).

```sql
SELECT syscall, restarts, count(*) AS calls, max(latency_ns) AS max_latency_ns
FROM file('/data/recording.parquet', Parquet)
WHERE restarts > 0
GROUP BY syscall, restarts
ORDER BY calls DESC;
```

- `restarts = 0` and an ordinary `ret`: the call was not interrupted, as far as ior saw.
- `restarts > 0` and an ordinary `ret`: the kernel interrupted the call that many times and
  carried it on each time; the program noticed nothing. `latency_ns` includes the time the
  process was stopped or spent in the signal handler, which is the usual reason such a row
  stands out in a latency query.
- `restarts = 0` and a restart code in `ret`: the interruption was not folded (the program got
  `EINTR`, or the proof was missing; next section). A continuation that became a row of its
  own - the `restart_syscall`, or the re-executed call - has `restarts = 0` as well.
- `restarts > 0` and a restart code in `ret`: the call was carried on that many times and then
  interrupted once more, and that last interruption was not folded.
- A `restart_syscall` row can have `restarts > 0` too: when it is a row of its own (the call it
  resumed is not in the recording, or that fold was refused) and was stopped in turn, the
  `restart_syscall` calls that followed are folded into it.

The count stops at 255: a call restarted more often than that (a sleep in a process that is
stopped and continued in a loop) reads 255, never a small number again. Every interruption that
is folded is counted, and nothing else is: `restarts` says how often ior joined pieces of one
call, not how many signals the thread received. The syscalls of a signal handler, a program's
own retry after `EINTR` and the calls of a run that folds nothing (see below) all have 0.

The column was appended to the schema after the others. A recording made before it has no
`restarts` column, so a query that names the column fails on such a file with an unknown-column
error; every other query is unaffected, and a recording with the column reads as before in a
tool that does not know it. The stream CSV export has `restarts` as its last column for the
same reason. `-plain` output and the Stream tab do not show it.

#### When a restart is not folded

The fold errs on the side of two rows. A kernel-restarted call keeps its restart-code row,
followed by a second row for the continuation (if that was recorded at all), when:

- the proof is missing: the `signal_deliver` or the `sched_process_exit` probe could not be
  attached (ior warns at startup; nothing is folded in such a run), or the kernel's drop
  counter is not available to ior (no -512/-513/-514 call is folded in such a run; a stopped
  sleep, -516, still is), a control record was lost to ring-buffer backpressure, or two
  threads whose ids collide in the kernel-side table were interrupted at the same time;
- the call is a stopped sleep (-516) and `restart_syscall` is not traced: there is no
  continuation to fold, and the -516 row is all the recording has of the call;
- the continuation's enter or exit was not recorded: sampled out, lost, or the trace ended or
  the thread exited first. With 1-in-N sampling of the syscall this is the common case: both
  halves are sampled independently, so a re-executed call is folded only when both happen to be
  recorded; otherwise you see the restart-code row alone, the continuation alone, or neither;
- the run samples `restart_syscall` (its effective rate, from
  `-syscall-sampling-syscalls restart_syscall=N` or `-syscall-sampling-families Process=N`,
  is not 1). Then no stopped sleep (-516) is folded, not even one whose `restart_syscall`
  happens to be recorded: see "A stopped sleep is one row". Re-executed calls
  (-512/-513/-514) are not affected by that rate;
- ior cannot rule out that the kernel dropped a record, any record of any process, between
  the interruption and the continuation's exit (see the drop counter). This applies to both
  folds, the stopped sleep (-516, continued by `restart_syscall`) and the re-executed call;
  only a stopped sleep in a run without a drop counter is folded unchecked. ior cannot know
  whose records were lost, so it folds nothing across a possible loss. The drop counter says how
  many records were lost, not when, so ior goes by when it first read the current count: a
  loss it had already seen before the call was interrupted does not matter, however recent,
  while a loss it first sees after the interruption counts as possibly later than it, even
  if it happened shortly before (ior reads the counter once a second, and again when it is
  about to fold). A fold refused for this reason costs no row: the
  restart-code row and the continuation's row are both recorded;
- you attached or detached syscall probes in the TUI's probes modal (`o`/`O`) after the call
  was interrupted and before its continuation was complete. While a syscall's probes are off
  ior cannot see a call being re-executed, and after they come back the thread's next call of
  that syscall would look like the continuation. So every probe change, of any syscall, ends
  the wait for all calls interrupted before it - or while it was under way: a probe's enter
  and exit side are attached one after the other, and for as long as a probe is being
  switched on ior folds nothing at all - and each is recorded as its restart-code
  row, and its continuation, if ior sees it, as a row of its own. Toggling a whole family
  changes its probes one after the other, so nothing is folded while that runs. Calls
  interrupted after the change are folded as usual;
- another record of the same thread arrived between the continuation's enter and its exit.
  The fold only takes an exit that directly follows the enter; a thread's `comm` being written
  by another thread (`/proc/<pid>/task/<tid>/comm`), or the exec record of a successful
  `execve`, in between ends it. Both rows are recorded: the restart-code row, then the
  continuation with the real result. An `execve` that was interrupted and restarted (-513: a
  signal arrived while it waited for a concurrent exec or a ptrace attach in its thread group)
  and then succeeded is therefore two rows rather than one folded row, `execve ret=-513` and
  `execve ret=0` (as long as both calls were recorded: not sampled out, and the exec record
  itself not lost), also
  when a thread other than the main thread made the call (both rows carry that thread's id);
- a restarting signal handler replaced the program with `execve` instead of returning: the
  interrupted call is never re-executed and keeps its restart-code row, listed before the
  `execve` row;
- a signal handler made more than about a hundred traced syscalls before returning, never
  returned (it left through `siglongjmp`), or was itself interrupted in a blocking call (that
  inner call is folded instead);
- a second signal with a handler arrived after the kernel had already set the restart up
  (ior judges that handler as if it had decided);
- the process is a 32-bit one (its syscalls are not traced at all).

A few exotic situations can make ior fold the wrong call into the row. In most of them the
kernel-side mark is left standing although no re-execution follows it (or ior never sees the
one that does), and the wrong fold happens only if the first syscall of that thread that ior
traces afterwards is the same syscall as the interrupted one - for a stopped sleep, the
`restart_syscall` of a later stopped call that is itself not recorded - (any other traced
syscall takes the mark and the row stays as it was):

- a signal handler that rewrites the saved user context to resume other code (a preemptive
  user-level thread switch), or a nested handler that leaves through `siglongjmp` into an
  outer handler;
- a debugger or tracer rewrites the registers of the interrupted call while the thread is
  stopped for the signal or at that call's syscall-exit stop, so the kernel neither restarts
  the call nor runs a handler (a `gdb` inferior function call);
- the re-executed call is taken away before the kernel's syscall-enter tracepoint, so ior
  never sees the re-execution: a tracer that cancels it or changes its syscall number at the
  syscall-entry stop (`strace --inject` with `error=` or `retval=`), a seccomp
  user-notification supervisor, or syscall user dispatch;
- a kernel or driver bug returns the restart code to the program with no signal pending.

Switching probes off and on in the TUI's probes modal is not among them: a call that was
interrupted and not yet completed when probes change, or that is interrupted while a probe
is being switched on, is not folded at all. The one exception is a run that warned that it
could not determine the boottime offset of its time namespace, if that offset is in fact
negative: ior's clock readings are then older than the timestamps they are compared with,
and switching the `restart_syscall` probes on while a thread is stopped and continued twice
within that one switch can still mark the later call.

One situation is different: the kernel did re-execute the call and the mark was right, but
the enter it announced was sampled out, and the timestamp that should tell that enter from
the thread's next call of the same syscall cannot:

- on a machine whose clocksource is too coarse to give two syscalls of a thread different
  timestamps (`jiffies`), a sampled-out re-execution followed within the same tick by another
  call of the same syscall, which is then folded in its place.

Kernel-side aggregate counts (sampled-out or aggregate-only syscalls) are per invocation and
are not folded.

Because ior waits for the thread's next records to decide whether an interrupted row is
carried on, such a row appears in the stream only when ior sees the thread's next traced
syscall, the signal handler being delivered, or the thread's exit (for a folded call, when
the call completes; in the TUI also when you change probes), so rows of other threads may be
listed before it. For a row that
stays as it is the wait is usually microseconds, except for a stopped sleep (-516) in a TUI
session that does not trace `restart_syscall`: that row appears only with the thread's next
traced syscall or its exit, seconds later for a long sleep (see "A stopped sleep is one row").
A headless run that does not trace `restart_syscall` does not wait for such a row at all,
and neither does any run, TUI or headless, that samples `restart_syscall`.

### Syscalls that never return

`exit`, `exit_group` and `rt_sigreturn` never return to their caller, so the kernel fires no
`sys_exit` tracepoint for them. ior records each call as a row at `sys_enter` instead, with
`time_ns` and `gap_ns` as for any row but `latency_ns = 0` and `ret = 0` as placeholders (there is
no latency and no return value) and `is_error = false`. Leave them out of latency statistics, for
example with `WHERE syscall NOT IN ('exit', 'exit_group', 'rt_sigreturn')`. ior's own views
already do:

- The stats engine counts them as calls without a duration, so they are in every call count
  but in no latency mean, minimum, maximum, percentile or histogram.
- The Stream tab shows `-` for their latency and return value, and `Enter` on one of those
  `-` cells of a paused stream pushes no filter. `-plain` leaves the `ret` column empty.
- The Syscalls and Processes tabs (tables, bubble and treemap details) show `-` in the latency
  columns of a syscall or process that has no timed call at all, such as a process seen only at
  its `exit_group`. One with timed calls shows the figures of those calls alone.
- A `latency` or `ret` filter never selects these rows, whatever its comparison (`ret == 0`,
  `ret != 0`, `latency < 1ms`, `latency >= 0` all leave them out), because they have no value to
  compare; neither does errors-only. Filters on the other fields (syscall, comm, pid, gap, ...)
  select them as usual.

Recordings made before this change hold no rows for these syscalls at all.

### Invalid UTF-8 in `comm`, `file` and `old_file`

These columns are Parquet STRING (UTF-8) columns, and strict readers such as DuckDB reject
every query that touches a column holding an invalid byte. Traced text is not always valid
UTF-8: the kernel cuts `comm` at 15 bytes even in the middle of a multi-byte character, and any
local user can create a file name with arbitrary bytes. So that recordings stay queryable, ior
sanitizes these three columns when it writes them:

- A partial multi-byte character at the end of `comm` (the kernel's cut) is dropped, so
  `ääääääääää` is stored as `äääääää`. The same is done for `file` and `old_file`, but only for
  a captured path that is exactly as long as the capture limit (255 bytes), or for the 255
  bytes plus the `...` ior appends to an over-long `getcwd` path. Only in those cases can ior
  tell that the path was cut mid-character. A relative path resolved against its directory
  descriptor is trimmed before it is joined to the directory, so the joined `file` value may
  be longer than 255 bytes. A shorter path that ends in a stray lead byte is a real (odd)
  file name and is escaped like any other invalid byte, as described next.
- Any other invalid byte is stored as the four characters `\xHH` in lower-case hex (the notation
  `-escape` uses), so a file named `f`, byte 0xff, `inv` is stored as `f\xffinv`. This includes a
  `comm` such as `a`, byte 0xff, `b` set with `prctl(PR_SET_NAME)`. Valid characters are never
  changed.

The mapping is not reversible: a name that literally contains the characters `\xff` is stored
the same as one containing the byte 0xff, and a backslash is not doubled. To find affected
rows, search for the two characters `\x` in the column.

This sanitizing always happens for Parquet output, whatever `-escape` says: `-escape` only
controls terminal output (`-plain`, `ior collapsed`) and has no effect on recordings.
Recordings made before this change may still hold raw invalid bytes in these columns, and
DuckDB keeps rejecting queries that touch the affected column in those files; they are not
rewritten. ClickHouse reads them fine, and `count(*)` or queries that skip the affected column
work in DuckDB too.

## Queries

Replace `recording.parquet` in these queries with the filename mounted at `/data`.

```sql
DESCRIBE TABLE file('/data/recording.parquet', Parquet);

SELECT syscall, count(*) AS calls
FROM file('/data/recording.parquet', Parquet)
GROUP BY syscall
ORDER BY calls DESC
LIMIT 15;

SELECT syscall, ret, count(*) AS calls
FROM file('/data/recording.parquet', Parquet)
WHERE is_error
GROUP BY syscall, ret
ORDER BY calls DESC
LIMIT 15;

SELECT syscall, count(*) AS calls,
       quantile(0.50)(latency_ns) AS p50_ns,
       quantile(0.99)(latency_ns) AS p99_ns
FROM file('/data/recording.parquet', Parquet)
GROUP BY syscall
ORDER BY p99_ns DESC
LIMIT 15;

SELECT file, sum(bytes) AS total_bytes, count(*) AS calls
FROM file('/data/recording.parquet', Parquet)
WHERE file != ''
GROUP BY file
ORDER BY total_bytes DESC
LIMIT 15;

SELECT intDiv(time_ns, 10000000) AS bucket_10ms,
       count(*) AS calls, sum(bytes) AS bytes
FROM file('/data/recording.parquet', Parquet)
GROUP BY bucket_10ms
ORDER BY bucket_10ms;
```

### Sampled recordings

A recording of a run with an explicit sampling rate (`-syscall-sampling-syscalls read=10`,
`-syscall-sampling-families`) holds only a sample of the sampled syscalls: about 1 in N
invocations of a rate-N syscall is written as a row, and none of a rate-0 (aggregate-only)
one. The file footer says so, in two key/value pairs that are absent from a recording that
traced everything:

- `ior.sampling`: the effective rates, for example `read=10,write=0`. A family-wide rate
  (`-syscall-sampling-families FS=10`) is named once, as `FS=10` (upper-case family names,
  lower-case syscall names), not once per syscall; an explicit per-syscall rate is listed
  next to it (`FS=10,read=5`). Only syscalls whose probe was actually attached are named.
- `ior.sampling.totals`: the exact population of each sampled syscall that was invoked,
  written when the recording ends, as JSON, for example
  `[{"syscall":"read","rate":10,"traced":110,"counted_only":890,"total":1000}]`:
  `traced` is the number of invocations ior handed to the recorder, `counted_only` the
  invocations only the kernel counted, `total` their sum. `traced` is not always the
  number of rows in the file of a headless recording: a pair of a probe that is not active
  is counted as traced but has no row, so compare `total`, not the row count, with the
  population (headless `-parquet` never sheds rows, it waits for the writer; for TUI
  recordings see below). When events were lost (the run statistics say
  `ring buffer drops: N` or `records discarded at stop: N`), the lost rows are in neither `traced` nor `counted_only`: every
  element then carries `"lower_bound":true` and its numbers are a lower bound (the true
  total is at least that). The value is the word `unavailable` when the totals cannot be
  trusted at all (a filter the kernel counters cannot apply, or a failed read of them).

Row counts of sampled syscalls in such a file are therefore not the population; use
`ior.sampling.totals` for that. The kernel counts carry no bytes, files or latency
percentiles: those stay sampled. Read the footer with, for example,
`SELECT decode(key), decode(value) FROM parquet_kv_metadata('trace.parquet')` in DuckDB.

#### TUI `R` recordings

A TUI recording (`ior.mode` = `tui`) carries the same two keys, in the same format, whenever
a sampled syscall's probe is attached when you press `R`. In the TUI, `futex`, `futex_wait`,
`futex_wake`, `futex_requeue`, `futex_waitv` and `clock_gettime` are aggregate-only (rate 0)
unless you pass a rate for them, so they never have a row in a TUI recording. They belong to
the IPC and Time families, though, and the TUI attaches only the FS family by default
(`-trace-families`), so a default TUI recording traces none of them and carries neither key.
Attach them (for example `-trace-families FS,IPC,Time`, `-trace-syscalls`, or the probes
modal) and the recording is marked `clock_gettime=0,futex=0,futex_requeue=0,...`, with their
true counts in `ior.sampling.totals`. Pass `-syscall-sampling-syscalls futex=1,...` to record
them as rows; a recording whose attached syscalls all have rate 1 is unmarked. What the keys
mean for a TUI recording:

- `ior.sampling` lists the sampled syscalls whose probe is attached when the recording starts
  (`R` pressed). The rates themselves cannot change while ior runs, so they hold for the whole
  file. A sampled syscall whose probe you attach later in the probes modal (`o`) is not in
  this key but appears in `ior.sampling.totals`, with its `rate`, once it was invoked.
- `ior.sampling.totals` covers this recording only: the rows it holds (`traced` is the
  number of rows in the file here, since it is counted where the rows are written) plus the
  invocations the kernel counted while it ran. Each `R` recording starts from zero, so two
  recordings of one trace do not share counts, and the kernel counters and the ring-buffer
  drop counter are read when the recording starts and stops (and before a filter change
  restarts the trace), so no invocation or drop from before the start or after the stop is
  attributed to it. The dashboard's auto-reset (`I`, 30s by default) and the `r` key do not
  affect it. Rows still in flight between the kernel and the recorder at the start or stop
  are attributed by when they reach the recorder, like any row of the file.
- The elements carry `"lower_bound":true` when events were lost while recording: ring-buffer
  drops (including those of the last moments before the stop), rows shed by the recorder's
  full queue (the status line then shows `rec: ... (dropped N)`), or a filter change that
  restarts the trace while its event loop is still running: the old trace's rows that had
  not reached the recorder yet are discarded with it, as the raw modes' `records discarded
  at stop` are.
- The value is `unavailable` when kernel counts arrived during the recording while a filter
  was active that the syscall-keyed kernel counters cannot apply (anything besides syscall, family, and
  the PID/TID the trace was started with: comm, file, latency, ...), or a read of the
  counters failed, including the one right before the recording starts (counts from before
  the start could then end up in the totals). The rows then follow the filter but the
  kernel-only invocations could not be counted under it.

`time_ns` is a boot-relative clock, so join it to wall time only if you have an independent
boot-time reference, and it must be the host's (inside a time namespace `uptime` and
`CLOCK_BOOTTIME` are shifted by the namespace's offset, `time_ns` is not).

## Check a recording

`mage parquetValidate` uses ClickHouse in Docker. It reads the latest timestamp-named
`*.parquet` in the repo root unless `PARQUET_FILE` is set:

```sh
mage parquetValidate
PARQUET_FILE=/absolute/path/to/trace.parquet mage parquetValidate
```

The target checks for all 23 columns, a nonzero row count, a nonzero minimum `time_ns`, and
a `seq` range with `max(seq) > min(seq)`. That last check does not prove row-by-row
ordering, and a one-row file fails it.
