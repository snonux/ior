# Troubleshooting and known limitations

## Warnings in the TUI

Setup and runtime warnings (a `-tid` that is not a thread of `-pid`, no probe attached,
libbpf warnings, dropped events) are rows in the Stream tab (`7`), whatever its filter. While
the stream holds any, the status line of every other tab shows `warnings: N (7:Stream)` in the
warning colour, shortened to `warn: N (7)` or `!N` and then dropped on a narrow terminal
before the filter summary is cut. It goes away once those rows scroll out of the stream's
10000-row buffer or a new PID/TID selection clears the stream. The Stream tab itself shows no
badge, although the rows need not be on screen there: a paused stream does not show warnings
that arrived after the pause (press space to resume), and an early warning scrolls up out of
the live view (press `g` to jump to the oldest rows). A warning row is one line, cut at its end;
pause the stream (space), select the row and press `Enter` to read the whole message (`Esc` or
`Enter` closes it, `j`/`k` scroll a long one).

## libbpf diagnostics

libbpf's own diagnostics are reduced to its warnings: in `-plain`, `-flamegraph` and
`-parquet` runs they go to stderr, in full (a failed BPF load is explained there). In the
TUI they appear as setup warnings when setup succeeds, and when the BPF load or attach
fails they are appended to the error screen under `Warnings logged during setup:`. A
rejected program is condensed there to one row: its name plus the last three lines of the
kernel verifier log (the offending instruction, the reason such as
`R1 invalid mem access 'scalar'`, and the `processed N insns` statistics) and a
`... (N more lines)` marker for the rest. Each row is cut to at most 512 bytes and only then
are its control characters shown escaped, so a row with many control or invalid bytes can
end up to about four times longer; at most 8 rows are listed (`... and N more warning(s)`
counts the others). The error screen fits the terminal at any size: text taller than the
terminal is cut with a `... (N more lines)` row and every line, the key hint included, is
wrapped or cut to the terminal width, so the key hint stays visible. For the complete
verifier log rerun the same options with `-plain` and
read stderr. The thousands of INFO/DEBUG lines libbpf prints while loading are
dropped by default. To see them in a headless run, for example when a BPF program fails to
load, set `IOR_LIBBPF_DEBUG=1` (`0`, `false`, `no` and `off` keep it off; the TUI ignores it
because its screen owns stderr):

```sh
sudo IOR_LIBBPF_DEBUG=1 ./ior -plain -duration 5 2> libbpf.log > /dev/null
```

`./ior -help` lists the variable too.

## Known limitations

- **io_uring changes descriptors without a syscall.** `IORING_OP_CLOSE` and
  `IORING_OP_OPENAT` (and the other ring operations that open or close a descriptor) are
  executed by the kernel from `io_uring_enter` (or a worker thread) and fire no
  `sys_enter`/`sys_exit` tracepoint, so ior never sees the descriptor change. If a program
  closes an fd through the ring and the number is reused by another open, ior notices on
  the next row that says which file the descriptor is (see the next item) and looks the
  name up in `/proc/<pid>/fd`; without that check, later rows on that fd keep the file ior
  last bound to it (for example `pread64` rows still show the old path while the kernel
  reads the new file). Descriptors the program opens and closes with
  ordinary syscalls are tracked correctly; the `io_uring_setup`, `io_uring_enter` and
  `io_uring_register` calls themselves are traced as usual.
- **A ring addressed through the registered-ring table is named only when ior saw it
  being registered.** `io_uring_enter` with `IORING_ENTER_REGISTERED_RING` (what liburing
  does after `io_uring_register_ring_fd()`) passes a per-thread table index instead of a
  descriptor. ior follows `IORING_REGISTER_RING_FDS`/`IORING_UNREGISTER_RING_FDS` and
  names such rows after the ring (`anon_inode:[io_uring]`, with the ring's descriptor
  while that number still is the ring's, fd -1 once it was closed - a registered ring
  stays usable after its descriptor is closed). `-plain` prints the index in front of the
  name, `io_uring:reg[0]=anon_inode:[io_uring]%(5,O_RDWR|O_CLOEXEC)`; everywhere else
  (the `-path` filter, the file ranking, the stream CSV export and Parquet recordings) the
  file is the plain ring name `anon_inode:[io_uring]`, so these rows count with the ones
  that address the same ring by its descriptor, and `-path 'io_uring:reg'` matches only
  the rows of a ring ior could not name. A ring registered before the trace
  started, by a thread or `io_uring_register` probe the trace does not cover, or whose
  registration record was lost keeps the label `io_uring:reg[<index>]` with fd -1, and so
  does a ring created with `IORING_SETUP_REGISTERED_FD_ONLY`, which has no descriptor.
- **Rows are checked against the file behind the descriptor only on kernels with the
  `bpf_rdonly_cast` kfunc (mainline 6.2 and newer), and only for some syscalls.** On such a
  kernel the records of the single-descriptor
  syscalls (`read`, `write`, `pread64`, `close`, `fsync`, `fstat`, ...) say which file the
  descriptor named when the call entered (the low 32 bits of its inode number), and the
  `open` family says which file it returned. A row is named only after that file: a
  descriptor that was rebound behind ior's back (io_uring, an untraced or lost call) is
  looked up again, and a `/proc/<pid>/fd` answer that describes another file - the number
  was closed and reused before ior got to the row - is not used. Such a row has no name;
  the plain output shows `E:ino:<n>` (the identity) instead of `E:name`, also for rows of a
  process that exited before ior got to them (when ior did not see the descriptor opened):
  ior cannot name a file that is no longer open when it looks, and the kernel side reports
  no name for `read`, `write` and the other frequent calls, where it would cost too much.
  A row whose call began before
  the descriptor number was bound to its current file (a `read` that blocked while another
  thread closed the number and an `open` returned it again) is left unnamed as well. The
  exception is `close`: for a descriptor ior never saw opened (opened before the trace, or
  by a call outside the trace set) it is named from a `/proc` answer read before that close
  began, and otherwise by the **last path component only**, which the kernel side reads
  from the file as the close begins. Such a row's file is `*/name` (`*/app.log` for
  `/var/log/app.log`; `*/<first 67 bytes>...` for a longer component): the directories are
  not known, so it does not match a `-path` filter for a directory and is not grouped with
  rows that carry the file's full path. Files of different directories that share a last
  component share the name too: two such closes of `/var/log/app.log` and `/srv/app.log`
  are both `*/app.log`, one file in the Files views and one value of the Parquet `file`
  column, and the directory-grouped views count them in the row of names without a
  directory (`.`), next to pipes and sockets. Pipes, sockets, eventfd and the like and
  memfds have no such component and stay `E:ino:<n>`, as do `close_range` rows and the
  close of the root of a mount: the root directory of a filesystem, a mounted subvolume, a
  bind-mounted directory, and a single file that is bind-mounted (a container volume, a
  Kubernetes `subPath`) - the kernel knows such a root by the name it has where it comes
  from, not by the name the process opened. A file *below* a bind-mounted directory is
  named, by its own last component. On a rename racing the close the component can be the
  old name, a prefix, or for a short name a mix of old and new bytes. Not checked, so still named by descriptor number alone: every row on a
  kernel without the kfunc (mainline before 6.2 and RHEL 8; RHEL 9 backports much of BPF and
  may have it, which is unverified - ior asks the kernel's BTF and switches the check off
  where it is missing), rows of syscalls whose record has no identity (`recvfrom`, `ioctl`,
  `fcntl`, `mmap`, `epoll_ctl`, ...), and files the identity cannot tell apart: the
  descriptors that share the kernel's anonymous inode (eventfd, epoll, io_uring, timerfd), a
  file that got the inode number of one unlinked just before (ext4 and xfs reuse a freed
  number at once), files with the same inode number on different filesystems or in
  different subvolumes or snapshots of one btrfs filesystem, and inode numbers that differ
  only above bit 31. The check was loaded and run on Linux 7.2 only; if another kernel's
  verifier refuses it, ior warns and loads once more without it. `IOR_FILE_IDENT=0` in
  ior's environment switches the check off, and with it the `*/name` of a close; neither
  exists on a kernel without the kfunc.
- **Calls a seccomp filter denies have no row.** The filter runs before `sys_enter`, so only
  `sys_exit` fires; ior drops an exit it has no enter for. They are not counted as
  mismatched enter/exit pairs either, but they do show in the `exits without an enter`
  statistic (see *Lost enter and exit records* below), among those that look like a
  filter's answer. So does a call a filter traps (`SECCOMP_RET_TRAP`, as browser sandboxes
  do). A call handed to a supervisor (`SECCOMP_RET_USER_NOTIF`) is counted in that line
  too, but in the share only when the supervisor fails it: a success it makes up cannot be
  told from a lost enter. All of this needs a thread ior has seen before and a syscall
  that is not sampled.
- **Time namespaces: timestamps are the host's.** The kernel stamps every record with the
  host's boot clock, which a time namespace does not shift, so `time_ns` is the host's
  `CLOCK_BOOTTIME` even when ior runs inside a namespace with a boottime offset
  (`unshare -T --boottime N`), where `clock_gettime` and `/proc/uptime` read `N` seconds
  more. ior reads the offset of its own namespace from `/proc/self/timens_offsets` at
  startup and takes it out of its own clock readings, so its bookkeeping (naming the close of
  a descriptor opened before the trace, folding an interrupted call with its restart) works
  as it does on the host. If the offset cannot be determined (the file is unreadable,
  malformed or missing although the kernel has time namespaces, or it describes another
  namespace than the one ior runs in), ior assumes none and warns once per trace session
  (on stderr in the headless modes, as a warning row in the TUI, again after each restart of
  the trace); with an actual offset such closes may then be unnamed or named after the file
  that reused the number, and interrupted calls may stay two rows or, with a negative offset,
  be folded with a later call (after lost records, or after a probe change in the TUI). With
  a positive offset ior also learns of a skipped probe run (next item) up to one poll of its
  loss counters late, and may fold an interrupted call across it in that time.
- **The kernel can skip a probe without running it.** A BPF tracepoint program is not run
  while another task was preempted on that CPU in the middle of the same program (the
  syscall probes on Linux 7.2) or of a BPF map operation of any program on the host (the
  syscall probes up to at least Linux 6.19; the process and signal probes on both). The
  events of those calls are missing although the ring buffer never filled. From Linux 6.7 on
  the kernel counts these runs and ior reports them: a `Kernel skipped N probe runs` warning
  while it happens, and `probe runs skipped by the kernel: N` in the end-of-run statistics,
  next to `ring buffer drops`. The count is taken before ior's filter and covers every task
  on the host, so it says that events *may* be missing, not how many: with `-pid`, `-tid` or
  `-comm` it includes the calls of tasks outside the filter, and can be large while the
  trace is complete. ior acts on it on the safe side: an interrupted call is not folded with
  its restart across a skipped run of the probes that fold depends on (the call's own
  syscall, `restart_syscall` for a stopped sleep, and the process and signal probes; two
  rows instead of one), and sampling totals are
  labelled `at least`. On an older kernel the line reads `not counted`, and such a loss
  leaves no trace. It needs a preemption inside the kernel, so it is rare on a desktop and
  common where real-time tasks or `preempt=full` preempt a syscall-heavy CPU.
- **Lost enter and exit records.** A dropped record or a skipped probe run usually costs a
  call one of its two halves, and such a call has no row. The end-of-run statistics count
  them for the traced calls themselves, next to the mismatched pairs (an exit paired with
  the enter of another syscall): `enters without an exit: N` is an enter the same thread's
  next enter superseded, so its exit record was lost; `exits without an enter: N` is an exit
  of a thread ior had seen enter a syscall before, so its enter record was lost - or the call
  was one a seccomp filter answered itself, which fires `sys_exit` only. The line says how
  many of them `look like a filter's answer`: they returned an error (`SECCOMP_RET_ERRNO`,
  or `SECCOMP_RET_TRACE` without a tracer), or they "returned" the syscall's own number,
  which is what a trapped call leaves (`SECCOMP_RET_TRAP` does not fail: the kernel rolls
  the return register back to the syscall number and raises `SIGSYS`; on x86_64 a trapped
  `sched_getscheduler` shows a return value of 145). A count made of those only points at
  a filter, not at loss - on a desktop a browser's sandbox produces them all the time. It
  is a hint, not a proof: a call that lost its enter can fail too or return its own number
  (on x86_64 a `read` of 0 bytes, a `write` of 1 byte), a filter that answers with errno 0
  or through a supervisor (`SECCOMP_RET_USER_NOTIF`, which may report success) is not
  recognised, and the syscall numbers are known for x86_64 only (elsewhere only the failed
  exits are recognised). A ptrace tracer normally makes no such exit: one that cancels a
  call by setting its number to -1 silences both halves, and only `PTRACE_SYSEMU` leaves the
  exit alone. Syscalls that are sampled or aggregate-only (`-syscall-sampling-syscalls` and
  the built-in defaults) emit no exit without an enter at all, so neither a lost enter nor
  a filter's answer shows for them.
  Calls that only look like a lost half are not counted: a call in flight when the trace
  started or stopped, a new thread's first return from `clone`/`fork`, a task killed inside
  a syscall, `exit`/`exit_group`/`rt_sigreturn` (they never return), an open the `-path` or
  `-comm` filter dropped at its enter, a call whose enter fell out of ior's bounded table of
  pending enters, an `execve` returning under another thread id, a call ior folds with its
  restart, and a call that may have run while its probes were still being attached.
  Sampling never cuts a call in half: an exit is recorded exactly when its enter was.
  Both counts are lower bounds and stay far below the kernel's own figures when records are
  dropped in bulk: a lost exit is only found when its thread enters another traced syscall
  (never for a thread's last traced call); a thread that loses the exit of one call and the
  enter of its next call of the same syscall pairs the two leftovers into one wrong row,
  with no count; a call that lost both halves, or a lost enter of a thread ior had not seen
  yet, leaves nothing to count. The statistics block is printed by headless runs only; the
  TUI does not show these counts. Where the TUI's probes dialog
  attaches or detaches a probe, halves around the change are left out as far as the change
  is known to the event loop, but a detach in progress can still count an exit that was
  merely no longer traced.
