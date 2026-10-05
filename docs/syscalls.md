# Syscall tracing

`ior` groups generated syscall tracepoints by family and kind. The lists below mirror
`syscallFamilies` and `syscallKinds` in
[`internal/tracepoints/generated_tracepoints.go`](../internal/tracepoints/generated_tracepoints.go).
They describe the tracepoints of the kernel used to generate the committed artifacts. The
`docs_drift_test.go` tests in that package fail when a list here diverges from those maps,
so update this page together with `mage generate`. Run `./ior -help` for the selector values
accepted by the current binary. A target kernel may lack some of these tracepoints;
attachment skips them with a warning.

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

The flags only choose the startup set. In the TUI, the probes modal (`o`, or `O` on the Flame tab where `o` cycles the frame order) changes it at
runtime: its Syscalls view toggles single probes, and its Families view (`tab`) lists every
family with its attached/total probe count and attaches or detaches a whole family with
`space`/`enter` (detach when any of its probes is attached, attach otherwise). Family
membership is the same registry `-trace-families` uses. A family batch runs in the
background with a progress line; a tracepoint the kernel lacks is reported and skipped,
and the rest of the family still attaches. Only one batch runs at a time, and while it runs
the Syscalls view refuses probe changes (`space`/`enter`, `a`, `n`); `a` and `n` set every
probe to attached or detached, so repeating them changes nothing. Once changed, the attached set is carried into
every later trace session, so a PID/TID reselect or a filter change that restarts the
trace keeps it instead of reverting to the flags. The carried set is normally read back
from the probes that are actually attached. A change still running when the trace restarts
or stops carries its intended set instead (a single-probe change only adds or removes that
probe); a family batch is also cancelled when its trace session ends, so it stops attaching
to the old session and the new session can start a family batch right away;
probes of it that cannot attach are retried at each session start and skipped with a log
line until the next probe change reads the attached set back. After detaching everything,
later sessions attach nothing, and only restarting `ior` returns to the startup selection. `[`/`]` only scope the dashboard view to
a family; when that family has no attached probe, the status line says how to attach it.

The selector kind describes a syscall's role. It is separate from the BPF record type. For
example, fd xattr calls and `recvfrom`/`recvmsg` still select as `fd` even though their requested
size (and, for the receives, flags) now travel in a dedicated `fd_size_event`; `memfd_create` still selects as `eventfd`, and `move_mount`
as `two-fd`. This wire split reduced ordinary ring-buffer records without changing selector
behavior.

## Traced Syscalls by Family

Family names are the values accepted by `-trace-families` and `-no-trace-families`.

- AIO: `io_cancel`, `io_destroy`, `io_getevents`, `io_pgetevents`, `io_setup`, `io_submit`, `io_uring_enter`, `io_uring_register`, `io_uring_setup`
- FS: `access`, `cachestat`, `chdir`, `chmod`, `chown`, `chroot`, `close`, `close_range`, `copy_file_range`, `creat`, `dup`, `dup2`, `dup3`, `faccessat`, `faccessat2`, `fadvise64`, `fallocate`, `fchdir`, `fchmod`, `fchmodat`, `fchmodat2`, `fchown`, `fchownat`, `fcntl`, `fdatasync`, `fgetxattr`, `file_getattr`, `file_setattr`, `flistxattr`, `flock`, `fremovexattr`, `fsconfig`, `fsetxattr`, `fsmount`, `fsopen`, `fspick`, `fstatfs`, `fsync`, `ftruncate`, `futimesat`, `getcwd`, `getdents`, `getdents64`, `getxattr`, `getxattrat`, `ioctl`, `lchown`, `lgetxattr`, `link`, `linkat`, `listmount`, `listns`, `listxattr`, `listxattrat`, `llistxattr`, `lremovexattr`, `lseek`, `lsetxattr`, `mkdir`, `mkdirat`, `mknod`, `mknodat`, `mount`, `mount_setattr`, `move_mount`, `msync`, `name_to_handle_at`, `newfstat`, `newfstatat`, `newlstat`, `newstat`, `open`, `open_by_handle_at`, `open_tree`, `open_tree_attr`, `openat`, `openat2`, `pread64`, `preadv`, `preadv2`, `pwrite64`, `pwritev`, `pwritev2`, `quotactl`, `quotactl_fd`, `read`, `readahead`, `readlink`, `readlinkat`, `readv`, `removexattr`, `removexattrat`, `rename`, `renameat`, `renameat2`, `rmdir`, `setxattr`, `setxattrat`, `statfs`, `statmount`, `statx`, `swapoff`, `swapon`, `symlink`, `symlinkat`, `sync`, `sync_file_range`, `syncfs`, `truncate`, `umount`, `unlink`, `unlinkat`, `ustat`, `utime`, `utimensat`, `utimes`, `write`, `writev`
- IPC: `eventfd`, `eventfd2`, `fanotify_init`, `fanotify_mark`, `futex`, `futex_requeue`, `futex_wait`, `futex_waitv`, `futex_wake`, `inotify_add_watch`, `inotify_init`, `inotify_init1`, `inotify_rm_watch`, `memfd_create`, `memfd_secret`, `mq_getsetattr`, `mq_notify`, `mq_open`, `mq_timedreceive`, `mq_timedsend`, `mq_unlink`, `msgctl`, `msgget`, `msgrcv`, `msgsnd`, `pidfd_getfd`, `pidfd_open`, `pidfd_send_signal`, `pipe`, `pipe2`, `semctl`, `semget`, `semop`, `semtimedop`, `shmat`, `shmctl`, `shmdt`, `shmget`, `signalfd`, `signalfd4`, `timerfd_create`, `timerfd_gettime`, `timerfd_settime`, `userfaultfd`
- Memory: `brk`, `get_mempolicy`, `madvise`, `map_shadow_stack`, `mbind`, `membarrier`, `migrate_pages`, `mincore`, `mlock`, `mlock2`, `mlockall`, `mmap`, `move_pages`, `mprotect`, `mremap`, `mseal`, `munlock`, `munlockall`, `munmap`, `pkey_alloc`, `pkey_free`, `pkey_mprotect`, `process_madvise`, `process_mrelease`, `process_vm_readv`, `process_vm_writev`, `remap_file_pages`, `set_mempolicy`, `set_mempolicy_home_node`
- Misc: `acct`, `get_robust_list`, `getcpu`, `ioperm`, `iopl`, `modify_ldt`, `newuname`, `rseq`, `set_robust_list`, `setdomainname`, `sethostname`, `sysfs`, `sysinfo`, `syslog`, `uprobe`, `uretprobe`
- Network: `accept`, `accept4`, `bind`, `connect`, `getpeername`, `getsockname`, `getsockopt`, `listen`, `recvfrom`, `recvmmsg`, `recvmsg`, `sendfile64`, `sendmmsg`, `sendmsg`, `sendto`, `setsockopt`, `shutdown`, `socket`, `socketpair`, `splice`, `tee`, `vmsplice`
- Polling: `epoll_create`, `epoll_create1`, `epoll_ctl`, `epoll_pwait`, `epoll_pwait2`, `epoll_wait`, `poll`, `ppoll`, `pselect6`, `select`
- Process: `arch_prctl`, `clone`, `clone3`, `execve`, `execveat`, `exit`, `exit_group`, `fork`, `getegid`, `geteuid`, `getgid`, `getgroups`, `getpgid`, `getpgrp`, `getpid`, `getppid`, `getpriority`, `getresgid`, `getresuid`, `getrlimit`, `getrusage`, `getsid`, `gettid`, `getuid`, `ioprio_get`, `ioprio_set`, `kcmp`, `personality`, `pivot_root`, `prctl`, `prlimit64`, `reboot`, `restart_syscall`, `set_tid_address`, `setfsgid`, `setfsuid`, `setgid`, `setgroups`, `setns`, `setpgid`, `setpriority`, `setregid`, `setresgid`, `setresuid`, `setreuid`, `setrlimit`, `setsid`, `setuid`, `umask`, `unshare`, `vfork`, `vhangup`, `wait4`, `waitid`
- Sched: `sched_get_priority_max`, `sched_get_priority_min`, `sched_getaffinity`, `sched_getattr`, `sched_getparam`, `sched_getscheduler`, `sched_rr_get_interval`, `sched_setaffinity`, `sched_setattr`, `sched_setparam`, `sched_setscheduler`, `sched_yield`
- Security: `add_key`, `bpf`, `capget`, `capset`, `delete_module`, `finit_module`, `getrandom`, `init_module`, `kexec_file_load`, `kexec_load`, `keyctl`, `landlock_add_rule`, `landlock_create_ruleset`, `landlock_restrict_self`, `lsm_get_self_attr`, `lsm_list_modules`, `lsm_set_self_attr`, `perf_event_open`, `ptrace`, `request_key`, `seccomp`
- Signals: `kill`, `pause`, `rt_sigaction`, `rt_sigpending`, `rt_sigprocmask`, `rt_sigqueueinfo`, `rt_sigreturn`, `rt_sigsuspend`, `rt_sigtimedwait`, `rt_tgsigqueueinfo`, `sigaltstack`, `tgkill`, `tkill`
- Time: `adjtimex`, `alarm`, `clock_adjtime`, `clock_getres`, `clock_gettime`, `clock_nanosleep`, `clock_settime`, `getitimer`, `gettimeofday`, `nanosleep`, `setitimer`, `settimeofday`, `time`, `timer_create`, `timer_delete`, `timer_getoverrun`, `timer_gettime`, `timer_settime`, `times`

## Traced Syscalls by TracepointKind

Kind names are the values accepted by `-trace-kinds` and `-no-trace-kinds` (`_` is accepted
in place of `-`). A kind describes the syscall's role for selection; it is separate from the
BPF record type (see What attaches).

- accept: `accept`, `accept4`
- bpf: `bpf`
- dup3: `dup3`
- epoll-ctl: `epoll_ctl`
- eventfd: `epoll_create`, `epoll_create1`, `eventfd`, `eventfd2`, `fanotify_init`, `fsmount`, `fsopen`, `inotify_init`, `inotify_init1`, `landlock_create_ruleset`, `memfd_create`, `memfd_secret`, `signalfd`, `signalfd4`, `timerfd_create`, `userfaultfd`
- exec: `execve`, `execveat`
- fcntl: `fcntl`, `ioctl`
- fd: `bind`, `cachestat`, `close`, `connect`, `copy_file_range`, `dup`, `dup2`, `fadvise64`, `fallocate`, `fchdir`, `fchmod`, `fchown`, `fdatasync`, `fgetxattr`, `finit_module`, `flistxattr`, `flock`, `fremovexattr`, `fsconfig`, `fsetxattr`, `fstatfs`, `fsync`, `ftruncate`, `getdents`, `getdents64`, `getpeername`, `getsockname`, `getsockopt`, `inotify_rm_watch`, `io_uring_enter`, `io_uring_register`, `kexec_file_load`, `landlock_add_rule`, `landlock_restrict_self`, `listen`, `lseek`, `mq_getsetattr`, `mq_notify`, `mq_timedreceive`, `mq_timedsend`, `newfstat`, `pidfd_getfd`, `pidfd_send_signal`, `pread64`, `preadv`, `preadv2`, `process_madvise`, `process_mrelease`, `pwrite64`, `pwritev`, `pwritev2`, `quotactl_fd`, `read`, `readahead`, `readv`, `recvfrom`, `recvmmsg`, `recvmsg`, `sendfile64`, `sendmmsg`, `sendmsg`, `sendto`, `setns`, `setsockopt`, `shutdown`, `splice`, `sync_file_range`, `syncfs`, `tee`, `timerfd_gettime`, `timerfd_settime`, `vmsplice`, `write`, `writev`
- fd-pathname: `fanotify_mark`, `inotify_add_watch`
- futex: `futex`, `futex_requeue`, `futex_wait`, `futex_waitv`, `futex_wake`
- keyctl: `add_key`, `keyctl`, `request_key`
- mem: `brk`, `madvise`, `map_shadow_stack`, `mincore`, `mlock`, `mlock2`, `mprotect`, `mremap`, `mseal`, `msync`, `munlock`, `munmap`, `pkey_mprotect`, `remap_file_pages`
- mmap: `mmap`
- module: `delete_module`, `init_module`
- mq-open: `mq_open`
- name: `link`, `linkat`, `rename`, `renameat`, `renameat2`, `symlink`, `symlinkat`
- null: `adjtimex`, `alarm`, `arch_prctl`, `capget`, `capset`, `clock_adjtime`, `clock_getres`, `clock_gettime`, `clock_settime`, `exit`, `exit_group`, `get_mempolicy`, `get_robust_list`, `getcpu`, `getcwd`, `getegid`, `geteuid`, `getgid`, `getgroups`, `getitimer`, `getpgid`, `getpgrp`, `getpid`, `getppid`, `getpriority`, `getrandom`, `getresgid`, `getresuid`, `getrlimit`, `getrusage`, `getsid`, `gettid`, `gettimeofday`, `getuid`, `io_cancel`, `io_destroy`, `io_getevents`, `io_pgetevents`, `io_setup`, `io_submit`, `io_uring_setup`, `ioperm`, `iopl`, `ioprio_get`, `ioprio_set`, `kexec_load`, `kill`, `listmount`, `listns`, `lsm_get_self_attr`, `lsm_list_modules`, `lsm_set_self_attr`, `mbind`, `membarrier`, `migrate_pages`, `mlockall`, `modify_ldt`, `move_pages`, `munlockall`, `newuname`, `pause`, `personality`, `pkey_alloc`, `pkey_free`, `prlimit64`, `process_vm_readv`, `process_vm_writev`, `reboot`, `restart_syscall`, `rseq`, `rt_sigaction`, `rt_sigpending`, `rt_sigprocmask`, `rt_sigqueueinfo`, `rt_sigreturn`, `rt_sigsuspend`, `rt_sigtimedwait`, `rt_tgsigqueueinfo`, `sched_get_priority_max`, `sched_get_priority_min`, `sched_getaffinity`, `sched_getattr`, `sched_getparam`, `sched_getscheduler`, `sched_rr_get_interval`, `sched_setaffinity`, `sched_setattr`, `sched_setparam`, `sched_setscheduler`, `sched_yield`, `set_mempolicy`, `set_mempolicy_home_node`, `set_robust_list`, `set_tid_address`, `setdomainname`, `setfsgid`, `setfsuid`, `setgid`, `setgroups`, `sethostname`, `setitimer`, `setpgid`, `setpriority`, `setregid`, `setresgid`, `setresuid`, `setreuid`, `setrlimit`, `setsid`, `settimeofday`, `setuid`, `sigaltstack`, `statmount`, `sync`, `sysfs`, `sysinfo`, `syslog`, `tgkill`, `time`, `times`, `tkill`, `umask`, `unshare`, `uprobe`, `uretprobe`, `ustat`, `vhangup`
- open: `open`, `openat`, `openat2`
- open-by-handle-at: `open_by_handle_at`
- open-tree: `open_tree`, `open_tree_attr`
- pathname: `access`, `acct`, `chdir`, `chmod`, `chown`, `chroot`, `creat`, `faccessat`, `faccessat2`, `fchmodat`, `fchmodat2`, `fchownat`, `file_getattr`, `file_setattr`, `fspick`, `futimesat`, `getxattr`, `getxattrat`, `lchown`, `lgetxattr`, `listxattr`, `listxattrat`, `llistxattr`, `lremovexattr`, `lsetxattr`, `mkdir`, `mkdirat`, `mknod`, `mknodat`, `mount`, `mount_setattr`, `mq_unlink`, `name_to_handle_at`, `newfstatat`, `newlstat`, `newstat`, `pivot_root`, `quotactl`, `readlink`, `readlinkat`, `removexattr`, `removexattrat`, `rmdir`, `setxattr`, `setxattrat`, `statfs`, `statx`, `swapoff`, `swapon`, `truncate`, `umount`, `unlink`, `unlinkat`, `utime`, `utimensat`, `utimes`
- perf-open: `perf_event_open`
- pidfd: `pidfd_open`
- pipe: `pipe`, `pipe2`
- poll: `epoll_pwait`, `epoll_pwait2`, `epoll_wait`, `poll`, `ppoll`, `pselect6`, `select`
- prctl: `prctl`
- proc: `clone`, `clone3`, `fork`, `vfork`, `wait4`, `waitid`
- ptrace: `ptrace`
- seccomp: `seccomp`
- sleep: `clock_nanosleep`, `nanosleep`
- socket: `socket`
- socketpair: `socketpair`
- sysv-id: `msgget`, `semget`, `shmget`
- sysv-op: `msgctl`, `msgrcv`, `msgsnd`, `semctl`, `semop`, `semtimedop`, `shmat`, `shmctl`, `shmdt`
- timer-obj: `timer_create`, `timer_delete`, `timer_getoverrun`, `timer_gettime`, `timer_settime`
- two-fd: `close_range`, `kcmp`, `move_mount`

For sampling, byte accounting and pointer-backed arguments, see [output details](./output.md#sampling).
