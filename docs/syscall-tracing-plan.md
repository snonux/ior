# Syscall Tracing Status: Shipped

As of May 21, 2026, the syscall-tracing expansion is implemented in `develop`.
This document replaces the previous implementation plan and records shipped
coverage and operator-facing behavior.

Source of truth:

- `internal/tracepoints/generated_tracepoints.go` (`syscallFamilies` / `syscallKinds`)
- `internal/generate/classify.go` (`retClassifications`)
- `./ior --help` (flag surface)

## Attach-Time Selection Flags

Dimension selectors:

- `-trace-families`
- `-trace-kinds`
- `-trace-syscalls`

Exclusions:

- `-no-trace-families`
- `-no-trace-kinds`
- `-no-trace-syscalls`

Examples:

```shell
# Families only
sudo ./ior -trace-families Time,Polling

# Kinds + exclusions
sudo ./ior -trace-kinds fd,open -no-trace-syscalls read

# Explicit syscall names + kind exclusion
sudo ./ior -trace-syscalls openat,recvmsg,nanosleep -no-trace-kinds null
```

## Traced Syscalls by Family

- AIO: `io_cancel`, `io_destroy`, `io_getevents`, `io_pgetevents`, `io_setup`, `io_submit`, `io_uring_enter`, `io_uring_register`, `io_uring_setup`
- FS: `access`, `cachestat`, `chdir`, `chmod`, `chown`, `chroot`, `close`, `close_range`, `copy_file_range`, `creat`, `dup`, `dup2`, `dup3`, `faccessat`, `faccessat2`, `fadvise64`, `fallocate`, `fchdir`, `fchmod`, `fchmodat`, `fchmodat2`, `fchown`, `fchownat`, `fcntl`, `fdatasync`, `fgetxattr`, `flistxattr`, `flock`, `fremovexattr`, `fsconfig`, `fsetxattr`, `fsmount`, `fsopen`, `fspick`, `fstatfs`, `fsync`, `ftruncate`, `futimesat`, `getcwd`, `getdents`, `getdents64`, `getxattr`, `getxattrat`, `ioctl`, `lchown`, `lgetxattr`, `link`, `linkat`, `listmount`, `listns`, `listxattr`, `listxattrat`, `llistxattr`, `lremovexattr`, `lseek`, `lsetxattr`, `mkdir`, `mkdirat`, `mknod`, `mknodat`, `mount`, `mount_setattr`, `move_mount`, `msync`, `name_to_handle_at`, `newfstat`, `newfstatat`, `newlstat`, `newstat`, `open`, `open_by_handle_at`, `open_tree`, `open_tree_attr`, `openat`, `openat2`, `pread64`, `preadv`, `preadv2`, `pwrite64`, `pwritev`, `pwritev2`, `quotactl`, `quotactl_fd`, `read`, `readahead`, `readlink`, `readlinkat`, `readv`, `removexattr`, `removexattrat`, `rename`, `renameat`, `renameat2`, `rmdir`, `setxattr`, `setxattrat`, `statfs`, `statmount`, `statx`, `swapoff`, `swapon`, `symlink`, `symlinkat`, `sync`, `sync_file_range`, `syncfs`, `truncate`, `umount`, `unlink`, `unlinkat`, `ustat`, `utime`, `utimensat`, `utimes`, `write`, `writev`
- IPC: `eventfd`, `eventfd2`, `futex`, `futex_requeue`, `futex_wait`, `futex_waitv`, `futex_wake`, `inotify_add_watch`, `inotify_init`, `inotify_init1`, `inotify_rm_watch`, `memfd_create`, `memfd_secret`, `mq_getsetattr`, `mq_notify`, `mq_open`, `mq_timedreceive`, `mq_timedsend`, `mq_unlink`, `msgctl`, `msgget`, `msgrcv`, `msgsnd`, `pidfd_getfd`, `pidfd_open`, `pidfd_send_signal`, `pipe`, `pipe2`, `semctl`, `semget`, `semop`, `semtimedop`, `shmat`, `shmctl`, `shmdt`, `shmget`, `signalfd`, `signalfd4`, `timerfd_create`, `timerfd_gettime`, `timerfd_settime`, `userfaultfd`
- Memory: `brk`, `get_mempolicy`, `madvise`, `map_shadow_stack`, `mbind`, `membarrier`, `migrate_pages`, `mincore`, `mlock`, `mlock2`, `mlockall`, `mmap`, `move_pages`, `mprotect`, `mremap`, `mseal`, `munlock`, `munlockall`, `munmap`, `pkey_alloc`, `pkey_free`, `pkey_mprotect`, `process_madvise`, `process_mrelease`, `process_vm_readv`, `process_vm_writev`, `remap_file_pages`, `set_mempolicy`, `set_mempolicy_home_node`
- Misc: `acct`, `alarm`, `fanotify_init`, `fanotify_mark`, `file_getattr`, `file_setattr`, `get_robust_list`, `getcpu`, `ioperm`, `iopl`, `modify_ldt`, `newuname`, `rseq`, `set_robust_list`, `setdomainname`, `sethostname`, `sysfs`, `sysinfo`, `syslog`, `uprobe`, `uretprobe`, `vmsplice`
- Network: `accept`, `accept4`, `bind`, `connect`, `getpeername`, `getsockname`, `getsockopt`, `listen`, `recvfrom`, `recvmmsg`, `recvmsg`, `sendfile64`, `sendmmsg`, `sendmsg`, `sendto`, `setsockopt`, `shutdown`, `socket`, `socketpair`, `splice`, `tee`
- Polling: `epoll_create`, `epoll_create1`, `epoll_ctl`, `epoll_pwait`, `epoll_pwait2`, `epoll_wait`, `poll`, `ppoll`, `pselect6`, `select`
- Process: `arch_prctl`, `clone`, `clone3`, `execve`, `execveat`, `exit`, `exit_group`, `fork`, `getegid`, `geteuid`, `getgid`, `getgroups`, `getpgid`, `getpgrp`, `getpid`, `getppid`, `getpriority`, `getresgid`, `getresuid`, `getrlimit`, `getrusage`, `getsid`, `gettid`, `getuid`, `ioprio_get`, `ioprio_set`, `kcmp`, `personality`, `pivot_root`, `prctl`, `prlimit64`, `reboot`, `restart_syscall`, `set_tid_address`, `setfsgid`, `setfsuid`, `setgid`, `setgroups`, `setns`, `setpgid`, `setpriority`, `setregid`, `setresgid`, `setresuid`, `setreuid`, `setrlimit`, `setsid`, `setuid`, `umask`, `unshare`, `vfork`, `vhangup`, `wait4`, `waitid`
- Sched: `sched_get_priority_max`, `sched_get_priority_min`, `sched_getaffinity`, `sched_getattr`, `sched_getparam`, `sched_getscheduler`, `sched_rr_get_interval`, `sched_setaffinity`, `sched_setattr`, `sched_setparam`, `sched_setscheduler`, `sched_yield`
- Security: `add_key`, `bpf`, `capget`, `capset`, `delete_module`, `finit_module`, `getrandom`, `init_module`, `kexec_file_load`, `kexec_load`, `keyctl`, `landlock_add_rule`, `landlock_create_ruleset`, `landlock_restrict_self`, `lsm_get_self_attr`, `lsm_list_modules`, `lsm_set_self_attr`, `perf_event_open`, `ptrace`, `request_key`, `seccomp`
- Signals: `kill`, `pause`, `rt_sigaction`, `rt_sigpending`, `rt_sigprocmask`, `rt_sigqueueinfo`, `rt_sigreturn`, `rt_sigsuspend`, `rt_sigtimedwait`, `rt_tgsigqueueinfo`, `sigaltstack`, `tgkill`, `tkill`
- Time: `adjtimex`, `clock_adjtime`, `clock_getres`, `clock_gettime`, `clock_nanosleep`, `clock_settime`, `getitimer`, `gettimeofday`, `nanosleep`, `setitimer`, `settimeofday`, `time`, `timer_create`, `timer_delete`, `timer_getoverrun`, `timer_gettime`, `timer_settime`, `times`

## Traced Syscalls by TracepointKind

- accept: `accept`, `accept4`
- bpf: `bpf`
- dup3: `dup3`
- epoll-ctl: `epoll_ctl`
- eventfd: `epoll_create`, `epoll_create1`, `eventfd`, `eventfd2`, `fanotify_init`, `fsmount`, `fsopen`, `inotify_init`, `inotify_init1`, `landlock_create_ruleset`, `memfd_create`, `memfd_secret`, `signalfd`, `signalfd4`, `timerfd_create`, `userfaultfd`
- exec: `execve`, `execveat`
- fcntl: `fcntl`
- fd: `bind`, `cachestat`, `close`, `connect`, `copy_file_range`, `dup`, `dup2`, `epoll_pwait`, `epoll_pwait2`, `epoll_wait`, `fadvise64`, `fallocate`, `fchdir`, `fchmod`, `fchown`, `fdatasync`, `fgetxattr`, `finit_module`, `flistxattr`, `flock`, `fremovexattr`, `fsconfig`, `fsetxattr`, `fstatfs`, `fsync`, `ftruncate`, `getdents`, `getdents64`, `getpeername`, `getsockname`, `getsockopt`, `inotify_add_watch`, `inotify_rm_watch`, `io_uring_enter`, `io_uring_register`, `ioctl`, `kexec_file_load`, `landlock_add_rule`, `landlock_restrict_self`, `listen`, `lseek`, `mmap`, `mq_getsetattr`, `mq_notify`, `mq_timedreceive`, `mq_timedsend`, `newfstat`, `pidfd_getfd`, `pidfd_send_signal`, `pread64`, `preadv`, `preadv2`, `process_madvise`, `process_mrelease`, `pwrite64`, `pwritev`, `pwritev2`, `quotactl_fd`, `read`, `readahead`, `readv`, `recvfrom`, `recvmmsg`, `recvmsg`, `sendfile64`, `sendmmsg`, `sendmsg`, `sendto`, `setns`, `setsockopt`, `shutdown`, `sync_file_range`, `syncfs`, `vmsplice`, `write`, `writev`
- futex: `futex`, `futex_requeue`, `futex_wait`, `futex_waitv`, `futex_wake`
- keyctl: `add_key`, `keyctl`, `request_key`
- mem: `brk`, `madvise`, `map_shadow_stack`, `mincore`, `mlock`, `mlock2`, `mprotect`, `mremap`, `mseal`, `munlock`, `munmap`, `pkey_mprotect`, `remap_file_pages`
- module: `delete_module`, `init_module`
- mq-open: `mq_open`
- name: `link`, `linkat`, `rename`, `renameat`, `renameat2`, `symlink`, `symlinkat`
- null: `adjtimex`, `alarm`, `arch_prctl`, `capget`, `capset`, `clock_adjtime`, `clock_getres`, `clock_gettime`, `clock_settime`, `exit`, `exit_group`, `get_mempolicy`, `get_robust_list`, `getcpu`, `getcwd`, `getegid`, `geteuid`, `getgid`, `getgroups`, `getitimer`, `getpgid`, `getpgrp`, `getpid`, `getppid`, `getpriority`, `getrandom`, `getresgid`, `getresuid`, `getrlimit`, `getrusage`, `getsid`, `gettid`, `gettimeofday`, `getuid`, `io_cancel`, `io_destroy`, `io_getevents`, `io_pgetevents`, `io_setup`, `io_submit`, `io_uring_setup`, `ioperm`, `iopl`, `ioprio_get`, `ioprio_set`, `kexec_load`, `kill`, `listmount`, `listns`, `lsm_get_self_attr`, `lsm_list_modules`, `lsm_set_self_attr`, `mbind`, `membarrier`, `migrate_pages`, `mlockall`, `modify_ldt`, `move_pages`, `msync`, `munlockall`, `newuname`, `pause`, `personality`, `pkey_alloc`, `pkey_free`, `prlimit64`, `process_vm_readv`, `process_vm_writev`, `reboot`, `restart_syscall`, `rseq`, `rt_sigaction`, `rt_sigpending`, `rt_sigprocmask`, `rt_sigqueueinfo`, `rt_sigreturn`, `rt_sigsuspend`, `rt_sigtimedwait`, `rt_tgsigqueueinfo`, `sched_get_priority_max`, `sched_get_priority_min`, `sched_getaffinity`, `sched_getattr`, `sched_getparam`, `sched_getscheduler`, `sched_rr_get_interval`, `sched_setaffinity`, `sched_setattr`, `sched_setparam`, `sched_setscheduler`, `sched_yield`, `set_mempolicy`, `set_mempolicy_home_node`, `set_robust_list`, `set_tid_address`, `setdomainname`, `setfsgid`, `setfsuid`, `setgid`, `setgroups`, `sethostname`, `setitimer`, `setpgid`, `setpriority`, `setregid`, `setresgid`, `setresuid`, `setreuid`, `setrlimit`, `setsid`, `settimeofday`, `setuid`, `sigaltstack`, `splice`, `statmount`, `sync`, `sysfs`, `sysinfo`, `syslog`, `tee`, `tgkill`, `time`, `timerfd_gettime`, `timerfd_settime`, `times`, `tkill`, `umask`, `unshare`, `uprobe`, `uretprobe`, `ustat`, `vhangup`
- open: `open`, `open_tree`, `open_tree_attr`, `openat`, `openat2`
- open-by-handle-at: `open_by_handle_at`
- pathname: `access`, `acct`, `chdir`, `chmod`, `chown`, `chroot`, `creat`, `faccessat`, `faccessat2`, `fanotify_mark`, `fchmodat`, `fchmodat2`, `fchownat`, `file_getattr`, `file_setattr`, `fspick`, `futimesat`, `getxattr`, `getxattrat`, `lchown`, `lgetxattr`, `listxattr`, `listxattrat`, `llistxattr`, `lremovexattr`, `lsetxattr`, `mkdir`, `mkdirat`, `mknod`, `mknodat`, `mount`, `mount_setattr`, `mq_unlink`, `name_to_handle_at`, `newfstatat`, `newlstat`, `newstat`, `pivot_root`, `quotactl`, `readlink`, `readlinkat`, `removexattr`, `removexattrat`, `rmdir`, `setxattr`, `setxattrat`, `statfs`, `statx`, `swapoff`, `swapon`, `truncate`, `umount`, `unlink`, `unlinkat`, `utime`, `utimensat`, `utimes`
- perf-open: `perf_event_open`
- pidfd: `pidfd_open`
- pipe: `pipe`, `pipe2`
- poll: `poll`, `ppoll`, `pselect6`, `select`
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

## Bytes vs Non-Bytes Classification

Payload bytes classified by return value:

- ReadClassified: `fgetxattr`, `flistxattr`, `getdents`, `getdents64`, `getrandom`, `getxattr`, `getxattrat`, `lgetxattr`, `listxattr`, `listxattrat`, `llistxattr`, `mq_timedreceive`, `msgrcv`, `pread64`, `preadv`, `preadv2`, `process_vm_readv`, `read`, `readlink`, `readlinkat`, `readv`, `recvfrom`, `recvmsg`, `syslog`
- TransferClassified: `copy_file_range`, `sendfile64`, `splice`, `tee`, `vmsplice`
- WriteClassified: `mq_timedsend`, `msgsnd`, `process_vm_writev`, `pwrite64`, `pwritev`, `pwritev2`, `sendmsg`, `sendto`, `write`, `writev`

All other traced syscalls are treated as non-bytes for throughput accounting.
Memory extent is tracked separately via address-space metrics.

## Runtime Notes

- Dashboard ships with a dedicated `Non-IO` tab (shortcut `8`) backed by
  per-family aggregates (`Snapshot.Families`); Non-IO filtering is applied in `internal/tui/dashboard`.
- Aggregate-only sampling mode is implemented (`rate=0`) via:
  - `-syscall-sampling-families`
  - `-syscall-sampling-syscalls`
- Current defaults include aggregate-only mode for:
  - `futex`, `futex_wait`, `futex_wake`, `futex_requeue`, `futex_waitv`
  - `clock_gettime`
