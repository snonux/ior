# Syscall Tracing Expansion Plan for IOR

This document is a **planning artefact**. No code changes are made here. It enumerates the Linux syscalls that ior does **not** yet trace, evaluates how each one could be classified inside ior's existing taxonomy, and recommends a phased rollout for extending the tracer beyond pure file-I/O coverage.

The motivation is the same observability story ior already tells for file I/O — *count, duration, latency* — but generalised to **every** syscall a process performs. Even non-IO syscalls (e.g. `futex`, `nanosleep`, `epoll_wait`) often dominate wall-time and are worth flame-graphing.

---

## 1. Baseline: What ior Already Traces

Source of truth: `internal/tracepoints/generated_tracepoints.go` (the enter/exit pair list) and `internal/c/generated_tracepoints.c` (the BPF handlers).

**Counts** (at the time of writing):

| | Count |
|---|---|
| Tracepoints currently active (`sys_enter_*` entries) | **117** |
| Syscalls explicitly *ignored* in `generated_tracepoints.c` | **230** |

The 117 active tracepoints cover what the project considers "I/O related" today, broadly:

| Family | Examples |
|---|---|
| **Read/write data** | `read`, `write`, `pread64`, `pwrite64`, `readv`, `writev`, `preadv`, `preadv2`, `pwritev`, `pwritev2`, `copy_file_range`, `vmsplice` |
| **Open/close/dup** | `open`, `openat`, `openat2`, `creat`, `close`, `close_range`, `dup`, `dup2`, `dup3` |
| **Metadata / stat** | `newstat`, `newlstat`, `newfstat`, `newfstatat`, `statx`, `statfs`, `fstatfs`, `getcwd`, `getdents`, `getdents64`, `readlink`, `readlinkat` |
| **Path mutation** | `mkdir(at)`, `rmdir`, `unlink(at)`, `link(at)`, `symlink(at)`, `rename(at|2)`, `truncate`, `ftruncate` |
| **Permissions** | `chmod`, `fchmod`, `fchmodat(2)`, `chown`, `lchown`, `fchown`, `fchownat`, `access`, `faccessat(2)` |
| **Extended attributes** | `getxattr`/`lgetxattr`/`fgetxattr`/`getxattrat`, `setxattr` family, `listxattr` family, `removexattr` family |
| **Sync / cache hints** | `sync`, `syncfs`, `fsync`, `fdatasync`, `sync_file_range`, `msync`, `readahead`, `fadvise64`, `cachestat`, `fallocate` |
| **Mount / fs control** | `open_tree`, `open_tree_attr`, `mount_setattr`, `fspick`, `fsconfig`, `name_to_handle_at`, `open_by_handle_at`, `file_getattr`, `file_setattr`, `quotactl_fd`, `fanotify_mark` |
| **Async I/O** | `io_setup`, `io_destroy`, `io_submit`, `io_cancel`, `io_getevents`, `io_pgetevents`, `io_uring_setup`, `io_uring_enter`, `io_uring_register` |
| **Misc fd ops** | `ioctl`, `fcntl`, `flock`, `lseek`, `chdir`, `fchdir`, `chroot`, `utimensat`, `futimesat`, `finit_module`, `mmap`, `pidfd_getfd`, `syslog` |

### Existing classification taxonomy

`internal/generate/classify.go` and `kindregistry.go` define how a tracepoint is shaped on the BPF side. The current `TracepointKind` enum is:

| Kind | C struct | Notes |
|---|---|---|
| `KindFd` | `fd_event` | Takes an fd; used for read/write/sync/seek-style ops |
| `KindOpen` | `open_event` | Has a `filename` argument that returns a new fd |
| `KindPathname` | `path_event` | Path-by-name op (no fd) |
| `KindName` | `name_event` | Newname target for rename/link |
| `KindRet` | `ret_event` | Exit-only (return-classified by `RetClassification`) |
| `KindFcntl` | `fcntl_event` | Special-cased `fcntl` |
| `KindNull` | `null_event` | Syscalls with no useful argument shape (e.g. `sync`, `getcwd`, `io_*`, `msync`, `syslog`) |
| `KindDup3` | `dup3_event` | `dup3`-style with explicit new fd |
| `KindOpenByHandleAt` | `open_by_handle_at_event` | Handle-based open |

`RetClassification` further tags exits as `ReadClassified`, `WriteClassified`, `TransferClassified`, or `Unclassified` to feed the "bytes" totals in the dashboard.

### What's missing today

Two structural gaps appear when looking at the bigger picture:

1. **No "non-IO" coverage.** Anything memory-mapping, process-control, signals, IPC, scheduling, time, security/keys, network, or epoll/poll/select is rejected outright by `shouldIgnore` and the static ignore comments in `generated_tracepoints.c`.
2. **The kind taxonomy is fd-or-path-centric.** It has no slot for syscalls whose dimension is a *byte count without an fd* (e.g. `mq_timedsend`/`mq_timedreceive` carry a length but the descriptor is a `mqd_t`), or a *sleep duration* (e.g. `nanosleep`), or a *pidfd/sigaction target* that is not a regular file fd. Adding more syscalls will require widening this enum (see §4).

---

## 2. Universe Definition: All Linux Syscalls

The plan treats the union of all tracepoints in `/sys/kernel/tracing/events/syscalls` as the universe. For the baseline machine that means every syscall enumerated as `Ignoring sys_enter_<name>` in `internal/c/generated_tracepoints.c` plus the 117 already enabled — **~250 syscalls** total. Architecture-specific syscalls (e.g. `arch_prctl`, `iopl`, `modify_ldt`, `mmap2`) are included where the tracepoint exists on x86_64.

---

## 3. Per-Syscall Plan (Not-Yet-Traced Syscalls)

For each syscall the columns mean:

- **fd in** — does the syscall *take* an fd as a kernel-visible argument? (yes / no / type — e.g. `mqd_t`, `pidfd`, `int *fdarray`)
- **fd out** — does the syscall *return* an fd via return value or out-parameter?
- **Bytes / size dim?** — is there a meaningful quantitative dimension that could feed a "bytes" or "size" accumulator like the existing read/write classification?
- **Suggested ior kind** — which existing or new `TracepointKind` would fit
- **Metrics** — beyond the universal *count / duration / latency*, what extra dimension is recommended
- **Priority** — `P1` (high-value, ship first), `P2` (useful), `P3` (long tail / rarely interesting)

> Convention: when "Bytes / size dim?" is "no", count+duration+latency still apply — those three are universal.

### 3.1 Network — socket I/O and lifecycle

These are conspicuously absent from ior (which already has read/write but not sockets). They are the single biggest *useful* gap.

| Syscall | fd in | fd out | Bytes / size dim? | Suggested kind | Extra metrics | Priority |
|---|---|---|---|---|---|---|
| `socket` | no | **yes** (ret) | no | new `KindSocket` (like `KindOpen` but no path) | family/type/protocol | P1 |
| `socketpair` | no | **yes** (out arr `sv[2]`) | no | new `KindSocketpair` | family/type/protocol, both fds | P1 |
| `connect` | yes | no | size of `sockaddr` | extend `KindFd` | sockaddr family | P1 |
| `bind` | yes | no | size of `sockaddr` | extend `KindFd` | sockaddr family | P1 |
| `listen` | yes | no | no (backlog int) | extend `KindFd` | backlog | P1 |
| `accept` | yes (listening) | **yes** (ret) | no | new `KindAccept` | both fds, sockaddr family | P1 |
| `accept4` | yes | **yes** (ret) | no | `KindAccept` | flags | P1 |
| `shutdown` | yes | no | no | extend `KindFd` | how (SHUT_RD/WR/RDWR) | P2 |
| `getsockname` | yes | no | yes (addrlen out) | extend `KindFd` | sockaddr family | P2 |
| `getpeername` | yes | no | yes (addrlen out) | extend `KindFd` | sockaddr family | P2 |
| `getsockopt` | yes | no | yes (optlen) | extend `KindFd` | level/optname | P2 |
| `setsockopt` | yes | no | yes (optlen) | extend `KindFd` | level/optname | P2 |
| `sendto` | yes | no | **yes** (len) | `KindRet` + `WriteClassified` (already in `retClassifications`!) | sockaddr family | P1 |
| `sendmsg` | yes | no | **yes** (iov total) | `KindRet` + `WriteClassified` (already mapped) | flags | P1 |
| `sendmmsg` | yes | no | **yes** (sum of msgs) | `KindRet` + `WriteClassified` (already mapped) | vlen, flags | P1 |
| `recvfrom` | yes | no | **yes** (len) | `KindRet` + `ReadClassified` (already mapped) | sockaddr family | P1 |
| `recvmsg` | yes | no | **yes** (iov total) | `KindRet` + `ReadClassified` (already mapped) | flags | P1 |
| `recvmmsg` | yes | no | **yes** (sum of msgs) | `KindRet` + `ReadClassified` (already mapped) | vlen, flags, timeout | P1 |
| `sendfile64` | yes (both in/out fd) | no | **yes** (count) | `KindRet` + `TransferClassified` (already mapped) | both fds | P1 |
| `splice` | yes (both fds) | no | **yes** (len) | `KindRet` + `TransferClassified` (already mapped) | both fds, flags | P1 |
| `tee` | yes (both fds) | no | **yes** (len) | `KindRet` + `TransferClassified` (already mapped) | both fds, flags | P1 |

> Note: `RetClassification` already lists the recv/send/sendfile/splice/tee/process_vm_* families. The classifier just refuses them today because `shouldIgnore`/`exactIgnores` short-circuits earlier in `classify.go`. **Removing those ignores is the cheapest possible win** — bytes accounting drops in for free.

### 3.2 IPC — pipes, eventfd, signalfd, message queues, shared mem, semaphores

| Syscall | fd in | fd out | Bytes / size dim? | Suggested kind | Extra metrics | Priority |
|---|---|---|---|---|---|---|
| `pipe` | no | **yes** (out `pipefd[2]`) | no | new `KindPipe` (like `KindSocketpair`) | both fds | P1 |
| `pipe2` | no | **yes** (out `pipefd[2]`) | no | `KindPipe` | both fds, flags | P1 |
| `eventfd` | no | **yes** (ret) | no | new `KindEventfd` | initval | P2 |
| `eventfd2` | no | **yes** (ret) | no | `KindEventfd` | initval, flags | P2 |
| `signalfd` | yes/no (ufd or -1) | **yes** (ret) | yes (sigsetsize) | new `KindSignalfd` | mask | P2 |
| `signalfd4` | yes/no | **yes** | yes | `KindSignalfd` | mask, flags | P2 |
| `timerfd_create` | no | **yes** (ret) | no | new `KindTimerfd` | clockid, flags | P2 |
| `timerfd_settime` | yes | no | no | extend `KindFd` | itimerspec | P2 |
| `timerfd_gettime` | yes | no | no | extend `KindFd` | — | P2 |
| `userfaultfd` | no | **yes** (ret) | no | new `KindEventfd` (reuse — simple ret-fd) | flags | P3 |
| `memfd_create` | no | **yes** (ret) | no | `KindOpen`-shaped (has a name) | name, flags | P2 |
| `memfd_secret` | no | **yes** (ret) | no | new `KindEventfd` (reuse) | flags | P3 |
| `pidfd_open` | no (takes pid_t, not fd) | **yes** (ret) | no | new `KindPidfd` | target pid, flags | P2 |
| `pidfd_send_signal` | yes (pidfd) | no | no | extend `KindFd` | signo | P2 |
| `inotify_init` | no | **yes** (ret) | no | `KindEventfd` (reuse) | — | P2 |
| `inotify_init1` | no | **yes** | no | `KindEventfd` | flags | P2 |
| `inotify_add_watch` | yes | yes (watch desc, *not* an fd) | yes (path len) | new `KindInotifyAdd` | path, mask | P2 |
| `inotify_rm_watch` | yes | no | no | extend `KindFd` | watch descriptor | P3 |
| `fanotify_init` | no | **yes** (ret) | no | `KindEventfd` (reuse) | flags, event_f_flags | P2 |
| `mq_open` | no | **yes** (ret mqd_t) | no | new `KindMqOpen` (path-style + ret fd) | name, oflag | P2 |
| `mq_unlink` | no | no | no | `KindPathname` (already shape-compatible) | name | P3 |
| `mq_timedsend` | yes (mqd_t) | no | **yes** (msg_len) | extend `KindFd` + `WriteClassified` | priority | P2 |
| `mq_timedreceive` | yes (mqd_t) | no | **yes** (msg_len) | extend `KindFd` + `ReadClassified` | priority | P2 |
| `mq_notify` | yes (mqd_t) | no | no | extend `KindFd` | — | P3 |
| `mq_getsetattr` | yes (mqd_t) | no | no | extend `KindFd` | — | P3 |
| `msgget` | no | yes (msqid, kernel id not fd) | no | new `KindSysVId` | key, flags | P3 |
| `msgsnd` | yes (msqid) | no | **yes** (msgsz) | new `KindSysVOp` + `WriteClassified` | mtype | P3 |
| `msgrcv` | yes (msqid) | no | **yes** (msgsz) | `KindSysVOp` + `ReadClassified` | mtype | P3 |
| `msgctl` | yes (msqid) | no | no | `KindSysVOp` | cmd | P3 |
| `semget` | no | yes (semid) | no | `KindSysVId` | key, nsems | P3 |
| `semop` | yes (semid) | no | yes (nsops) | `KindSysVOp` | — | P3 |
| `semtimedop` | yes (semid) | no | yes (nsops) | `KindSysVOp` | timeout | P3 |
| `semctl` | yes (semid) | no | no | `KindSysVOp` | cmd | P3 |
| `shmget` | no | yes (shmid) | yes (size) | `KindSysVId` | key, size | P3 |
| `shmat` | yes (shmid) | no | no (addr returned) | `KindSysVOp` | shmflg | P3 |
| `shmdt` | no (addr) | no | no | `KindNull` | — | P3 |
| `shmctl` | yes (shmid) | no | no | `KindSysVOp` | cmd | P3 |

### 3.3 Process & Thread lifecycle

| Syscall | fd in | fd out | Bytes / size dim? | Suggested kind | Extra metrics | Priority |
|---|---|---|---|---|---|---|
| `clone` | no | no | no (stack size arg) | new `KindProc` | flags, child pid (ret) | P1 |
| `clone3` | no (clone_args struct) | no | no | `KindProc` | flags, child pid (ret) | P1 |
| `fork` | no | no | no | `KindProc` | child pid | P1 |
| `vfork` | no | no | no | `KindProc` | child pid | P2 |
| `execve` | no | no | yes (argv/envp count, len of filename) | new `KindExec` | filename, argv count | P1 |
| `execveat` | **yes** (dirfd) | no | yes | `KindExec` | filename, dirfd, flags | P1 |
| `exit` | no | no | no | `KindNull` | exit code | P1 |
| `exit_group` | no | no | no | `KindNull` | exit code | P1 |
| `wait4` | no | no | no | new `KindProc` | pid waited, options | P2 |
| `waitid` | optional (P_PIDFD: pidfd) | no | no | `KindProc` | idtype, options | P2 |
| `kill` | no | no | no | `KindNull` | pid, signo | P2 |
| `tkill` | no | no | no | `KindNull` | tid, signo | P3 |
| `tgkill` | no | no | no | `KindNull` | tgid, tid, signo | P3 |
| `rt_sigqueueinfo` | no | no | yes (siginfo size) | `KindNull` | pid, signo | P3 |
| `rt_tgsigqueueinfo` | no | no | yes | `KindNull` | tgid, tid, signo | P3 |
| `set_tid_address` | no | no | no | `KindNull` | tid pointer | P3 |
| `setsid` / `getsid` | no | no | no | `KindNull` | pid | P3 |
| `setpgid` / `getpgid` / `getpgrp` | no | no | no | `KindNull` | pid, pgid | P3 |
| `getpid` / `gettid` / `getppid` / `getuid` / `geteuid` / `getgid` / `getegid` / `getresuid` / `getresgid` | no | no | no | `KindNull` | — | P3 |
| `setuid` / `seteuid` / `setgid` / `setegid` / `setresuid` / `setresgid` / `setreuid` / `setregid` / `setfsuid` / `setfsgid` / `setgroups` / `getgroups` | no | no | no | `KindNull` | uid/gid values | P3 |
| `prctl` | no | optional | yes (option-dependent) | new `KindPrctl` | option (PR_*) | P2 |
| `arch_prctl` | no | no | no | `KindPrctl` | code | P3 |
| `personality` | no | no | no | `KindNull` | persona | P3 |
| `unshare` | no | no | no | `KindNull` | flags | P2 |
| `setns` | yes (nsfd) | no | no | extend `KindFd` | nstype | P2 |
| `pivot_root` | no | no | no | `KindPathname` | new_root, put_old | P3 |
| `reboot` | no | no | no | `KindNull` | cmd | P3 |
| `restart_syscall` | no | no | no | `KindNull` | — | P3 |
| `vhangup` | no | no | no | `KindNull` | — | P3 |
| `umask` | no | no | no | `KindNull` | new mask | P3 |
| `getrusage` | no | no | yes (struct out) | `KindNull` | who | P3 |
| `getrlimit` / `setrlimit` / `prlimit64` | optional (prlimit64 takes pid) | no | yes (rlim struct) | `KindNull` | resource | P3 |
| `getpriority` / `setpriority` | no | no | no | `KindNull` | which, who | P3 |

### 3.4 Signals

| Syscall | fd in | fd out | Bytes / size dim? | Suggested kind | Extra metrics | Priority |
|---|---|---|---|---|---|---|
| `rt_sigaction` | no | no | yes (sigsetsize) | `KindNull` | signum | P2 |
| `rt_sigprocmask` | no | no | yes (sigsetsize) | `KindNull` | how | P2 |
| `rt_sigpending` | no | no | yes (sigsetsize) | `KindNull` | — | P3 |
| `rt_sigsuspend` | no | no | yes (sigsetsize) | `KindNull` | — | P3 |
| `rt_sigtimedwait` | no | no | yes (sigsetsize) | `KindNull` | timeout | P3 |
| `rt_sigreturn` | no | no | no | `KindNull` | — | P3 |
| `sigaltstack` | no | no | no | `KindNull` | — | P3 |
| `pause` | no | no | no | `KindNull` | — | P3 |

### 3.5 Memory

This family is *very* hot in many workloads and arguably the single most valuable non-IO addition after sockets.

| Syscall | fd in | fd out | Bytes / size dim? | Suggested kind | Extra metrics | Priority |
|---|---|---|---|---|---|---|
| `brk` | no | no | **yes** (new break addr → delta) | new `KindMem` | new break | P2 |
| `mmap` | optional (`MAP_ANONYMOUS` → -1, else fd) | no | **yes** (length) | extend existing `KindFd` (already traced!) — `mmap` is *already in the active list*. Confirm bytes-accounting wiring. | length, prot, flags, offset | (covered) |
| `mmap2` | optional | no | **yes** (length) | extend `KindFd` (where present, 32-bit) | as `mmap` | P3 |
| `munmap` | no | no | **yes** (length) | `KindMem` | addr, length | P1 |
| `mremap` | no | no | **yes** (old_size, new_size) | `KindMem` | flags | P1 |
| `mprotect` | no | no | **yes** (length) | `KindMem` | prot | P2 |
| `pkey_mprotect` | no | no | **yes** (length) | `KindMem` | prot, pkey | P3 |
| `pkey_alloc` | no | no | no | `KindNull` | flags, access_rights | P3 |
| `pkey_free` | no | no | no | `KindNull` | pkey | P3 |
| `madvise` | no | no | **yes** (length) | `KindMem` | advice | P2 |
| `process_madvise` | yes (pidfd) | no | **yes** (iov total) | extend `KindFd` | advice | P3 |
| `process_mrelease` | yes (pidfd) | no | no | extend `KindFd` | flags | P3 |
| `mincore` | no | no | **yes** (length) | `KindMem` | — | P3 |
| `mlock` / `mlock2` / `munlock` | no | no | **yes** (length) | `KindMem` | flags | P3 |
| `mlockall` / `munlockall` | no | no | no | `KindNull` | flags | P3 |
| `mbind` / `set_mempolicy` / `get_mempolicy` / `set_mempolicy_home_node` | no | no | yes (maxnode, length) | `KindMem` | mode, flags | P3 |
| `migrate_pages` | no | no | yes (maxnode) | `KindMem` | pid | P3 |
| `move_pages` | no | no | yes (nr_pages) | `KindMem` | pid, flags | P3 |
| `remap_file_pages` | no | no | **yes** (size) | `KindMem` | prot, pgoff | P3 |
| `map_shadow_stack` | no | no | **yes** (size) | `KindMem` | flags | P3 |
| `mseal` | no | no | **yes** (len) | `KindMem` | flags | P3 |
| `process_vm_readv` | no (takes pid) | no | **yes** (iov total) | `KindRet` + `ReadClassified` (already mapped) | pid | P2 |
| `process_vm_writev` | no (takes pid) | no | **yes** (iov total) | `KindRet` + `WriteClassified` (already mapped) | pid | P2 |

> `process_vm_readv` and `process_vm_writev` are already in `retClassifications`. Like the network send/recv family, they are blocked only by `shouldIgnore`. Cheap to enable.

### 3.6 Polling & event waiting

These don't move bytes but their *duration/latency* is critical for explaining "where did the time go" — exactly the question ior is built to answer.

| Syscall | fd in | fd out | Bytes / size dim? | Suggested kind | Extra metrics | Priority |
|---|---|---|---|---|---|---|
| `epoll_create` | no | **yes** (ret) | no | `KindEventfd` (reuse) | size | P1 |
| `epoll_create1` | no | **yes** (ret) | no | `KindEventfd` | flags | P1 |
| `epoll_ctl` | yes (epfd + target fd) | no | no | new `KindEpollCtl` (two fds) | op, events | P1 |
| `epoll_wait` | yes (epfd) | no | yes (maxevents → events ret) | extend `KindFd` | timeout, ret count | P1 |
| `epoll_pwait` | yes (epfd) | no | yes | extend `KindFd` | timeout, sigmask | P1 |
| `epoll_pwait2` | yes (epfd) | no | yes | extend `KindFd` | timespec, sigmask | P1 |
| `poll` | no (pollfd array passed by ref) | no | yes (nfds → ready count) | new `KindPoll` | nfds, timeout | P1 |
| `ppoll` | no | no | yes | `KindPoll` | nfds, timespec, sigmask | P1 |
| `select` / `pselect6` | yes (nfds upper) | no | yes (ready count) | `KindPoll` | nfds, timeout | P1 |
| `io_pgetevents` | yes (ctx is aio_context_t, not fd) | no | yes | already traced (`KindNull`) | — | (covered) |

### 3.7 Time

| Syscall | fd in | fd out | Bytes / size dim? | Suggested kind | Extra metrics | Priority |
|---|---|---|---|---|---|---|
| `nanosleep` | no | no | yes (timespec) | new `KindSleep` | requested ns | P1 |
| `clock_nanosleep` | no | no | yes | `KindSleep` | clockid, flags, requested ns | P1 |
| `clock_gettime` | no | no | no | `KindNull` | clockid | P2 |
| `clock_settime` | no | no | no | `KindNull` | clockid | P3 |
| `clock_getres` | no | no | no | `KindNull` | clockid | P3 |
| `clock_adjtime` | no | no | no | `KindNull` | clockid | P3 |
| `gettimeofday` / `settimeofday` | no | no | no | `KindNull` | — | P3 |
| `time` | no | no | no | `KindNull` | — | P3 |
| `times` | no | no | yes (tms struct out) | `KindNull` | — | P3 |
| `adjtimex` | no | no | no | `KindNull` | — | P3 |
| `alarm` | no | no | no | `KindNull` | seconds | P3 |
| `getitimer` / `setitimer` | no | no | no | `KindNull` | which | P3 |
| `timer_create` | no | yes (timer_t out) | no | new `KindTimerObj` | clockid | P3 |
| `timer_settime` / `timer_gettime` / `timer_getoverrun` / `timer_delete` | no (timer_t) | no | no | `KindTimerObj` | timer id | P3 |

### 3.8 Scheduling & CPU affinity

| Syscall | fd in | fd out | Bytes / size dim? | Suggested kind | Extra metrics | Priority |
|---|---|---|---|---|---|---|
| `sched_yield` | no | no | no | `KindNull` | — | P2 |
| `futex` | no | no | no | new `KindFutex` | op, addr, val, timeout | **P1** (hottest non-IO call in many workloads) |
| `futex_wait` / `futex_wake` / `futex_requeue` / `futex_waitv` | no | no | no | `KindFutex` | as above | P1 |
| `sched_setaffinity` / `sched_getaffinity` | no | no | yes (cpusetsize) | `KindNull` | pid | P3 |
| `sched_setparam` / `sched_getparam` / `sched_setscheduler` / `sched_getscheduler` / `sched_setattr` / `sched_getattr` / `sched_get_priority_max` / `sched_get_priority_min` / `sched_rr_get_interval` | no | no | no | `KindNull` | pid, policy | P3 |
| `getcpu` | no | no | no | `KindNull` | — | P3 |

### 3.9 Filesystem mount / quotas (already partially covered)

| Syscall | fd in | fd out | Bytes / size dim? | Suggested kind | Extra metrics | Priority |
|---|---|---|---|---|---|---|
| `mount` | optional (source/target are paths) | no | no | `KindPathname` (mount-source flavor) | filesystemtype, flags | P2 |
| `umount` / `umount2` | no | no | no | `KindPathname` | target, flags | P2 |
| `move_mount` | yes (from_dfd, to_dfd) | no | no | new `KindTwoFd` (two dirfds) | flags | P2 |
| `fsmount` | yes (fsfd) | **yes** (ret) | no | new `KindEventfd`-shaped + dirfd in | attr_flags, ms_flags | P2 |
| `fsopen` | no | **yes** (ret) | no | `KindEventfd`-shaped | fs_name, flags | P2 |
| `pivot_root` | no | no | no | `KindPathname` | (see §3.3) | P3 |
| `quotactl` | no | no | yes (struct size) | `KindPathname` (special block-dev) | cmd, id | P3 |
| `statmount` | no | no | yes (bufsize) | `KindNull` | mnt_id | P3 |
| `listmount` | no | no | yes (nr_request → nr_ret) | `KindNull` | mnt_id | P3 |
| `listns` | no | no | yes (nr_request → nr_ret) | `KindNull` | — | P3 |

### 3.10 Security / capabilities / keys / Landlock / seccomp / BPF / module loading

| Syscall | fd in | fd out | Bytes / size dim? | Suggested kind | Extra metrics | Priority |
|---|---|---|---|---|---|---|
| `bpf` | optional (BPF_*_GET_FD_BY_ID etc) | optional (many ops return fd) | yes (attr size) | new `KindBpf` | cmd, attr size, ret fd | P1 (very useful for tracer-on-tracer debugging) |
| `seccomp` | optional (SECCOMP_FILTER_FLAG_NEW_LISTENER → ret fd) | optional | yes (filter size) | new `KindSeccomp` | operation, flags | P2 |
| `landlock_create_ruleset` | no | **yes** (ret) | yes (attr size) | `KindEventfd` (reuse) | flags | P2 |
| `landlock_add_rule` | yes (ruleset_fd) | no | yes (attr size) | extend `KindFd` | rule_type, flags | P2 |
| `landlock_restrict_self` | yes (ruleset_fd) | no | no | extend `KindFd` | flags | P2 |
| `lsm_get_self_attr` / `lsm_set_self_attr` / `lsm_list_modules` | no | no | yes (size out) | `KindNull` | attr, flags | P3 |
| `keyctl` | no (key_serial) | no | yes (option-dependent) | new `KindKeyctl` | option | P3 |
| `add_key` | no | yes (key_serial, not fd) | yes (plen) | new `KindKeyctl` | type, description | P3 |
| `request_key` | no | yes (key_serial) | yes (description len) | `KindKeyctl` | type | P3 |
| `capget` / `capset` | no | no | yes (struct size) | `KindNull` | — | P3 |
| `init_module` | no | no | yes (len) | new `KindModule` | name, param_values | P2 |
| `finit_module` | yes | no | no | already traced (`KindFd`) | flags, params | (covered) |
| `delete_module` | no | no | no | `KindNull` | name, flags | P2 |
| `kexec_load` / `kexec_file_load` | optional (kexec_file_load takes fd) | no | yes (entries / len) | extend `KindFd` for `kexec_file_load` | flags | P3 |
| `kcmp` | yes (two fds for KCMP_FILE) | no | no | new `KindTwoFd` | type, pid1, pid2 | P3 |

### 3.11 Miscellaneous & sysinfo

| Syscall | fd in | fd out | Bytes / size dim? | Suggested kind | Extra metrics | Priority |
|---|---|---|---|---|---|---|
| `newuname` | no | no | no | `KindNull` | — | P3 |
| `sysinfo` | no | no | yes (struct out) | `KindNull` | — | P3 |
| `sysfs` | no | no | yes | `KindNull` | option | P3 |
| `ustat` | no | no | yes (struct out) | `KindNull` | dev | P3 |
| `sethostname` / `setdomainname` | no | no | yes (len) | `KindNull` | name (truncated) | P3 |
| `acct` | no | no | no | `KindPathname` | filename | P3 |
| `getrandom` | no | no | **yes** (buflen, ret bytes) | `KindRet` + `ReadClassified` (new mapping) | flags | P2 |
| `mknod` | no | no | no | `KindPathname` (with mode/dev) | mode, dev | P3 |
| `mknodat` | yes (dirfd) | no | no | extend `KindFd` + `KindPathname` mix | mode, dev | P3 |
| `utime` / `utimes` | no | no | no | `KindPathname` | times | P3 |
| `swapon` / `swapoff` | no | no | no | `KindPathname` | flags | P3 |
| `ptrace` | no (pid + addr) | no | yes (data, depending on request) | new `KindPtrace` | request, pid | P2 |
| `perf_event_open` | yes (group_fd) | **yes** (ret) | yes (attr size) | new `KindPerfOpen` | type, config, pid, cpu | P2 |
| `uprobe` / `uretprobe` (placeholders if present) | n/a | n/a | n/a | `KindNull` | — | P3 |
| `ioperm` / `iopl` | no | no | no | `KindNull` | from, num, level | P3 |
| `modify_ldt` | no | no | yes (bytecount) | `KindNull` | func | P3 |
| `rseq` | no | no | yes (rseq_len) | `KindNull` | flags, sig | P3 |
| `set_robust_list` / `get_robust_list` | no | no | yes (len) | `KindNull` | — | P3 |
| `membarrier` | no | no | no | `KindNull` | cmd, flags | P3 |
| `mq_unlink` (listed above) | — | — | — | — | — | — |

---

## 4. Cross-Cutting Findings

### 4.1 Which syscalls have an fd as argument? (Summary)

Out of the ~230 currently-ignored syscalls, **fd as argument** appears in:

- Network: `connect`, `bind`, `listen`, `accept(4)`, `shutdown`, `getsockname`, `getpeername`, `getsockopt`, `setsockopt`, `sendto/sendmsg/sendmmsg`, `recvfrom/recvmsg/recvmmsg`, `sendfile64` (two), `splice` (two), `tee` (two)
- IPC: `mq_*` (all but `mq_open`/`mq_unlink`), `inotify_add_watch`, `inotify_rm_watch`, `pidfd_send_signal`, `signalfd[4]` (sometimes), `timerfd_settime/gettime`
- Polling: `epoll_ctl` (two fds), `epoll_wait/pwait/pwait2`, `select`/`pselect6` (nfds upper bound)
- Process: `setns`, `execveat` (dirfd), `process_madvise` (pidfd), `process_mrelease` (pidfd), `waitid` (P_PIDFD), `kcmp` (two)
- Security: `landlock_add_rule` (ruleset_fd), `landlock_restrict_self`, `kexec_file_load`
- Mount: `move_mount` (two), `fsmount` (fsfd)
- Perf: `perf_event_open` (group_fd)
- Already-mapped Ret-classified bytes-carrying entries that block on `shouldIgnore` only: all send/recv variants, `sendfile64`, `splice`, `tee`, `vmsplice` (already traced), `process_vm_readv`, `process_vm_writev`

### 4.2 Which syscalls return an fd? (Summary)

`socket`, `socketpair` (two out), `accept(4)`, `pipe/pipe2` (two out), `eventfd(2)`, `signalfd[4]`, `timerfd_create`, `userfaultfd`, `memfd_create`, `memfd_secret`, `pidfd_open`, `inotify_init[1]`, `fanotify_init`, `epoll_create[1]`, `mq_open` (mqd_t), `bpf` (most ops), `seccomp` (listener), `landlock_create_ruleset`, `perf_event_open`, `fsopen`, `fsmount`, `open_tree` (already covered), `kexec_file_load` (no), `add_key`/`request_key` (key_serial, *not* an fd).

### 4.3 Which syscalls have a meaningful "bytes" or "size" dimension?

Two distinct cases:

1. **True payload bytes** (move data) — these should plug into the existing `RetClassification` (Read/Write/Transfer):
   - Already mapped but blocked by `shouldIgnore`: all socket send/recv, `sendfile64`, `splice`, `tee`, `process_vm_readv/writev`.
   - New candidates worth adding to `retClassifications`:
     - `getrandom` → ReadClassified
     - `mq_timedsend` → WriteClassified
     - `mq_timedreceive` → ReadClassified
     - `msgsnd` → WriteClassified
     - `msgrcv` → ReadClassified
2. **Address-space size** (no data movement but a meaningful "extent"): `mmap` (already traced), `munmap`, `mremap`, `mprotect`, `madvise`, `mincore`, `mlock`, `mlock2`, `munlock`, `remap_file_pages`, `pkey_mprotect`, `map_shadow_stack`, `mseal`, `brk` (delta). These warrant a **new accumulator** ("address-space bytes" or "mem ops bytes") rather than overloading the I/O byte counters — mixing the two would distort the IO flamegraph.
3. **Auxiliary "size" that doesn't fit a bytes bucket** but is still worth recording per-event (e.g. `epoll_wait` maxevents/returned, `poll`/`select` nfds, `nanosleep` requested ns, `clock_nanosleep` requested ns, `sched_setaffinity` cpusetsize, `rt_sigaction` sigsetsize). These should remain per-event metadata, not aggregated into the bytes accumulator.

### 4.4 Required taxonomy extensions

To cover §3 cleanly, `TracepointKind` should grow these new kinds (each maps to one C struct in `internal/c/types.h`):

| New kind | Purpose | Shape |
|---|---|---|
| `KindSocket` | `socket(family,type,protocol)` returning a new fd | flags + ret fd |
| `KindAccept` | `accept`/`accept4` — listening fd in, new fd out, optional sockaddr | two fds + sockaddr family |
| `KindSocketpair` | two-out-fd creation | flags + sv[0], sv[1] |
| `KindPipe` | as above for `pipe`/`pipe2` | flags + pipefd[0], pipefd[1] |
| `KindEventfd` | generic "no-arg → ret fd" (eventfd, signalfd, timerfd_create, userfaultfd, memfd_secret, inotify_init[1], fanotify_init, epoll_create[1], landlock_create_ruleset, fsopen) | flags only |
| `KindEpollCtl` | epfd + target fd + op + events | two fds |
| `KindPoll` | poll/ppoll/select/pselect6 | nfds + timeout |
| `KindMem` | memory-region ops with addr+length | addr + length + mode/flags |
| `KindProc` | clone/fork/wait/exec metadata | pid (ret), flags |
| `KindExec` | execve(at) with path + dirfd | path + dirfd + flags |
| `KindFutex` | futex op grouping | op + addr + val + timeout |
| `KindSleep` | nanosleep/clock_nanosleep | requested timespec |
| `KindBpf` | bpf(cmd, attr, size) | cmd + attr_size + ret fd |
| `KindPrctl` | prctl option-keyed | option |
| `KindPtrace` | ptrace request + pid | request + pid |
| `KindPerfOpen` | perf_event_open with attr + group_fd | attr_type/config + group_fd + ret fd |
| `KindKeyctl` | key_serial-based, no fd | option + key_serial |
| `KindMqOpen` | mq_open (path + flags + ret mqd_t) | path + flags + mqd_t |
| `KindPidfd` | pidfd_open (pid → ret pidfd) | pid + ret fd |
| `KindSysVId` | msgget/semget/shmget — IPC id allocations | key + flags + ret id |
| `KindSysVOp` | msgsnd/msgrcv/semop/semtimedop/semctl/shmat/shmctl | id + size + cmd |
| `KindTwoFd` | for `move_mount`/`kcmp` etc. needing two fds | fd_a + fd_b + extra |
| `KindModule` | init_module/delete_module | name + image_len |
| `KindTimerObj` | POSIX timer_create/settime family | timer_t + clockid |

> Each entry above will need a registration in `kindRegistry` (which already follows OCP: a new entry is sufficient and no switch needs updating elsewhere — see `internal/generate/kindregistry.go`).

### 4.5 Filters and dashboards

The existing `internal/globalfilter/` and dashboard tabs categorise by *file/path/pid*. Many non-IO syscalls have no path. Two recommendations:

1. **Add a "syscall family" dimension** (Network, Memory, Signals, Sched, IPC, Time, Process, Security, FS, Polling, AIO, Other) to the stats engine so dashboards can group at a higher level than per-syscall.
2. **Add a "non-IO" tab** (or extend the syscalls tab) so the existing tabs stay focused on file path / fd while a new tab summarises the broader set.

### 4.6 Volume / cardinality risk

Tracing `futex`, `clock_gettime`, `epoll_wait`, `nanosleep`, and `read`/`write` on a busy box can flood the ring buffer. Recommendations:

- Default new syscalls to **disabled** behind a flag (e.g. `-trace-non-io=family1,family2` or a single `-trace-all-syscalls`).
- Make the per-family enable list opt-in.
- Sample very-high-frequency syscalls (`futex`, `clock_gettime`) via a 1-in-N counter at the BPF probe before submitting to the ring buffer; the duration/latency stats can still be aggregated in-kernel via a `BPF_MAP_TYPE_HASH` keyed by syscall id without per-event ring-buffer pressure.
- Consider an *aggregate-only* mode that maintains in-kernel count/duration histograms and surfaces them once per dashboard tick rather than per event.

### 4.7 Code generator impact

`internal/generate/classify.go` currently uses `shouldIgnore` to short-circuit the parser. The cleanest migration is:

1. Replace the static ignore list with a *category* tag on every parsed `Format` (every tracepoint gets a family). The generator emits handlers for *all* families; per-family inclusion is gated at runtime (BPF map / userspace flag), not at codegen time.
2. Expand `classifyNameOnly` / `classifyByField` / `classifyNameAndField` to recognise the new kinds.
3. Add new C struct templates in `internal/c/types.h` for the new event shapes.
4. Expand `retClassifications` (in `classify.go`) with the already-listed-but-currently-unreachable network entries plus the new candidates (`getrandom`, `mq_timedsend`, `mq_timedreceive`, `msgsnd`, `msgrcv`).
5. Regenerate (`mage generate`), then test (`mage test`, `mage integrationTest`).

---

## 5. Prioritised Rollout

A pragmatic, low-risk order of work — each step ships independent value:

**Phase A — "free wins"** (no new kind needed, just unblock ignores)
- Network read/write bytes: enable `sendto`/`sendmsg`/`sendmmsg`/`recvfrom`/`recvmsg`/`recvmmsg`, `sendfile64`, `splice`, `tee`, `process_vm_readv`, `process_vm_writev`. These already appear in `retClassifications`; only `shouldIgnore` blocks them. Need a `KindRet` exit handler and minimal enter wiring.

**Phase B — high-impact families** (new kinds, but small set, very visible payoff)
- `socket`/`socketpair`/`accept[4]`/`bind`/`connect`/`listen`/`shutdown` + getsock*/setsock*
- `pipe`/`pipe2`/`eventfd[2]`/`memfd_create`/`epoll_create[1]`/`signalfd[4]`/`timerfd_create`
- `epoll_ctl`/`epoll_wait`/`epoll_pwait[2]`/`poll`/`ppoll`/`select`/`pselect6`
- `futex` family (with sampling)
- `nanosleep`/`clock_nanosleep`
- `mmap` (already covered) + `munmap`/`mremap`/`mprotect`/`madvise`/`brk`

**Phase C — process & exec lifecycle**
- `clone`/`clone3`/`fork`/`vfork`/`execve`/`execveat`/`exit`/`exit_group`/`wait4`/`waitid`
- `prctl`, `setns`, `unshare`

**Phase D — security & module**
- `bpf`, `seccomp`, `landlock_*`, `keyctl`/`add_key`/`request_key`, `init_module`/`delete_module`

**Phase E — long tail / P3**
- All remaining `getX/setX` identity calls, sched_*, time_*, SysV IPC, sysinfo, ptrace, perf_event_open, etc.

---

## 6. Estimated Final Coverage

| Phase | New syscalls covered | Running total / 250 |
|---|---|---|
| Baseline (today) | 0 | 117 |
| Phase A | +12 (recv/send/sendfile/splice/tee/process_vm_*) | 129 |
| Phase B | +~40 (sockets, pipes, fds-from-air, polling, futex, sleep, memory) | ~170 |
| Phase C | +~15 (process lifecycle) | ~185 |
| Phase D | +~15 (security, modules, keys) | ~200 |
| Phase E | +~50 (long tail) | ~250 |

When all phases ship, the generator should also stop emitting `Ignoring ...` comments for these and instead emit a per-syscall family tag.

---

## 7. Out of Scope (Explicit Non-Goals)

- **Per-syscall implementation.** This document is plan-only.
- **Replacing the existing IO classification.** Read/write bytes remain the primary accumulator; new families add *alongside* it.
- **Network packet inspection.** ior is a syscall tracer, not a packet-capture tool — sockaddr decoding is acceptable, payload decoding is not.
- **Cross-OS support.** Linux-only, matching the rest of ior.

---

## 8. Open Questions for Discussion

1. Should `KindMem` aggregate "address-space bytes" into the same dashboard tile as I/O bytes, into a separate tile, or into a derived "memory pressure" metric?
2. Should sampling be (a) at BPF probe (skip events), (b) at userspace ingest (drop events but keep histograms), or (c) hybrid?
3. Is per-family enable/disable enough, or do we need per-syscall granularity in the CLI flag? (Implementation cost is similar; UX is the trade-off.)
4. For `futex` (and similar very-hot calls) should the default be "off entirely, opt-in only" or "aggregate-only by default, per-event opt-in"?
5. How do we want to surface return-value-only metrics (e.g. `epoll_wait` ready-count, `select` ready-count, `poll` nfds) in the TUI? A new column in the per-syscall tab, or a dedicated polling tab?

---

*Document version: 1.0 — initial plan. Maintainer: see `AGENTS.md`.*
