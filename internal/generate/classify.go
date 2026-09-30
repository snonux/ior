package generate

import (
	"maps"
	"slices"
	"strings"
)

// TracepointKind is the payload shape a syscall tracepoint was classified
// into: it decides which C event struct the generated handler stores the
// payload in and, on the userspace side, which exit handler consumes the
// pair.
type TracepointKind int

const (
	// KindNone means the format could not be classified.
	KindNone TracepointKind = iota
	// KindFd carries the descriptor number at the classifier-selected
	// argument slot - args[0] for nearly all of the cohort.
	KindFd
	// KindOpen carries a pathname plus open flags.
	KindOpen
	// KindMqOpen is the mq_open variant of the open shape.
	KindMqOpen
	// KindOpenTree carries an open_tree/open_tree_attr pathname plus their
	// mount-API flags. It uses the open_event transport, but remains distinct
	// from KindOpen so userspace can translate that syscall-specific flag word
	// before registering the returned O_PATH descriptor.
	KindOpenTree
	// KindExec carries a filename and the caller's comm.
	KindExec
	// KindPathname carries the pathname argument selected by the
	// classifier's PathnameField - args[1] for the *at() cohort, args[0]
	// for the mount/chmod-style callers.
	KindPathname
	// KindFdPathname carries a notification-group fd and its watched pathname,
	// with independent dirfd context for fanotify_mark.
	KindFdPathname
	// KindName carries two pathnames (oldname, newname) for the rename family.
	KindName
	// KindRet is the bare enter/exit shape carrying only the return value.
	KindRet
	// KindFcntl carries fd, cmd and arg.
	KindFcntl
	// KindNull carries no extra payload beyond the common header.
	KindNull
	// KindDup3 carries fd plus the dup3 flags.
	KindDup3
	// KindOpenByHandleAt carries the open flags.
	KindOpenByHandleAt
	// KindSocket carries family, type and protocol.
	KindSocket
	// KindSocketpair carries family, type, protocol and both returned fds.
	KindSocketpair
	// KindAccept carries the listening fd and the accepted fd's return.
	KindAccept
	// KindPipe carries flags and both returned fds.
	KindPipe
	// KindEventfd carries flags and the returned fd (the eventfd/epoll/signalfd
	// family of fd-creating calls).
	KindEventfd
	// KindNamedEventfd adds an identifying string to the eventfd payload, in
	// its own eventfd_name_event so that the other eventfd-family calls keep
	// the lean eventfd_event. It keeps the stable "eventfd" metadata name and
	// its exit is plain KindEventfd, while the enter side enables exit-time
	// recovery when the enter-side nofault read misses.
	KindNamedEventfd
	// KindPidfd is the pidfd_open variant of the eventfd shape.
	KindPidfd
	// KindEpollCtl carries epfd, op, target fd and events.
	KindEpollCtl
	// KindTwoFd carries two descriptor numbers: close_range's first/last
	// bounds, move_mount's from/to fds, and kcmp's KCMP_FILE indices.
	KindTwoFd
	// KindPoll carries the polled fd count and timeout.
	KindPoll
	// KindMem carries address, length (plus length2 for the mremap
	// variants) and flags - the mprotect/mremap/mlock/msync cohort.
	KindMem
	// KindMmap carries mmap's fd together with the complete mapping range,
	// protection and flags. It is distinct from KindFd because mmap's length
	// contributes to address-space accounting, and distinct from KindMem
	// because file-backed mappings still need descriptor resolution.
	KindMmap
	// KindSleep carries the requested sleep duration.
	KindSleep
	// KindKeyctl carries the keyctl option, key serial and value.
	KindKeyctl
	// KindPtrace carries the request, target pid and data.
	KindPtrace
	// KindPerfOpen carries the perf_event_attr subset plus target/cpu/group.
	KindPerfOpen
	// KindSeccomp maps to the header-only null_event: the seccomp operation
	// and flags are not captured.
	KindSeccomp
	// KindModule maps to the header-only null_event: the module flags are
	// not captured.
	KindModule
	// KindSysVId maps to the header-only null_event: the SysV IPC id is
	// not captured.
	KindSysVId
	// KindSysVOp maps to the header-only null_event: the SysV IPC operation
	// buffer is not captured.
	KindSysVOp
	// KindProc maps to the header-only null_event: the pid/proc argument is
	// not captured.
	KindProc
	// KindBpf captures the command selector used to decide whether a successful
	// return value is a new descriptor. The attr pointer stays uncaptured.
	KindBpf
	// KindFutex maps to the header-only null_event: argument capture is
	// deliberately skipped (see the futex comment in family.go).
	KindFutex
	// KindPrctl maps to the header-only null_event: the option and arg are
	// not captured.
	KindPrctl
	// KindTimerObj maps to the header-only null_event: the timer object id
	// is not captured.
	KindTimerObj
	// KindFdSize is KindFd plus the requested output-buffer size, for the
	// fd-based xattr reads whose zero-size call is a size probe. It has its
	// own fd_size_event so that every other fd syscall - read and write above
	// all - keeps the lean fd_event. Its metadata name stays "fd".
	KindFdSize
	// KindTwoFdNames is KindTwoFd plus the two pathnames move_mount passes
	// alongside its descriptors. It has its own two_fd_names_event so that
	// close_range and kcmp do not carry 512 unused name bytes. Its metadata
	// name stays "two-fd".
	KindTwoFdNames
)

// kindMetadataNames maps each kind to its stable metadata name. It is a data
// table rather than a switch so adding a kind is a one-line change. Several
// kinds deliberately share a name: the size/names variants (KindFdSize,
// KindTwoFdNames) keep their base kind's name, and KindNamedEventfd shares
// "eventfd", so downstream metadata consumers see one stable label.
var kindMetadataNames = map[TracepointKind]string{
	KindFd:             "fd",
	KindFdSize:         "fd",
	KindOpen:           "open",
	KindMqOpen:         "mq-open",
	KindOpenTree:       "open-tree",
	KindExec:           "exec",
	KindPathname:       "pathname",
	KindFdPathname:     "fd-pathname",
	KindName:           "name",
	KindRet:            "ret",
	KindFcntl:          "fcntl",
	KindNull:           "null",
	KindDup3:           "dup3",
	KindOpenByHandleAt: "open-by-handle-at",
	KindSocket:         "socket",
	KindSocketpair:     "socketpair",
	KindAccept:         "accept",
	KindPipe:           "pipe",
	KindEventfd:        "eventfd",
	KindNamedEventfd:   "eventfd",
	KindPidfd:          "pidfd",
	KindEpollCtl:       "epoll-ctl",
	KindTwoFd:          "two-fd",
	KindTwoFdNames:     "two-fd",
	KindPoll:           "poll",
	KindMem:            "mem",
	KindMmap:           "mmap",
	KindSleep:          "sleep",
	KindKeyctl:         "keyctl",
	KindPtrace:         "ptrace",
	KindPerfOpen:       "perf-open",
	KindSeccomp:        "seccomp",
	KindModule:         "module",
	KindSysVId:         "sysv-id",
	KindSysVOp:         "sysv-op",
	KindProc:           "proc",
	KindBpf:            "bpf",
	KindFutex:          "futex",
	KindPrctl:          "prctl",
	KindTimerObj:       "timer-obj",
}

// MetadataName returns the kind's stable name as written into
// generated_tracepoints.c metadata comments and the Go tracepoint list.
// KindNone and any kind missing from kindMetadataNames report "none".
func (k TracepointKind) MetadataName() string {
	if name, ok := kindMetadataNames[k]; ok {
		return name
	}
	return "none"
}

// RetClassification labels what a KindRet syscall's return value counts, so
// the userspace exit handler can extract transferred bytes from it.
type RetClassification string

const (
	// Unclassified means the return carries no byte semantics.
	Unclassified RetClassification = "UNCLASSIFIED"
	// ReadClassified means a positive return is a byte count read.
	ReadClassified RetClassification = "READ_CLASSIFIED"
	// WriteClassified means a positive return is a byte count written.
	WriteClassified RetClassification = "WRITE_CLASSIFIED"
	// TransferClassified means a positive return is a byte count moved
	// (splice, sendfile, copy_file_range, ...).
	TransferClassified RetClassification = "TRANSFER_CLASSIFIED"
)

// ClassificationResult is what ClassifyFormat decided about one tracepoint:
// its payload kind and, for the pathname kinds, which format field carries
// the path.
type ClassificationResult struct {
	Kind          TracepointKind
	PathnameField string // for KindPathname: e.g. "pathname", "path", "filename", "name", "u_name"
}

// ClassifyFormat determines the tracepoint kind for a parsed format section.
// It mirrors the Raku multi-dispatch: name-based ignores take priority,
// then name-only mappings, then each external field is tried in order until
// one matches a name+field or generic field pattern.
func ClassifyFormat(f *Format) ClassificationResult {
	if len(f.ExternalFields) == 0 {
		return ClassificationResult{Kind: KindNone}
	}

	if r, ok := classifyNameOnly(f.Name); ok {
		return r
	}

	for _, field := range f.ExternalFields {
		if field.Name == "__syscall_nr" {
			continue
		}
		if r, ok := classifyNameAndField(f.Name, field.Type, field.Name); ok {
			return r
		}
		if r, ok := classifyByField(field.Type, field.Name); ok {
			return r
		}
	}

	return ClassificationResult{Kind: KindNone}
}

// classifyNameOnly handles tracepoints classified by name alone,
// independent of any field.
//
// Keep newly-added syscall expansion mappings in this table first to reduce
// switch churn and merge conflicts across incremental tracing phases.
var nameOnlyKindsTable = map[string]TracepointKind{
	"sys_enter_inotify_add_watch": KindFdPathname,
	"sys_enter_fanotify_mark":     KindFdPathname,
	"sys_enter_open_by_handle_at": KindOpenByHandleAt,
	"sys_enter_open_tree":         KindOpenTree,
	"sys_enter_open_tree_attr":    KindOpenTree,
	"sys_enter_io_uring_enter":    KindFd,
	"sys_enter_io_uring_register": KindFd,
	"sys_enter_fcntl":             KindFcntl,
	// ioctl(fd, cmd, arg) shares fcntl's argument layout. Capturing cmd lets
	// userspace apply FIOCLEX/FIONCLEX, which set/clear close-on-exec exactly
	// like fcntl F_SETFD; userspace routes it by trace ID, not by fcntl cmd.
	"sys_enter_ioctl":  KindFcntl,
	"sys_enter_syslog": KindNull,
	"sys_enter_sync":   KindNull,
	"sys_enter_msync":  KindMem,
	"sys_enter_getcwd": KindNull,

	"sys_enter_socket":     KindSocket,
	"sys_enter_socketpair": KindSocketpair,
	"sys_exit_socketpair":  KindSocketpair,
	"sys_enter_accept":     KindAccept,
	"sys_exit_accept":      KindAccept,
	"sys_enter_accept4":    KindAccept,
	"sys_exit_accept4":     KindAccept,
	"sys_enter_pipe":       KindPipe,
	"sys_exit_pipe":        KindPipe,
	"sys_enter_pipe2":      KindPipe,
	"sys_exit_pipe2":       KindPipe,

	"sys_enter_eventfd":        KindEventfd,
	"sys_exit_eventfd":         KindEventfd,
	"sys_enter_eventfd2":       KindEventfd,
	"sys_exit_eventfd2":        KindEventfd,
	"sys_enter_memfd_create":   KindNamedEventfd,
	"sys_exit_memfd_create":    KindEventfd,
	"sys_enter_memfd_secret":   KindEventfd,
	"sys_exit_memfd_secret":    KindEventfd,
	"sys_enter_userfaultfd":    KindEventfd,
	"sys_exit_userfaultfd":     KindEventfd,
	"sys_enter_signalfd":       KindEventfd,
	"sys_exit_signalfd":        KindEventfd,
	"sys_enter_signalfd4":      KindEventfd,
	"sys_exit_signalfd4":       KindEventfd,
	"sys_enter_timerfd_create": KindEventfd,
	"sys_exit_timerfd_create":  KindEventfd,
	// timerfd_settime/timerfd_gettime operate on an EXISTING timerfd whose
	// tracepoint arg0 is named "ufd" (int), not literally "fd". The generic
	// field matcher (classifyByField) only maps fieldName=="fd" -> KindFd, so
	// without these overrides they fall through to KindNull and capture NO
	// descriptor — dropping the timerfd they act on. Classify them KindFd so
	// the enter handler captures the timerfd at args[0], mirroring the
	// epoll_wait(epfd) and mq_*(mqdes) precedent. timerfd_create above is the
	// fd CREATOR (KindEventfd) and is intentionally left unchanged.
	"sys_enter_timerfd_settime": KindFd,
	"sys_enter_timerfd_gettime": KindFd,
	// The fd-based xattr reads capture their requested buffer size (see
	// requestedSizeArgument): a zero size makes the call a size probe whose
	// positive return is not a byte count.
	"sys_enter_fgetxattr":  KindFdSize,
	"sys_enter_flistxattr": KindFdSize,

	"sys_enter_epoll_create":  KindEventfd,
	"sys_exit_epoll_create":   KindEventfd,
	"sys_enter_epoll_create1": KindEventfd,
	"sys_exit_epoll_create1":  KindEventfd,
	"sys_enter_inotify_init":  KindEventfd,
	"sys_exit_inotify_init":   KindEventfd,
	"sys_enter_inotify_init1": KindEventfd,
	"sys_exit_inotify_init1":  KindEventfd,
	"sys_enter_fanotify_init": KindEventfd,
	"sys_exit_fanotify_init":  KindEventfd,

	"sys_enter_landlock_create_ruleset": KindEventfd,
	"sys_exit_landlock_create_ruleset":  KindEventfd,
	"sys_enter_landlock_add_rule":       KindFd,
	"sys_enter_landlock_restrict_self":  KindFd,
	"sys_enter_fsopen":                  KindNamedEventfd,
	"sys_exit_fsopen":                   KindEventfd,
	"sys_enter_fsmount":                 KindEventfd,
	"sys_exit_fsmount":                  KindEventfd,

	"sys_enter_pidfd_open": KindPidfd,
	"sys_exit_pidfd_open":  KindPidfd,

	"sys_enter_bind":        KindFd,
	"sys_enter_connect":     KindFd,
	"sys_enter_listen":      KindFd,
	"sys_enter_shutdown":    KindFd,
	"sys_enter_getsockname": KindFd,
	"sys_enter_getpeername": KindFd,
	"sys_enter_getsockopt":  KindFd,
	"sys_enter_setsockopt":  KindFd,

	"sys_enter_epoll_wait":   KindPoll,
	"sys_enter_epoll_pwait":  KindPoll,
	"sys_enter_epoll_pwait2": KindPoll,
	"sys_enter_epoll_ctl":    KindEpollCtl,

	// move_mount is the one two-fd syscall that also passes pathnames.
	"sys_enter_move_mount": KindTwoFdNames,
	// close_range(first, last, flags) needs all three arguments, so it is a
	// two_fd_event (fd_a=first, fd_b=last, extra=flags) rather than a single-fd
	// fd_event. This lets the runtime honour the upper bound and the
	// CLOSE_RANGE_CLOEXEC flag instead of closing every fd >= first.
	"sys_enter_close_range": KindTwoFd,
	// The transfer cohort uses a single-fd payload and consistently captures its
	// destination descriptor. The per-syscall argument slots live in
	// fdArgumentOverrides; these name-only entries keep syscalls without a field
	// literally named "fd" from falling through to KindNull.
	"sys_enter_sendfile64": KindFd,
	"sys_enter_splice":     KindFd,
	"sys_enter_tee":        KindFd,
	"sys_enter_statmount":  KindNull,
	"sys_enter_listmount":  KindNull,
	"sys_enter_listns":     KindNull,

	"sys_enter_poll":     KindPoll,
	"sys_enter_ppoll":    KindPoll,
	"sys_enter_select":   KindPoll,
	"sys_enter_pselect6": KindPoll,

	"sys_enter_msgget":     KindSysVId,
	"sys_enter_semget":     KindSysVId,
	"sys_enter_shmget":     KindSysVId,
	"sys_enter_msgsnd":     KindSysVOp,
	"sys_enter_msgrcv":     KindSysVOp,
	"sys_enter_msgctl":     KindSysVOp,
	"sys_enter_semop":      KindSysVOp,
	"sys_enter_semtimedop": KindSysVOp,
	"sys_enter_semctl":     KindSysVOp,
	"sys_enter_shmat":      KindSysVOp,
	"sys_enter_shmdt":      KindSysVOp,
	"sys_enter_shmctl":     KindSysVOp,

	"sys_enter_clone":  KindProc,
	"sys_enter_clone3": KindProc,
	"sys_enter_fork":   KindProc,
	"sys_enter_vfork":  KindProc,
	"sys_enter_wait4":  KindProc,
	"sys_enter_waitid": KindProc,

	"sys_enter_bpf": KindBpf,

	"sys_enter_mprotect":         KindMem,
	"sys_enter_mmap":             KindMmap,
	"sys_enter_madvise":          KindMem,
	"sys_enter_pkey_mprotect":    KindMem,
	"sys_enter_brk":              KindMem,
	"sys_enter_munmap":           KindMem,
	"sys_enter_mremap":           KindMem,
	"sys_enter_mincore":          KindMem,
	"sys_enter_remap_file_pages": KindMem,
	"sys_enter_mlock":            KindMem,
	"sys_enter_mlock2":           KindMem,
	"sys_enter_munlock":          KindMem,
	"sys_enter_mseal":            KindMem,
	"sys_enter_map_shadow_stack": KindMem,

	"sys_enter_pkey_alloc":              KindNull,
	"sys_enter_pkey_free":               KindNull,
	"sys_enter_mbind":                   KindNull,
	"sys_enter_set_mempolicy":           KindNull,
	"sys_enter_get_mempolicy":           KindNull,
	"sys_enter_set_mempolicy_home_node": KindNull,
	"sys_enter_migrate_pages":           KindNull,
	"sys_enter_move_pages":              KindNull,
	"sys_enter_mlockall":                KindNull,
	"sys_enter_munlockall":              KindNull,
	"sys_enter_process_madvise":         KindFd,
	"sys_enter_process_mrelease":        KindFd,
	"sys_enter_pidfd_send_signal":       KindFd,
	"sys_enter_kexec_file_load":         KindFd,
	"sys_enter_kcmp":                    KindTwoFd,
	"sys_enter_mq_timedsend":            KindFd,
	"sys_enter_mq_timedreceive":         KindFd,
	"sys_enter_mq_notify":               KindFd,
	"sys_enter_mq_getsetattr":           KindFd,

	"sys_enter_execve":            KindExec,
	"sys_enter_execveat":          KindExec,
	"sys_enter_exit":              KindNull,
	"sys_enter_exit_group":        KindNull,
	"sys_enter_rt_sigaction":      KindNull,
	"sys_enter_rt_sigprocmask":    KindNull,
	"sys_enter_rt_sigpending":     KindNull,
	"sys_enter_rt_sigsuspend":     KindNull,
	"sys_enter_rt_sigtimedwait":   KindNull,
	"sys_enter_rt_sigreturn":      KindNull,
	"sys_enter_sigaltstack":       KindNull,
	"sys_enter_pause":             KindNull,
	"sys_enter_rt_sigqueueinfo":   KindNull,
	"sys_enter_rt_tgsigqueueinfo": KindNull,

	"sys_enter_futex":         KindFutex,
	"sys_enter_futex_wait":    KindFutex,
	"sys_enter_futex_wake":    KindFutex,
	"sys_enter_futex_requeue": KindFutex,
	"sys_enter_futex_waitv":   KindFutex,

	"sys_enter_kill":    KindNull,
	"sys_enter_prctl":   KindPrctl,
	"sys_enter_setns":   KindFd,
	"sys_enter_unshare": KindNull,

	"sys_enter_nanosleep":        KindSleep,
	"sys_enter_clock_nanosleep":  KindSleep,
	"sys_enter_clock_gettime":    KindNull,
	"sys_enter_clock_settime":    KindNull,
	"sys_enter_clock_getres":     KindNull,
	"sys_enter_clock_adjtime":    KindNull,
	"sys_enter_gettimeofday":     KindNull,
	"sys_enter_settimeofday":     KindNull,
	"sys_enter_time":             KindNull,
	"sys_enter_times":            KindNull,
	"sys_enter_adjtimex":         KindNull,
	"sys_enter_alarm":            KindNull,
	"sys_enter_getitimer":        KindNull,
	"sys_enter_setitimer":        KindNull,
	"sys_enter_timer_create":     KindTimerObj,
	"sys_enter_timer_settime":    KindTimerObj,
	"sys_enter_timer_gettime":    KindTimerObj,
	"sys_enter_timer_getoverrun": KindTimerObj,
	"sys_enter_timer_delete":     KindTimerObj,
	"sys_enter_keyctl":           KindKeyctl,
	"sys_enter_add_key":          KindKeyctl,
	"sys_enter_request_key":      KindKeyctl,
	"sys_enter_ptrace":           KindPtrace,
	"sys_enter_perf_event_open":  KindPerfOpen,
	// seccomp/init_module/delete_module are pinned on the ENTER side only.
	// KindSeccomp/KindModule map to null_event, which has no ret field, so
	// pinning the exit side too made these three exits emit a payload-less
	// null_event: ior_on_syscall_exit() still fed ctx->ret to the kernel-side
	// aggregate map, but the ring-buffer record carried no return value, so
	// consumers reading it (streamrow.New and friends, via event.RetCarrier)
	// had to report ret=0/is_error=false even for failed calls. Leaving the exits
	// unpinned lets field-based classification see "long ret" and pick KindRet
	// (ret_event), like every other generic syscall exit.
	"sys_enter_seccomp":       KindSeccomp,
	"sys_enter_init_module":   KindModule,
	"sys_enter_delete_module": KindModule,

	"sys_enter_getpid":          KindNull,
	"sys_enter_gettid":          KindNull,
	"sys_enter_getppid":         KindNull,
	"sys_enter_getuid":          KindNull,
	"sys_enter_geteuid":         KindNull,
	"sys_enter_getgid":          KindNull,
	"sys_enter_getegid":         KindNull,
	"sys_enter_getresuid":       KindNull,
	"sys_enter_getresgid":       KindNull,
	"sys_enter_getgroups":       KindNull,
	"sys_enter_setuid":          KindNull,
	"sys_enter_seteuid":         KindNull,
	"sys_enter_setgid":          KindNull,
	"sys_enter_setegid":         KindNull,
	"sys_enter_setresuid":       KindNull,
	"sys_enter_setresgid":       KindNull,
	"sys_enter_setreuid":        KindNull,
	"sys_enter_setregid":        KindNull,
	"sys_enter_setfsuid":        KindNull,
	"sys_enter_setfsgid":        KindNull,
	"sys_enter_setgroups":       KindNull,
	"sys_enter_umask":           KindNull,
	"sys_enter_setsid":          KindNull,
	"sys_enter_getsid":          KindNull,
	"sys_enter_setpgid":         KindNull,
	"sys_enter_getpgid":         KindNull,
	"sys_enter_getpgrp":         KindNull,
	"sys_enter_set_tid_address": KindNull,

	"sys_enter_sched_yield":            KindNull,
	"sys_enter_sched_setaffinity":      KindNull,
	"sys_enter_sched_getaffinity":      KindNull,
	"sys_enter_sched_setparam":         KindNull,
	"sys_enter_sched_getparam":         KindNull,
	"sys_enter_sched_setscheduler":     KindNull,
	"sys_enter_sched_getscheduler":     KindNull,
	"sys_enter_sched_setattr":          KindNull,
	"sys_enter_sched_getattr":          KindNull,
	"sys_enter_sched_get_priority_max": KindNull,
	"sys_enter_sched_get_priority_min": KindNull,
	"sys_enter_sched_rr_get_interval":  KindNull,
	"sys_enter_getcpu":                 KindNull,
	"sys_enter_getrusage":              KindNull,
	"sys_enter_getrlimit":              KindNull,
	"sys_enter_setrlimit":              KindNull,
	"sys_enter_prlimit64":              KindNull,
	"sys_enter_getpriority":            KindNull,
	"sys_enter_setpriority":            KindNull,
	"sys_enter_membarrier":             KindNull,
	"sys_enter_rseq":                   KindNull,
	"sys_enter_set_robust_list":        KindNull,
	"sys_enter_get_robust_list":        KindNull,
	"sys_enter_mmap2":                  KindNull,
	"sys_enter_kexec_load":             KindNull,

	"sys_enter_sysinfo":           KindNull,
	"sys_enter_sysfs":             KindNull,
	"sys_enter_ustat":             KindNull,
	"sys_enter_newuname":          KindNull,
	"sys_enter_sethostname":       KindNull,
	"sys_enter_setdomainname":     KindNull,
	"sys_enter_capget":            KindNull,
	"sys_enter_capset":            KindNull,
	"sys_enter_personality":       KindNull,
	"sys_enter_reboot":            KindNull,
	"sys_enter_restart_syscall":   KindNull,
	"sys_enter_vhangup":           KindNull,
	"sys_enter_arch_prctl":        KindNull,
	"sys_enter_ioperm":            KindNull,
	"sys_enter_iopl":              KindNull,
	"sys_enter_modify_ldt":        KindNull,
	"sys_enter_lsm_get_self_attr": KindNull,
	"sys_enter_lsm_set_self_attr": KindNull,
	"sys_enter_lsm_list_modules":  KindNull,
}

var nameOnlyPrefixKinds = []struct {
	prefix string
	kind   TracepointKind
}{
	{prefix: "sys_enter_io_", kind: KindNull},
}

func classifyNameOnly(name string) (ClassificationResult, bool) {
	if kind, ok := nameOnlyKindsTable[name]; ok {
		return ClassificationResult{Kind: kind}, true
	}

	for _, prefixKind := range nameOnlyPrefixKinds {
		if strings.HasPrefix(name, prefixKind.prefix) {
			return ClassificationResult{Kind: prefixKind.kind}, true
		}
	}

	return ClassificationResult{}, false
}

// nameFieldRule classifies one specific syscall-enter tracepoint when it
// carries the expected field: the field must be named fieldName and its C type
// must satisfy typeOK.
type nameFieldRule struct {
	fieldName string
	typeOK    func(string) bool
	result    ClassificationResult
}

// isUnsignedIntType matches the exact "unsigned int" type the dup family uses
// for its descriptor argument (stricter than isFdType on purpose).
func isUnsignedIntType(t string) bool { return t == "unsigned int" }

// pathnameRule builds a rule that captures the given C-string field as the
// tracepoint's pathname.
func pathnameRule(field string) nameFieldRule {
	return nameFieldRule{
		fieldName: field,
		typeOK:    isCStringPtrType,
		result:    ClassificationResult{Kind: KindPathname, PathnameField: field},
	}
}

// nameFieldRules holds the tracepoints that need both their name and a
// specific field to classify. A tracepoint whose field does not match its rule
// is not rejected: it falls through to the generic open-filename check below.
var nameFieldRules = map[string]nameFieldRule{
	"sys_enter_dup":               {fieldName: "fildes", typeOK: isUnsignedIntType, result: ClassificationResult{Kind: KindFd}},
	"sys_enter_dup2":              {fieldName: "oldfd", typeOK: isUnsignedIntType, result: ClassificationResult{Kind: KindFd}},
	"sys_enter_dup3":              {fieldName: "oldfd", typeOK: isUnsignedIntType, result: ClassificationResult{Kind: KindDup3}},
	"sys_enter_name_to_handle_at": pathnameRule("name"),
	"sys_enter_copy_file_range":   {fieldName: "fd_in", typeOK: isFdType, result: ClassificationResult{Kind: KindFd}},
	"sys_enter_mount":             pathnameRule("dir_name"),
	"sys_enter_umount":            pathnameRule("name"),
	"sys_enter_acct":              pathnameRule("name"),
	"sys_enter_pivot_root":        pathnameRule("new_root"),
	"sys_enter_quotactl":          pathnameRule("special"),
	"sys_enter_swapon":            pathnameRule("specialfile"),
	"sys_enter_swapoff":           pathnameRule("specialfile"),
	"sys_enter_mq_open":           {fieldName: "u_name", typeOK: isCStringPtrType, result: ClassificationResult{Kind: KindMqOpen}},
	"sys_enter_mq_unlink":         pathnameRule("u_name"),
}

// classifyNameAndField handles tracepoints that need both the name and
// a specific field to classify: first the per-name rules in nameFieldRules,
// then the generic "any sys_enter_*open* with a filename string" rule.
func classifyNameAndField(name, fieldType, fieldName string) (ClassificationResult, bool) {
	if rule, ok := nameFieldRules[name]; ok && rule.fieldName == fieldName && rule.typeOK(fieldType) {
		return rule.result, true
	}

	if strings.HasPrefix(name, "sys_enter") &&
		strings.Contains(name, "open") &&
		isCStringPtrType(fieldType) && fieldName == "filename" {
		return ClassificationResult{Kind: KindOpen}, true
	}

	return ClassificationResult{}, false
}

func classifyByField(fieldType, fieldName string) (ClassificationResult, bool) {
	switch {
	case fieldName == "fd" && isFdType(fieldType):
		return ClassificationResult{Kind: KindFd}, true
	case isCStringPtrType(fieldType) && fieldName == "newname":
		return ClassificationResult{Kind: KindName}, true
	case isCStringPtrType(fieldType) && fieldName == "pathname":
		return ClassificationResult{Kind: KindPathname, PathnameField: "pathname"}, true
	case isCStringPtrType(fieldType) && fieldName == "path":
		return ClassificationResult{Kind: KindPathname, PathnameField: "path"}, true
	case isCStringPtrType(fieldType) && fieldName == "filename":
		return ClassificationResult{Kind: KindPathname, PathnameField: "filename"}, true
	case fieldType == "long" && fieldName == "ret":
		return ClassificationResult{Kind: KindRet}, true
	}
	return ClassificationResult{}, false
}

func isFdType(t string) bool {
	return t == "unsigned int" || t == "unsigned long" || t == "int"
}

func isCStringPtrType(t string) bool {
	return t == "const char *" || t == "char *"
}

// ClassifyRet returns the RetClassification for a syscall exit name.
func ClassifyRet(name string) RetClassification {
	syscall := strings.ToLower(strings.TrimPrefix(name, "sys_exit_"))
	if c, ok := retClassifications[syscall]; ok {
		return c
	}
	return Unclassified
}

// outputPathSyscalls maps each syscall whose identifying path is an OUTPUT
// buffer - one the kernel fills in and that only holds the path once the call
// has returned - to that buffer's argument index. The enter side has nothing
// to read yet (it stays a header-only null_event), so the generated enter
// handler stashes the buffer pointer on the tid's enter state and the exit
// handler reads the string back after a successful return, publishing it as
// the same OPEN_NAME_FIXUP_EVENT control record the faulted-filename recovery
// uses (see renderHandlerPrologue and internal/c/filter.c).
//
// getcwd is the reason this exists: userspace used to readlink
// /proc/<tid>/cwd while processing the pair, which reported the directory at
// processing time (wrong once the tracee had moved on, empty once it had
// exited) and cost a syscall on the event loop per getcwd. Its raw return is
// the copied byte count including the NUL (see retClassifications), which is
// what lets userspace detect a path longer than the captured field.
var outputPathSyscalls = map[string]int{
	"getcwd": 0,
}

// OutputPathSyscalls returns the names of the syscalls whose output path
// buffer the generated exit handlers capture (outputPathSyscalls), sorted.
// Userspace must handle exactly this set (capturedOutputPathEnters in
// internal/eventloop_getcwd.go); a test there pins the two together.
func OutputPathSyscalls() []string {
	return slices.Sorted(maps.Keys(outputPathSyscalls))
}

// outputPathArgIndex returns the argument index of syscall's output path
// buffer, or false when the syscall has none (see outputPathSyscalls).
func outputPathArgIndex(syscall string) (int, bool) {
	idx, ok := outputPathSyscalls[syscall]
	return idx, ok
}

var retClassifications = map[string]RetClassification{
	"fgetxattr":  ReadClassified,
	"flistxattr": ReadClassified,
	// The raw getcwd syscall returns the pathname byte count including its NUL;
	// libc's getcwd wrapper turns that successful value into the buffer pointer.
	"getcwd":     ReadClassified,
	"getdents":   ReadClassified,
	"getdents64": ReadClassified,
	"getxattr":   ReadClassified,
	// getxattrat (Linux 6.13+) returns the size in bytes of the xattr value,
	// exactly like getxattr/lgetxattr/fgetxattr, so it is a read byte-count.
	"getxattrat": ReadClassified,
	"lgetxattr":  ReadClassified,
	"listxattr":  ReadClassified,
	// listxattrat (Linux 6.13+) returns the size in bytes of the list of
	// extended attribute names, exactly like listxattr/llistxattr/flistxattr,
	// so it is a read byte-count.
	"listxattrat":      ReadClassified,
	"llistxattr":       ReadClassified,
	"pread64":          ReadClassified,
	"preadv":           ReadClassified,
	"preadv2":          ReadClassified,
	"process_vm_readv": ReadClassified,
	"read":             ReadClassified,
	"readlink":         ReadClassified,
	"readlinkat":       ReadClassified,
	"readv":            ReadClassified,
	"recvmsg":          ReadClassified,
	"recvfrom":         ReadClassified,
	// The raw sched_getaffinity syscall returns the mask byte count copied;
	// libc-style wrappers commonly reduce that successful value to zero.
	"sched_getaffinity": ReadClassified,
	"msgrcv":            ReadClassified,
	"getrandom":         ReadClassified,
	// syslog has action-dependent return semantics: only actions 2/3/4 return
	// bytes copied, while 9/10 return required sizes and the remaining actions
	// return status. Keep it unclassified until its action is part of the event.
	"mq_timedreceive": ReadClassified,

	"copy_file_range": TransferClassified,
	"sendfile64":      TransferClassified,
	"splice":          TransferClassified,
	"tee":             TransferClassified,
	"vmsplice":        TransferClassified,

	"process_vm_writev": WriteClassified,
	"pwrite64":          WriteClassified,
	"pwritev":           WriteClassified,
	"pwritev2":          WriteClassified,
	"sendmsg":           WriteClassified,
	"sendto":            WriteClassified,
	// msgsnd is deliberately NOT listed here: msgsnd(2) returns 0 on success or
	// -1 on error — it is NOT a byte count (the payload size msgsz is an INPUT
	// arg, never the return). Like its SysV IPC siblings (msgrcv excepted, which
	// genuinely returns a received byte count), msgsnd's int status must stay
	// UNCLASSIFIED so the stats engine never treats the return as bytes written.
	"write":  WriteClassified,
	"writev": WriteClassified,
	// mq_timedsend is deliberately NOT listed here: mq_timedsend(2)/mq_send(3)
	// return 0 on success or -1 on error — NOT a byte count (msg_len is an
	// INPUT arg, never the return). Listing it as WriteClassified made
	// bytesFromRet attribute its 0 return as "bytes written". Like its POSIX mq
	// sibling mq_timedreceive (which genuinely returns the received byte count
	// and stays ReadClassified), mq_timedsend's int status must stay
	// UNCLASSIFIED. This mirrors the SysV IPC msgsnd vs msgrcv asymmetry.
}
