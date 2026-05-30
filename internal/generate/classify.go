package generate

import "strings"

type TracepointKind int

const (
	KindNone TracepointKind = iota
	KindFd
	KindOpen
	KindMqOpen
	KindExec
	KindPathname
	KindName
	KindRet
	KindFcntl
	KindNull
	KindDup3
	KindOpenByHandleAt
	KindSocket
	KindSocketpair
	KindAccept
	KindPipe
	KindEventfd
	KindPidfd
	KindEpollCtl
	KindTwoFd
	KindPoll
	KindMem
	KindSleep
	KindKeyctl
	KindPtrace
	KindPerfOpen
	KindSeccomp
	KindModule
	KindSysVId
	KindSysVOp
	KindProc
	KindBpf
	KindFutex
	KindPrctl
	KindTimerObj
)

func (k TracepointKind) MetadataName() string {
	switch k {
	case KindFd:
		return "fd"
	case KindOpen:
		return "open"
	case KindMqOpen:
		return "mq-open"
	case KindExec:
		return "exec"
	case KindPathname:
		return "pathname"
	case KindName:
		return "name"
	case KindRet:
		return "ret"
	case KindFcntl:
		return "fcntl"
	case KindNull:
		return "null"
	case KindDup3:
		return "dup3"
	case KindOpenByHandleAt:
		return "open-by-handle-at"
	case KindSocket:
		return "socket"
	case KindSocketpair:
		return "socketpair"
	case KindAccept:
		return "accept"
	case KindPipe:
		return "pipe"
	case KindEventfd:
		return "eventfd"
	case KindPidfd:
		return "pidfd"
	case KindEpollCtl:
		return "epoll-ctl"
	case KindTwoFd:
		return "two-fd"
	case KindPoll:
		return "poll"
	case KindMem:
		return "mem"
	case KindSleep:
		return "sleep"
	case KindKeyctl:
		return "keyctl"
	case KindPtrace:
		return "ptrace"
	case KindPerfOpen:
		return "perf-open"
	case KindSeccomp:
		return "seccomp"
	case KindModule:
		return "module"
	case KindSysVId:
		return "sysv-id"
	case KindSysVOp:
		return "sysv-op"
	case KindProc:
		return "proc"
	case KindBpf:
		return "bpf"
	case KindFutex:
		return "futex"
	case KindPrctl:
		return "prctl"
	case KindTimerObj:
		return "timer-obj"
	default:
		return "none"
	}
}

type RetClassification string

const (
	Unclassified       RetClassification = "UNCLASSIFIED"
	ReadClassified     RetClassification = "READ_CLASSIFIED"
	WriteClassified    RetClassification = "WRITE_CLASSIFIED"
	TransferClassified RetClassification = "TRANSFER_CLASSIFIED"
)

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
	"sys_enter_open_by_handle_at": KindOpenByHandleAt,
	"sys_enter_io_uring_enter":    KindFd,
	"sys_enter_io_uring_register": KindFd,
	"sys_enter_fcntl":             KindFcntl,
	"sys_enter_syslog":            KindNull,
	"sys_enter_sync":              KindNull,
	"sys_enter_msync":             KindNull,
	"sys_enter_getcwd":            KindNull,

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
	"sys_enter_memfd_create":   KindEventfd,
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
	"sys_enter_fsopen":                  KindEventfd,
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

	"sys_enter_epoll_wait":   KindFd,
	"sys_enter_epoll_pwait":  KindFd,
	"sys_enter_epoll_pwait2": KindFd,
	"sys_enter_epoll_ctl":    KindEpollCtl,

	"sys_enter_move_mount": KindTwoFd,
	// close_range(first, last, flags) needs all three arguments, so it is a
	// two_fd_event (fd_a=first, fd_b=last, extra=flags) rather than a single-fd
	// fd_event. This lets the runtime honour the upper bound and the
	// CLOSE_RANGE_CLOEXEC flag instead of closing every fd >= first.
	"sys_enter_close_range": KindTwoFd,
	// sendfile64(out_fd, in_fd, offset, count) transfers bytes between two file
	// descriptors inside the kernel and returns the number of bytes written to
	// out_fd (TransferClassified, see retClassifications). Its tracepoint fields
	// (out_fd, in_fd, offset, count) carry no field literally named "fd", so
	// without an explicit override it would fall through to KindNull and capture
	// no descriptor at all — unlike its sibling copy_file_range, which is a
	// KindFd event. Capture out_fd (args[0], the destination the bytes are
	// written to) so sendfile64 attributes its transfer to a concrete fd, matching
	// the single-fd KindFd convention used for copy_file_range and the
	// read/write/sendto/recvfrom families.
	"sys_enter_sendfile64": KindFd,
	"sys_enter_statmount":  KindNull,
	"sys_enter_listmount":   KindNull,
	"sys_enter_listns":      KindNull,

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
	"sys_enter_seccomp":          KindSeccomp,
	"sys_exit_seccomp":           KindSeccomp,
	"sys_enter_init_module":      KindModule,
	"sys_exit_init_module":       KindModule,
	"sys_enter_delete_module":    KindModule,
	"sys_exit_delete_module":     KindModule,

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

// classifyNameAndField handles tracepoints that need both the name and
// a specific field to classify.
func classifyNameAndField(name, fieldType, fieldName string) (ClassificationResult, bool) {
	switch name {
	case "sys_enter_dup":
		if fieldType == "unsigned int" && fieldName == "fildes" {
			return ClassificationResult{Kind: KindFd}, true
		}
	case "sys_enter_dup2":
		if fieldType == "unsigned int" && fieldName == "oldfd" {
			return ClassificationResult{Kind: KindFd}, true
		}
	case "sys_enter_dup3":
		if fieldType == "unsigned int" && fieldName == "oldfd" {
			return ClassificationResult{Kind: KindDup3}, true
		}
	case "sys_enter_name_to_handle_at":
		if isCStringPtrType(fieldType) && fieldName == "name" {
			return ClassificationResult{Kind: KindPathname, PathnameField: "name"}, true
		}
	case "sys_enter_copy_file_range":
		if isFdType(fieldType) && fieldName == "fd_in" {
			return ClassificationResult{Kind: KindFd}, true
		}
	case "sys_enter_mount":
		if isCStringPtrType(fieldType) && fieldName == "dir_name" {
			return ClassificationResult{Kind: KindPathname, PathnameField: "dir_name"}, true
		}
	case "sys_enter_umount":
		if isCStringPtrType(fieldType) && fieldName == "name" {
			return ClassificationResult{Kind: KindPathname, PathnameField: "name"}, true
		}
	case "sys_enter_acct":
		if isCStringPtrType(fieldType) && fieldName == "name" {
			return ClassificationResult{Kind: KindPathname, PathnameField: "name"}, true
		}
	case "sys_enter_pivot_root":
		if isCStringPtrType(fieldType) && fieldName == "new_root" {
			return ClassificationResult{Kind: KindPathname, PathnameField: "new_root"}, true
		}
	case "sys_enter_quotactl":
		if isCStringPtrType(fieldType) && fieldName == "special" {
			return ClassificationResult{Kind: KindPathname, PathnameField: "special"}, true
		}
	case "sys_enter_swapon":
		if isCStringPtrType(fieldType) && fieldName == "specialfile" {
			return ClassificationResult{Kind: KindPathname, PathnameField: "specialfile"}, true
		}
	case "sys_enter_swapoff":
		if isCStringPtrType(fieldType) && fieldName == "specialfile" {
			return ClassificationResult{Kind: KindPathname, PathnameField: "specialfile"}, true
		}
	case "sys_enter_mq_open":
		if isCStringPtrType(fieldType) && fieldName == "u_name" {
			return ClassificationResult{Kind: KindMqOpen}, true
		}
	case "sys_enter_mq_unlink":
		if isCStringPtrType(fieldType) && fieldName == "u_name" {
			return ClassificationResult{Kind: KindPathname, PathnameField: "u_name"}, true
		}
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

var retClassifications = map[string]RetClassification{
	"fgetxattr":        ReadClassified,
	"flistxattr":       ReadClassified,
	"getdents":         ReadClassified,
	"getdents64":       ReadClassified,
	"getxattr":         ReadClassified,
	"lgetxattr":        ReadClassified,
	"listxattr":        ReadClassified,
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
	"msgrcv":           ReadClassified,
	"getrandom":        ReadClassified,
	"syslog":           ReadClassified,
	"mq_timedreceive":  ReadClassified,

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
	"msgsnd":            WriteClassified,
	"write":             WriteClassified,
	"writev":            WriteClassified,
	"mq_timedsend":      WriteClassified,
}
