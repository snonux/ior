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
func classifyNameOnly(name string) (ClassificationResult, bool) {
	switch name {
	case "sys_enter_open_by_handle_at":
		return ClassificationResult{Kind: KindOpenByHandleAt}, true
	case "sys_enter_io_uring_enter":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_io_uring_register":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_fcntl":
		return ClassificationResult{Kind: KindFcntl}, true
	case "sys_enter_syslog":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_sync":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_msync":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_getcwd":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_socket":
		return ClassificationResult{Kind: KindSocket}, true
	case "sys_enter_socketpair":
		return ClassificationResult{Kind: KindSocketpair}, true
	case "sys_exit_socketpair":
		return ClassificationResult{Kind: KindSocketpair}, true
	case "sys_enter_accept":
		return ClassificationResult{Kind: KindAccept}, true
	case "sys_exit_accept":
		return ClassificationResult{Kind: KindAccept}, true
	case "sys_enter_accept4":
		return ClassificationResult{Kind: KindAccept}, true
	case "sys_exit_accept4":
		return ClassificationResult{Kind: KindAccept}, true
	case "sys_enter_pipe":
		return ClassificationResult{Kind: KindPipe}, true
	case "sys_exit_pipe":
		return ClassificationResult{Kind: KindPipe}, true
	case "sys_enter_pipe2":
		return ClassificationResult{Kind: KindPipe}, true
	case "sys_exit_pipe2":
		return ClassificationResult{Kind: KindPipe}, true
	case "sys_enter_eventfd":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_exit_eventfd":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_enter_eventfd2":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_exit_eventfd2":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_enter_memfd_create":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_exit_memfd_create":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_enter_memfd_secret":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_exit_memfd_secret":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_enter_userfaultfd":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_exit_userfaultfd":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_enter_signalfd":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_exit_signalfd":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_enter_signalfd4":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_exit_signalfd4":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_enter_timerfd_create":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_exit_timerfd_create":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_enter_epoll_create":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_exit_epoll_create":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_enter_epoll_create1":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_exit_epoll_create1":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_enter_inotify_init":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_exit_inotify_init":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_enter_inotify_init1":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_exit_inotify_init1":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_enter_fanotify_init":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_exit_fanotify_init":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_enter_landlock_create_ruleset":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_exit_landlock_create_ruleset":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_enter_fsopen":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_exit_fsopen":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_enter_pidfd_open":
		return ClassificationResult{Kind: KindPidfd}, true
	case "sys_exit_pidfd_open":
		return ClassificationResult{Kind: KindPidfd}, true
	case "sys_enter_bind":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_connect":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_listen":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_shutdown":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_getsockname":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_getpeername":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_getsockopt":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_setsockopt":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_epoll_wait":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_epoll_pwait":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_epoll_pwait2":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_epoll_ctl":
		return ClassificationResult{Kind: KindEpollCtl}, true
	case "sys_enter_move_mount":
		return ClassificationResult{Kind: KindTwoFd}, true
	case "sys_enter_fsmount":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_exit_fsmount":
		return ClassificationResult{Kind: KindEventfd}, true
	case "sys_enter_statmount":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_listmount":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_listns":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_poll":
		return ClassificationResult{Kind: KindPoll}, true
	case "sys_enter_ppoll":
		return ClassificationResult{Kind: KindPoll}, true
	case "sys_enter_select":
		return ClassificationResult{Kind: KindPoll}, true
	case "sys_enter_pselect6":
		return ClassificationResult{Kind: KindPoll}, true
	case "sys_enter_munmap":
		return ClassificationResult{Kind: KindMem}, true
	case "sys_enter_mremap":
		return ClassificationResult{Kind: KindMem}, true
	case "sys_enter_mincore":
		return ClassificationResult{Kind: KindMem}, true
	case "sys_enter_remap_file_pages":
		return ClassificationResult{Kind: KindMem}, true
	case "sys_enter_mlock":
		return ClassificationResult{Kind: KindMem}, true
	case "sys_enter_mlock2":
		return ClassificationResult{Kind: KindMem}, true
	case "sys_enter_munlock":
		return ClassificationResult{Kind: KindMem}, true
	case "sys_enter_mseal":
		return ClassificationResult{Kind: KindMem}, true
	case "sys_enter_map_shadow_stack":
		return ClassificationResult{Kind: KindMem}, true
	case "sys_enter_nanosleep":
		return ClassificationResult{Kind: KindSleep}, true
	case "sys_enter_clock_nanosleep":
		return ClassificationResult{Kind: KindSleep}, true
	case "sys_enter_keyctl":
		return ClassificationResult{Kind: KindKeyctl}, true
	case "sys_enter_add_key":
		return ClassificationResult{Kind: KindKeyctl}, true
	case "sys_enter_request_key":
		return ClassificationResult{Kind: KindKeyctl}, true
	case "sys_enter_ptrace":
		return ClassificationResult{Kind: KindPtrace}, true
	case "sys_enter_perf_event_open":
		return ClassificationResult{Kind: KindPerfOpen}, true
	case "sys_enter_seccomp":
		return ClassificationResult{Kind: KindSeccomp}, true
	case "sys_exit_seccomp":
		return ClassificationResult{Kind: KindSeccomp}, true
	case "sys_enter_init_module":
		return ClassificationResult{Kind: KindModule}, true
	case "sys_exit_init_module":
		return ClassificationResult{Kind: KindModule}, true
	case "sys_enter_delete_module":
		return ClassificationResult{Kind: KindModule}, true
	case "sys_exit_delete_module":
		return ClassificationResult{Kind: KindModule}, true
	case "sys_enter_msgget":
		return ClassificationResult{Kind: KindSysVId}, true
	case "sys_enter_semget":
		return ClassificationResult{Kind: KindSysVId}, true
	case "sys_enter_shmget":
		return ClassificationResult{Kind: KindSysVId}, true
	case "sys_enter_msgsnd":
		return ClassificationResult{Kind: KindSysVOp}, true
	case "sys_enter_msgrcv":
		return ClassificationResult{Kind: KindSysVOp}, true
	case "sys_enter_msgctl":
		return ClassificationResult{Kind: KindSysVOp}, true
	case "sys_enter_semop":
		return ClassificationResult{Kind: KindSysVOp}, true
	case "sys_enter_semtimedop":
		return ClassificationResult{Kind: KindSysVOp}, true
	case "sys_enter_semctl":
		return ClassificationResult{Kind: KindSysVOp}, true
	case "sys_enter_shmat":
		return ClassificationResult{Kind: KindSysVOp}, true
	case "sys_enter_shmdt":
		return ClassificationResult{Kind: KindSysVOp}, true
	case "sys_enter_shmctl":
		return ClassificationResult{Kind: KindSysVOp}, true
	case "sys_enter_pidfd_send_signal":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_kexec_file_load":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_kcmp":
		return ClassificationResult{Kind: KindTwoFd}, true
	case "sys_enter_mq_timedsend":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_mq_timedreceive":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_mq_notify":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_mq_getsetattr":
		return ClassificationResult{Kind: KindFd}, true
	case "sys_enter_execve":
		return ClassificationResult{Kind: KindExec}, true
	case "sys_enter_execveat":
		return ClassificationResult{Kind: KindExec}, true
	case "sys_enter_exit":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_exit_group":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_rt_sigaction":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_rt_sigprocmask":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_rt_sigpending":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_rt_sigsuspend":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_rt_sigtimedwait":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_rt_sigreturn":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_sigaltstack":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_pause":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_rt_sigqueueinfo":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_rt_tgsigqueueinfo":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_getpid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_gettid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_getppid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_getuid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_geteuid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_getgid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_getegid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_getresuid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_getresgid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_getgroups":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_setuid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_seteuid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_setgid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_setegid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_setresuid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_setresgid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_setreuid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_setregid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_setfsuid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_setfsgid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_setgroups":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_umask":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_setsid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_getsid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_setpgid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_getpgid":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_getpgrp":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_set_tid_address":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_sched_yield":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_sched_setaffinity":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_sched_getaffinity":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_sched_setparam":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_sched_getparam":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_sched_setscheduler":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_sched_getscheduler":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_sched_setattr":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_sched_getattr":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_sched_get_priority_max":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_sched_get_priority_min":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_sched_rr_get_interval":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_getcpu":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_getrusage":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_getrlimit":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_setrlimit":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_prlimit64":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_getpriority":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_setpriority":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_membarrier":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_rseq":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_set_robust_list":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_get_robust_list":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_mmap2":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_kexec_load":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_sysinfo":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_sysfs":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_ustat":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_newuname":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_sethostname":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_setdomainname":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_capget":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_capset":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_personality":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_reboot":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_restart_syscall":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_vhangup":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_arch_prctl":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_ioperm":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_iopl":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_modify_ldt":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_lsm_get_self_attr":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_lsm_set_self_attr":
		return ClassificationResult{Kind: KindNull}, true
	case "sys_enter_lsm_list_modules":
		return ClassificationResult{Kind: KindNull}, true
	}
	if strings.HasPrefix(name, "sys_enter_io_") {
		return ClassificationResult{Kind: KindNull}, true
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
