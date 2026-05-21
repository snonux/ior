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
	KindEpollCtl
	KindTwoFd
	KindPoll
	KindMem
	KindSleep
	KindKeyctl
	KindPtrace
	KindPerfOpen
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
	"write":             WriteClassified,
	"writev":            WriteClassified,
	"mq_timedsend":      WriteClassified,
}
