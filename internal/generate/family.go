package generate

import "strings"

// SyscallFamily is the broad syscall grouping attached to every parsed format.
type SyscallFamily string

const (
	FamilyNetwork  SyscallFamily = "Network"
	FamilyIPC      SyscallFamily = "IPC"
	FamilyMemory   SyscallFamily = "Memory"
	FamilyProcess  SyscallFamily = "Process"
	FamilySignals  SyscallFamily = "Signals"
	FamilyTime     SyscallFamily = "Time"
	FamilySched    SyscallFamily = "Sched"
	FamilyFS       SyscallFamily = "FS"
	FamilyPolling  SyscallFamily = "Polling"
	FamilyAIO      SyscallFamily = "AIO"
	FamilySecurity SyscallFamily = "Security"
	FamilyMisc     SyscallFamily = "Misc"
)

var syscallFamilies = map[string]SyscallFamily{
	"accept": FamilyNetwork, "accept4": FamilyNetwork, "bind": FamilyNetwork,
	"connect": FamilyNetwork, "getpeername": FamilyNetwork, "getsockname": FamilyNetwork,
	"getsockopt": FamilyNetwork, "listen": FamilyNetwork, "recvfrom": FamilyNetwork,
	"recvmmsg": FamilyNetwork, "recvmsg": FamilyNetwork, "sendfile64": FamilyNetwork,
	"sendmmsg": FamilyNetwork, "sendmsg": FamilyNetwork, "sendto": FamilyNetwork,
	"setsockopt": FamilyNetwork, "shutdown": FamilyNetwork, "socket": FamilyNetwork,
	"socketpair": FamilyNetwork, "splice": FamilyNetwork, "tee": FamilyNetwork,

	"eventfd": FamilyIPC, "eventfd2": FamilyIPC, "inotify_add_watch": FamilyIPC,
	"inotify_init": FamilyIPC, "inotify_init1": FamilyIPC, "inotify_rm_watch": FamilyIPC,
	"memfd_create": FamilyIPC, "memfd_secret": FamilyIPC, "mq_getsetattr": FamilyIPC,
	"mq_notify": FamilyIPC, "mq_open": FamilyIPC, "mq_timedreceive": FamilyIPC,
	"mq_timedsend": FamilyIPC, "mq_unlink": FamilyIPC, "msgctl": FamilyIPC,
	"msgget": FamilyIPC, "msgrcv": FamilyIPC, "msgsnd": FamilyIPC,
	"pidfd_getfd": FamilyIPC, "pidfd_open": FamilyIPC, "pidfd_send_signal": FamilyIPC,
	"pipe": FamilyIPC, "pipe2": FamilyIPC, "semctl": FamilyIPC, "semget": FamilyIPC,
	"semop": FamilyIPC, "semtimedop": FamilyIPC, "shmat": FamilyIPC,
	"shmctl": FamilyIPC, "shmdt": FamilyIPC, "shmget": FamilyIPC,
	"signalfd": FamilyIPC, "signalfd4": FamilyIPC, "timerfd_create": FamilyIPC,
	"timerfd_gettime": FamilyIPC, "timerfd_settime": FamilyIPC, "userfaultfd": FamilyIPC,
	// Futexes ("fast user-space locking", futex(2)) are shared-memory
	// synchronization/IPC primitives in the same vein as the System V
	// semaphores (semop/semget) above; group them under IPC rather than
	// letting them fall through to Misc. Covers the classic futex() plus the
	// Linux 6.7+ split syscalls (futex_wait/futex_wake/futex_requeue) and
	// futex_waitv. The futex word is a userspace pointer, so argument capture
	// is handled by KindFutex (null_event); the family tag only affects
	// per-family aggregation/reporting.
	"futex": FamilyIPC, "futex_wait": FamilyIPC, "futex_wake": FamilyIPC,
	"futex_requeue": FamilyIPC, "futex_waitv": FamilyIPC,

	"brk": FamilyMemory, "get_mempolicy": FamilyMemory, "madvise": FamilyMemory,
	"map_shadow_stack": FamilyMemory,
	"mbind": FamilyMemory, "membarrier": FamilyMemory, "migrate_pages": FamilyMemory,
	"mincore": FamilyMemory, "mlock": FamilyMemory, "mlock2": FamilyMemory,
	"mlockall": FamilyMemory, "mmap": FamilyMemory, "mmap2": FamilyMemory,
	"mprotect": FamilyMemory, "mremap": FamilyMemory, "mseal": FamilyMemory,
	"munlock": FamilyMemory, "munlockall": FamilyMemory, "munmap": FamilyMemory,
	"move_pages": FamilyMemory, "pkey_alloc": FamilyMemory, "pkey_free": FamilyMemory,
	"pkey_mprotect": FamilyMemory, "process_madvise": FamilyMemory,
	"process_mrelease": FamilyMemory, "process_vm_readv": FamilyMemory,
	"process_vm_writev": FamilyMemory, "remap_file_pages": FamilyMemory,
	"set_mempolicy": FamilyMemory, "set_mempolicy_home_node": FamilyMemory,

	"arch_prctl": FamilyProcess, "clone": FamilyProcess, "clone3": FamilyProcess,
	"execve": FamilyProcess, "execveat": FamilyProcess, "exit": FamilyProcess,
	"exit_group": FamilyProcess, "fork": FamilyProcess, "getegid": FamilyProcess,
	"geteuid": FamilyProcess, "getgid": FamilyProcess, "getgroups": FamilyProcess,
	"getpgid": FamilyProcess, "getpgrp": FamilyProcess, "getpid": FamilyProcess,
	"getppid": FamilyProcess, "getpriority": FamilyProcess, "getresgid": FamilyProcess,
	"getresuid": FamilyProcess, "getrlimit": FamilyProcess, "getrusage": FamilyProcess,
	"getsid": FamilyProcess, "gettid": FamilyProcess, "getuid": FamilyProcess,
	// ioprio_get/ioprio_set query/set the I/O scheduling class and priority of a
	// process, process group, or user (ioprio_set(which, who, ioprio)). They are
	// the I/O-priority analogues of getpriority/setpriority (the CPU nice value
	// for a process/group/user) and share the identical which/who selector
	// signature, so they classify as Process alongside them rather than falling
	// through to Misc. The who argument is a pid/pgid/uid (selected by which),
	// never an fd or path, so argument capture is KindNull (null_event).
	"ioprio_get": FamilyProcess, "ioprio_set": FamilyProcess,
	"kcmp": FamilyProcess, "personality": FamilyProcess, "pivot_root": FamilyProcess,
	"prctl": FamilyProcess, "prlimit64": FamilyProcess, "reboot": FamilyProcess,
	"restart_syscall": FamilyProcess, "set_tid_address": FamilyProcess,
	"setfsuid": FamilyProcess, "setfsgid": FamilyProcess, "setgid": FamilyProcess,
	"setgroups": FamilyProcess, "setns": FamilyProcess, "setpgid": FamilyProcess,
	"setpriority": FamilyProcess, "setregid": FamilyProcess, "setresgid": FamilyProcess,
	"setresuid": FamilyProcess, "setreuid": FamilyProcess, "setrlimit": FamilyProcess,
	"setsid": FamilyProcess, "setuid": FamilyProcess, "umask": FamilyProcess,
	"unshare": FamilyProcess, "vfork": FamilyProcess, "vhangup": FamilyProcess,
	"wait4": FamilyProcess, "waitid": FamilyProcess,

	"kill": FamilySignals, "pause": FamilySignals, "rt_sigaction": FamilySignals,
	"rt_sigpending": FamilySignals, "rt_sigprocmask": FamilySignals,
	"rt_sigqueueinfo": FamilySignals, "rt_sigreturn": FamilySignals,
	"rt_sigsuspend": FamilySignals, "rt_sigtimedwait": FamilySignals,
	"rt_tgsigqueueinfo": FamilySignals, "sigaltstack": FamilySignals,
	"tgkill": FamilySignals, "tkill": FamilySignals,

	"clock_adjtime": FamilyTime, "clock_getres": FamilyTime, "clock_gettime": FamilyTime,
	"clock_nanosleep": FamilyTime, "clock_settime": FamilyTime, "getitimer": FamilyTime,
	"gettimeofday": FamilyTime, "nanosleep": FamilyTime, "setitimer": FamilyTime,
	"settimeofday": FamilyTime, "time": FamilyTime, "timer_create": FamilyTime,
	"timer_delete": FamilyTime, "timer_getoverrun": FamilyTime,
	"timer_gettime": FamilyTime, "timer_settime": FamilyTime, "times": FamilyTime,

	"sched_get_priority_max": FamilySched, "sched_get_priority_min": FamilySched,
	"sched_getaffinity": FamilySched, "sched_getattr": FamilySched,
	"sched_getparam": FamilySched, "sched_getscheduler": FamilySched,
	"sched_rr_get_interval": FamilySched, "sched_setaffinity": FamilySched,
	"sched_setattr": FamilySched, "sched_setparam": FamilySched,
	"sched_setscheduler": FamilySched, "sched_yield": FamilySched,

	"epoll_create": FamilyPolling, "epoll_create1": FamilyPolling,
	"epoll_ctl": FamilyPolling, "epoll_pwait": FamilyPolling,
	"epoll_pwait2": FamilyPolling, "epoll_wait": FamilyPolling,
	"poll": FamilyPolling, "ppoll": FamilyPolling, "pselect6": FamilyPolling,
	"select": FamilyPolling,

	"io_cancel": FamilyAIO, "io_destroy": FamilyAIO, "io_getevents": FamilyAIO,
	"io_pgetevents": FamilyAIO, "io_setup": FamilyAIO, "io_submit": FamilyAIO,
	"io_uring_enter": FamilyAIO, "io_uring_register": FamilyAIO,
	"io_uring_setup": FamilyAIO,

	"add_key": FamilySecurity, "bpf": FamilySecurity, "capget": FamilySecurity,
	"capset": FamilySecurity, "delete_module": FamilySecurity, "finit_module": FamilySecurity,
	"getrandom": FamilySecurity, "init_module": FamilySecurity,
	"kexec_file_load": FamilySecurity, "keyctl": FamilySecurity,
	"landlock_add_rule": FamilySecurity, "landlock_create_ruleset": FamilySecurity,
	"landlock_restrict_self": FamilySecurity, "lookup_dcookie": FamilySecurity,
	// lsm_* are the Linux Security Module (LSM) introspection syscalls
	// (Linux 6.8+): list loaded LSMs and get/set per-task LSM attributes.
	// They belong with the other security syscalls, alongside their
	// landlock_* and *_key siblings.
	"lsm_get_self_attr": FamilySecurity, "lsm_list_modules": FamilySecurity,
	"lsm_set_self_attr": FamilySecurity,
	"perf_event_open":   FamilySecurity, "ptrace": FamilySecurity,
	"request_key": FamilySecurity, "seccomp": FamilySecurity,
}

// ClassifySyscallFamily returns the high-level syscall family for a tracepoint.
func ClassifySyscallFamily(tracepointName string) SyscallFamily {
	syscall := syscallName(tracepointName)
	if family, ok := syscallFamilies[syscall]; ok {
		return family
	}
	if isFSSyscall(syscall) {
		return FamilyFS
	}
	return FamilyMisc
}

func syscallName(tracepointName string) string {
	name := strings.TrimPrefix(tracepointName, "sys_enter_")
	return strings.TrimPrefix(name, "sys_exit_")
}

func isFSSyscall(syscall string) bool {
	for _, marker := range fsNameMarkers {
		if strings.Contains(syscall, marker) {
			return true
		}
	}
	_, ok := fsSyscalls[syscall]
	return ok
}

var fsNameMarkers = []string{"xattr", "stat", "chmod", "chown"}

var fsSyscalls = map[string]struct{}{
	"access": {}, "cachestat": {}, "chdir": {}, "chroot": {}, "close": {},
	"close_range": {}, "copy_file_range": {}, "creat": {}, "dup": {}, "dup2": {},
	"dup3": {}, "faccessat": {}, "faccessat2": {}, "fadvise64": {}, "fallocate": {},
	"fcntl": {}, "fdatasync": {}, "fchdir": {}, "flock": {}, "fsconfig": {},
	"fsmount": {}, "fsopen": {}, "fspick": {}, "fsync": {}, "ftruncate": {},
	"futimesat": {}, "getcwd": {}, "getdents": {}, "getdents64": {}, "ioctl": {},
	"link": {}, "linkat": {}, "lseek": {}, "mkdir": {}, "mkdirat": {},
	"listmount": {}, "listns": {}, "mknod": {}, "mknodat": {}, "mount": {},
	"mount_setattr": {}, "move_mount": {},
	"msync":             {},
	"name_to_handle_at": {}, "newfstat": {}, "newfstatat": {}, "newlstat": {},
	"newstat": {}, "open": {}, "open_by_handle_at": {}, "open_tree": {},
	"open_tree_attr": {}, "openat": {}, "openat2": {}, "quotactl": {},
	"quotactl_fd": {}, "read": {}, "readahead": {}, "readlink": {}, "readlinkat": {},
	"readv": {}, "rename": {}, "renameat": {}, "renameat2": {}, "rmdir": {},
	"statfs": {}, "statmount": {}, "swapoff": {}, "swapon": {}, "sync": {},
	"sync_file_range": {}, "syncfs": {}, "symlink": {}, "symlinkat": {},
	"truncate": {}, "umount": {}, "umount2": {}, "unlink": {}, "unlinkat": {},
	// utime/utimes change a file's access and modification times by path
	// (filename at args[0] is a real filesystem path, captured as
	// KindPathname). They belong with their siblings utimensat/futimesat
	// in the FS family rather than falling through to Misc.
	"utime": {}, "utimes": {},
	"utimensat": {}, "write": {}, "writev": {}, "pread64": {}, "preadv": {},
	"preadv2": {}, "pwrite64": {}, "pwritev": {}, "pwritev2": {},
}
