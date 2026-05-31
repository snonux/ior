package generate

import "testing"

func TestClassifyRetRead(t *testing.T) {
	reads := []string{
		"fgetxattr", "flistxattr", "getdents", "getdents64", "getxattr",
		// getxattrat (Linux 6.13+) returns the xattr value size in bytes, the
		// same read byte-count as getxattr/lgetxattr/fgetxattr.
		"getxattrat",
		"lgetxattr", "listxattr",
		// listxattrat (Linux 6.13+) returns the size in bytes of the xattr
		// name list, the same read byte-count as listxattr/llistxattr/flistxattr.
		"listxattrat",
		"llistxattr", "pread64", "preadv",
		"preadv2", "process_vm_readv", "read", "readlink", "readlinkat",
		"readv", "recvmsg", "recvfrom", "syslog", "mq_timedreceive", "getrandom", "msgrcv",
	}
	for _, name := range reads {
		if got := ClassifyRet("sys_exit_" + name); got != ReadClassified {
			t.Errorf("ClassifyRet(sys_exit_%s) = %q, want READ_CLASSIFIED", name, got)
		}
	}
}

func TestClassifyRetWrite(t *testing.T) {
	writes := []string{
		"process_vm_writev", "pwrite64", "pwritev", "pwritev2",
		"sendmsg", "sendto", "write", "writev", "mq_timedsend", "msgsnd",
	}
	for _, name := range writes {
		if got := ClassifyRet("sys_exit_" + name); got != WriteClassified {
			t.Errorf("ClassifyRet(sys_exit_%s) = %q, want WRITE_CLASSIFIED", name, got)
		}
	}
}

func TestClassifyRetTransfer(t *testing.T) {
	transfers := []string{
		"copy_file_range", "sendfile64", "splice", "tee", "vmsplice",
	}
	for _, name := range transfers {
		if got := ClassifyRet("sys_exit_" + name); got != TransferClassified {
			t.Errorf("ClassifyRet(sys_exit_%s) = %q, want TRANSFER_CLASSIFIED", name, got)
		}
	}
}

func TestClassifyRetUnclassified(t *testing.T) {
	unclassified := []string{
		"openat", "close", "rename", "unlink", "fcntl", "dup", "dup2", "dup3",
		"mkdir", "rmdir", "chmod", "chown", "chdir", "stat",
		"truncate", "fallocate", "mmap", "fsync", "flock", "recvmmsg", "sendmmsg",
		// lseek(2) repositions the file offset of args[0]'s fd and returns the
		// RESULTING file OFFSET (off_t, bytes from the start of the file) on
		// success, or -1 on error. That return is a file POSITION, NOT a count of
		// bytes transferred — so its exit must stay UNCLASSIFIED (plain
		// ret_event). Classifying it as READ/WRITE/TRANSFER would wrongly add the
		// absolute file position into I/O byte totals and grossly inflate them
		// (e.g. an lseek to offset 1 GiB would look like a 1 GiB transfer). lseek
		// is a KindFd FamilyFS syscall like its read/write/fsync siblings; only
		// read/write actually move bytes and carry a byte-count return.
		"lseek",
		// syncfs(2) returns int 0/-1 (no byte count); it commits the filesystem
		// containing args[0]'s fd and transfers no bytes, so its exit must stay
		// UNCLASSIFIED (plain ret_event), like its fsync/fdatasync siblings.
		"syncfs",
		// gettimeofday(2) returns int 0/-1 (no byte count); its exit carries a
		// plain ret_event and must stay UNCLASSIFIED, not a read/write transfer.
		"gettimeofday",
		// times(2) returns a clock_t tick count (clock ticks since an arbitrary
		// point in the past), or (clock_t)-1 on error. That is a tick count, NOT
		// a transferred byte count, so its exit must stay UNCLASSIFIED (plain
		// ret_event), like its time sibling gettimeofday.
		"times",
		// rseq(2) returns int 0/-1 on (un)registration of the restartable-
		// sequences area; it transfers no bytes, so its exit must stay
		// UNCLASSIFIED (plain ret_event), like its KindNull siblings.
		"rseq",
		// set_mempolicy_home_node(2) sets the home NUMA node for a memory range
		// and returns int 0/-1 (no byte count), so its exit carries a plain
		// ret_event and must stay UNCLASSIFIED, like its NUMA siblings
		// set_mempolicy/mbind/migrate_pages/move_pages.
		"set_mempolicy_home_node",
		// migrate_pages(2) moves all pages of a process (selected by pid, NOT an
		// fd) between NUMA node sets; on success it returns the number of pages
		// that could NOT be moved (>=0, zero meaning all moved), or -1 on error.
		// That count is a page tally, not a transferred byte count, so its exit
		// must stay UNCLASSIFIED (plain ret_event), like its NUMA siblings
		// set_mempolicy/mbind/set_mempolicy_home_node and move_pages.
		"migrate_pages",
		// move_pages(2) is the per-page NUMA sibling of migrate_pages(2); it also
		// returns 0/-1 (with per-page status reported via a userspace array, not
		// the return value), so its exit likewise stays UNCLASSIFIED.
		"move_pages",
		// setsid(2) returns the new session ID (a pid_t) on success, or
		// (pid_t)-1 on error; that return is a session/process identifier, not a
		// transferred byte count. Its exit must stay UNCLASSIFIED (plain
		// ret_event), exactly like its pid-returning siblings getsid/getpid/
		// getppid (asserted below), so it is never mistaken for a read/write
		// byte transfer.
		"setsid",
		"getsid",
		// setpgid(2) sets the process group ID of a process and returns int
		// 0 on success or -1 on error — a status code, not a transferred byte
		// count. Its exit must stay UNCLASSIFIED (plain ret_event), exactly
		// like its session/process-group siblings setsid/getsid above and the
		// pid-returning getpid/getppid below.
		"setpgid",
		"getpid",
		"getppid",
		// set_tid_address(2) sets the calling thread's clear_child_tid pointer
		// and ALWAYS returns the caller's thread ID — it never fails and never
		// returns -1 (set_tid_address(2): "always succeeds"). That return is a
		// thread identifier (a pid_t/tid), NOT a transferred byte count, so its
		// exit must stay UNCLASSIFIED (plain ret_event), exactly like its
		// pid/tid-returning Process siblings setsid/getsid/getpid/getppid above.
		"set_tid_address",
		// bind(2) assigns an address to a socket and returns int 0 on success or
		// -1 on error — a status code, NOT a transferred byte count. Its exit must
		// stay UNCLASSIFIED (plain ret_event), exactly like its socket-setup
		// siblings connect/listen/getsockname/getpeername (asserted alongside it),
		// so it is never mistaken for a recvfrom/sendto-style byte transfer.
		"bind",
		"connect",
		"listen",
		"getsockname",
		"getpeername",
		// kexec_load(2) loads a new kernel for later execution by reboot(2) and
		// returns long 0 on success or -1 on error — a status code, NOT a
		// transferred byte count. Its exit must stay UNCLASSIFIED (plain
		// ret_event), exactly like its sibling kexec_file_load and the
		// system/admin syscall reboot below.
		"kexec_load",
		"kexec_file_load",
		"reboot",
	}
	for _, name := range unclassified {
		if got := ClassifyRet("sys_exit_" + name); got != Unclassified {
			t.Errorf("ClassifyRet(sys_exit_%s) = %q, want UNCLASSIFIED", name, got)
		}
	}
}

func TestBatchMessageSyscallsDeferredFromRetByteClassification(t *testing.T) {
	tests := []string{"recvmmsg", "sendmmsg"}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			if got := ClassifyRet("sys_exit_" + name); got != Unclassified {
				t.Fatalf("ClassifyRet(sys_exit_%s) = %q, want %q", name, got, Unclassified)
			}
		})
	}
}

func TestClassifyRetCaseInsensitive(t *testing.T) {
	if got := ClassifyRet("sys_exit_READ"); got != ReadClassified {
		t.Errorf("ClassifyRet(sys_exit_READ) = %q, want READ_CLASSIFIED", got)
	}
}

func TestPhaseAByteClassifiedSyscallsUseExistingRetClassifications(t *testing.T) {
	tests := []struct {
		name string
		want RetClassification
	}{
		{"recvfrom", ReadClassified},
		{"recvmsg", ReadClassified},
		{"sendto", WriteClassified},
		{"sendmsg", WriteClassified},
		{"sendfile64", TransferClassified},
		{"splice", TransferClassified},
		{"tee", TransferClassified},
		{"process_vm_readv", ReadClassified},
		{"process_vm_writev", WriteClassified},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyRet("sys_exit_" + tt.name); got != tt.want {
				t.Fatalf("ClassifyRet(sys_exit_%s) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}
