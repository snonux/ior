package generate

import "testing"

func TestClassifyRetRead(t *testing.T) {
	reads := []string{
		"fgetxattr", "flistxattr", "getdents", "getdents64", "getxattr",
		"lgetxattr", "listxattr", "llistxattr", "pread64", "preadv",
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
		"mkdir", "rmdir", "chmod", "chown", "chdir", "stat", "lseek",
		"truncate", "fallocate", "mmap", "fsync", "flock", "recvmmsg", "sendmmsg",
		// syncfs(2) returns int 0/-1 (no byte count); it commits the filesystem
		// containing args[0]'s fd and transfers no bytes, so its exit must stay
		// UNCLASSIFIED (plain ret_event), like its fsync/fdatasync siblings.
		"syncfs",
		// gettimeofday(2) returns int 0/-1 (no byte count); its exit carries a
		// plain ret_event and must stay UNCLASSIFIED, not a read/write transfer.
		"gettimeofday",
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
		"getpid",
		"getppid",
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
