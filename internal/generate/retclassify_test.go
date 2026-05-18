package generate

import "testing"

func TestClassifyRetRead(t *testing.T) {
	reads := []string{
		"fgetxattr", "flistxattr", "getdents", "getdents64", "getxattr",
		"lgetxattr", "listxattr", "llistxattr", "pread64", "preadv",
		"preadv2", "process_vm_readv", "read", "readlink", "readlinkat",
		"readv", "recvmsg", "recvfrom", "syslog",
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
		"sendmsg", "sendto", "write", "writev",
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
