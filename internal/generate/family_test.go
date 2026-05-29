package generate

import "testing"

func TestClassifySyscallFamily(t *testing.T) {
	tests := []struct {
		name string
		want SyscallFamily
	}{
		{"sys_enter_accept", FamilyNetwork},
		{"sys_exit_accept", FamilyNetwork},
		{"sys_enter_pipe2", FamilyIPC},
		{"sys_enter_munmap", FamilyMemory},
		{"sys_enter_execve", FamilyProcess},
		{"sys_enter_rt_sigaction", FamilySignals},
		{"sys_enter_clock_gettime", FamilyTime},
		// gettimeofday(2) gets wall-clock time via a userspace timeval/timezone
		// pointer; it is a time/clock syscall and shares FamilyTime with its
		// sibling clock_gettime/settimeofday/time syscalls.
		{"sys_enter_gettimeofday", FamilyTime},
		{"sys_exit_gettimeofday", FamilyTime},
		{"sys_enter_sched_yield", FamilySched},
		{"sys_enter_openat", FamilyFS},
		{"sys_enter_epoll_wait", FamilyPolling},
		{"sys_enter_io_uring_enter", FamilyAIO},
		{"sys_enter_bpf", FamilySecurity},
		// Futexes are shared-memory synchronization/IPC primitives ("fast
		// user-space locking", futex(2)); the classic futex() and the Linux
		// 6.7+ split syscalls all classify as IPC alongside the System V
		// semaphores, not Misc.
		{"sys_enter_futex", FamilyIPC},
		{"sys_enter_futex_wait", FamilyIPC},
		{"sys_enter_futex_wake", FamilyIPC},
		{"sys_exit_futex_wake", FamilyIPC},
		{"sys_enter_futex_requeue", FamilyIPC},
		{"sys_enter_futex_waitv", FamilyIPC},
		// x86 I/O-port / CPU-state syscalls are not in the explicit family
		// table and intentionally fall through to Misc (ioperm/iopl/modify_ldt
		// set port-access or LDT state, not file I/O). arch_prctl/personality
		// are deliberately classified as Process, so they are not listed here.
		{"sys_enter_ioperm", FamilyMisc},
		{"sys_enter_iopl", FamilyMisc},
		{"sys_enter_modify_ldt", FamilyMisc},
		{"sys_enter_unlisted_future_syscall", FamilyMisc},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifySyscallFamily(tt.name); got != tt.want {
				t.Errorf("ClassifySyscallFamily(%q) = %s, want %s", tt.name, got, tt.want)
			}
		})
	}
}

func TestParseFormatsTagsEveryFormatWithFamily(t *testing.T) {
	formats := mustParseAll(t, FormatRead+"\n"+FormatExitSocket+"\n"+FormatExitKill)

	tests := []struct {
		index int
		want  SyscallFamily
	}{
		{0, FamilyFS},
		{1, FamilyNetwork},
		{2, FamilySignals},
	}

	for _, tt := range tests {
		if got := formats[tt.index].Family; got != tt.want {
			t.Errorf("formats[%d].Family = %s, want %s", tt.index, got, tt.want)
		}
	}
}
