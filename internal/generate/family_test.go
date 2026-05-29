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
		// process_madvise(2) gives memory advice (MADV_COLD/PAGEOUT/...) about
		// address ranges of another process selected by a pidfd. Although its
		// first arg is a pidfd (KindFd) rather than an address, the operation is
		// fundamentally a memory-advice call, so it shares FamilyMemory with its
		// madvise(2)/process_mrelease(2)/process_vm_readv/writev(2) siblings — not
		// FamilyIPC (where the pidfd_* lifecycle syscalls live).
		{"sys_enter_process_madvise", FamilyMemory},
		{"sys_exit_process_madvise", FamilyMemory},
		// set_mempolicy_home_node(2) (Linux 5.17+) sets the home NUMA node for a
		// memory range (start,len,home_node,flags); it returns 0/-1 with no byte
		// count, so it is KindNull and Unclassified. It is a NUMA memory-policy
		// syscall and shares FamilyMemory with its siblings set_mempolicy(2),
		// mbind(2), migrate_pages(2), and move_pages(2). NOTE: get_mempolicy(2) is
		// the one NUMA sibling currently classified FamilySecurity instead of
		// FamilyMemory — that inconsistency is tracked separately and is out of
		// scope for this set_mempolicy_home_node assertion.
		{"sys_enter_set_mempolicy_home_node", FamilyMemory},
		{"sys_exit_set_mempolicy_home_node", FamilyMemory},
		{"sys_enter_set_mempolicy", FamilyMemory},
		{"sys_enter_mbind", FamilyMemory},
		{"sys_enter_migrate_pages", FamilyMemory},
		{"sys_enter_move_pages", FamilyMemory},
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
		// rseq(2) registers/unregisters a per-thread restartable-sequences area
		// (a userspace struct pointer, not an fd/path). It is not in the explicit
		// family table and intentionally falls through to Misc, sharing the family
		// with its closest per-thread sibling set_robust_list/get_robust_list
		// (also Misc). set_tid_address is Process, but rseq is grouped with the
		// robust-list pair rather than the tid-address syscall; keep this in sync
		// with the Misc list in docs/syscall-tracing-plan.md.
		{"sys_enter_rseq", FamilyMisc},
		{"sys_exit_rseq", FamilyMisc},
		{"sys_enter_set_robust_list", FamilyMisc},
		{"sys_enter_get_robust_list", FamilyMisc},
		// rt_sigpending(2) examines the set of signals pending for delivery
		// (sigset_t *set, size_t sigsetsize). It is a signal-handling syscall and
		// shares FamilySignals with the whole rt_sig* group as well as kill/pause/
		// sigaltstack/tkill/tgkill. The entire group must stay consistent; assert
		// every rt_sig* sibling alongside rt_sigpending so a stray reclassification
		// of any one of them trips this test. Keep in sync with the Signals list in
		// docs/syscall-tracing-plan.md.
		{"sys_enter_rt_sigpending", FamilySignals},
		{"sys_exit_rt_sigpending", FamilySignals},
		{"sys_enter_rt_sigprocmask", FamilySignals},
		{"sys_enter_rt_sigsuspend", FamilySignals},
		{"sys_enter_rt_sigtimedwait", FamilySignals},
		{"sys_enter_rt_sigreturn", FamilySignals},
		{"sys_enter_rt_sigqueueinfo", FamilySignals},
		{"sys_enter_rt_tgsigqueueinfo", FamilySignals},
		{"sys_enter_sigaltstack", FamilySignals},
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
