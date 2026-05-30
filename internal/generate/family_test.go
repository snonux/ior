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
		// get_mempolicy(2), mbind(2), migrate_pages(2), and move_pages(2). Pin the
		// whole NUMA memory-policy cluster (enter+exit) so a stray reclassification
		// of any one syscall trips this test. In particular get_mempolicy(2)
		// retrieves the NUMA policy of a thread/address (not a security operation)
		// and was previously misclassified FamilySecurity; assert it here so the
		// group stays consistent. Keep in sync with the Memory list in
		// docs/syscall-tracing-plan.md.
		{"sys_enter_set_mempolicy_home_node", FamilyMemory},
		{"sys_exit_set_mempolicy_home_node", FamilyMemory},
		{"sys_enter_set_mempolicy", FamilyMemory},
		{"sys_exit_set_mempolicy", FamilyMemory},
		{"sys_enter_get_mempolicy", FamilyMemory},
		{"sys_exit_get_mempolicy", FamilyMemory},
		{"sys_enter_mbind", FamilyMemory},
		{"sys_enter_migrate_pages", FamilyMemory},
		{"sys_enter_move_pages", FamilyMemory},
		{"sys_enter_execve", FamilyProcess},
		// setsid(2) creates a new session and returns the new session ID
		// (a pid_t), or -1 on error; it takes no arguments. It is a
		// process/session-management syscall and shares FamilyProcess with its
		// session/process-group siblings getsid(2), setpgid(2), getpgid(2), and
		// getpgrp(2), as well as the pid-returning getpid(2)/getppid(2). Assert
		// the whole session/pgrp cluster so a stray reclassification of any one
		// trips this test. Keep in sync with the Process list in
		// docs/syscall-tracing-plan.md.
		{"sys_enter_setsid", FamilyProcess},
		{"sys_exit_setsid", FamilyProcess},
		{"sys_enter_getsid", FamilyProcess},
		{"sys_enter_setpgid", FamilyProcess},
		{"sys_enter_getpgid", FamilyProcess},
		{"sys_enter_getpgrp", FamilyProcess},
		{"sys_enter_getpid", FamilyProcess},
		{"sys_enter_getppid", FamilyProcess},
		{"sys_enter_rt_sigaction", FamilySignals},
		{"sys_enter_clock_gettime", FamilyTime},
		// gettimeofday(2) gets wall-clock time via a userspace timeval/timezone
		// pointer; it is a time/clock syscall and shares FamilyTime with its
		// sibling clock_gettime/settimeofday/time syscalls.
		{"sys_enter_gettimeofday", FamilyTime},
		{"sys_exit_gettimeofday", FamilyTime},
		// times(2) stores the calling process's CPU times (struct tms *buf) and
		// returns a clock_t tick count. It is a time/clock syscall and shares
		// FamilyTime with gettimeofday/clock_gettime — NOT FamilyProcess (where
		// getrusage lives). Assert both enter and exit so a stray reclassification
		// trips this test. Keep in sync with the Time list in
		// docs/syscall-tracing-plan.md.
		{"sys_enter_times", FamilyTime},
		{"sys_exit_times", FamilyTime},
		{"sys_enter_sched_yield", FamilySched},
		{"sys_enter_openat", FamilyFS},
		// access(2) checks the calling process's permissions for a file named by
		// a real filesystem path (pathname at args[0]; no dirfd). Its siblings
		// faccessat(2)/faccessat2(2) perform the same check relative to a dirfd
		// (path at args[1]). All three are filesystem-metadata syscalls and must
		// stay in FamilyFS together — assert the whole cluster so a stray
		// reclassification of any one trips this test. Keep in sync with the FS
		// list in docs/syscall-tracing-plan.md.
		{"sys_enter_access", FamilyFS},
		{"sys_exit_access", FamilyFS},
		{"sys_enter_faccessat", FamilyFS},
		{"sys_exit_faccessat", FamilyFS},
		{"sys_enter_faccessat2", FamilyFS},
		{"sys_exit_faccessat2", FamilyFS},
		// utime(2)/utimes(2) change a file's access and modification times by
		// path (filename at args[0] is a real filesystem path, captured as
		// KindPathname). They are filesystem-metadata syscalls and share
		// FamilyFS with their siblings utimensat(2) and futimesat(2); they must
		// NOT fall through to Misc. Assert all four siblings so a stray
		// reclassification of any one trips this test. Keep in sync with the FS
		// list in docs/syscall-tracing-plan.md.
		{"sys_enter_utime", FamilyFS},
		{"sys_exit_utime", FamilyFS},
		{"sys_enter_utimes", FamilyFS},
		{"sys_exit_utimes", FamilyFS},
		{"sys_enter_utimensat", FamilyFS},
		{"sys_enter_futimesat", FamilyFS},
		// The filesystem-sync family commits cached file data/metadata to disk
		// and all classify as FamilyFS: sync(2) (no args, whole system),
		// syncfs(2) (one fd, the filesystem containing that fd), and the
		// per-file fsync(2)/fdatasync(2)/sync_file_range(2). syncfs and its
		// siblings must stay together in FamilyFS — assert the whole group so a
		// stray reclassification of any one trips this test. Keep in sync with
		// the FS list in docs/syscall-tracing-plan.md.
		{"sys_enter_sync", FamilyFS},
		{"sys_exit_sync", FamilyFS},
		{"sys_enter_syncfs", FamilyFS},
		{"sys_exit_syncfs", FamilyFS},
		{"sys_enter_fsync", FamilyFS},
		{"sys_enter_fdatasync", FamilyFS},
		{"sys_enter_sync_file_range", FamilyFS},
		// fallocate(2) manipulates the allocated disk space (preallocate,
		// punch-hole, collapse, zero, insert) for the file referred to by its
		// args[0] fd; it is a per-file space-management syscall and shares
		// FamilyFS with its fd-based siblings fadvise64(2) (access-pattern
		// advice), ftruncate(2) (resize by fd), and sync_file_range(2) (flush a
		// byte range). Assert the group so a stray reclassification of any one
		// trips this test. Keep in sync with the FS list in
		// docs/syscall-tracing-plan.md.
		{"sys_enter_fallocate", FamilyFS},
		{"sys_exit_fallocate", FamilyFS},
		{"sys_enter_fadvise64", FamilyFS},
		{"sys_enter_ftruncate", FamilyFS},
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
		//
		// Boundary rule (see family.go futex block): a syscall is IPC only if it
		// PERFORMS the actual IPC/sync operation (futex wait/wake/requeue, or an
		// op on an IPC object). set_robust_list/get_robust_list merely register or
		// query the per-thread robust-futex list head pointer — "managed in user
		// space: the kernel knows only about the location of the head"
		// (get_robust_list(2)) — and never wait/wake or touch the shared futex
		// word. That is registration/bookkeeping, exactly like rseq, so they stay
		// Misc and are NOT promoted to IPC alongside futex_* (asserted as IPC just
		// above). The split axis is operation-vs-registration, not name similarity.
		{"sys_enter_rseq", FamilyMisc},
		{"sys_exit_rseq", FamilyMisc},
		{"sys_enter_set_robust_list", FamilyMisc},
		{"sys_enter_get_robust_list", FamilyMisc},
		// sysinfo(2) returns overall system statistics (memory/swap usage and
		// load averages) into a single userspace struct sysinfo *info pointer
		// (an output buffer, not an fd/path). It is not in the explicit family
		// table and intentionally falls through to Misc, sharing the family with
		// its closest system-introspection siblings newuname/sysfs (also Misc).
		// NOTE: other "system info" relatives are deliberately classified
		// elsewhere — getrusage is Process, times/gettimeofday are Time — so
		// sysinfo is grouped with the uname/sysfs cluster rather than any of
		// those. ustat(2) is NOT a sibling here: it contains the "stat" name
		// marker and is classified FamilyFS by isFSSyscall. Keep this in sync
		// with the Misc list in docs/syscall-tracing-plan.md.
		{"sys_enter_sysinfo", FamilyMisc},
		{"sys_exit_sysinfo", FamilyMisc},
		{"sys_enter_newuname", FamilyMisc},
		{"sys_enter_sysfs", FamilyMisc},
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
		// ioprio_get/ioprio_set query/set the I/O scheduling class and priority of
		// a process, process group, or user. They are the I/O-priority analogues of
		// getpriority/setpriority (the CPU nice value) and share the identical
		// which/who selector signature, so they classify as Process alongside them
		// rather than falling through to Misc. Assert the ioprio pair together with
		// their getpriority/setpriority siblings so a stray reclassification of any
		// one of them trips this test. Note: the x86 I/O-port syscalls ioperm/iopl
		// (asserted above as Misc) only share an "io" name prefix; they set
		// port-access state, not process I/O priority, and stay in Misc. Keep in
		// sync with the Process list in docs/syscall-tracing-plan.md.
		{"sys_enter_ioprio_get", FamilyProcess},
		{"sys_exit_ioprio_get", FamilyProcess},
		{"sys_enter_ioprio_set", FamilyProcess},
		{"sys_exit_ioprio_set", FamilyProcess},
		{"sys_enter_getpriority", FamilyProcess},
		{"sys_enter_setpriority", FamilyProcess},
		// setuid(2) sets the process credential (effective, and possibly real and
		// saved, user ID); it is a process/credential-management syscall and shares
		// FamilyProcess with its credential-setting cluster — the uid setters
		// setresuid/setreuid/setfsuid, the gid analogues
		// setgid/setresgid/setregid/setfsgid/setgroups, and the matching credential
		// readers getuid/geteuid/getgid/getegid/getresuid/getresgid/getgroups.
		// Assert the cluster (enter and exit for setuid) so a stray
		// reclassification of any one credential syscall trips this test.
		// seteuid/setegid (set effective uid/gid) belong with the cluster too,
		// but have no dedicated kernel tracepoints (they are libc wrappers over
		// setreuid/setresuid), so they never reach the generated tracepoint map
		// or docs/syscall-tracing-plan.md. They are still classified as Process
		// in family.go for consistency, so assert them here by name directly
		// (no tracepoint required) to lock in that latent classification.
		{"sys_enter_setuid", FamilyProcess},
		{"sys_exit_setuid", FamilyProcess},
		{"sys_enter_seteuid", FamilyProcess},
		{"sys_exit_seteuid", FamilyProcess},
		{"sys_enter_setegid", FamilyProcess},
		{"sys_exit_setegid", FamilyProcess},
		{"sys_enter_setresuid", FamilyProcess},
		{"sys_enter_setreuid", FamilyProcess},
		{"sys_enter_setfsuid", FamilyProcess},
		{"sys_enter_setgid", FamilyProcess},
		{"sys_enter_setresgid", FamilyProcess},
		{"sys_enter_setregid", FamilyProcess},
		{"sys_enter_setfsgid", FamilyProcess},
		{"sys_enter_setgroups", FamilyProcess},
		{"sys_enter_getuid", FamilyProcess},
		{"sys_enter_geteuid", FamilyProcess},
		{"sys_enter_getgid", FamilyProcess},
		{"sys_enter_getegid", FamilyProcess},
		{"sys_enter_getresuid", FamilyProcess},
		{"sys_enter_getresgid", FamilyProcess},
		{"sys_enter_getgroups", FamilyProcess},
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
