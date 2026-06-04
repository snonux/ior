package generate

import (
	"strconv"
	"strings"
	"testing"
)

// This file retains only the classifier tests that exercise actual code
// generation (tracing behavior / argument extraction / event-kind selection),
// plus the shared test helpers used by codegen_test.go and family-codegen
// tests. The former pure-classification unit tests — those whose sole assertion
// was "ClassifyFormat(X).Kind == Y", "ClassifySyscallFamily(X) == Z", or
// "ClassifyRet(X) == ..." with no tracing component — were removed (task j20)
// as redundant: classification correctness is verified by inspection against
// the man pages and the classifier rules, and the tracing-relevant outcome
// (which fd/path/byte-count the generated BPF C actually captures) is covered by
// the GenerateTracepointsC tests kept below and in codegen_test.go.

// TestClassifySendfile64CapturesOutFd locks in the sendfile64 audit (task az):
// sendfile64(out_fd, in_fd, offset, count) transfers bytes between two file
// descriptors inside the kernel and returns the count written to out_fd. Its
// real tracepoint fields carry no field literally named "fd", so without the
// explicit nameOnlyKindsTable override it would fall through to KindNull and
// capture no descriptor — inconsistent with its sibling copy_file_range (KindFd)
// and the read/write/sendto/recvfrom families. This test pins that sendfile64 is
// a KindFd event capturing out_fd (args[0], the write destination) and that the
// generated C emits exactly that capture, never a null_event.
func TestClassifySendfile64CapturesOutFd(t *testing.T) {
	// Realistic enter layout from /sys/kernel/tracing for sys_enter_sendfile64.
	enter := &Format{
		Name: "sys_enter_sendfile64",
		ExternalFields: []Field{
			{Type: "long", Name: "__syscall_nr"},
			{Type: "int", Name: "out_fd"},
			{Type: "int", Name: "in_fd"},
			{Type: "off_t *", Name: "offset"},
			{Type: "size_t", Name: "count"},
		},
	}
	r := ClassifyFormat(enter)
	if r.Kind != KindFd {
		t.Fatalf("sendfile64: got kind %d, want KindFd (must not fall back to KindNull)", r.Kind)
	}
	// Negative guard: out_fd/in_fd must not be mistaken for a two-fd event; the
	// audit deliberately keeps sendfile64 single-fd like copy_file_range.
	if r.Kind == KindTwoFd || r.Kind == KindNull {
		t.Fatalf("sendfile64: kind %d, want single-fd KindFd, not two-fd/null", r.Kind)
	}

	// Generated C must capture out_fd at args[0] (the byte-write destination) via
	// a struct fd_event, never a struct null_event.
	output := GenerateTracepointsC(phaseAFormats("sendfile64", 9500))
	if !strings.Contains(output, "/// sys_enter_sendfile64 is a struct fd_event") {
		t.Fatalf("sys_enter_sendfile64 should be a struct fd_event:\n%s", output)
	}
	if strings.Contains(output, "/// sys_enter_sendfile64 is a struct null_event") {
		t.Fatalf("sys_enter_sendfile64 must not be a struct null_event:\n%s", output)
	}
	if !strings.Contains(output, "ev->fd = (__s32)ctx->args[0];") {
		t.Fatalf("sys_enter_sendfile64 should capture out_fd from args[0]:\n%s", output)
	}
	// Return value stays TransferClassified: sendfile64 moves bytes between two
	// fds, consistent with copy_file_range/splice/tee/vmsplice.
	if c := ClassifyRet("sys_exit_sendfile64"); c != TransferClassified {
		t.Fatalf("sendfile64 ret: got %v, want TransferClassified", c)
	}
}

// --- End-to-end codegen: enter+exit pairs must be accepted and emit handlers ---

func TestClassifySyscallPairAccepted(t *testing.T) {
	tests := []struct {
		name      string
		enter     string
		exit      string
		enterKind TracepointKind
	}{
		{"read", FormatRead, FormatExitRead, KindFd},
		{"lseek", FormatLseek, FormatExitLseek, KindFd},
		{"openat", FormatOpenat, FormatExitOpenat, KindOpen},
		{"rename", FormatRename, FormatExitRename, KindName},
		{"close", FormatClose, FormatExitClose, KindFd},
		{"dup3", FormatDup3, FormatExitDup3, KindDup3},
		{"fcntl", FormatFcntl, FormatExitFcntl, KindFcntl},
		{"sync", FormatSync, FormatExitSync, KindNull},
		{"msync", FormatMsync, FormatExitMsync, KindNull},
		{"getcwd", FormatGetcwd, FormatExitGetcwd, KindNull},
		{"pidfd_getfd", FormatPidfdGetfd, FormatExitPidfdGetfd, KindFd},
		{"copy_file_range", FormatCopyFileRange, FormatExitCopyFileRange, KindFd},
		{"syslog", FormatSyslog, FormatExitSyslog, KindNull},
		{"open_by_handle_at", FormatOpenByHandleAt, FormatExitOpenByHandleAt, KindOpenByHandleAt},
		{"name_to_handle_at", FormatNameToHandleAt, FormatExitNameToHandleAt, KindPathname},
		{"io_uring_enter", FormatIoUringEnter, FormatExitIoUringEnter, KindFd},
		{"io_uring_register", FormatIoUringRegister, FormatExitIoUringRegister, KindFd},
		{"pread64", FormatPread64, FormatExitPread64, KindFd},
		{"symlink", FormatSymlink, FormatExitSymlink, KindName},
		{"mknod", FormatMknod, FormatExitMknod, KindPathname},
		{"mknodat", FormatMknodat, FormatExitMknodat, KindPathname},
		{"execve", FormatExecve, FormatExitExecve, KindExec},
		{"execveat", FormatExecveat, FormatExitExecveat, KindExec},
		{"accept", FormatAccept, FormatExitAccept, KindAccept},
		{"accept4", FormatAccept4, FormatExitAccept4, KindAccept},
		{"socket", FormatSocket, FormatExitSocket, KindSocket},
		{"socketpair", FormatSocketpair, FormatExitSocketpair, KindSocketpair},
		{"pipe", FormatPipe, FormatExitPipe, KindPipe},
		{"pipe2", FormatPipe2, FormatExitPipe2, KindPipe},
		{"eventfd", FormatEventfd, FormatExitEventfd, KindEventfd},
		{"eventfd2", FormatEventfd2, FormatExitEventfd2, KindEventfd},
		{"epoll_create", syntheticEnter("epoll_create", 9340), syntheticExit("epoll_create", 9339), KindEventfd},
		{"epoll_create1", syntheticEnter("epoll_create1", 9342), syntheticExit("epoll_create1", 9341), KindEventfd},
		{"inotify_init", syntheticEnter("inotify_init", 9344), syntheticExit("inotify_init", 9343), KindEventfd},
		{"inotify_init1", syntheticEnter("inotify_init1", 9346), syntheticExit("inotify_init1", 9345), KindEventfd},
		{"fanotify_init", syntheticEnter("fanotify_init", 9348), syntheticExit("fanotify_init", 9347), KindEventfd},
		{"landlock_create_ruleset", syntheticEnter("landlock_create_ruleset", 9350), syntheticExit("landlock_create_ruleset", 9349), KindEventfd},
		{"landlock_add_rule", syntheticEnter("landlock_add_rule", 9418), syntheticExit("landlock_add_rule", 9417), KindFd},
		{"landlock_restrict_self", syntheticEnter("landlock_restrict_self", 9420), syntheticExit("landlock_restrict_self", 9419), KindFd},
		{"fsopen", syntheticEnter("fsopen", 9352), syntheticExit("fsopen", 9351), KindEventfd},
		{"pidfd_open", syntheticEnter("pidfd_open", 9320), syntheticExit("pidfd_open", 9319), KindPidfd},
		{"pidfd_send_signal", syntheticEnter("pidfd_send_signal", 9322), syntheticExit("pidfd_send_signal", 9321), KindFd},
		{"epoll_ctl", FormatEpollCtl, FormatExitEpollCtl, KindEpollCtl},
		{"epoll_wait", FormatEpollWait, FormatExitEpollWait, KindFd},
		{"epoll_pwait", FormatEpollPwait, FormatExitEpollPwait, KindFd},
		{"epoll_pwait2", FormatEpollPwait2, FormatExitEpollPwait2, KindFd},
		{"poll", FormatPoll, FormatExitPoll, KindPoll},
		{"ppoll", FormatPpoll, FormatExitPpoll, KindPoll},
		{"select", FormatSelect, FormatExitSelect, KindPoll},
		{"pselect6", FormatPselect6, FormatExitPselect6, KindPoll},
		{"munmap", FormatMunmap, FormatExitMunmap, KindMem},
		{"mremap", FormatMremap, FormatExitMremap, KindMem},
		{"mincore", syntheticEnter("mincore", 9354), syntheticExit("mincore", 9353), KindMem},
		{"remap_file_pages", syntheticEnter("remap_file_pages", 9356), syntheticExit("remap_file_pages", 9355), KindMem},
		{"mlock", syntheticEnter("mlock", 9358), syntheticExit("mlock", 9357), KindMem},
		{"mlock2", syntheticEnter("mlock2", 9360), syntheticExit("mlock2", 9359), KindMem},
		{"munlock", syntheticEnter("munlock", 9362), syntheticExit("munlock", 9361), KindMem},
		{"mseal", syntheticEnter("mseal", 9364), syntheticExit("mseal", 9363), KindMem},
		{"map_shadow_stack", syntheticEnter("map_shadow_stack", 9366), syntheticExit("map_shadow_stack", 9365), KindMem},
		{"nanosleep", FormatNanosleep, FormatExitNanosleep, KindSleep},
		{"clock_nanosleep", FormatClockNanosleep, FormatExitClockNanosleep, KindSleep},
		{"keyctl", syntheticEnter("keyctl", 9200), syntheticExit("keyctl", 9199), KindKeyctl},
		{"add_key", syntheticEnter("add_key", 9202), syntheticExit("add_key", 9201), KindKeyctl},
		{"request_key", syntheticEnter("request_key", 9204), syntheticExit("request_key", 9203), KindKeyctl},
		{"ptrace", syntheticEnter("ptrace", 9206), syntheticExit("ptrace", 9205), KindPtrace},
		{"perf_event_open", syntheticEnter("perf_event_open", 9208), syntheticExit("perf_event_open", 9207), KindPerfOpen},
		{"seccomp", syntheticEnter("seccomp", 9368), syntheticExit("seccomp", 9367), KindSeccomp},
		{"init_module", syntheticEnter("init_module", 9370), syntheticExit("init_module", 9369), KindModule},
		{"delete_module", syntheticEnter("delete_module", 9372), syntheticExit("delete_module", 9371), KindModule},
		{"msgget", syntheticEnter("msgget", 9394), syntheticExit("msgget", 9393), KindSysVId},
		{"semget", syntheticEnter("semget", 9396), syntheticExit("semget", 9395), KindSysVId},
		{"shmget", syntheticEnter("shmget", 9398), syntheticExit("shmget", 9397), KindSysVId},
		{"msgsnd", syntheticEnter("msgsnd", 9400), syntheticExit("msgsnd", 9399), KindSysVOp},
		{"msgrcv", syntheticEnter("msgrcv", 9402), syntheticExit("msgrcv", 9401), KindSysVOp},
		{"msgctl", syntheticEnter("msgctl", 9404), syntheticExit("msgctl", 9403), KindSysVOp},
		{"semop", syntheticEnter("semop", 9406), syntheticExit("semop", 9405), KindSysVOp},
		{"semtimedop", syntheticEnter("semtimedop", 9408), syntheticExit("semtimedop", 9407), KindSysVOp},
		{"semctl", syntheticEnter("semctl", 9410), syntheticExit("semctl", 9409), KindSysVOp},
		{"shmat", syntheticEnter("shmat", 9412), syntheticExit("shmat", 9411), KindSysVOp},
		{"shmdt", syntheticEnter("shmdt", 9414), syntheticExit("shmdt", 9413), KindSysVOp},
		{"shmctl", syntheticEnter("shmctl", 9416), syntheticExit("shmctl", 9415), KindSysVOp},
		{"mount", FormatMount, FormatExitMount, KindPathname},
		{"umount", FormatUmount, FormatExitUmount, KindPathname},
		{"move_mount", FormatMoveMount, FormatExitMoveMount, KindTwoFd},
		{"close_range", syntheticEnter("close_range", 9322), syntheticExit("close_range", 9321), KindTwoFd},
		{"kcmp", syntheticEnter("kcmp", 9324), syntheticExit("kcmp", 9323), KindTwoFd},
		{"kexec_file_load", syntheticEnter("kexec_file_load", 9326), syntheticExit("kexec_file_load", 9325), KindFd},
		{"membarrier", syntheticEnter("membarrier", 9328), syntheticExit("membarrier", 9327), KindNull},
		{"rseq", syntheticEnter("rseq", 9330), syntheticExit("rseq", 9329), KindNull},
		{"set_robust_list", syntheticEnter("set_robust_list", 9332), syntheticExit("set_robust_list", 9331), KindNull},
		{"get_robust_list", syntheticEnter("get_robust_list", 9334), syntheticExit("get_robust_list", 9333), KindNull},
		{"mmap2", syntheticEnter("mmap2", 9336), syntheticExit("mmap2", 9335), KindNull},
		{"kexec_load", syntheticEnter("kexec_load", 9338), syntheticExit("kexec_load", 9337), KindNull},
		{"fsmount", FormatFsmount, FormatExitFsmount, KindEventfd},
		{"pivot_root", FormatPivotRoot, FormatExitPivotRoot, KindPathname},
		{"quotactl", FormatQuotactl, FormatExitQuotactl, KindPathname},
		{"statmount", FormatStatmount, FormatExitStatmount, KindNull},
		{"listmount", FormatListmount, FormatExitListmount, KindNull},
		{"listns", FormatListns, FormatExitListns, KindNull},
		{"swapon", FormatSwapon, FormatExitSwapon, KindPathname},
		{"swapoff", FormatSwapoff, FormatExitSwapoff, KindPathname},
		{"kill", FormatKill, FormatExitKill, KindNull},
		{"rt_sigaction", syntheticEnter("rt_sigaction", 9374), syntheticExit("rt_sigaction", 9373), KindNull},
		{"rt_sigprocmask", syntheticEnter("rt_sigprocmask", 9376), syntheticExit("rt_sigprocmask", 9375), KindNull},
		{"rt_sigpending", syntheticEnter("rt_sigpending", 9378), syntheticExit("rt_sigpending", 9377), KindNull},
		{"rt_sigsuspend", syntheticEnter("rt_sigsuspend", 9380), syntheticExit("rt_sigsuspend", 9379), KindNull},
		{"rt_sigtimedwait", syntheticEnter("rt_sigtimedwait", 9382), syntheticExit("rt_sigtimedwait", 9381), KindNull},
		{"rt_sigreturn", syntheticEnter("rt_sigreturn", 9384), syntheticExit("rt_sigreturn", 9383), KindNull},
		{"sigaltstack", syntheticEnter("sigaltstack", 9386), syntheticExit("sigaltstack", 9385), KindNull},
		{"pause", syntheticEnter("pause", 9388), syntheticExit("pause", 9387), KindNull},
		{"rt_sigqueueinfo", syntheticEnter("rt_sigqueueinfo", 9390), syntheticExit("rt_sigqueueinfo", 9389), KindNull},
		{"rt_tgsigqueueinfo", syntheticEnter("rt_tgsigqueueinfo", 9392), syntheticExit("rt_tgsigqueueinfo", 9391), KindNull},
		{"exit", syntheticEnter("exit", 9310), syntheticExit("exit", 9309), KindNull},
		{"exit_group", syntheticEnter("exit_group", 9312), syntheticExit("exit_group", 9311), KindNull},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.enter + "\n" + tt.exit
			output := GenerateTracepointsC(mustParseAll(t, input))
			if strings.Contains(output, "Ignoring") {
				t.Errorf("syscall %s was ignored, expected accepted", tt.name)
			}
		})
	}
}

func TestClassifySyscallPairEmitsAllFamilies(t *testing.T) {
	tests := []struct {
		name   string
		enter  string
		exit   string
		family SyscallFamily
	}{
		{"mknod", FormatMknod, FormatExitMknod, FamilyFS},
		{"mknodat", FormatMknodat, FormatExitMknodat, FamilyFS},
		{"execve", FormatExecve, FormatExitExecve, FamilyProcess},
		{"execveat", FormatExecveat, FormatExitExecveat, FamilyProcess},
		{"accept", FormatAccept, FormatExitAccept, FamilyNetwork},
		{"accept4", FormatAccept4, FormatExitAccept4, FamilyNetwork},
		{"socket", FormatSocket, FormatExitSocket, FamilyNetwork},
		{"socketpair", FormatSocketpair, FormatExitSocketpair, FamilyNetwork},
		{"pipe", FormatPipe, FormatExitPipe, FamilyIPC},
		{"pipe2", FormatPipe2, FormatExitPipe2, FamilyIPC},
		{"eventfd", FormatEventfd, FormatExitEventfd, FamilyIPC},
		{"eventfd2", FormatEventfd2, FormatExitEventfd2, FamilyIPC},
		{"epoll_ctl", FormatEpollCtl, FormatExitEpollCtl, FamilyPolling},
		{"epoll_wait", FormatEpollWait, FormatExitEpollWait, FamilyPolling},
		{"poll", FormatPoll, FormatExitPoll, FamilyPolling},
		{"ppoll", FormatPpoll, FormatExitPpoll, FamilyPolling},
		{"select", FormatSelect, FormatExitSelect, FamilyPolling},
		{"pselect6", FormatPselect6, FormatExitPselect6, FamilyPolling},
		{"munmap", FormatMunmap, FormatExitMunmap, FamilyMemory},
		{"mremap", FormatMremap, FormatExitMremap, FamilyMemory},
		{"nanosleep", FormatNanosleep, FormatExitNanosleep, FamilyTime},
		{"clock_nanosleep", FormatClockNanosleep, FormatExitClockNanosleep, FamilyTime},
		{"keyctl", syntheticEnter("keyctl", 9300), syntheticExit("keyctl", 9299), FamilySecurity},
		{"add_key", syntheticEnter("add_key", 9302), syntheticExit("add_key", 9301), FamilySecurity},
		{"request_key", syntheticEnter("request_key", 9304), syntheticExit("request_key", 9303), FamilySecurity},
		{"ptrace", syntheticEnter("ptrace", 9306), syntheticExit("ptrace", 9305), FamilySecurity},
		{"perf_event_open", syntheticEnter("perf_event_open", 9308), syntheticExit("perf_event_open", 9307), FamilySecurity},
		// lsm_* are the Linux Security Module introspection syscalls (Linux
		// 6.8+); they belong with their landlock_*/keyctl/*_key siblings in
		// the Security family, not Misc.
		{"lsm_list_modules", syntheticEnter("lsm_list_modules", 9412), syntheticExit("lsm_list_modules", 9411), FamilySecurity},
		{"lsm_get_self_attr", syntheticEnter("lsm_get_self_attr", 9414), syntheticExit("lsm_get_self_attr", 9413), FamilySecurity},
		{"lsm_set_self_attr", syntheticEnter("lsm_set_self_attr", 9416), syntheticExit("lsm_set_self_attr", 9415), FamilySecurity},
		{"mount", FormatMount, FormatExitMount, FamilyFS},
		{"umount", FormatUmount, FormatExitUmount, FamilyFS},
		{"move_mount", FormatMoveMount, FormatExitMoveMount, FamilyFS},
		{"fsmount", FormatFsmount, FormatExitFsmount, FamilyFS},
		{"quotactl", FormatQuotactl, FormatExitQuotactl, FamilyFS},
		{"statmount", FormatStatmount, FormatExitStatmount, FamilyFS},
		{"listmount", FormatListmount, FormatExitListmount, FamilyFS},
		{"listns", FormatListns, FormatExitListns, FamilyFS},
		{"swapon", FormatSwapon, FormatExitSwapon, FamilyFS},
		{"swapoff", FormatSwapoff, FormatExitSwapoff, FamilyFS},
		// Bare sync() takes no args and returns void, but it DOES return (it is
		// not noreturn like exit/exit_group), so it belongs in FamilyFS and must
		// still emit a live exit handler. Its fd-taking siblings (syncfs/fsync/
		// fdatasync/sync_file_range) are FamilyFS+KindFd and covered elsewhere.
		{"sync", FormatSync, FormatExitSync, FamilyFS},
		{"kill", FormatKill, FormatExitKill, FamilySignals},
		{"exit_group", syntheticEnter("exit_group", 9316), syntheticExit("exit_group", 9315), FamilyProcess},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.enter + "\n" + tt.exit
			formats := mustParseAll(t, input)
			if formats[0].Family != tt.family {
				t.Fatalf("%s family = %s, want %s", tt.name, formats[0].Family, tt.family)
			}
			output := GenerateTracepointsC(formats)
			if strings.Contains(output, "Ignoring") {
				t.Errorf("syscall %s was ignored, expected accepted", tt.name)
			}
			if !strings.Contains(output, `SEC("tracepoint/syscalls/sys_enter_`+tt.name+`")`) {
				t.Errorf("syscall %s missing enter handler", tt.name)
			}
			// Noreturn syscalls (exit, exit_group) are deliberately exempt from
			// the exit-handler requirement: their sys_exit handler can never
			// fire because the syscall never returns, so codegen suppresses it
			// via isNoreturnSyscall (see TestGenerateExitNoreturnHandlers). For
			// every other syscall the exit handler is still required.
			hasExitHandler := strings.Contains(output, `SEC("tracepoint/syscalls/sys_exit_`+tt.name+`")`)
			if isNoreturnSyscall(tt.name) {
				if hasExitHandler {
					t.Errorf("noreturn syscall %s must not emit an exit handler", tt.name)
				}
			} else if !hasExitHandler {
				t.Errorf("syscall %s missing exit handler", tt.name)
			}
		})
	}
}

func TestClassifyPhaseAByteSyscallPairsAccepted(t *testing.T) {
	tests := []struct {
		name          string
		enterKindText string
		retText       string
	}{
		{"recvfrom", "struct fd_event", "READ_CLASSIFIED"},
		{"recvmsg", "struct fd_event", "READ_CLASSIFIED"},
		{"sendto", "struct fd_event", "WRITE_CLASSIFIED"},
		{"sendmsg", "struct fd_event", "WRITE_CLASSIFIED"},
		{"sendfile64", "struct fd_event", "TRANSFER_CLASSIFIED"},
		{"splice", "struct fd_event", "TRANSFER_CLASSIFIED"},
		{"tee", "struct fd_event", "TRANSFER_CLASSIFIED"},
		{"process_vm_readv", "struct null_event", "READ_CLASSIFIED"},
		{"process_vm_writev", "struct null_event", "WRITE_CLASSIFIED"},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formats := phaseAFormats(tt.name, 9000+i*2)
			output := GenerateTracepointsC(formats)
			if strings.Contains(output, "Ignoring") || strings.Contains(output, "Skipping") {
				t.Fatalf("syscall %s was not accepted:\n%s", tt.name, output)
			}
			if !strings.Contains(output, "/// sys_enter_"+tt.name+" is a "+tt.enterKindText) {
				t.Fatalf("sys_enter_%s did not use %s:\n%s", tt.name, tt.enterKindText, output)
			}
			if !strings.Contains(output, "/// sys_exit_"+tt.name+" is a struct ret_event ("+tt.retText+")") {
				t.Fatalf("sys_exit_%s did not use %s:\n%s", tt.name, tt.retText, output)
			}
		})
	}
}

func TestBatchMessageSyscallPairsDeferByteClassification(t *testing.T) {
	tests := []string{"sendmmsg", "recvmmsg"}
	for i, name := range tests {
		t.Run(name, func(t *testing.T) {
			output := GenerateTracepointsC(phaseAFormats(name, 9100+i*2))
			if strings.Contains(output, "Ignoring") || strings.Contains(output, "Skipping") {
				t.Fatalf("syscall %s was not accepted:\n%s", name, output)
			}
			if !strings.Contains(output, "/// sys_exit_"+name+" is a struct ret_event (UNCLASSIFIED)") {
				t.Fatalf("sys_exit_%s should be generated without byte classification:\n%s", name, output)
			}
		})
	}
}

func TestClassifyMqSyscallPairsAcceptedAndClassified(t *testing.T) {
	tests := []struct {
		name               string
		enterKindText      string
		exitClassification string
	}{
		{"mq_open", "struct open_event", "UNCLASSIFIED"},
		{"mq_unlink", "struct path_event", "UNCLASSIFIED"},
		// mq_timedsend returns 0/-1 (a status), not a byte count, so its ret is
		// UNCLASSIFIED. Only mq_timedreceive returns a real received byte count.
		{"mq_timedsend", "struct fd_event", "UNCLASSIFIED"},
		{"mq_timedreceive", "struct fd_event", "READ_CLASSIFIED"},
		{"mq_notify", "struct fd_event", "UNCLASSIFIED"},
		{"mq_getsetattr", "struct fd_event", "UNCLASSIFIED"},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := GenerateTracepointsC(mqFormats(tt.name, 9200+i*2))
			if strings.Contains(output, "Ignoring") || strings.Contains(output, "Skipping") {
				t.Fatalf("syscall %s was not accepted:\n%s", tt.name, output)
			}
			if !strings.Contains(output, "/// sys_enter_"+tt.name+" is a "+tt.enterKindText) {
				t.Fatalf("sys_enter_%s did not use %s:\n%s", tt.name, tt.enterKindText, output)
			}
			if !strings.Contains(output, "/// sys_exit_"+tt.name+" is a struct ret_event ("+tt.exitClassification+")") {
				t.Fatalf("sys_exit_%s did not use %s:\n%s", tt.name, tt.exitClassification, output)
			}
		})
	}
}

// --- Shared test helpers (used here and by codegen_test.go) ---

func phaseAFormats(name string, enterID int) []Format {
	enterFields := []Field{
		{Type: "long", Name: "__syscall_nr"},
	}
	if name == "sendto" || name == "recvfrom" || name == "sendmsg" || name == "recvmsg" ||
		name == "sendmmsg" || name == "recvmmsg" {
		enterFields = append(enterFields, Field{Type: "int", Name: "fd"})
	}

	return []Format{
		{
			Name:           "sys_enter_" + name,
			ID:             enterID,
			Family:         ClassifySyscallFamily("sys_enter_" + name),
			ExternalFields: enterFields,
		},
		{
			Name:   "sys_exit_" + name,
			ID:     enterID - 1,
			Family: ClassifySyscallFamily("sys_exit_" + name),
			ExternalFields: []Field{
				{Type: "long", Name: "__syscall_nr"},
				{Type: "long", Name: "ret"},
			},
		},
	}
}

func mqFormats(name string, enterID int) []Format {
	enterFields := []Field{
		{Type: "long", Name: "__syscall_nr"},
	}
	switch name {
	case "mq_open":
		enterFields = append(enterFields,
			Field{Type: "const char *", Name: "u_name"},
			Field{Type: "int", Name: "oflag"},
			Field{Type: "umode_t", Name: "mode"},
		)
	case "mq_unlink":
		enterFields = append(enterFields, Field{Type: "const char *", Name: "u_name"})
	default:
		enterFields = append(enterFields, Field{Type: "mqd_t", Name: "mqdes"})
	}

	return []Format{
		{
			Name:           "sys_enter_" + name,
			ID:             enterID,
			Family:         ClassifySyscallFamily("sys_enter_" + name),
			ExternalFields: enterFields,
		},
		{
			Name:   "sys_exit_" + name,
			ID:     enterID - 1,
			Family: ClassifySyscallFamily("sys_exit_" + name),
			ExternalFields: []Field{
				{Type: "long", Name: "__syscall_nr"},
				{Type: "long", Name: "ret"},
			},
		},
	}
}

func syntheticEnter(syscall string, id int) string {
	return strings.Replace(strings.Replace(FormatKill, "sys_enter_kill", "sys_enter_"+syscall, 1), "ID: 183", "ID: "+itoa(id), 1)
}

func syntheticExit(syscall string, id int) string {
	return strings.Replace(strings.Replace(FormatExitKill, "sys_exit_kill", "sys_exit_"+syscall, 1), "ID: 182", "ID: "+itoa(id), 1)
}

func itoa(v int) string {
	return strconv.Itoa(v)
}

func mustParseAll(t *testing.T, data string) []Format {
	t.Helper()
	formats, err := ParseFormats(strings.NewReader(data))
	if err != nil {
		t.Fatalf("ParseFormats failed: %v", err)
	}
	return formats
}
