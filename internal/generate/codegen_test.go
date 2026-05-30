package generate

import (
	"strings"
	"testing"
)

func generateFromPair(t *testing.T, enter, exit string) string {
	t.Helper()
	input := enter + "\n" + exit
	formats := mustParseAll(t, input)
	return GenerateTracepointsC(formats)
}

func TestGenerateFdHandler(t *testing.T) {
	output := generateFromPair(t, FormatRead, FormatExitRead)

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_read")`)
	requireContains(t, output, "struct syscall_trace_enter *ctx")
	requireContains(t, output, "struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);")
	requireContains(t, output, "ev->event_type = ENTER_FD_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_READ;")
	requireContains(t, output, "ev->fd = (__s32)ctx->args[0];")
	requireContains(t, output, "#define SYS_ENTER_READ 844")
}

// TestGenerateModuleHandlers locks in the generated BPF C for the module-load
// syscalls (man 2 init_module). init_module is a null_event: it must capture no
// fd and no path/filename (its param_values arg is a parameter string, not a
// path). finit_module is an fd_event capturing fd = args[0].
func TestGenerateModuleHandlers(t *testing.T) {
	initOut := generateFromPair(t, FormatInitModule, FormatExitInitModule)
	requireContains(t, initOut, `SEC("tracepoint/syscalls/sys_enter_init_module")`)
	requireContains(t, initOut, "struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);")
	requireContains(t, initOut, "ev->event_type = ENTER_NULL_EVENT;")
	// init_module must not capture an fd or any filename/path.
	if strings.Contains(initOut, "ev->fd =") {
		t.Error("init_module handler must not capture an fd")
	}
	if strings.Contains(initOut, "ev->filename") || strings.Contains(initOut, "bpf_probe_read_user_str") {
		t.Error("init_module handler must not capture param_values as a path/filename")
	}

	finitOut := generateFromPair(t, FormatFinitModule, FormatExitFinitModule)
	requireContains(t, finitOut, `SEC("tracepoint/syscalls/sys_enter_finit_module")`)
	requireContains(t, finitOut, "struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);")
	requireContains(t, finitOut, "ev->event_type = ENTER_FD_EVENT;")
	requireContains(t, finitOut, "ev->fd = (__s32)ctx->args[0];")
}

// TestGenerateBindHandler locks in the generated BPF C for bind(2):
//
//	int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
//
// bind assigns an address to a socket and returns 0 on success or -1 on error.
// Its sockfd is at args[0], so the enter handler is a KindFd fd_event capturing
// ev->fd = args[0] — matching its socket siblings connect/listen/accept/
// getsockname/getpeername. The addr pointer (args[1]) and addrlen (args[2]) must
// NOT be captured: bind reads no path and copies no userspace buffer we track.
// The exit handler is a plain ret_event marked UNCLASSIFIED (0/-1, no byte
// count), so it must not carry a READ/WRITE/TRANSFER classification.
func TestGenerateBindHandler(t *testing.T) {
	output := generateFromPair(t, FormatBind, FormatExitBind)

	// Enter: KindFd fd_event capturing the sockfd from args[0].
	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_bind")`)
	requireContains(t, output, "struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);")
	requireContains(t, output, "ev->event_type = ENTER_FD_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_BIND;")
	requireContains(t, output, "ev->fd = (__s32)ctx->args[0];")

	// Negative guards: the sockaddr pointer (args[1]) must never be read as a
	// path/buffer, and addrlen (args[2]) must not be captured as another fd.
	requireNotContains(t, output, "bpf_probe_read_user_str")
	requireNotContains(t, output, "ev->fd = (__s32)ctx->args[1];")
	requireNotContains(t, output, "ev->fd = (__s32)ctx->args[2];")

	// Exit: plain ret_event, UNCLASSIFIED (bind returns 0/-1, no byte count).
	requireContains(t, output, `SEC("tracepoint/syscalls/sys_exit_bind")`)
	requireContains(t, output, "struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
	requireNotContains(t, output, "ev->ret_type = READ_CLASSIFIED;")
	requireNotContains(t, output, "ev->ret_type = WRITE_CLASSIFIED;")
	requireNotContains(t, output, "ev->ret_type = TRANSFER_CLASSIFIED;")
}

// TestGenerateGetsocknameHandler locks in the generated BPF C for getsockname(2):
//
//	int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
//
// getsockname returns the local address a socket is bound to and yields 0 on
// success or -1 on error. Its sockfd is at args[0], so the enter handler is a
// KindFd fd_event capturing ev->fd = args[0] — matching its socket siblings
// bind/connect/listen/accept/getpeername. The addr output pointer (args[1]) and
// the addrlen in/out pointer (args[2]) must NOT be captured: getsockname reads
// no path and copies no userspace buffer we track. The exit handler is a plain
// ret_event marked UNCLASSIFIED (0/-1, no byte count), so it must not carry a
// READ/WRITE/TRANSFER classification — guarding against any mistaken
// recvfrom/sendto-style byte-transfer accounting.
func TestGenerateGetsocknameHandler(t *testing.T) {
	output := generateFromPair(t, FormatGetsockname, FormatExitGetsockname)

	// Enter: KindFd fd_event capturing the sockfd from args[0].
	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_getsockname")`)
	requireContains(t, output, "struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);")
	requireContains(t, output, "ev->event_type = ENTER_FD_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_GETSOCKNAME;")
	requireContains(t, output, "ev->fd = (__s32)ctx->args[0];")

	// Negative guards: the sockaddr output pointer (args[1]) must never be read
	// as a path/buffer, and the addrlen pointer (args[2]) must not be captured as
	// another fd.
	requireNotContains(t, output, "bpf_probe_read_user_str")
	requireNotContains(t, output, "ev->fd = (__s32)ctx->args[1];")
	requireNotContains(t, output, "ev->fd = (__s32)ctx->args[2];")

	// Exit: plain ret_event, UNCLASSIFIED (getsockname returns 0/-1, no byte count).
	requireContains(t, output, `SEC("tracepoint/syscalls/sys_exit_getsockname")`)
	requireContains(t, output, "struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
	requireNotContains(t, output, "ev->ret_type = READ_CLASSIFIED;")
	requireNotContains(t, output, "ev->ret_type = WRITE_CLASSIFIED;")
	requireNotContains(t, output, "ev->ret_type = TRANSFER_CLASSIFIED;")
}

func TestGeneratePidfdGetfdHandlerUsesPidfdArgument(t *testing.T) {
	output := generateFromPair(t, FormatPidfdGetfd, FormatExitPidfdGetfd)

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_pidfd_getfd")`)
	requireContains(t, output, "ev->event_type = ENTER_FD_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_PIDFD_GETFD;")
	requireContains(t, output, "ev->fd = (__s32)ctx->args[0];")
}

// TestGenerateProcessMadviseHandlerUsesFirstArgumentAsFd locks in the BPF
// handler wiring for process_madvise(2):
//
//	ssize_t process_madvise(int pidfd, const struct iovec iovec[.n], size_t n,
//	                        int advice, unsigned int flags).
//
// Unlike the sibling madvise(2) (KindMem, addr/length at args[0]/args[1]), the
// first argument here is a pidfd — a PID *file descriptor* selecting the target
// process (see pidfd_open(2)) — so process_madvise is classified KindFd and the
// enter handler must capture ev->fd from args[0], NOT treat args[0] as an
// address. process_madvise returns the number of bytes advised on success or -1
// on error, but that count is advisory (no data is actually transferred), so the
// exit handler reports the raw status as UNCLASSIFIED exactly like madvise(2) —
// it must never be misclassified as a READ/WRITE/TRANSFER byte count.
func TestGenerateProcessMadviseHandlerUsesFirstArgumentAsFd(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("process_madvise")))

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_process_madvise")`)
	requireContains(t, output, "struct fd_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_FD_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_PROCESS_MADVISE;")
	requireContains(t, output, "ev->fd = (__s32)ctx->args[0];")
	// args[0] is a pidfd, never an address: the KindMem addr wiring must not leak
	// into the process_madvise enter handler.
	if strings.Contains(output, "ev->addr = (__u64)ctx->args[0];") &&
		strings.Contains(output, `SEC("tracepoint/syscalls/sys_enter_process_madvise")`) &&
		strings.Contains(output, "struct mem_event *ev") {
		t.Error("process_madvise must be KindFd (fd=args[0]), not KindMem (addr=args[0])")
	}
	// The exit handler returns the advisory byte count generically as the raw
	// status, classified UNCLASSIFIED — not as a transfer/byte-count.
	requireContains(t, output, `SEC("tracepoint/syscalls/sys_exit_process_madvise")`)
	requireContains(t, output, "ev->ret = ctx->ret;")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
}

// TestClassifyRetProcessMadviseUnclassified locks in that process_madvise's
// return value is UNCLASSIFIED. The man page says it returns "the number of
// bytes advised", but that is advisory accounting, not real I/O: no bytes move
// between buffers. Classifying it as TRANSFER/READ/WRITE would double-count it as
// data movement, so it must stay UNCLASSIFIED like madvise(2).
func TestClassifyRetProcessMadviseUnclassified(t *testing.T) {
	if got := ClassifyRet("sys_exit_process_madvise"); got != Unclassified {
		t.Errorf("process_madvise ret classification = %q, want %q", got, Unclassified)
	}
}

// TestGenerateRtSigpendingHandler locks in how rt_sigpending(2) is generated.
// Per the man page:
//
//	int rt_sigpending(sigset_t *set, size_t sigsetsize)
//
// It reports the set of signals pending for delivery into the userspace *set
// buffer and returns 0 on success or -1 on error. Neither argument is an fd or
// a path: args[0] is a userspace output pointer to a sigset_t (a signal mask,
// not an I/O resource) and args[1] is the byte size of that set. ior therefore
// classifies rt_sigpending as KindNull in FamilySignals, alongside the rest of
// the rt_sig* group. Consequently:
//   - The enter handler emits a struct null_event and must NOT capture args[0]
//     as an fd/path/addr — the sigset pointer is not a traced I/O resource.
//   - The exit handler reports the raw int status as UNCLASSIFIED; the 0/-1
//     return is not a byte count, so it must never be tagged READ/WRITE/TRANSFER.
func TestGenerateRtSigpendingHandler(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("rt_sigpending")))

	enterSec := `SEC("tracepoint/syscalls/sys_enter_rt_sigpending")`
	exitSec := `SEC("tracepoint/syscalls/sys_exit_rt_sigpending")`
	requireContains(t, output, enterSec)
	requireContains(t, output, "struct null_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_NULL_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_RT_SIGPENDING;")

	// The KindNull enter handler must not wire the sigset pointer (args[0]) or the
	// sigsetsize (args[1]) as an fd/path/addr — they are not traced I/O resources.
	// Scope to the enter handler body (everything from the enter SEC up to the
	// exit SEC) so we only check what the enter handler emits.
	enterStart := strings.Index(output, enterSec)
	exitStart := strings.Index(output, exitSec)
	if enterStart < 0 || exitStart < 0 || exitStart <= enterStart {
		t.Fatalf("rt_sigpending: handlers not found in expected order")
	}
	enterBody := output[enterStart:exitStart]
	if strings.Contains(enterBody, "ctx->args[") {
		t.Error("rt_sigpending must be KindNull: enter handler must not capture any arg")
	}

	// The exit handler reports the raw 0/-1 status as UNCLASSIFIED, not a byte count.
	requireContains(t, output, exitSec)
	requireContains(t, output, "ev->ret = ctx->ret;")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
}

// TestGenerateRtTgsigqueueinfoHandler locks in how rt_tgsigqueueinfo(2) is
// generated. Per the man page:
//
//	int rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *info)
//
// It queues signal sig (plus the accompanying siginfo data) to the thread tid
// within thread group tgid, and returns 0 on success or -1 on error. NONE of
// the arguments is an fd or a filesystem path: args[0] (tgid) and args[1] (tid)
// are process/thread IDs (pids, not fds — they must not be misclassified as
// file descriptors), args[2] (sig) is a signal number, and args[3] (info) is a
// userspace pointer to a siginfo_t control block, not a traced I/O resource.
// ior therefore classifies rt_tgsigqueueinfo as KindNull in FamilySignals,
// alongside its sibling rt_sigqueueinfo and the rest of the rt_sig* group.
// Consequently:
//   - The enter handler emits a struct null_event and must NOT capture any arg
//     as an fd/path/addr — the pids and siginfo pointer are not traced I/O.
//   - The exit handler reports the raw int status as UNCLASSIFIED; the 0/-1
//     return is not a byte count, so it must never be tagged READ/WRITE/TRANSFER.
func TestGenerateRtTgsigqueueinfoHandler(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("rt_tgsigqueueinfo")))

	enterSec := `SEC("tracepoint/syscalls/sys_enter_rt_tgsigqueueinfo")`
	exitSec := `SEC("tracepoint/syscalls/sys_exit_rt_tgsigqueueinfo")`
	requireContains(t, output, enterSec)
	requireContains(t, output, "struct null_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_NULL_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_RT_TGSIGQUEUEINFO;")

	// The KindNull enter handler must not wire tgid/tid (the pids, args[0]/args[1])
	// or the siginfo pointer (args[3]) as an fd/path/addr — none are traced I/O
	// resources, and the pids in particular must never be treated as fds. Scope to
	// the enter handler body (from the enter SEC up to the exit SEC).
	enterStart := strings.Index(output, enterSec)
	exitStart := strings.Index(output, exitSec)
	if enterStart < 0 || exitStart < 0 || exitStart <= enterStart {
		t.Fatalf("rt_tgsigqueueinfo: handlers not found in expected order")
	}
	enterBody := output[enterStart:exitStart]
	if strings.Contains(enterBody, "ctx->args[") {
		t.Error("rt_tgsigqueueinfo must be KindNull: enter handler must not capture any arg (tgid/tid are pids, not fds)")
	}

	// The exit handler reports the raw 0/-1 status as UNCLASSIFIED, not a byte count.
	requireContains(t, output, exitSec)
	requireContains(t, output, "ev->ret = ctx->ret;")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
}

// TestClassifyRetRtTgsigqueueinfoUnclassified locks in that rt_tgsigqueueinfo's
// return value is UNCLASSIFIED. The syscall returns an int status (0 on success,
// -1 on error) — never a byte count — so it must never be tagged as a
// READ/WRITE/TRANSFER transfer size.
func TestClassifyRetRtTgsigqueueinfoUnclassified(t *testing.T) {
	if got := ClassifyRet("sys_exit_rt_tgsigqueueinfo"); got != Unclassified {
		t.Errorf("rt_tgsigqueueinfo ret classification = %q, want %q", got, Unclassified)
	}
}

// TestGenerateClone3Handler locks in how clone3(2) is generated. Per the man
// page:
//
//	long clone3(struct clone_args *cl_args, size_t size)
//
// clone3 is the modern superset of clone/fork/vfork: it creates a new process
// or thread. args[0] is a userspace pointer to a struct clone_args (a control
// block, not an fd or filesystem path) and args[1] is its byte size. The return
// value is a pid_t: the child's PID in the parent, 0 in the child, or -1 on
// error — never a byte count. ior therefore classifies clone3 as KindProc in
// FamilyProcess, identical to its siblings clone/fork/vfork. Consequently:
//   - The enter handler emits a struct null_event and must NOT capture args[0]
//     (the clone_args pointer) or args[1] (size) as an fd/path/addr — neither is
//     a traced I/O resource.
//   - The exit handler reports the raw pid/0/-1 status as UNCLASSIFIED; it is not
//     a byte count, so it must never be tagged READ/WRITE/TRANSFER.
//
// This guards against a misclassification to KindNull (which would still emit a
// null_event but break sibling/dimension consistency) or to any fd/path kind
// (which would wrongly treat the clone_args pointer as a resource).
func TestGenerateClone3Handler(t *testing.T) {
	// Classification consistency with the clone/fork/vfork siblings. clone3's
	// real tracepoint args are (struct clone_args *, size_t); we feed a generic
	// pointer arg here to prove the name-only table — not a field heuristic —
	// pins all four siblings to KindProc.
	for _, name := range []string{"sys_enter_clone3", "sys_enter_clone", "sys_enter_fork", "sys_enter_vfork"} {
		r := ClassifyFormat(&Format{
			Name: name,
			ExternalFields: []Field{
				{Type: "long", Name: "__syscall_nr"},
				{Type: "struct clone_args *", Name: "uargs"},
				{Type: "unsigned long", Name: "size"},
			},
		})
		if r.Kind != KindProc {
			t.Errorf("%s kind = %v, want KindProc", name, r.Kind)
		}
	}
	if got := ClassifySyscallFamily("sys_enter_clone3"); got != FamilyProcess {
		t.Errorf("clone3 family = %q, want %q", got, FamilyProcess)
	}
	if got := ClassifyRet("sys_exit_clone3"); got != Unclassified {
		t.Errorf("clone3 ret classification = %q, want %q (pid, not a byte count)", got, Unclassified)
	}

	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("clone3")))

	enterSec := `SEC("tracepoint/syscalls/sys_enter_clone3")`
	exitSec := `SEC("tracepoint/syscalls/sys_exit_clone3")`
	requireContains(t, output, enterSec)
	requireContains(t, output, "struct null_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_NULL_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_CLONE3;")

	// The KindProc enter handler must not wire args[0] (clone_args ptr) or
	// args[1] (size) as an fd/path/addr — neither is a traced I/O resource.
	// Scope to the enter handler body (from the enter SEC up to the exit SEC).
	enterStart := strings.Index(output, enterSec)
	exitStart := strings.Index(output, exitSec)
	if enterStart < 0 || exitStart < 0 || exitStart <= enterStart {
		t.Fatalf("clone3: handlers not found in expected order")
	}
	enterBody := output[enterStart:exitStart]
	if strings.Contains(enterBody, "ctx->args[") {
		t.Error("clone3 must be KindProc: enter handler must not capture any arg")
	}

	// The exit handler reports the raw pid/0/-1 status as UNCLASSIFIED.
	requireContains(t, output, exitSec)
	requireContains(t, output, "ev->ret = ctx->ret;")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
}

// TestGenerateWait4Handler locks in how wait4(2) is generated. Per the man
// page:
//
//	pid_t wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage)
//
// wait4 waits for a child process to change state and optionally retrieves its
// resource usage. NONE of the arguments is an fd or a filesystem path: args[0]
// (pid) is a process/group selector — a pid, NOT a file descriptor, so it must
// never be misclassified as one; args[1] (wstatus) is a userspace output pointer
// for the wait status; args[2] (options) is an int flag set; and args[3]
// (rusage) is a userspace output pointer to a struct rusage. The return value is
// a pid_t: the pid of the child whose state changed, 0 (WNOHANG, none ready), or
// -1 on error — never a byte count. ior therefore classifies wait4 as KindProc
// in FamilyProcess, identical to its siblings waitid/clone/fork/vfork.
// Consequently:
//   - The enter handler emits a struct null_event and must NOT capture any arg
//     as an fd/path/addr — neither the pid selector, the status/rusage pointers,
//     nor the options flags are traced I/O resources.
//   - The exit handler reports the raw pid/0/-1 status as UNCLASSIFIED; it is not
//     a byte count, so it must never be tagged READ/WRITE/TRANSFER.
//
// This guards against a misclassification to KindNull (which would still emit a
// null_event but break sibling/dimension consistency) or to any fd kind (which
// would wrongly treat the pid at args[0] as a file descriptor).
func TestGenerateWait4Handler(t *testing.T) {
	// Classification consistency with the waitid/clone/fork/vfork siblings. We
	// feed a generic pointer arg so the name-only table — not a field heuristic —
	// is what pins both wait* siblings to KindProc.
	for _, name := range []string{"sys_enter_wait4", "sys_enter_waitid"} {
		r := ClassifyFormat(&Format{
			Name: name,
			ExternalFields: []Field{
				{Type: "long", Name: "__syscall_nr"},
				{Type: "pid_t", Name: "upid"},
			},
		})
		if r.Kind != KindProc {
			t.Errorf("%s kind = %v, want KindProc", name, r.Kind)
		}
	}
	if got := ClassifySyscallFamily("sys_enter_wait4"); got != FamilyProcess {
		t.Errorf("wait4 family = %q, want %q", got, FamilyProcess)
	}
	if got := ClassifyRet("sys_exit_wait4"); got != Unclassified {
		t.Errorf("wait4 ret classification = %q, want %q (pid, not a byte count)", got, Unclassified)
	}

	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("wait4")))

	enterSec := `SEC("tracepoint/syscalls/sys_enter_wait4")`
	exitSec := `SEC("tracepoint/syscalls/sys_exit_wait4")`
	requireContains(t, output, enterSec)
	requireContains(t, output, "struct null_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_NULL_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_WAIT4;")

	// The KindProc enter handler must not wire any arg as an fd/path/addr — in
	// particular the pid at args[0] must never be treated as an fd. Scope to the
	// enter handler body (from the enter SEC up to the exit SEC).
	enterStart := strings.Index(output, enterSec)
	exitStart := strings.Index(output, exitSec)
	if enterStart < 0 || exitStart < 0 || exitStart <= enterStart {
		t.Fatalf("wait4: handlers not found in expected order")
	}
	enterBody := output[enterStart:exitStart]
	if strings.Contains(enterBody, "ctx->args[") {
		t.Error("wait4 must be KindProc: enter handler must not capture any arg (pid at args[0] is not an fd)")
	}

	// The exit handler reports the raw pid/0/-1 status as UNCLASSIFIED.
	requireContains(t, output, exitSec)
	requireContains(t, output, "ev->ret = ctx->ret;")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
}

// TestGenerateSigaltstackHandler locks in how sigaltstack(2) is generated. Per
// the man page:
//
//	int sigaltstack(const stack_t *ss, stack_t *old_ss)
//
// It sets and/or gets the calling thread's alternate signal stack and returns 0
// on success or -1 on error. Neither argument is an fd or a path: args[0] is a
// userspace input pointer to a stack_t describing a new alternate stack and
// args[1] is a userspace output pointer that receives the previously installed
// stack. Both are signal-handling control structures, not I/O resources, so ior
// classifies sigaltstack as KindNull in FamilySignals, alongside the rest of the
// signal group (rt_sig*/kill/pause/tkill/tgkill). Consequently:
//   - The enter handler emits a struct null_event and must NOT capture args[0] or
//     args[1] as an fd/path/addr — the stack_t pointers are not traced I/O.
//   - The exit handler reports the raw int status as UNCLASSIFIED; the 0/-1
//     return is not a byte count, so it must never be tagged READ/WRITE/TRANSFER.
func TestGenerateSigaltstackHandler(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("sigaltstack")))

	enterSec := `SEC("tracepoint/syscalls/sys_enter_sigaltstack")`
	exitSec := `SEC("tracepoint/syscalls/sys_exit_sigaltstack")`
	requireContains(t, output, enterSec)
	requireContains(t, output, "struct null_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_NULL_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_SIGALTSTACK;")

	// The KindNull enter handler must not wire the new-stack pointer (args[0]) or
	// the old-stack output pointer (args[1]) as an fd/path/addr — neither is a
	// traced I/O resource. Scope to the enter handler body (everything from the
	// enter SEC up to the exit SEC) so we only check what the enter handler emits.
	enterStart := strings.Index(output, enterSec)
	exitStart := strings.Index(output, exitSec)
	if enterStart < 0 || exitStart < 0 || exitStart <= enterStart {
		t.Fatalf("sigaltstack: handlers not found in expected order")
	}
	enterBody := output[enterStart:exitStart]
	if strings.Contains(enterBody, "ctx->args[") {
		t.Error("sigaltstack must be KindNull: enter handler must not capture any arg")
	}

	// The exit handler reports the raw 0/-1 status as UNCLASSIFIED, not a byte count.
	requireContains(t, output, exitSec)
	requireContains(t, output, "ev->ret = ctx->ret;")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
}

// TestClassifyRetSigaltstackUnclassified locks in that sigaltstack's return value
// is UNCLASSIFIED. It returns 0 on success or -1 on error — a status code, not a
// number of bytes transferred — so classifying it as READ/WRITE/TRANSFER would
// wrongly count it as data movement.
func TestClassifyRetSigaltstackUnclassified(t *testing.T) {
	if got := ClassifyRet("sys_exit_sigaltstack"); got != Unclassified {
		t.Errorf("sigaltstack ret classification = %q, want %q", got, Unclassified)
	}
}

// TestGenerateTkillHandler locks in how tkill(2) is generated. Per the man page:
//
//	int tkill(pid_t tid, int sig)
//
// tkill sends signal sig to the thread whose thread id is tid; it is the
// obsolete predecessor of tgkill(tgid, tid, sig) (the kernel recommends tgkill
// because a bare tid can be recycled). It returns 0 on success or -1 on error.
// Neither argument is an fd or a path: args[0] is a thread id (a signal target,
// NOT a file descriptor) and args[1] is the signal number. tkill is not listed
// in the name-only kind table; it carries fields named "pid"/"sig" that match no
// fd/path/name pattern, so ClassifyFormat returns KindNone and the generation
// fallback (classifyEnterForGeneration) promotes it to KindNull. This test guards
// that path: tkill must emit a struct null_event and the args[0] tid must never be
// captured as an fd. Consequently:
//   - The enter handler emits a struct null_event and must NOT capture any arg —
//     in particular the tid must not be mistaken for an fd.
//   - The exit handler reports the raw int status as UNCLASSIFIED; the 0/-1
//     return is not a byte count, so it must never be tagged READ/WRITE/TRANSFER.
func TestGenerateTkillHandler(t *testing.T) {
	// syntheticPair derives the fixture from FormatKill, whose fields
	// (pid_t pid; int sig) match the real sys_enter_tkill tracepoint layout
	// exactly, so this exercises tkill's true argument shape.
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("tkill")))

	enterSec := `SEC("tracepoint/syscalls/sys_enter_tkill")`
	exitSec := `SEC("tracepoint/syscalls/sys_exit_tkill")`
	requireContains(t, output, enterSec)
	requireContains(t, output, "struct null_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_NULL_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_TKILL;")

	// The KindNull enter handler must not wire the tid (args[0]) or sig (args[1])
	// as an fd/path/addr — the tid is a signal target, not a traced I/O resource.
	// Scope to the enter handler body (from the enter SEC up to the exit SEC).
	enterStart := strings.Index(output, enterSec)
	exitStart := strings.Index(output, exitSec)
	if enterStart < 0 || exitStart < 0 || exitStart <= enterStart {
		t.Fatalf("tkill: handlers not found in expected order")
	}
	enterBody := output[enterStart:exitStart]
	if strings.Contains(enterBody, "ctx->args[") {
		t.Error("tkill must be KindNull: enter handler must not capture any arg (tid is not an fd)")
	}

	// The exit handler reports the raw 0/-1 status as UNCLASSIFIED, not a byte count.
	requireContains(t, output, exitSec)
	requireContains(t, output, "ev->ret = ctx->ret;")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
}

// TestClassifyTkillFallsThroughToNull pins the classifier behaviour that makes
// tkill safe: ClassifyFormat itself returns KindNone (no field matches an
// fd/path/name pattern — crucially the pid_t tid field is NOT treated as an fd),
// and only the generation-time fallback turns that into KindNull. If a future
// change made the tid match the fd rule, this test would flip to KindFd and fail.
func TestClassifyTkillFallsThroughToNull(t *testing.T) {
	f := mustParseOne(t, strings.Replace(
		strings.Replace(FormatKill, "sys_enter_kill", "sys_enter_tkill", 1),
		"ID: 183", "ID: 177", 1))
	if r := ClassifyFormat(&f); r.Kind != KindNone {
		t.Errorf("tkill ClassifyFormat = %d, want KindNone (tid must not match the fd rule)", r.Kind)
	}
	if r := classifyEnterForGeneration(&f); r.Kind != KindNull {
		t.Errorf("tkill classifyEnterForGeneration = %d, want KindNull", r.Kind)
	}
}

// TestClassifyRetTkillUnclassified locks in that tkill's return value is
// UNCLASSIFIED. It returns 0 on success or -1 on error — a status code, not a
// number of bytes transferred — so classifying it as READ/WRITE/TRANSFER would
// wrongly count it as data movement.
func TestClassifyRetTkillUnclassified(t *testing.T) {
	if got := ClassifyRet("sys_exit_tkill"); got != Unclassified {
		t.Errorf("tkill ret classification = %q, want %q", got, Unclassified)
	}
}

// TestGenerateSysinfoHandler locks in how sysinfo(2) is generated. Per the man
// page:
//
//	int sysinfo(struct sysinfo *info)
//
// It returns overall system statistics (memory/swap usage and load averages)
// into the single userspace *info output buffer and returns 0 on success or -1
// on error. The lone argument is NOT an fd or a path: it is a userspace output
// pointer to a struct sysinfo (a statistics buffer, not an I/O resource). ior
// therefore classifies sysinfo as KindNull in FamilyMisc, alongside its
// system-introspection siblings newuname/sysfs/ustat. Consequently:
//   - The enter handler emits a struct null_event and must NOT capture args[0]
//     as an fd/path/addr — the info pointer is not a traced I/O resource.
//   - The exit handler reports the raw int status as UNCLASSIFIED; the 0/-1
//     return is not a byte count, so it must never be tagged READ/WRITE/TRANSFER.
func TestGenerateSysinfoHandler(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("sysinfo")))

	enterSec := `SEC("tracepoint/syscalls/sys_enter_sysinfo")`
	exitSec := `SEC("tracepoint/syscalls/sys_exit_sysinfo")`
	requireContains(t, output, enterSec)
	requireContains(t, output, "struct null_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_NULL_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_SYSINFO;")

	// The KindNull enter handler must not wire the info pointer (args[0]) as an
	// fd/path/addr — it is not a traced I/O resource. Scope to the enter handler
	// body (everything from the enter SEC up to the exit SEC) so we only check
	// what the enter handler emits.
	enterStart := strings.Index(output, enterSec)
	exitStart := strings.Index(output, exitSec)
	if enterStart < 0 || exitStart < 0 || exitStart <= enterStart {
		t.Fatalf("sysinfo: handlers not found in expected order")
	}
	enterBody := output[enterStart:exitStart]
	if strings.Contains(enterBody, "ctx->args[") {
		t.Error("sysinfo must be KindNull: enter handler must not capture any arg")
	}

	// The exit handler reports the raw 0/-1 status as UNCLASSIFIED, not a byte count.
	requireContains(t, output, exitSec)
	requireContains(t, output, "ev->ret = ctx->ret;")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
}

// TestClassifyRetSysinfoUnclassified locks in that sysinfo's return value is
// UNCLASSIFIED. sysinfo(2) returns 0 on success or -1 on error — a status code,
// not a number of bytes transferred — so classifying it as READ/WRITE/TRANSFER
// would wrongly count it as data movement.
func TestClassifyRetSysinfoUnclassified(t *testing.T) {
	if got := ClassifyRet("sys_exit_sysinfo"); got != Unclassified {
		t.Errorf("sysinfo ret classification = %q, want %q", got, Unclassified)
	}
}

// TestClassifyRetRtSigpendingUnclassified locks in that rt_sigpending's return
// value is UNCLASSIFIED. It returns 0 on success or -1 on error — a status code,
// not a number of bytes transferred — so classifying it as READ/WRITE/TRANSFER
// would wrongly count it as data movement.
func TestClassifyRetRtSigpendingUnclassified(t *testing.T) {
	if got := ClassifyRet("sys_exit_rt_sigpending"); got != Unclassified {
		t.Errorf("rt_sigpending ret classification = %q, want %q", got, Unclassified)
	}
}

func TestGenerateLandlockAddRuleHandlerUsesFirstArgumentAsFd(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("landlock_add_rule")))

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_landlock_add_rule")`)
	requireContains(t, output, "struct fd_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_FD_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_LANDLOCK_ADD_RULE;")
	requireContains(t, output, "ev->fd = (__s32)ctx->args[0];")
}

func TestGenerateOpenHandler(t *testing.T) {
	output := generateFromPair(t, FormatOpenat, FormatExitOpenat)

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_openat")`)
	requireContains(t, output, "struct open_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_OPEN_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_OPENAT;")
	requireContains(t, output, "__builtin_memset(&(ev->filename), 0, sizeof(ev->filename) + sizeof(ev->comm));")
	requireContains(t, output, "bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)ctx->args[1]);")
	requireContains(t, output, "bpf_get_current_comm(&ev->comm, sizeof(ev->comm));")
	requireContains(t, output, "ev->flags = ctx->args[2];")
}

func TestGenerateOpenHandlerDirect(t *testing.T) {
	output := generateFromPair(t, FormatOpen, FormatExitOpen)

	requireContains(t, output, "bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)ctx->args[0]);")
	requireContains(t, output, "ev->flags = ctx->args[1];")
}

func TestGenerateMqOpenHandler(t *testing.T) {
	output := GenerateTracepointsC(mqFormats("mq_open", 9300))

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_mq_open")`)
	requireContains(t, output, "struct open_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_OPEN_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_MQ_OPEN;")
	requireContains(t, output, "bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)ctx->args[0]);")
	requireContains(t, output, "ev->flags = ctx->args[1];")
}

// TestGenerateMkdiratHandlerCapturesPathFromArgs1 locks in that mkdirat(2) is a
// KindPathname event whose path is read from args[1]. mkdirat(dirfd, pathname,
// mode) places the dirfd at args[0] and the real filesystem path at args[1];
// reading args[0] would capture the dir fd (often AT_FDCWD) instead of the path.
// The arg index is data-driven from the kernel format (FieldNumber of the
// "pathname" field), so this guards against a regression in that derivation.
func TestGenerateMkdiratHandlerCapturesPathFromArgs1(t *testing.T) {
	output := generateFromPair(t, FormatMkdirat, FormatExitMkdirat)

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_mkdirat")`)
	requireContains(t, output, "struct path_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_PATH_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_MKDIRAT;")
	requireContains(t, output, "bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), (void*)ctx->args[1]);")
	// Negative guard: the path must NOT be read from args[0] (the dirfd).
	requireNotContains(t, output, "bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), (void*)ctx->args[0]);")
	// Return value is a 0/-1 status code, not a byte count: UNCLASSIFIED.
	requireContains(t, output, "ev->trace_id = SYS_EXIT_MKDIRAT;")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
}

// TestGenerateMkdirHandlerCapturesPathFromArgs0 locks in that the sibling
// mkdir(2) — which has no dirfd — reads its pathname from args[0]. Contrasting
// it with mkdirat above ensures the two never collapse onto a shared arg index.
func TestGenerateMkdirHandlerCapturesPathFromArgs0(t *testing.T) {
	output := generateFromPair(t, FormatMkdir, FormatExitMkdir)

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_mkdir")`)
	requireContains(t, output, "struct path_event *ev")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_MKDIR;")
	requireContains(t, output, "bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), (void*)ctx->args[0]);")
	requireContains(t, output, "ev->trace_id = SYS_EXIT_MKDIR;")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
}

// TestMkdiratFamilyAndKindMatchSiblings locks in that mkdirat and its siblings
// mkdir/mknodat share the same FS family and pathname kind classification. A
// drift here (e.g. mkdirat slipping into Misc) would split related directory/
// node-creation syscalls across families in the dashboard.
func TestMkdiratFamilyAndKindMatchSiblings(t *testing.T) {
	for _, syscall := range []string{"mkdirat", "mkdir", "mknodat"} {
		if got := ClassifySyscallFamily("sys_enter_" + syscall); got != FamilyFS {
			t.Errorf("%s family = %q, want %q", syscall, got, FamilyFS)
		}
	}

	mkdirat := mustParseOne(t, FormatMkdirat)
	if r := ClassifyFormat(&mkdirat); r.Kind != KindPathname || r.PathnameField != "pathname" {
		t.Errorf("mkdirat classified as kind=%d field=%q, want KindPathname/pathname", r.Kind, r.PathnameField)
	}
	if n := mkdirat.FieldNumber("pathname"); n != 1 {
		t.Errorf("mkdirat FieldNumber(pathname) = %d, want 1", n)
	}

	mkdir := mustParseOne(t, FormatMkdir)
	if n := mkdir.FieldNumber("pathname"); n != 0 {
		t.Errorf("mkdir FieldNumber(pathname) = %d, want 0", n)
	}
}

func TestGenerateExecHandler(t *testing.T) {
	output := generateFromPair(t, FormatExecveat, FormatExitExecveat)

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_execveat")`)
	requireContains(t, output, "struct exec_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_EXEC_EVENT;")
	requireContains(t, output, "bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)ctx->args[1]);")
	requireContains(t, output, "ev->dirfd = (__s32)ctx->args[0];")
	requireContains(t, output, "ev->flags = (__s32)ctx->args[4];")
}

func TestGenerateExecHandlerDirfdFallbackForExecveat(t *testing.T) {
	enter := strings.ReplaceAll(FormatExecveat, "dfd", "fd")
	output := generateFromPair(t, enter, FormatExitExecveat)

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_execveat")`)
	requireContains(t, output, "ev->dirfd = (__s32)ctx->args[0];")
	if strings.Contains(output, "ev->dirfd = -1;") {
		t.Fatal("execveat handler unexpectedly falls back to ev->dirfd = -1")
	}
}

func TestGenerateOpenat2Handler(t *testing.T) {
	f := mustParseOne(t, FormatOpenat2)
	r := ClassifyFormat(&f)
	if r.Kind != KindOpen {
		t.Fatalf("openat2 classified as %d, want KindOpen", r.Kind)
	}
	// openat2 has filename at args[1] but flags field name = "how" (not "flags"),
	// so FieldNumber("flags") returns -1
	if n := f.FieldNumber("flags"); n != -1 {
		t.Errorf("openat2 FieldNumber(flags) = %d, want -1", n)
	}
}

func TestGenerateRetHandlerRead(t *testing.T) {
	output := generateFromPair(t, FormatRead, FormatExitRead)

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_exit_read")`)
	requireContains(t, output, "struct syscall_trace_exit *ctx")
	requireContains(t, output, "struct ret_event *ev")
	requireContains(t, output, "ev->event_type = EXIT_RET_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_EXIT_READ;")
	requireContains(t, output, "ev->ret = ctx->ret;")
	requireContains(t, output, "ev->ret_type = READ_CLASSIFIED;")
}

func TestGenerateRetHandlerWrite(t *testing.T) {
	output := generateFromPair(t, FormatWrite, FormatExitWrite)

	requireContains(t, output, "ev->ret_type = WRITE_CLASSIFIED;")
	requireContains(t, output, "ev->trace_id = SYS_EXIT_WRITE;")
}

func TestGenerateRetHandlerOpenat(t *testing.T) {
	output := generateFromPair(t, FormatOpenat, FormatExitOpenat)

	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
	requireContains(t, output, "ev->trace_id = SYS_EXIT_OPENAT;")
}

func TestGenerateNameHandler(t *testing.T) {
	output := generateFromPair(t, FormatRename, FormatExitRename)

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_rename")`)
	requireContains(t, output, "struct name_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_NAME_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_RENAME;")
	requireContains(t, output, "__builtin_memset(&(ev->oldname), 0, sizeof(ev->oldname) + sizeof(ev->newname));")
	requireContains(t, output, "bpf_probe_read_user_str(ev->oldname, sizeof(ev->oldname), (void*)ctx->args[0]);")
	requireContains(t, output, "bpf_probe_read_user_str(ev->newname, sizeof(ev->newname), (void*)ctx->args[1]);")
}

func TestGeneratePathnameHandler(t *testing.T) {
	// Use exit_unlink (same structure as exit_read) paired with enter_unlink
	exitUnlink := strings.Replace(FormatExitRead, "sys_exit_read", "sys_exit_unlink", 1)
	exitUnlink = strings.Replace(exitUnlink, "ID: 843", "ID: 883", 1)
	output := generateFromPair(t, FormatUnlink, exitUnlink)

	requireContains(t, output, "struct path_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_PATH_EVENT;")
	requireContains(t, output, "__builtin_memset(&(ev->pathname), 0, sizeof(ev->pathname));")
	requireContains(t, output, "bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), (void*)ctx->args[0]);")
}

// TestGenerateAccessFaccessatHandlers locks in the generated BPF C for
// access(2) and its dirfd-relative sibling faccessat(2). Both capture a real
// path into a path_event's pathname member, but from DIFFERENT argument slots:
// access(2) has no dirfd so its path is at args[0], whereas faccessat(2) takes
// dfd at args[0] and the path at args[1]. This guards against a regression that
// would read the wrong arg (e.g. capturing faccessat's dirfd as a path, or
// dropping access's path entirely). The exit side is a ret_event (int 0/-1,
// UNCLASSIFIED) — verified via the shared ret_event handler shape.
func TestGenerateAccessFaccessatHandlers(t *testing.T) {
	exitAccess := strings.Replace(FormatExitRead, "sys_exit_read", "sys_exit_access", 1)
	exitAccess = strings.Replace(exitAccess, "ID: 843", "ID: 816", 1)
	accessOut := generateFromPair(t, FormatAccess, exitAccess)
	requireContains(t, accessOut, `SEC("tracepoint/syscalls/sys_enter_access")`)
	requireContains(t, accessOut, "struct path_event *ev")
	requireContains(t, accessOut, "ev->event_type = ENTER_PATH_EVENT;")
	requireContains(t, accessOut, "ev->trace_id = SYS_ENTER_ACCESS;")
	// access(2): path (filename) is at args[0] — no dirfd precedes it.
	requireContains(t, accessOut, "bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), (void*)ctx->args[0]);")

	exitFaccessat := strings.Replace(FormatExitRead, "sys_exit_read", "sys_exit_faccessat", 1)
	exitFaccessat = strings.Replace(exitFaccessat, "ID: 843", "ID: 820", 1)
	faccessatOut := generateFromPair(t, FormatFaccessat, exitFaccessat)
	requireContains(t, faccessatOut, `SEC("tracepoint/syscalls/sys_enter_faccessat")`)
	requireContains(t, faccessatOut, "struct path_event *ev")
	requireContains(t, faccessatOut, "ev->trace_id = SYS_ENTER_FACCESSAT;")
	// faccessat(2): dfd is at args[0], so the path (filename) is at args[1].
	requireContains(t, faccessatOut, "bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), (void*)ctx->args[1]);")
}

// TestGenerateMknodMknodatHandlers locks in the generated BPF C for mknod(2)
// and its dirfd-relative sibling mknodat(2). Both create a filesystem node and
// capture a real path into a path_event's pathname member, but from DIFFERENT
// argument slots: mknod(2) has no dirfd so its path is at args[0], whereas
// mknodat(2) takes dfd at args[0] and the path at args[1]. This guards against
// a regression that would read the wrong arg (e.g. capturing mknodat's dirfd
// as a path, or dropping mknod's path entirely). The exit side is a ret_event
// (int 0/-1, UNCLASSIFIED) — verified via the shared ret_event handler shape.
func TestGenerateMknodMknodatHandlers(t *testing.T) {
	exitMknod := strings.Replace(FormatExitRead, "sys_exit_read", "sys_exit_mknod", 1)
	exitMknod = strings.Replace(exitMknod, "ID: 843", "ID: 893", 1)
	mknodOut := generateFromPair(t, FormatMknod, exitMknod)
	requireContains(t, mknodOut, `SEC("tracepoint/syscalls/sys_enter_mknod")`)
	requireContains(t, mknodOut, "struct path_event *ev")
	requireContains(t, mknodOut, "ev->event_type = ENTER_PATH_EVENT;")
	requireContains(t, mknodOut, "ev->trace_id = SYS_ENTER_MKNOD;")
	// mknod(2): path (filename) is at args[0] — no dirfd precedes it.
	requireContains(t, mknodOut, "bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), (void*)ctx->args[0]);")

	exitMknodat := strings.Replace(FormatExitRead, "sys_exit_read", "sys_exit_mknodat", 1)
	exitMknodat = strings.Replace(exitMknodat, "ID: 843", "ID: 895", 1)
	mknodatOut := generateFromPair(t, FormatMknodat, exitMknodat)
	requireContains(t, mknodatOut, `SEC("tracepoint/syscalls/sys_enter_mknodat")`)
	requireContains(t, mknodatOut, "struct path_event *ev")
	requireContains(t, mknodatOut, "ev->trace_id = SYS_ENTER_MKNODAT;")
	// mknodat(2): dfd is at args[0], so the path (filename) is at args[1].
	requireContains(t, mknodatOut, "bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), (void*)ctx->args[1]);")
}

func TestGenerateFcntlHandler(t *testing.T) {
	output := generateFromPair(t, FormatFcntl, FormatExitFcntl)

	requireContains(t, output, "struct fcntl_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_FCNTL_EVENT;")
	requireContains(t, output, "ev->fd = ctx->args[0];")
	requireContains(t, output, "ev->cmd = ctx->args[1];")
	requireContains(t, output, "ev->arg = ctx->args[2];")
}

func TestGenerateNullHandler(t *testing.T) {
	output := generateFromPair(t, FormatSync, FormatExitSync)

	requireContains(t, output, "struct null_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_NULL_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_SYNC;")
	// Null handler should NOT have ev->fd, ev->filename, etc.
	if strings.Contains(output, "ev->fd") {
		t.Error("null handler should not have ev->fd")
	}
}

// TestGenerateSyncHandler locks in how the bare sync(2) syscall is generated.
// Per sync(2): `void sync(void)` — it flushes all filesystem buffers to disk,
// takes NO arguments and returns NO value. This makes it distinct from its
// filesystem-sync siblings, which all take a leading fd and return int:
//   - int syncfs(int fd)
//   - int fsync(int fd)
//   - int fdatasync(int fd)
//   - int sync_file_range(int fd, off64_t off, off64_t n, unsigned flags)
//
// Because sync has no arguments, ior classifies it as KindNull in FamilyFS, so:
//   - The enter handler emits a struct null_event and, since there are no args
//     at all, must NOT reference ctx->args[...] anywhere in its body.
//   - Crucially, although sync returns void, the syscall still *completes* and
//     the kernel sys_exit_sync tracepoint fires with a (meaningless) ret field.
//     Unlike the noreturn exit(2)/exit_group(2) syscalls, sync DOES return, so
//     the generator must emit a live exit handler — it must NOT be suppressed.
//   - The void return is recorded generically via EXIT_RET_EVENT and classified
//     UNCLASSIFIED: it is not a byte count and must never be tagged
//     READ/WRITE/TRANSFER.
func TestGenerateSyncHandler(t *testing.T) {
	output := generateFromPair(t, FormatSync, FormatExitSync)

	enterSec := `SEC("tracepoint/syscalls/sys_enter_sync")`
	exitSec := `SEC("tracepoint/syscalls/sys_exit_sync")`

	// Enter: null_event, no argument capture (sync takes no arguments).
	requireContains(t, output, enterSec)
	requireContains(t, output, "struct null_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_NULL_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_SYNC;")

	enterStart := strings.Index(output, enterSec)
	exitStart := strings.Index(output, exitSec)
	if enterStart < 0 || exitStart < 0 || exitStart <= enterStart {
		t.Fatalf("sync: enter/exit handlers not found in expected order")
	}
	enterBody := output[enterStart:exitStart]
	if strings.Contains(enterBody, "ctx->args[") {
		t.Error("sync must be KindNull and takes no args: enter handler must not capture any arg")
	}

	// Exit: sync is void but DOES return, so unlike exit/exit_group the exit
	// handler must be emitted and report the meaningless ret as UNCLASSIFIED.
	requireContains(t, output, exitSec)
	requireContains(t, output, "ev->ret = ctx->ret;")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
}

// TestClassifyRetSyncUnclassified locks in that the bare sync(2) return value is
// UNCLASSIFIED. sync returns void; the sys_exit_sync tracepoint still carries a
// ret field, but it is meaningless and certainly not a byte count, so it must
// stay UNCLASSIFIED — never READ/WRITE/TRANSFER.
func TestClassifyRetSyncUnclassified(t *testing.T) {
	if got := ClassifyRet("sys_exit_sync"); got != Unclassified {
		t.Errorf("sync ret classification = %q, want %q", got, Unclassified)
	}
}

// TestSyncIsNotNoreturn locks in that bare sync(2) is NOT treated as a noreturn
// syscall: it is void but returns control to userspace, so its exit handler must
// be generated (see TestGenerateSyncHandler). Only exit(2)/exit_group(2) are
// noreturn. This guards against sync accidentally being added to the noreturn
// suppression list, which would silently drop its exit events.
func TestSyncIsNotNoreturn(t *testing.T) {
	if isNoreturnSyscall("sync") {
		t.Error("sync must not be noreturn: it is void but DOES return, so its exit handler must be emitted")
	}
}

func TestGenerateIoUringEnterHandler(t *testing.T) {
	output := generateFromPair(t, FormatIoUringEnter, FormatExitIoUringEnter)

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_io_uring_enter")`)
	requireContains(t, output, "struct fd_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_FD_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_IO_URING_ENTER;")
	requireContains(t, output, "ev->fd = (__s32)ctx->args[0];")
}

func TestGenerateIoUringRegisterHandler(t *testing.T) {
	output := generateFromPair(t, FormatIoUringRegister, FormatExitIoUringRegister)

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_io_uring_register")`)
	requireContains(t, output, "struct fd_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_FD_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_IO_URING_REGISTER;")
	requireContains(t, output, "ev->fd = (__s32)ctx->args[0];")
}

func TestGenerateMmapHandlerUsesFdArgumentIndex(t *testing.T) {
	output := generateFromPair(t, FormatMmap, FormatExitMmap)

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_mmap")`)
	requireContains(t, output, "struct fd_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_FD_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_MMAP;")
	requireContains(t, output, "ev->fd = (__s32)ctx->args[4];")
}

func TestGenerateMemHandler(t *testing.T) {
	output := generateFromPair(t, FormatMremap, FormatExitMremap)

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_mremap")`)
	requireContains(t, output, "struct mem_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_MEM_EVENT;")
	requireContains(t, output, "ev->addr = (__u64)ctx->args[0];")
	requireContains(t, output, "ev->length = (__u64)ctx->args[1];")
	requireContains(t, output, "ev->length2 = (__u64)ctx->args[2];")
	requireContains(t, output, "ev->flags = (__u64)ctx->args[3];")
}

func TestGenerateMemHandlerMlock2(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("mlock2")))

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_mlock2")`)
	requireContains(t, output, "struct mem_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_MEM_EVENT;")
	requireContains(t, output, "ev->addr = (__u64)ctx->args[0];")
	requireContains(t, output, "ev->length = (__u64)ctx->args[1];")
	requireContains(t, output, "ev->flags = (__u64)ctx->args[2];")
}

// TestGenerateMemHandlerMunlock locks in the BPF handler wiring for munlock(2):
// int munlock(const void addr[.size], size_t size). munlock unlocks the page
// range [addr, addr+size) so it may be paged out again — the converse of
// mlock(2). The range is args[0]/args[1] (addr/length). Crucially munlock has
// NO flags argument (unlike its sibling mlock2(2), which carries
// MLOCK_ONFAULT at args[2]) and no second length region, so both ev->flags and
// ev->length2 must stay zero. This guards against accidentally copying the
// mlock2 wiring and surfacing a nonexistent args[2] as flags. munlock must not
// be confused with munlockall(2), which takes no address range and is
// classified KindNull. munlock returns int 0 on success / -1 on error,
// captured generically via ev->ret as UNCLASSIFIED like every other KindMem
// exit (it is not a byte-count, so it is intentionally absent from
// retClassifications).
func TestGenerateMemHandlerMunlock(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("munlock")))

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_munlock")`)
	requireContains(t, output, "struct mem_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_MEM_EVENT;")
	requireContains(t, output, "ev->addr = (__u64)ctx->args[0];")
	requireContains(t, output, "ev->length = (__u64)ctx->args[1];")
	requireContains(t, output, "ev->length2 = 0;")
	requireContains(t, output, "ev->flags = 0;")
	// munlock has no flags argument; args[2] must never be wired into ev->flags
	// (that is the mlock2-only MLOCK_ONFAULT slot).
	if strings.Contains(output, "ev->flags = (__u64)ctx->args[2];") {
		t.Error("munlock handler must keep flags zero; munlock has no flags argument (that is mlock2's args[2])")
	}
	// munlock has no second length region.
	if strings.Contains(output, "ev->length2 = (__u64)ctx->args") {
		t.Error("munlock handler must keep length2 zero; it has no second length argument")
	}
	// addr (args[0]) must never be reused as flags.
	if strings.Contains(output, "ev->flags = (__u64)ctx->args[0];") {
		t.Error("munlock handler must keep flags zero; args[0] is the addr, not a flags value")
	}
	// The exit handler returns the int status generically (0 on success, -1 on
	// error), not via a byte-count classification.
	requireContains(t, output, `SEC("tracepoint/syscalls/sys_exit_munlock")`)
	requireContains(t, output, "ev->ret = ctx->ret;")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
}

// TestGenerateMemHandlerRemapFilePages locks in the BPF handler wiring for the
// (deprecated) remap_file_pages(2):
// int remap_file_pages(void *addr, size_t size, int prot, size_t pgoff, int flags).
// The mapping address range is args[0]/args[1] (addr/length). Crucially, the
// flags argument is at args[4], NOT args[2] — args[2] is `prot` (which the man
// page requires to be 0 and which carries no useful information). The pgoff
// argument (args[3]) is a file offset in pages and is parked in the generic
// length2 slot. The historical hazard here is wiring flags from args[2] (prot)
// the way flags-bearing siblings (madvise/mlock2/mseal/mprotect) legitimately
// do — doing so would surface the always-zero prot value as flags and drop the
// real MAP_NONBLOCK flag. remap_file_pages returns int 0 on success / -1 on
// error, captured generically via ev->ret as UNCLASSIFIED like every other
// KindMem exit (it is not a byte-count, so it is intentionally absent from
// retClassifications).
func TestGenerateMemHandlerRemapFilePages(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("remap_file_pages")))

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_remap_file_pages")`)
	requireContains(t, output, "struct mem_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_MEM_EVENT;")
	requireContains(t, output, "ev->addr = (__u64)ctx->args[0];")
	requireContains(t, output, "ev->length = (__u64)ctx->args[1];")
	// pgoff (args[3]) is parked in the generic length2 slot.
	requireContains(t, output, "ev->length2 = (__u64)ctx->args[3];")
	// flags is at args[4]; prot (args[2]) must never be wired into ev->flags.
	requireContains(t, output, "ev->flags = (__u64)ctx->args[4];")
	if strings.Contains(output, "ev->flags = (__u64)ctx->args[2];") {
		t.Error("remap_file_pages handler must read flags from args[4]; args[2] is prot (always 0), not a flags value")
	}
	// addr (args[0]) must never be reused as flags.
	if strings.Contains(output, "ev->flags = (__u64)ctx->args[0];") {
		t.Error("remap_file_pages handler must read flags from args[4]; args[0] is the addr, not a flags value")
	}
	// The exit handler returns the int status generically (0 on success, -1 on
	// error), not via a byte-count classification.
	requireContains(t, output, `SEC("tracepoint/syscalls/sys_exit_remap_file_pages")`)
	requireContains(t, output, "ev->ret = ctx->ret;")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
}

func TestGenerateMemHandlerMprotect(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("mprotect")))

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_mprotect")`)
	requireContains(t, output, "struct mem_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_MEM_EVENT;")
	requireContains(t, output, "ev->addr = (__u64)ctx->args[0];")
	requireContains(t, output, "ev->length = (__u64)ctx->args[1];")
	requireContains(t, output, "ev->length2 = 0;")
	requireContains(t, output, "ev->flags = (__u64)ctx->args[2];")
}

// TestGenerateMemHandlerMadvise locks in the BPF handler wiring for madvise(2):
// int madvise(void addr[.size], size_t size, int advice).
// The address range is args[0]/args[1] (addr/length) and the `advice` enum
// (MADV_DONTNEED, MADV_WILLNEED, ...) is flags-like, so it maps to ev->flags at
// args[2]. There is no second length, so length2 must stay zero. madvise returns
// int 0 on success / -1 on error, captured generically via ev->ret as
// UNCLASSIFIED like every other KindMem exit. This must NOT be confused with the
// sibling process_madvise(2), whose first arg is a pidfd and is classified KindFd
// (covered by TestGenerateProcessMadviseHandlerUsesFirstArgumentAsFd).
func TestGenerateMemHandlerMadvise(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("madvise")))

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_madvise")`)
	requireContains(t, output, "struct mem_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_MEM_EVENT;")
	requireContains(t, output, "ev->addr = (__u64)ctx->args[0];")
	requireContains(t, output, "ev->length = (__u64)ctx->args[1];")
	requireContains(t, output, "ev->length2 = 0;")
	requireContains(t, output, "ev->flags = (__u64)ctx->args[2];")
	// The advice enum lives at args[2]; addr (args[0]) must never be reused as flags.
	if strings.Contains(output, "ev->flags = (__u64)ctx->args[0];") {
		t.Error("madvise handler must use args[2] (advice) as flags, not args[0] (addr)")
	}
	// madvise has no second length region (unlike mremap/pkey_mprotect).
	if strings.Contains(output, "ev->length2 = (__u64)ctx->args") {
		t.Error("madvise handler must keep length2 zero; it has no second length argument")
	}
	// The exit handler returns the int status generically, not via a byte-count
	// classification.
	requireContains(t, output, `SEC("tracepoint/syscalls/sys_exit_madvise")`)
	requireContains(t, output, "ev->ret = ctx->ret;")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
}

// TestGenerateMemHandlerMincore locks in the BPF handler wiring for mincore(2):
// int mincore(void addr[.length], size_t length, unsigned char *vec).
// The queried address range is args[0]/args[1] (addr/length). args[2] is `vec`,
// a *userspace output pointer* where the kernel writes one byte per page telling
// whether that page is resident — it is NOT a flags value. mincore therefore has
// neither a flags argument nor a second length, so both ev->flags and ev->length2
// must stay zero. This guards against the historical mistake of blindly mapping
// args[2] onto ev->flags (as flags-bearing siblings like madvise/mlock2/mseal do);
// doing so here would surface a meaningless userspace pointer as a flags field.
// mincore returns int 0 on success / -1 on error, captured generically via
// ev->ret as UNCLASSIFIED like every other KindMem exit.
func TestGenerateMemHandlerMincore(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("mincore")))

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_mincore")`)
	requireContains(t, output, "struct mem_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_MEM_EVENT;")
	requireContains(t, output, "ev->addr = (__u64)ctx->args[0];")
	requireContains(t, output, "ev->length = (__u64)ctx->args[1];")
	requireContains(t, output, "ev->length2 = 0;")
	requireContains(t, output, "ev->flags = 0;")
	// args[2] is the userspace `vec` output pointer, not flags. It must never be
	// wired into ev->flags (nor ev->length2).
	if strings.Contains(output, "ev->flags = (__u64)ctx->args[2];") {
		t.Error("mincore handler must keep flags zero; args[2] is the vec output pointer, not a flags value")
	}
	if strings.Contains(output, "ev->length2 = (__u64)ctx->args") {
		t.Error("mincore handler must keep length2 zero; it has no second length argument")
	}
	// The exit handler returns the int status generically (0 on success, -1 on
	// error), not via a byte-count classification.
	requireContains(t, output, `SEC("tracepoint/syscalls/sys_exit_mincore")`)
	requireContains(t, output, "ev->ret = ctx->ret;")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
}

func TestGenerateMemHandlerPkeyMprotect(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("pkey_mprotect")))

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_pkey_mprotect")`)
	requireContains(t, output, "struct mem_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_MEM_EVENT;")
	requireContains(t, output, "ev->addr = (__u64)ctx->args[0];")
	requireContains(t, output, "ev->length = (__u64)ctx->args[1];")
	requireContains(t, output, "ev->length2 = (__u64)ctx->args[3];")
	requireContains(t, output, "ev->flags = (__u64)ctx->args[2];")
}

// TestGenerateMemHandlerMapShadowStack locks in the BPF handler wiring for the
// x86 CET map_shadow_stack syscall (Linux 6.6+):
// void *map_shadow_stack(unsigned long addr, unsigned long size, unsigned int flags).
// The hint addr and size are args[0]/args[1] and flags is args[2]; there is no
// second length, so length2 must stay zero. The return is a mapped address (or
// -errno), captured generically via ev->ret like every other KindMem exit.
func TestGenerateMemHandlerMapShadowStack(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("map_shadow_stack")))

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_map_shadow_stack")`)
	requireContains(t, output, "struct mem_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_MEM_EVENT;")
	requireContains(t, output, "ev->addr = (__u64)ctx->args[0];")
	requireContains(t, output, "ev->length = (__u64)ctx->args[1];")
	requireContains(t, output, "ev->length2 = 0;")
	requireContains(t, output, "ev->flags = (__u64)ctx->args[2];")
}

func TestGenerateMemHandlerBrk(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("brk")))

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_brk")`)
	requireContains(t, output, "struct mem_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_MEM_EVENT;")
	requireContains(t, output, "ev->addr = (__u64)ctx->args[0];")
	requireContains(t, output, "ev->length = 0;")
	requireContains(t, output, "ev->length2 = 0;")
	requireContains(t, output, "ev->flags = 0;")
}

func TestGenerateDup3Handler(t *testing.T) {
	output := generateFromPair(t, FormatDup3, FormatExitDup3)

	requireContains(t, output, "struct dup3_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_DUP3_EVENT;")
	requireContains(t, output, "ev->fd = (__s32)ctx->args[0];")
	requireContains(t, output, "ev->flags = (__s32)ctx->args[2];")
}

// TestGenerateDup2Handler locks in the generated BPF C for dup2(2):
//
//	int dup2(int oldfd, int newfd)
//
// dup2 duplicates oldfd onto newfd and returns the new descriptor (newfd) on
// success, or -1 on error. It is classified KindFd (a plain fd_event), so the
// enter handler must capture ev->fd from args[0] (oldfd) — the SAME convention
// as dup (args[0]=fildes) and dup3 (args[0]=oldfd). Unlike dup3, dup2 carries
// NO flags (it always clears FD_CLOEXEC on the duplicate), so the dup2 handler
// must emit a struct fd_event (not a dup3_event) and must NOT wire any flags or
// read args[1] (newfd) / args[2]. The exit returns the new fd number as a plain
// ret_event (UNCLASSIFIED), exactly like dup/dup3/open — never a byte-count
// transfer.
func TestGenerateDup2Handler(t *testing.T) {
	output := generateFromPair(t, FormatDup2, FormatExitDup2)

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_dup2")`)
	requireContains(t, output, "struct fd_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_FD_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_DUP2;")
	// fd must come from oldfd (args[0]), never newfd (args[1]).
	requireContains(t, output, "ev->fd = (__s32)ctx->args[0];")
	if strings.Contains(output, "ev->fd = (__s32)ctx->args[1];") {
		t.Error("dup2 must capture fd from args[0] (oldfd), not args[1] (newfd)")
	}
	// dup2 is a plain fd_event: it must not be promoted to a dup3_event and must
	// not capture any flags (it always clears FD_CLOEXEC on the duplicate).
	if strings.Contains(output, "struct dup3_event *ev") &&
		strings.Contains(output, `SEC("tracepoint/syscalls/sys_enter_dup2")`) {
		t.Error("dup2 must be KindFd (fd_event), not KindDup3 (dup3_event)")
	}
	if strings.Contains(output, "ev->flags") &&
		strings.Contains(output, `int handle_sys_enter_dup2`) {
		t.Error("dup2 handler must not capture any flags (dup2 has no flags arg)")
	}
	// The exit handler returns the new fd number generically as the raw status,
	// classified UNCLASSIFIED — not a read/write/transfer byte count.
	requireContains(t, output, `SEC("tracepoint/syscalls/sys_exit_dup2")`)
	requireContains(t, output, "struct ret_event *ev")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
}

func TestGenerateOpenByHandleAtHandler(t *testing.T) {
	output := generateFromPair(t, FormatOpenByHandleAt, FormatExitOpenByHandleAt)

	requireContains(t, output, "struct open_by_handle_at_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_OPEN_BY_HANDLE_AT_EVENT;")
	requireContains(t, output, "ev->flags = (__s32)ctx->args[2];")
}

func TestGenerateSocketHandler(t *testing.T) {
	output := generateFromPair(t, FormatSocket, FormatExitSocket)

	requireContains(t, output, "struct socket_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_SOCKET_EVENT;")
	requireContains(t, output, "ev->family = (__s32)ctx->args[0];")
	requireContains(t, output, "ev->type = (__s32)ctx->args[1];")
	requireContains(t, output, "ev->protocol = (__s32)ctx->args[2];")
}

func TestGenerateSocketpairHandler(t *testing.T) {
	output := generateFromPair(t, FormatSocketpair, FormatExitSocketpair)

	requireContains(t, output, "struct socketpair_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_SOCKETPAIR_EVENT;")
	requireContains(t, output, "struct socketpair_ctx pending;")
	requireContains(t, output, "bpf_map_update_elem(&socketpair_ctx_map, &tid, &pending, BPF_ANY);")
	requireContains(t, output, "ev->sv0 = -1;")
	requireContains(t, output, "ev->ret = 0;")
	requireContains(t, output, "SEC(\"tracepoint/syscalls/sys_exit_socketpair\")")
	requireContains(t, output, "ev->event_type = EXIT_SOCKETPAIR_EVENT;")
	requireContains(t, output, "struct socketpair_ctx *pending = bpf_map_lookup_elem(&socketpair_ctx_map, &tid);")
	requireContains(t, output, "if (ctx->ret == 0 && pending->usockvec != 0) {")
	requireContains(t, output, "ev->ret = ctx->ret;")
	requireContains(t, output, "ev->family = pending.family;")
}

func TestGenerateAcceptHandler(t *testing.T) {
	output := generateFromPair(t, FormatAccept, FormatExitAccept)

	requireContains(t, output, "struct accept_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_ACCEPT_EVENT;")
	requireContains(t, output, "ev->fd = (__s32)ctx->args[0];")
	requireContains(t, output, "ev->ret = -1;")
	requireContains(t, output, "SEC(\"tracepoint/syscalls/sys_exit_accept\")")
	requireContains(t, output, "ev->event_type = EXIT_ACCEPT_EVENT;")
	requireContains(t, output, "ev->fd = -1;")
	requireContains(t, output, "ev->ret = ctx->ret;")
}

func TestGeneratePipeHandler(t *testing.T) {
	output := generateFromPair(t, FormatPipe2, FormatExitPipe2)

	requireContains(t, output, "struct pipe_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_PIPE_EVENT;")
	requireContains(t, output, "struct pipe_ctx pending;")
	requireContains(t, output, "pending.upipefd = ctx->args[0];")
	requireContains(t, output, "pending.flags = (__s32)ctx->args[1];")
	requireContains(t, output, "bpf_map_update_elem(&pipe_ctx_map, &tid, &pending, BPF_ANY);")
	requireContains(t, output, "ev->fd0 = -1;")
	requireContains(t, output, "ev->fd1 = -1;")
	requireContains(t, output, "SEC(\"tracepoint/syscalls/sys_exit_pipe2\")")
	requireContains(t, output, "ev->event_type = EXIT_PIPE_EVENT;")
	requireContains(t, output, "struct pipe_ctx *pending = bpf_map_lookup_elem(&pipe_ctx_map, &tid);")
	requireContains(t, output, "ev->ret = ctx->ret;")
}

func TestGenerateEventfdHandler(t *testing.T) {
	output := generateFromPair(t, FormatEventfd2, FormatExitEventfd2)

	requireContains(t, output, "struct eventfd_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_EVENTFD_EVENT;")
	requireContains(t, output, "bpf_map_update_elem(&eventfd_flags_map, &tid, &flags, BPF_ANY);")
	requireContains(t, output, "ev->flags = flags;")
	requireContains(t, output, "ev->ret = -1;")
	requireContains(t, output, "SEC(\"tracepoint/syscalls/sys_exit_eventfd2\")")
	requireContains(t, output, "ev->event_type = EXIT_EVENTFD_EVENT;")
	requireContains(t, output, "ev->ret = ctx->ret;")
}

func TestGenerateEpollCreateHandlerUsesZeroFlags(t *testing.T) {
	output := generateFromPair(t, FormatEpollCreate, FormatExitEpollCreate)

	requireContains(t, output, "struct eventfd_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_EVENTFD_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_EPOLL_CREATE;")
	// epoll_create(size) has no flags argument; the generated code must
	// hardcode flags to 0 instead of reading ctx->args[0] (which is size).
	requireContains(t, output, "__s32 flags = 0;")
	if strings.Contains(output, "flags = (__s32)ctx->args[0]") {
		t.Error("epoll_create handler must not use ctx->args[0] (size) as flags")
	}
	requireContains(t, output, "ev->ret = -1;")
	requireContains(t, output, "SEC(\"tracepoint/syscalls/sys_exit_epoll_create\")")
	requireContains(t, output, "ev->event_type = EXIT_EVENTFD_EVENT;")
	requireContains(t, output, "ev->ret = ctx->ret;")
}

func TestGenerateEpollCreate1HandlerUsesArg0Flags(t *testing.T) {
	output := generateFromPair(t, FormatEpollCreate1, FormatExitEpollCreate1)

	requireContains(t, output, "struct eventfd_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_EVENTFD_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_EPOLL_CREATE1;")
	// epoll_create1(flags) carries its flags (e.g. EPOLL_CLOEXEC) in args[0];
	// the generated enter handler must capture it rather than hardcoding 0.
	requireContains(t, output, "__s32 flags = (__s32)ctx->args[0];")
	if strings.Contains(output, "__s32 flags = 0;\n    bpf_map_update_elem") {
		t.Error("epoll_create1 enter handler must read ctx->args[0] as flags, not 0")
	}
	requireContains(t, output, "ev->ret = -1;")
	requireContains(t, output, "SEC(\"tracepoint/syscalls/sys_exit_epoll_create1\")")
	requireContains(t, output, "ev->event_type = EXIT_EVENTFD_EVENT;")
	requireContains(t, output, "ev->ret = ctx->ret;")
}

func TestGeneratePidfdOpenHandlerUsesArg1Flags(t *testing.T) {
	output := generateFromPair(t, FormatPidfdOpen, FormatExitPidfdOpen)

	requireContains(t, output, "struct eventfd_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_EVENTFD_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_PIDFD_OPEN;")
	// pidfd_open(pid, flags): flags is at args[1], not args[0] (which is pid).
	requireContains(t, output, "__s32 flags = (__s32)ctx->args[1];")
	if strings.Contains(output, "flags = (__s32)ctx->args[0]") {
		t.Error("pidfd_open handler must not use ctx->args[0] (pid) as flags")
	}
	requireContains(t, output, "ev->ret = -1;")
	requireContains(t, output, "SEC(\"tracepoint/syscalls/sys_exit_pidfd_open\")")
	requireContains(t, output, "ev->event_type = EXIT_EVENTFD_EVENT;")
	requireContains(t, output, "ev->ret = ctx->ret;")
}

// TestGenerateSignalfd4HandlerUsesArg3Flags locks in that signalfd4(2) is
// emitted as a KindEventfd handler whose flags are read from args[3]. The raw
// syscall is signalfd4(int ufd, const sigset_t *mask, size_t sizemask, int
// flags): args[0] (ufd) is an existing signalfd or -1, args[1]/args[2] are the
// mask pointer and its size — none of those are the flags. A wrong index would
// silently report bogus SFD_NONBLOCK/SFD_CLOEXEC bits, so guard args[3]
// explicitly. The exit returns the new (or modified) fd, captured as a plain
// ret with no read/write byte classification.
func TestGenerateSignalfd4HandlerUsesArg3Flags(t *testing.T) {
	output := generateFromPair(t, FormatSignalfd4, FormatExitSignalfd4)

	requireContains(t, output, "struct eventfd_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_EVENTFD_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_SIGNALFD4;")
	// signalfd4(ufd, mask, sizemask, flags): flags is at args[3].
	requireContains(t, output, "__s32 flags = (__s32)ctx->args[3];")
	// Must not mistake ufd (args[0]), the mask pointer (args[1]) or sizemask
	// (args[2]) for the flags argument.
	for _, wrong := range []string{
		"flags = (__s32)ctx->args[0]",
		"flags = (__s32)ctx->args[1]",
		"flags = (__s32)ctx->args[2]",
	} {
		if strings.Contains(output, wrong) {
			t.Errorf("signalfd4 handler must read flags from args[3], not via %q", wrong)
		}
	}
	requireContains(t, output, "ev->ret = -1;")
	requireContains(t, output, "SEC(\"tracepoint/syscalls/sys_exit_signalfd4\")")
	requireContains(t, output, "ev->event_type = EXIT_EVENTFD_EVENT;")
	requireContains(t, output, "ev->ret = ctx->ret;")
}

func TestGenerateEpollCtlHandler(t *testing.T) {
	output := generateFromPair(t, FormatEpollCtl, FormatExitEpollCtl)

	requireContains(t, output, "struct epoll_ctl_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_EPOLL_CTL_EVENT;")
	requireContains(t, output, "ev->epfd = (__s32)ctx->args[0];")
	requireContains(t, output, "ev->op = (__s32)ctx->args[1];")
	requireContains(t, output, "ev->fd = (__s32)ctx->args[2];")
	requireContains(t, output, "ev->events = 0;")
	requireContains(t, output, "if (ctx->args[3] != 0) {")
	requireContains(t, output, "bpf_probe_read_user(&user_events, sizeof(user_events), (void *)ctx->args[3])")
	requireContains(t, output, "ev->event_type = EXIT_RET_EVENT;")
}

func TestGenerateMoveMountHandler(t *testing.T) {
	output := generateFromPair(t, FormatMoveMount, FormatExitMoveMount)

	requireContains(t, output, "struct two_fd_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_TWO_FD_EVENT;")
	requireContains(t, output, "ev->fd_a = (__s32)ctx->args[0];")
	requireContains(t, output, "ev->fd_b = (__s32)ctx->args[2];")
	requireContains(t, output, "ev->extra = (__u64)ctx->args[4];")
	requireContains(t, output, "ev->event_type = EXIT_RET_EVENT;")
}

func TestGenerateFsmountHandler(t *testing.T) {
	output := generateFromPair(t, FormatFsmount, FormatExitFsmount)

	requireContains(t, output, "struct eventfd_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_EVENTFD_EVENT;")
	requireContains(t, output, "flags = (__s32)ctx->args[1];")
	requireContains(t, output, "ev->event_type = EXIT_EVENTFD_EVENT;")
	requireContains(t, output, "ev->ret = ctx->ret;")
}

func TestGenerateEpollWaitHandlerUsesEpollFd(t *testing.T) {
	output := generateFromPair(t, FormatEpollWait, FormatExitEpollWait)

	requireContains(t, output, "struct fd_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_FD_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_EPOLL_WAIT;")
	requireContains(t, output, "ev->fd = (__s32)ctx->args[0];")
}

func TestGeneratePollHandlerCapturesNfdsAndTimeout(t *testing.T) {
	output := generateFromPair(t, FormatPoll, FormatExitPoll)

	requireContains(t, output, "struct poll_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_POLL_EVENT;")
	requireContains(t, output, "ev->nfds = (__s32)ctx->args[1];")
	requireContains(t, output, "ev->timeout_ns = ((__s64)timeout_ms) * 1000000LL;")
	requireContains(t, output, "ev->event_type = EXIT_RET_EVENT;")
}

func TestGeneratePselect6HandlerCapturesTimeoutPointer(t *testing.T) {
	output := generateFromPair(t, FormatPselect6, FormatExitPselect6)

	requireContains(t, output, "struct poll_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_POLL_EVENT;")
	requireContains(t, output, "ev->nfds = (__s32)ctx->args[0];")
	requireContains(t, output, "if (ctx->args[4] != 0) {")
	requireContains(t, output, "ev->timeout_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;")
}

// TestGenerateSelectHandlerCapturesNfdsAndTimevalTimeout locks in the select
// argument layout. select(int nfds, fd_set *readfds, fd_set *writefds,
// fd_set *exceptfds, struct timeval *timeout): args[0] is nfds — the highest
// fd number plus one, i.e. a COUNT, NOT a file descriptor — and args[1..3] are
// userspace fd_set bitmask pointers (also NOT single fds). The timeout is a
// timeval pointer at args[4]. The handler must therefore capture nfds from
// args[0] and the timeout from the args[4] timeval (sec*1e9 + usec*1e3), and
// must NEVER read any argument as an fd: capturing args[0] as an fd would
// record a garbage fd (it is a count), and capturing the bitmask pointers
// would record garbage pointers. The exit is an UNCLASSIFIED ret_event because
// the return value is a ready-fd count (>=0) or -1, never a byte transfer.
func TestGenerateSelectHandlerCapturesNfdsAndTimevalTimeout(t *testing.T) {
	output := generateFromPair(t, FormatSelect, FormatExitSelect)

	// Enter: poll_event with nfds from args[0] and timeval timeout from args[4].
	requireContains(t, output, "struct poll_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_POLL_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_SELECT;")
	requireContains(t, output, "ev->nfds = (__s32)ctx->args[0];")
	requireContains(t, output, "if (ctx->args[4] != 0) {")
	requireContains(t, output, "ev->timeout_ns = tv.tv_sec * 1000000000LL + tv.tv_usec * 1000LL;")

	// Negative: nfds is a count and the fd_set args are bitmask pointers, so no
	// argument may ever be captured as an fd, and the exit carries no bytes/fd
	// fields (the ready count is not a byte transfer).
	requireNotContains(t, output, "ev->fd = (__s32)ctx->args[0];")
	requireNotContains(t, output, "ev->fd = (__s32)ctx->args[1];")
	requireNotContains(t, output, "ev->bytes")

	// Exit: plain ret_event recording the ready-count (>=0) or -1, UNCLASSIFIED.
	requireContains(t, output, "ev->event_type = EXIT_RET_EVENT;")
	requireContains(t, output, "ev->ret = ctx->ret;")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
}

// TestGeneratePpollHandlerCapturesNfdsAndTimeoutPointer locks in the ppoll
// argument layout. ppoll(struct pollfd *fds, nfds_t nfds,
// const struct timespec *tmo_p, const sigset_t *sigmask): args[0] is a
// userspace pointer to an ARRAY of pollfd structs (NOT a file descriptor),
// nfds is args[1], and the timeout is a timespec pointer at args[2]. The
// handler must therefore capture nfds from args[1] and the timeout from the
// args[2] timespec, and must NEVER read args[0] as an fd (that would be a real
// bug: args[0] is a pointer, so an fd capture would record a garbage fd).
func TestGeneratePpollHandlerCapturesNfdsAndTimeoutPointer(t *testing.T) {
	output := generateFromPair(t, FormatPpoll, FormatExitPpoll)

	// Enter: poll_event with nfds from args[1] and timespec timeout from args[2].
	requireContains(t, output, "struct poll_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_POLL_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_PPOLL;")
	requireContains(t, output, "ev->nfds = (__s32)ctx->args[1];")
	requireContains(t, output, "if (ctx->args[2] != 0) {")
	requireContains(t, output, "ev->timeout_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;")

	// Negative: args[0] is a pollfd-array pointer and must never be captured
	// as an fd, and the exit is an UNCLASSIFIED ret_event (ready count, not a
	// byte transfer), so no bytes/fd fields are emitted.
	requireNotContains(t, output, "ev->fd = (__s32)ctx->args[0];")
	requireNotContains(t, output, "ev->bytes")
	// Exit: plain ret_event recording the ready-count (>=0) or -1.
	requireContains(t, output, "ev->event_type = EXIT_RET_EVENT;")
	requireContains(t, output, "ev->ret = ctx->ret;")
}

func TestGenerateSleepHandlerCapturesRequestedTimespec(t *testing.T) {
	output := generateFromPair(t, FormatNanosleep, FormatExitNanosleep)

	requireContains(t, output, "struct sleep_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_SLEEP_EVENT;")
	requireContains(t, output, "ev->requested_ns = -1;")
	requireContains(t, output, "if (ctx->args[0] != 0) {")
	requireContains(t, output, "ev->requested_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;")
	// nanosleep is ALWAYS a relative sleep (no flags argument), so its handler
	// must compute the duration unconditionally — no TIMER_ABSTIME flags check.
	requireNotContains(t, output, "TIMER_ABSTIME")
	requireNotContains(t, output, "& 1 /* TIMER_ABSTIME */")
}

func TestGenerateClockNanosleepHandlerCapturesRequestedTimespec(t *testing.T) {
	output := generateFromPair(t, FormatClockNanosleep, FormatExitClockNanosleep)

	requireContains(t, output, "struct sleep_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_SLEEP_EVENT;")
	// clock_nanosleep(clockid_t, int flags, const struct timespec *request,
	// struct timespec *remain): the request pointer is args[2], not args[0]
	// (which is the clockid). The sentinel -1 marks a missing/unreadable ptr.
	requireContains(t, output, "ev->requested_ns = -1;")
	requireContains(t, output, "if (ctx->args[2] != 0) {")
	requireContains(t, output, "ev->requested_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;")
}

// TestGenerateClockNanosleepHandlerSkipsAbsoluteSleeps locks in the
// TIMER_ABSTIME fix: when flags (args[1]) has TIMER_ABSTIME set, the request
// timespec is an ABSOLUTE wakeup time, not a relative duration, so the handler
// must keep the -1 sentinel instead of exporting a bogus multi-decade
// "sleep duration". The relative-duration computation is therefore guarded by a
// flags check, and only runs when the flag is clear.
func TestGenerateClockNanosleepHandlerSkipsAbsoluteSleeps(t *testing.T) {
	output := generateFromPair(t, FormatClockNanosleep, FormatExitClockNanosleep)

	// The flags check on args[1] against TIMER_ABSTIME (value 1) must be present,
	// guarding the relative-duration assignment.
	requireContains(t, output, "if ((ctx->args[1] & 1 /* TIMER_ABSTIME */) == 0) {")
	// The duration is computed inside the guard (relative branch only); the abs
	// branch leaves the -1 sentinel set above.
	requireContains(t, output,
		"        if (bpf_probe_read_user(&ts, sizeof(ts), (void *)ctx->args[2]) == 0) {\n"+
			"            if ((ctx->args[1] & 1 /* TIMER_ABSTIME */) == 0) {\n"+
			"                ev->requested_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;\n"+
			"            }\n        }")
}

// TestClockNanosleepExitHandlerIsUnclassifiedRet locks in that the exit side of
// clock_nanosleep records a plain ret_event with ret_type UNCLASSIFIED. The
// syscall returns 0 on success or a positive errno (and -1 only when invoked
// via the libc wrapper on error), never an fd or byte count, so UNCLASSIFIED is
// the correct return classification — same as its nanosleep sibling.
func TestClockNanosleepExitHandlerIsUnclassifiedRet(t *testing.T) {
	output := generateFromPair(t, FormatClockNanosleep, FormatExitClockNanosleep)

	requireContains(t, output, "handle_sys_exit_clock_nanosleep")
	requireContains(t, output, "ev->event_type = EXIT_RET_EVENT;")
	requireContains(t, output, "ev->ret = ctx->ret;")
	requireContains(t, output, "ev->ret_type = UNCLASSIFIED;")
	// The exit handler must not try to read a timespec or treat ret as an fd.
	requireNotContains(t, output, "handle_sys_exit_clock_nanosleep(struct syscall_trace_exit *ctx) {\n    __u32 pid, tid;\n    if (filter(&pid, &tid))\n        return 0;\n\n    if (!ior_on_syscall_exit(tid, SYS_ENTER_CLOCK_NANOSLEEP, ctx->ret))\n        return 0;\n\n    struct sleep_event")
}

func TestGenerateKeyctlHandler(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("keyctl")))

	requireContains(t, output, "struct keyctl_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_KEYCTL_EVENT;")
	requireContains(t, output, "ev->option = (__s32)ctx->args[0];")
	requireContains(t, output, "ev->key_serial = (__s32)ctx->args[1];")
	requireContains(t, output, "ev->value = (__u64)ctx->args[2];")
	requireContains(t, output, "ev->event_type = EXIT_RET_EVENT;")
}

func TestGenerateAddKeyHandler(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("add_key")))

	requireContains(t, output, "struct keyctl_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_KEYCTL_EVENT;")
	requireContains(t, output, "ev->option = -1;")
	requireContains(t, output, "ev->key_serial = (__s32)ctx->args[4];")
	requireContains(t, output, "ev->value = (__u64)ctx->args[3];")
}

func TestGenerateRequestKeyHandler(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("request_key")))

	requireContains(t, output, "struct keyctl_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_KEYCTL_EVENT;")
	requireContains(t, output, "ev->option = -2;")
	requireContains(t, output, "ev->key_serial = (__s32)ctx->args[3];")
}

func TestGeneratePtraceHandler(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("ptrace")))

	requireContains(t, output, "struct ptrace_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_PTRACE_EVENT;")
	requireContains(t, output, "ev->request = (__s64)ctx->args[0];")
	requireContains(t, output, "ev->target_pid = (__s32)ctx->args[1];")
	requireContains(t, output, "ev->data = (__u64)ctx->args[3];")
}

func TestGeneratePerfEventOpenHandler(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("perf_event_open")))

	requireContains(t, output, "struct perf_open_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_PERF_OPEN_EVENT;")
	requireContains(t, output, "struct __ior_perf_event_attr {")
	requireContains(t, output, "ev->attr_type = attr.type;")
	requireContains(t, output, "ev->config = attr.config;")
	requireContains(t, output, "ev->target_pid = (__s32)ctx->args[1];")
	requireContains(t, output, "ev->group_fd = (__s32)ctx->args[3];")
	requireContains(t, output, "ev->event_type = EXIT_RET_EVENT;")
}

func TestGenerateNameToHandleAtHandler(t *testing.T) {
	output := generateFromPair(t, FormatNameToHandleAt, FormatExitNameToHandleAt)

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_name_to_handle_at")`)
	requireContains(t, output, "struct path_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_PATH_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_NAME_TO_HANDLE_AT;")
	requireContains(t, output, "bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), (void*)ctx->args[1]);")
}

func TestGenerateFallbackNullHandler(t *testing.T) {
	output := generateFromPair(t, FormatKill, FormatExitKill)

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_kill")`)
	requireContains(t, output, "struct null_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_NULL_EVENT;")
	requireContains(t, output, `SEC("tracepoint/syscalls/sys_exit_kill")`)
	requireContains(t, output, "ev->event_type = EXIT_RET_EVENT;")
}

// TestGenerateExitNoreturnHandlers locks in how the noreturn process-exit
// syscalls are generated. Per exit(2)/exit_group(2): both take a single
// `int status` argument and never return. ior classifies them as KindNull
// (FamilyProcess), so:
//   - The enter handler emits a struct null_event and intentionally does NOT
//     capture the int status arg (it is not an I/O resource like an fd/path).
//   - The kernel still exposes sys_exit_{exit,exit_group} tracepoints, but
//     those handlers can never fire at runtime because the syscall does not
//     return. The generator suppresses the dead exit handlers.
func TestGenerateExitNoreturnHandlers(t *testing.T) {
	for _, syscall := range []string{"exit", "exit_group"} {
		t.Run(syscall, func(t *testing.T) {
			output := GenerateTracepointsC(mustParseAll(t, syntheticPair(syscall)))

			enterSec := `SEC("tracepoint/syscalls/sys_enter_` + syscall + `")`
			exitSec := `SEC("tracepoint/syscalls/sys_exit_` + syscall + `")`
			requireContains(t, output, enterSec)
			requireContains(t, output, "struct null_event *ev")
			requireContains(t, output, "ev->event_type = ENTER_NULL_EVENT;")
			if strings.Contains(output, exitSec) {
				t.Errorf("%s: noreturn syscall must not emit an exit handler", syscall)
			}

			enterStart := strings.Index(output, enterSec)
			if enterStart < 0 {
				t.Fatalf("%s: enter handler not found", syscall)
			}
			enterBody := output[enterStart:]
			if strings.Contains(enterBody, "ctx->args[") {
				t.Errorf("%s: enter handler unexpectedly captures an arg; the int status must be ignored", syscall)
			}

			// Regression guard (task z10): the noreturn enter handler must emit
			// the enter null_event WITHOUT recording enter-state. Because the
			// exit handler is suppressed, nothing would ever look up or delete a
			// syscall_enter_state_map entry, so recording one would leak a stale
			// per-tid entry in the bounded map. The handler must therefore call
			// the dedicated ior_on_noreturn_syscall_enter hook (which only makes
			// the sampling decision) and must NOT call the state-recording
			// ior_on_syscall_enter that normal returning syscalls use.
			requireContains(t, output, "ior_on_noreturn_syscall_enter("+strings.ToUpper("sys_enter_"+syscall)+")")
			if strings.Contains(enterBody, "ior_on_syscall_enter(") {
				t.Errorf("%s: noreturn enter handler must not record enter-state "+
					"(found ior_on_syscall_enter, which writes syscall_enter_state_map)", syscall)
			}
		})
	}
}

// TestGenerateReturningSyscallEnterRecordsState is the positive contrast to
// TestGenerateExitNoreturnHandlers: a normal returning syscall's enter handler
// DOES record enter-state via ior_on_syscall_enter (so its later exit handler
// can pair durations and delete the entry), and must NOT use the noreturn hook.
func TestGenerateReturningSyscallEnterRecordsState(t *testing.T) {
	syscall := "sched_get_priority_min" // a returning KindNull syscall
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair(syscall)))

	enterSec := `SEC("tracepoint/syscalls/sys_enter_` + syscall + `")`
	enterStart := strings.Index(output, enterSec)
	if enterStart < 0 {
		t.Fatalf("%s: enter handler not found", syscall)
	}
	enterEnd := strings.Index(output[enterStart+len(enterSec):], `SEC("tracepoint/`)
	enterBody := output[enterStart:]
	if enterEnd >= 0 {
		enterBody = output[enterStart : enterStart+len(enterSec)+enterEnd]
	}

	if !strings.Contains(enterBody, "ior_on_syscall_enter(tid, "+strings.ToUpper("sys_enter_"+syscall)+")") {
		t.Errorf("%s: returning syscall enter handler must record enter-state via ior_on_syscall_enter", syscall)
	}
	if strings.Contains(enterBody, "ior_on_noreturn_syscall_enter(") {
		t.Errorf("%s: returning syscall enter handler must not use the noreturn hook", syscall)
	}
}

// TestGenerateSchedGetPriorityMinHandler locks in how sched_get_priority_min
// (and its identical sibling sched_get_priority_max) are generated. Per
// sched_get_priority_min(2): `int sched_get_priority_min(int policy)` takes a
// single `int policy` scheduling-policy enum (SCHED_FIFO, SCHED_RR, ...) and
// returns the minimum static priority value for that policy on success, or -1
// on error. The `policy` arg is neither an fd nor a path, so ior classifies the
// syscall as KindNull in FamilySched (alongside every other sched_* syscall).
// Therefore:
//   - The enter handler emits a struct null_event and intentionally does NOT
//     capture the int policy arg (it is not an I/O resource).
//   - Unlike the noreturn exit() syscalls, this syscall DOES return, so the
//     kernel sys_exit_sched_get_priority_min tracepoint fires and the generator
//     emits a live exit handler that records the int return value (-1 or the
//     priority) via the generic EXIT_RET_EVENT path.
func TestGenerateSchedGetPriorityMinHandler(t *testing.T) {
	for _, syscall := range []string{"sched_get_priority_min", "sched_get_priority_max"} {
		t.Run(syscall, func(t *testing.T) {
			formats := mustParseAll(t, syntheticPair(syscall))
			if got := formats[0].Family; got != FamilySched {
				t.Fatalf("%s family = %s, want %s", syscall, got, FamilySched)
			}
			if got := ClassifySyscallFamily("sys_enter_" + syscall); got != FamilySched {
				t.Fatalf("ClassifySyscallFamily(%s) = %s, want %s", syscall, got, FamilySched)
			}

			output := GenerateTracepointsC(formats)
			if strings.Contains(output, "Skipping") {
				t.Fatalf("%s was skipped: %s", syscall, output)
			}

			enterSec := `SEC("tracepoint/syscalls/sys_enter_` + syscall + `")`
			exitSec := `SEC("tracepoint/syscalls/sys_exit_` + syscall + `")`
			requireContains(t, output, enterSec)
			requireContains(t, output, "struct null_event *ev")
			requireContains(t, output, "ev->event_type = ENTER_NULL_EVENT;")
			// Returning syscall: the exit handler must exist and emit the ret value.
			requireContains(t, output, exitSec)
			requireContains(t, output, "ev->event_type = EXIT_RET_EVENT;")

			// The int policy arg is not an fd/path, so the enter handler must not
			// capture any ctx->args[].
			enterStart := strings.Index(output, enterSec)
			if enterStart < 0 {
				t.Fatalf("%s: enter handler not found", syscall)
			}
			enterEnd := strings.Index(output[enterStart+len(enterSec):], `SEC("tracepoint/`)
			enterBody := output[enterStart:]
			if enterEnd >= 0 {
				enterBody = output[enterStart : enterStart+len(enterSec)+enterEnd]
			}
			if strings.Contains(enterBody, "ctx->args[") {
				t.Errorf("%s: enter handler unexpectedly captures an arg; the int policy must be ignored", syscall)
			}
		})
	}
}

func TestGenerateHandlersForEverySyscallFamily(t *testing.T) {
	tests := []struct {
		syscall string
		family  SyscallFamily
	}{
		{"accept", FamilyNetwork},
		{"pipe2", FamilyIPC},
		{"munmap", FamilyMemory},
		{"execve", FamilyProcess},
		{"kill", FamilySignals},
		{"nanosleep", FamilyTime},
		{"sched_yield", FamilySched},
		{"mknod", FamilyFS},
		{"epoll_wait", FamilyPolling},
		{"io_setup", FamilyAIO},
		{"bpf", FamilySecurity},
		{"sysinfo", FamilyMisc},
	}

	for _, tt := range tests {
		t.Run(tt.syscall, func(t *testing.T) {
			input := syntheticPair(tt.syscall)
			formats := mustParseAll(t, input)
			if formats[0].Family != tt.family {
				t.Fatalf("%s family = %s, want %s", tt.syscall, formats[0].Family, tt.family)
			}
			output := GenerateTracepointsC(formats)
			if strings.Contains(output, "Skipping") {
				t.Fatalf("%s was skipped: %s", tt.syscall, output)
			}
			requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_`+tt.syscall+`")`)
			requireContains(t, output, `SEC("tracepoint/syscalls/sys_exit_`+tt.syscall+`")`)
		})
	}
}

func TestGenerateDefineConstants(t *testing.T) {
	output := generateFromPair(t, FormatRead, FormatExitRead)

	requireContains(t, output, "#define SYS_ENTER_READ 844")
	requireContains(t, output, "#define SYS_EXIT_READ 843")
}

func TestGenerateDefinesSortedByIDDesc(t *testing.T) {
	input := FormatRead + "\n" + FormatExitRead + "\n" + FormatClose + "\n" + FormatExitClose
	formats := mustParseAll(t, input)
	output := GenerateTracepointsC(formats)

	enterReadPos := strings.Index(output, "#define SYS_ENTER_READ")
	enterClosePos := strings.Index(output, "#define SYS_ENTER_CLOSE")
	if enterReadPos < 0 || enterClosePos < 0 {
		t.Fatal("missing #define lines")
	}
	if enterReadPos > enterClosePos {
		t.Error("#define SYS_ENTER_READ (844) should come before SYS_ENTER_CLOSE (778)")
	}
}

func TestGenerateHandlerStructure(t *testing.T) {
	output := generateFromPair(t, FormatClose, FormatExitClose)

	requireContains(t, output, "int handle_sys_enter_close(struct syscall_trace_enter *ctx) {")
	requireContains(t, output, "__u32 pid, tid;")
	requireContains(t, output, "if (filter(&pid, &tid))")
	requireContains(t, output, "ev->pid = pid;")
	requireContains(t, output, "ev->tid = tid;")
	requireContains(t, output, "ev->time = bpf_ktime_get_boot_ns();")
	requireContains(t, output, "bpf_ringbuf_submit(ev, 0);")
	requireContains(t, output, "return 0;")
}

func TestGenerateAllEventTypes(t *testing.T) {
	// Verify every event type constant appears correctly
	tests := []struct {
		kind  TracepointKind
		enter string
		exit  string
	}{
		{KindFd, "ENTER_FD_EVENT", "EXIT_FD_EVENT"},
		{KindOpen, "ENTER_OPEN_EVENT", "EXIT_OPEN_EVENT"},
		{KindMqOpen, "ENTER_OPEN_EVENT", "EXIT_OPEN_EVENT"},
		{KindExec, "ENTER_EXEC_EVENT", "EXIT_EXEC_EVENT"},
		{KindPathname, "ENTER_PATH_EVENT", "EXIT_PATH_EVENT"},
		{KindName, "ENTER_NAME_EVENT", "EXIT_NAME_EVENT"},
		{KindRet, "ENTER_RET_EVENT", "EXIT_RET_EVENT"},
		{KindFcntl, "ENTER_FCNTL_EVENT", "EXIT_FCNTL_EVENT"},
		{KindNull, "ENTER_NULL_EVENT", "EXIT_NULL_EVENT"},
		{KindDup3, "ENTER_DUP3_EVENT", "EXIT_DUP3_EVENT"},
		{KindOpenByHandleAt, "ENTER_OPEN_BY_HANDLE_AT_EVENT", "EXIT_OPEN_BY_HANDLE_AT_EVENT"},
		{KindSocket, "ENTER_SOCKET_EVENT", "EXIT_SOCKET_EVENT"},
		{KindSocketpair, "ENTER_SOCKETPAIR_EVENT", "EXIT_SOCKETPAIR_EVENT"},
		{KindAccept, "ENTER_ACCEPT_EVENT", "EXIT_ACCEPT_EVENT"},
		{KindPipe, "ENTER_PIPE_EVENT", "EXIT_PIPE_EVENT"},
		{KindEventfd, "ENTER_EVENTFD_EVENT", "EXIT_EVENTFD_EVENT"},
		{KindPidfd, "ENTER_EVENTFD_EVENT", "EXIT_EVENTFD_EVENT"},
		{KindEpollCtl, "ENTER_EPOLL_CTL_EVENT", "EXIT_EPOLL_CTL_EVENT"},
		{KindTwoFd, "ENTER_TWO_FD_EVENT", "EXIT_TWO_FD_EVENT"},
		{KindPoll, "ENTER_POLL_EVENT", "EXIT_POLL_EVENT"},
		{KindMem, "ENTER_MEM_EVENT", "EXIT_MEM_EVENT"},
		{KindSleep, "ENTER_SLEEP_EVENT", "EXIT_SLEEP_EVENT"},
		{KindKeyctl, "ENTER_KEYCTL_EVENT", "EXIT_KEYCTL_EVENT"},
		{KindPtrace, "ENTER_PTRACE_EVENT", "EXIT_PTRACE_EVENT"},
		{KindPerfOpen, "ENTER_PERF_OPEN_EVENT", "EXIT_PERF_OPEN_EVENT"},
		{KindSeccomp, "ENTER_NULL_EVENT", "EXIT_NULL_EVENT"},
		{KindModule, "ENTER_NULL_EVENT", "EXIT_NULL_EVENT"},
		{KindSysVId, "ENTER_NULL_EVENT", "EXIT_NULL_EVENT"},
		{KindSysVOp, "ENTER_NULL_EVENT", "EXIT_NULL_EVENT"},
		{KindProc, "ENTER_NULL_EVENT", "EXIT_NULL_EVENT"},
		{KindBpf, "ENTER_NULL_EVENT", "EXIT_NULL_EVENT"},
		{KindFutex, "ENTER_NULL_EVENT", "EXIT_NULL_EVENT"},
		{KindPrctl, "ENTER_NULL_EVENT", "EXIT_NULL_EVENT"},
		{KindTimerObj, "ENTER_NULL_EVENT", "EXIT_NULL_EVENT"},
	}

	for _, tt := range tests {
		if got := eventTypeConstant(tt.kind, true); got != tt.enter {
			t.Errorf("eventTypeConstant(%d, true) = %q, want %q", tt.kind, got, tt.enter)
		}
		if got := eventTypeConstant(tt.kind, false); got != tt.exit {
			t.Errorf("eventTypeConstant(%d, false) = %q, want %q", tt.kind, got, tt.exit)
		}
	}
}

func TestEventStructNames(t *testing.T) {
	tests := []struct {
		kind TracepointKind
		want string
	}{
		{KindFd, "fd_event"},
		{KindOpen, "open_event"},
		{KindMqOpen, "open_event"},
		{KindExec, "exec_event"},
		{KindPathname, "path_event"},
		{KindName, "name_event"},
		{KindRet, "ret_event"},
		{KindFcntl, "fcntl_event"},
		{KindNull, "null_event"},
		{KindDup3, "dup3_event"},
		{KindOpenByHandleAt, "open_by_handle_at_event"},
		{KindSocket, "socket_event"},
		{KindSocketpair, "socketpair_event"},
		{KindAccept, "accept_event"},
		{KindPipe, "pipe_event"},
		{KindEventfd, "eventfd_event"},
		{KindPidfd, "eventfd_event"},
		{KindEpollCtl, "epoll_ctl_event"},
		{KindTwoFd, "two_fd_event"},
		{KindPoll, "poll_event"},
		{KindMem, "mem_event"},
		{KindSleep, "sleep_event"},
		{KindKeyctl, "keyctl_event"},
		{KindPtrace, "ptrace_event"},
		{KindPerfOpen, "perf_open_event"},
		{KindSeccomp, "null_event"},
		{KindModule, "null_event"},
		{KindSysVId, "null_event"},
		{KindSysVOp, "null_event"},
		{KindProc, "null_event"},
		{KindBpf, "null_event"},
		{KindFutex, "null_event"},
		{KindPrctl, "null_event"},
		{KindTimerObj, "null_event"},
	}

	for _, tt := range tests {
		if got := eventStructName(tt.kind); got != tt.want {
			t.Errorf("eventStructName(%d) = %q, want %q", tt.kind, got, tt.want)
		}
	}
}

func TestEnterReject(t *testing.T) {
	// RetTracepoint as enter type should be rejected
	if !isEnterRejected(KindRet) {
		t.Error("KindRet should be enter-rejected")
	}
	if !isEnterRejected(KindNone) {
		t.Error("KindNone should be enter-rejected")
	}

	accepted := []TracepointKind{KindFd, KindOpen, KindMqOpen, KindExec, KindPathname, KindName, KindFcntl, KindNull, KindDup3, KindOpenByHandleAt, KindSocket, KindSocketpair, KindAccept, KindPipe, KindEventfd, KindPidfd, KindEpollCtl, KindTwoFd, KindPoll, KindMem, KindSleep, KindKeyctl, KindPtrace, KindPerfOpen, KindSeccomp, KindModule, KindSysVId, KindSysVOp, KindProc, KindBpf, KindFutex, KindPrctl, KindTimerObj}
	for _, k := range accepted {
		if isEnterRejected(k) {
			t.Errorf("kind %d should NOT be enter-rejected", k)
		}
	}
}

func TestEventStructNameUnknown(t *testing.T) {
	if got := eventStructName(TracepointKind(999)); got != "unknown_event" {
		t.Errorf("eventStructName(999) = %q, want \"unknown_event\"", got)
	}
}

func TestEventTypeConstantUnknown(t *testing.T) {
	if got := eventTypeConstant(TracepointKind(999), true); got != "ENTER_UNKNOWN_EVENT" {
		t.Errorf("eventTypeConstant(999, true) = %q, want \"ENTER_UNKNOWN_EVENT\"", got)
	}
	if got := eventTypeConstant(TracepointKind(999), false); got != "EXIT_UNKNOWN_EVENT" {
		t.Errorf("eventTypeConstant(999, false) = %q, want \"EXIT_UNKNOWN_EVENT\"", got)
	}
}

func TestGroupBySyscallInvalid(t *testing.T) {
	formats := []Format{
		{Name: "tooshort", ID: 1},
		{Name: "also_short", ID: 2},
	}
	output := GenerateTracepointsC(formats)
	if strings.Contains(output, "SEC(") {
		t.Error("formats with fewer than 3 name parts should not produce SEC handlers")
	}
}

func TestClassifySyscallNoExit(t *testing.T) {
	formats := mustParseAll(t, FormatRead)
	output := GenerateTracepointsC(formats)
	requireContains(t, output, "Skipping")
	if strings.Contains(output, "SEC(") {
		t.Error("syscall with only enter and no exit should be ignored")
	}
}

func TestEnterConstForHandler(t *testing.T) {
	tests := []struct {
		name    string
		isEnter bool
		want    string
	}{
		{"sys_enter_read", true, "SYS_ENTER_READ"},
		{"sys_exit_read", false, "SYS_ENTER_READ"},
		{"sys_enter_openat", true, "SYS_ENTER_OPENAT"},
		{"sys_exit_openat", false, "SYS_ENTER_OPENAT"},
		{"sys_exit_io_uring_enter", false, "SYS_ENTER_IO_URING_ENTER"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := enterConstForHandler(tt.name, tt.isEnter)
			if got != tt.want {
				t.Errorf("enterConstForHandler(%q, %v) = %q, want %q", tt.name, tt.isEnter, got, tt.want)
			}
		})
	}
}

func TestExitHandlerPassesEnterTraceID(t *testing.T) {
	output := generateFromPair(t, FormatRead, FormatExitRead)

	requireContains(t, output, "ior_on_syscall_exit(tid, SYS_ENTER_READ, ctx->ret)")
	if strings.Contains(output, "ior_on_syscall_exit(tid, SYS_EXIT_READ") {
		t.Error("exit handler must pass the enter trace ID, not the exit trace ID")
	}
}

func TestExitHandlerDoesNotRelyOnIDAdjacency(t *testing.T) {
	input := FormatRead + "\n" + FormatExitRead
	formats := mustParseAll(t, input)
	enterID := -1
	exitID := -1
	for _, f := range formats {
		if strings.HasPrefix(f.Name, "sys_enter_") {
			enterID = f.ID
		}
		if strings.HasPrefix(f.Name, "sys_exit_") {
			exitID = f.ID
		}
	}
	if enterID < 0 || exitID < 0 {
		t.Fatal("missing enter or exit format")
	}
	if enterID != exitID+1 {
		t.Skipf("IDs are not adjacent (enter=%d, exit=%d), adjacency test not applicable", enterID, exitID)
	}

	output := GenerateTracepointsC(formats)
	if strings.Contains(output, "ior_on_syscall_exit(tid, SYS_EXIT_") {
		t.Error("generated exit handler passes exit trace ID; should pass enter trace ID to avoid adjacency dependency")
	}
	requireContains(t, output, "ior_on_syscall_exit(tid, SYS_ENTER_READ, ctx->ret)")
}

func syntheticPair(syscall string) string {
	enter := strings.Replace(FormatKill, "sys_enter_kill", "sys_enter_"+syscall, 1)
	enter = strings.Replace(enter, "ID: 183", "ID: 1001", 1)
	exit := strings.Replace(FormatExitKill, "sys_exit_kill", "sys_exit_"+syscall, 1)
	exit = strings.Replace(exit, "ID: 182", "ID: 1000", 1)
	return enter + "\n" + exit
}

func requireContains(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("output missing expected string: %q", needle)
	}
}

// requireNotContains fails when haystack unexpectedly contains needle. Used for
// negative assertions, e.g. that a pointer argument is not misclassified as an
// fd capture.
func requireNotContains(t *testing.T, haystack, needle string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		t.Errorf("output unexpectedly contains forbidden string: %q", needle)
	}
}
