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

func TestGeneratePidfdGetfdHandlerUsesPidfdArgument(t *testing.T) {
	output := generateFromPair(t, FormatPidfdGetfd, FormatExitPidfdGetfd)

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_pidfd_getfd")`)
	requireContains(t, output, "ev->event_type = ENTER_FD_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_PIDFD_GETFD;")
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

func TestGenerateDup3Handler(t *testing.T) {
	output := generateFromPair(t, FormatDup3, FormatExitDup3)

	requireContains(t, output, "struct dup3_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_DUP3_EVENT;")
	requireContains(t, output, "ev->fd = (__s32)ctx->args[0];")
	requireContains(t, output, "ev->flags = (__s32)ctx->args[2];")
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

func TestGenerateSleepHandlerCapturesRequestedTimespec(t *testing.T) {
	output := generateFromPair(t, FormatNanosleep, FormatExitNanosleep)

	requireContains(t, output, "struct sleep_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_SLEEP_EVENT;")
	requireContains(t, output, "ev->requested_ns = -1;")
	requireContains(t, output, "if (ctx->args[0] != 0) {")
	requireContains(t, output, "ev->requested_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;")
}

func TestGenerateClockNanosleepHandlerCapturesRequestedTimespec(t *testing.T) {
	output := generateFromPair(t, FormatClockNanosleep, FormatExitClockNanosleep)

	requireContains(t, output, "struct sleep_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_SLEEP_EVENT;")
	requireContains(t, output, "if (ctx->args[2] != 0) {")
	requireContains(t, output, "ev->requested_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;")
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
		{KindEpollCtl, "ENTER_EPOLL_CTL_EVENT", "EXIT_EPOLL_CTL_EVENT"},
		{KindPoll, "ENTER_POLL_EVENT", "EXIT_POLL_EVENT"},
		{KindMem, "ENTER_MEM_EVENT", "EXIT_MEM_EVENT"},
		{KindSleep, "ENTER_SLEEP_EVENT", "EXIT_SLEEP_EVENT"},
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
		{KindEpollCtl, "epoll_ctl_event"},
		{KindPoll, "poll_event"},
		{KindMem, "mem_event"},
		{KindSleep, "sleep_event"},
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

	accepted := []TracepointKind{KindFd, KindOpen, KindPathname, KindName, KindFcntl, KindNull, KindDup3, KindOpenByHandleAt, KindSocket, KindSocketpair, KindAccept, KindPipe, KindEventfd, KindEpollCtl, KindPoll, KindMem, KindSleep}
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
