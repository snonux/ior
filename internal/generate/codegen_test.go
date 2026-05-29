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

func TestGenerateProcessMadviseHandlerUsesFirstArgumentAsFd(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("process_madvise")))

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_process_madvise")`)
	requireContains(t, output, "struct fd_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_FD_EVENT;")
	requireContains(t, output, "ev->trace_id = SYS_ENTER_PROCESS_MADVISE;")
	requireContains(t, output, "ev->fd = (__s32)ctx->args[0];")
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

func TestGenerateMemHandlerMlock2(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("mlock2")))

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_mlock2")`)
	requireContains(t, output, "struct mem_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_MEM_EVENT;")
	requireContains(t, output, "ev->addr = (__u64)ctx->args[0];")
	requireContains(t, output, "ev->length = (__u64)ctx->args[1];")
	requireContains(t, output, "ev->flags = (__u64)ctx->args[2];")
}

func TestGenerateMemHandlerRemapFilePages(t *testing.T) {
	output := GenerateTracepointsC(mustParseAll(t, syntheticPair("remap_file_pages")))

	requireContains(t, output, `SEC("tracepoint/syscalls/sys_enter_remap_file_pages")`)
	requireContains(t, output, "struct mem_event *ev")
	requireContains(t, output, "ev->event_type = ENTER_MEM_EVENT;")
	requireContains(t, output, "ev->addr = (__u64)ctx->args[0];")
	requireContains(t, output, "ev->length = (__u64)ctx->args[1];")
	requireContains(t, output, "ev->length2 = (__u64)ctx->args[3];")
	requireContains(t, output, "ev->flags = (__u64)ctx->args[4];")
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
