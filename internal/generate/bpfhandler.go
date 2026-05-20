package generate

import (
	"fmt"
	"strings"
)

func generateBPFHandler(tp GeneratedTracepoint) string {
	f := tp.Format
	isEnter := strings.Split(f.Name, "_")[1] == "enter"

	// Use the kernel's actual tracepoint context structs (syscall_trace_enter/exit)
	// rather than the BTF-emitted trace_event_raw_sys_enter/exit aliases. On RHEL 9
	// kernels (5.14 with the rt-merge backport that added preempt_lazy_count to
	// trace_entry) the two diverge: trace_event_raw_sys_* grows by 8 bytes and
	// the args/ret offsets shift, but the real context handed to the BPF program
	// is still syscall_trace_*. Reading via the wider alias trips the verifier's
	// max_ctx_offset check and the attach fails with EACCES. The two structs are
	// identical on non-RHEL kernels, so this is a no-op everywhere else.
	ctxStruct := "syscall_trace_exit"
	if isEnter {
		ctxStruct = "syscall_trace_enter"
	}

	eventStruct := eventStructName(tp.Classification.Kind)
	comment := eventStruct
	if tp.Classification.Kind == KindRet {
		comment = fmt.Sprintf("%s (%s)", eventStruct, ClassifyRet(f.Name))
	}

	eventTypeConst := eventTypeConstant(tp.Classification.Kind, isEnter)
	extra := generateExtra(tp, isEnter)

	return renderHandler(f.Name, ctxStruct, eventStruct, comment, eventTypeConst, extra, isEnter)
}

func renderHandler(name, ctxStruct, eventStruct, comment, eventTypeConst, extra string, isEnter bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "/// %s is a struct %s\n", name, comment)
	fmt.Fprintf(&b, "SEC(\"tracepoint/syscalls/%s\")\n", name)
	fmt.Fprintf(&b, "int handle_%s(struct %s *ctx) {\n", strings.ToLower(name), ctxStruct)
	b.WriteString("    __u32 pid, tid;\n")
	b.WriteString("    if (filter(&pid, &tid))\n")
	b.WriteString("        return 0;\n")
	b.WriteString("\n")
	if isEnter {
		fmt.Fprintf(&b, "    if (!ior_on_syscall_enter(tid, %s))\n", strings.ToUpper(name))
		b.WriteString("        return 0;\n")
	} else {
		fmt.Fprintf(&b, "    if (!ior_on_syscall_exit(tid, %s, ctx->ret))\n", strings.ToUpper(name))
		b.WriteString("        return 0;\n")
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "    struct %s *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct %s), 0);\n", eventStruct, eventStruct)
	b.WriteString("    if (!ev)\n")
	b.WriteString("        return 0;\n")
	b.WriteString("\n")
	fmt.Fprintf(&b, "    ev->event_type = %s;\n", eventTypeConst)
	fmt.Fprintf(&b, "    ev->trace_id = %s;\n", strings.ToUpper(name))
	b.WriteString("    ev->pid = pid;\n")
	b.WriteString("    ev->tid = tid;\n")
	b.WriteString("    ev->time = bpf_ktime_get_boot_ns();\n")
	if extra != "" {
		b.WriteString(extra)
	}
	b.WriteString("\n")
	b.WriteString("    bpf_ringbuf_submit(ev, 0);\n")
	b.WriteString("    return 0;\n")
	b.WriteString("}\n")
	return b.String()
}

// generateExtra returns the kind-specific C body lines for a tracepoint handler,
// dispatching to a per-kind helper so that each case stays concise.
func generateExtra(tp GeneratedTracepoint, isEnter bool) string {
	f := tp.Format
	switch tp.Classification.Kind {
	case KindFd:
		return generateExtraFd(f)
	case KindDup3:
		return "    ev->fd = (__s32)ctx->args[0];\n    ev->flags = (__s32)ctx->args[2];\n"
	case KindOpenByHandleAt:
		return "    ev->flags = (__s32)ctx->args[2];\n"
	case KindSocket:
		return generateExtraSocket()
	case KindSocketpair:
		return generateExtraSocketpair(isEnter)
	case KindAccept:
		return generateExtraAccept(isEnter)
	case KindPipe:
		return generateExtraPipe(f, isEnter)
	case KindEventfd:
		return generateExtraEventfd(f, isEnter)
	case KindEpollCtl:
		return generateExtraEpollCtl()
	case KindTwoFd:
		return generateExtraTwoFd(f.Name)
	case KindPoll:
		return generateExtraPoll(f.Name)
	case KindMem:
		return generateExtraMem(f.Name)
	case KindSleep:
		return generateExtraSleep(f.Name)
	case KindOpen:
		return generateExtraOpen(f)
	case KindMqOpen:
		return generateExtraMqOpen(f)
	case KindPathname:
		return generateExtraPathname(tp, f)
	case KindName:
		return generateExtraName(f)
	case KindFcntl:
		return generateExtraFcntl(f)
	case KindRet:
		return fmt.Sprintf("    ev->ret = ctx->ret;\n    ev->ret_type = %s;\n", ClassifyRet(f.Name))
	case KindNull:
		return ""
	}
	return ""
}

// generateExtraFd returns the fd-capture lines for fd-family events.
func generateExtraFd(f *Format) string {
	if f.Name == "sys_enter_pidfd_getfd" {
		return "    ev->fd = (__s32)ctx->args[0];\n"
	}
	fdIdx := f.FieldNumber("fd")
	if fdIdx >= 0 {
		return fmt.Sprintf("    ev->fd = (__s32)ctx->args[%d];\n", fdIdx)
	}
	return "    ev->fd = (__s32)ctx->args[0];\n"
}

// generateExtraOpen returns the filename/comm/flags capture lines for open-family events.
func generateExtraOpen(f *Format) string {
	return generateExtraOpenWithFields(f, "filename", "flags")
}

func generateExtraMqOpen(f *Format) string {
	return generateExtraOpenWithFields(f, "u_name", "oflag")
}

func generateExtraOpenWithFields(f *Format, pathnameField, flagsField string) string {
	filenameIdx := f.FieldNumber(pathnameField)
	flagsIdx := f.FieldNumber(flagsField)
	var b strings.Builder
	b.WriteString("    __builtin_memset(&(ev->filename), 0, sizeof(ev->filename) + sizeof(ev->comm));\n")
	fmt.Fprintf(&b, "    bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)ctx->args[%d]);\n", filenameIdx)
	b.WriteString("    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));\n")
	if flagsIdx > -1 {
		fmt.Fprintf(&b, "    ev->flags = ctx->args[%d];\n", flagsIdx)
	} else {
		b.WriteString("    ev->flags = -1; // Probably OK\n")
	}
	return b.String()
}

// generateExtraPathname returns the pathname capture lines for path-family events.
func generateExtraPathname(tp GeneratedTracepoint, f *Format) string {
	fieldName := tp.Classification.PathnameField
	fieldIdx := f.FieldNumber(fieldName)
	var b strings.Builder
	b.WriteString("    __builtin_memset(&(ev->pathname), 0, sizeof(ev->pathname));\n")
	fmt.Fprintf(&b, "    bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), (void*)ctx->args[%d]);\n", fieldIdx)
	return b.String()
}

// generateExtraName returns the oldname/newname capture lines for rename/link-family events.
func generateExtraName(f *Format) string {
	oldIdx := f.FieldNumber("oldname")
	newIdx := f.FieldNumber("newname")
	var b strings.Builder
	b.WriteString("    __builtin_memset(&(ev->oldname), 0, sizeof(ev->oldname) + sizeof(ev->newname));\n")
	fmt.Fprintf(&b, "    bpf_probe_read_user_str(ev->oldname, sizeof(ev->oldname), (void*)ctx->args[%d]);\n", oldIdx)
	fmt.Fprintf(&b, "    bpf_probe_read_user_str(ev->newname, sizeof(ev->newname), (void*)ctx->args[%d]);\n", newIdx)
	return b.String()
}

// generateExtraFcntl returns the fd/cmd/arg capture lines for fcntl events.
func generateExtraFcntl(f *Format) string {
	fdIdx := f.FieldNumber("fd")
	cmdIdx := f.FieldNumber("cmd")
	argIdx := f.FieldNumber("arg")
	return fmt.Sprintf(
		"    ev->fd = ctx->args[%d];\n    ev->cmd = ctx->args[%d];\n    ev->arg = ctx->args[%d];\n",
		fdIdx, cmdIdx, argIdx,
	)
}

func generateExtraSocket() string {
	return "    ev->family = (__s32)ctx->args[0];\n    ev->type = (__s32)ctx->args[1];\n    ev->protocol = (__s32)ctx->args[2];\n"
}

func generateExtraSocketpair(isEnter bool) string {
	if isEnter {
		return "    struct socketpair_ctx pending;\n    pending.usockvec = ctx->args[3];\n    pending.family = (__s32)ctx->args[0];\n    pending.type = (__s32)ctx->args[1];\n    pending.protocol = (__s32)ctx->args[2];\n    bpf_map_update_elem(&socketpair_ctx_map, &tid, &pending, BPF_ANY);\n    ev->family = pending.family;\n    ev->type = pending.type;\n    ev->protocol = pending.protocol;\n    ev->sv0 = -1;\n    ev->sv1 = -1;\n    ev->ret = 0;\n"
	}
	return "    __s32 family = -1;\n    __s32 type = -1;\n    __s32 protocol = -1;\n    __s32 sv0 = -1;\n    __s32 sv1 = -1;\n    struct socketpair_ctx *pending = bpf_map_lookup_elem(&socketpair_ctx_map, &tid);\n    if (pending) {\n        family = pending->family;\n        type = pending->type;\n        protocol = pending->protocol;\n        if (ctx->ret == 0 && pending->usockvec != 0) {\n            int sv[2];\n            if (bpf_probe_read_user(&sv, sizeof(sv), (void *)pending->usockvec) == 0) {\n                sv0 = (__s32)sv[0];\n                sv1 = (__s32)sv[1];\n            }\n        }\n        bpf_map_delete_elem(&socketpair_ctx_map, &tid);\n    }\n    ev->family = family;\n    ev->type = type;\n    ev->protocol = protocol;\n    ev->sv0 = sv0;\n    ev->sv1 = sv1;\n    ev->ret = ctx->ret;\n"
}

func generateExtraAccept(isEnter bool) string {
	if isEnter {
		return "    ev->fd = (__s32)ctx->args[0];\n    ev->ret = -1;\n"
	}
	return "    ev->fd = -1;\n    ev->ret = ctx->ret;\n"
}

func generateExtraPipe(f *Format, isEnter bool) string {
	if isEnter {
		flagsExpr := "0"
		if f.Name == "sys_enter_pipe2" {
			flagsExpr = "(__s32)ctx->args[1]"
		}
		return "    struct pipe_ctx pending;\n    pending.upipefd = ctx->args[0];\n    pending.flags = " + flagsExpr + ";\n    bpf_map_update_elem(&pipe_ctx_map, &tid, &pending, BPF_ANY);\n    ev->flags = pending.flags;\n    ev->fd0 = -1;\n    ev->fd1 = -1;\n    ev->ret = 0;\n"
	}
	return "    __s32 flags = 0;\n    __s32 fd0 = -1;\n    __s32 fd1 = -1;\n    struct pipe_ctx *pending = bpf_map_lookup_elem(&pipe_ctx_map, &tid);\n    if (pending) {\n        flags = pending->flags;\n        if (ctx->ret == 0 && pending->upipefd != 0) {\n            int pipefd[2];\n            if (bpf_probe_read_user(&pipefd, sizeof(pipefd), (void *)pending->upipefd) == 0) {\n                fd0 = (__s32)pipefd[0];\n                fd1 = (__s32)pipefd[1];\n            }\n        }\n        bpf_map_delete_elem(&pipe_ctx_map, &tid);\n    }\n    ev->flags = flags;\n    ev->fd0 = fd0;\n    ev->fd1 = fd1;\n    ev->ret = ctx->ret;\n"
}

func generateExtraEventfd(f *Format, isEnter bool) string {
	if isEnter {
		flagsExpr := "0"
		switch f.Name {
		case "sys_enter_eventfd2":
			flagsExpr = "(__s32)ctx->args[1]"
		case "sys_enter_fsmount":
			flagsExpr = "(__s32)ctx->args[1]"
		case "sys_enter_fsopen":
			flagsExpr = "(__s32)ctx->args[1]"
		}
		return "    __s32 flags = " + flagsExpr + ";\n    bpf_map_update_elem(&eventfd_flags_map, &tid, &flags, BPF_ANY);\n    ev->flags = flags;\n    ev->ret = -1;\n"
	}
	return "    __s32 flags = 0;\n    __s32 *pending = bpf_map_lookup_elem(&eventfd_flags_map, &tid);\n    if (pending) {\n        flags = *pending;\n        bpf_map_delete_elem(&eventfd_flags_map, &tid);\n    }\n    ev->flags = flags;\n    ev->ret = ctx->ret;\n"
}

func generateExtraEpollCtl() string {
	return "    ev->epfd = (__s32)ctx->args[0];\n    ev->op = (__s32)ctx->args[1];\n    ev->fd = (__s32)ctx->args[2];\n    ev->events = 0;\n    if (ctx->args[3] != 0) {\n        __u32 user_events = 0;\n        if (bpf_probe_read_user(&user_events, sizeof(user_events), (void *)ctx->args[3]) == 0) {\n            ev->events = user_events;\n        }\n    }\n"
}

func generateExtraTwoFd(name string) string {
	switch name {
	case "sys_enter_move_mount":
		return "    ev->fd_a = (__s32)ctx->args[0];\n    ev->fd_b = (__s32)ctx->args[2];\n    ev->extra = (__u64)ctx->args[4];\n"
	default:
		return "    ev->fd_a = (__s32)ctx->args[0];\n    ev->fd_b = (__s32)ctx->args[1];\n    ev->extra = (__u64)ctx->args[2];\n"
	}
}

func generateExtraPoll(name string) string {
	switch name {
	case "sys_enter_poll":
		return "    ev->nfds = (__s32)ctx->args[1];\n    ev->timeout_ns = -1;\n    __s32 timeout_ms = (__s32)ctx->args[2];\n    if (timeout_ms >= 0) {\n        ev->timeout_ns = ((__s64)timeout_ms) * 1000000LL;\n    }\n"
	case "sys_enter_ppoll":
		return "    ev->nfds = (__s32)ctx->args[1];\n    ev->timeout_ns = -1;\n    if (ctx->args[2] != 0) {\n        struct __ior_timespec {\n            __s64 tv_sec;\n            __s64 tv_nsec;\n        } ts = {};\n        if (bpf_probe_read_user(&ts, sizeof(ts), (void *)ctx->args[2]) == 0) {\n            ev->timeout_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;\n        }\n    }\n"
	case "sys_enter_select":
		return "    ev->nfds = (__s32)ctx->args[0];\n    ev->timeout_ns = -1;\n    if (ctx->args[4] != 0) {\n        struct __ior_timeval {\n            __s64 tv_sec;\n            __s64 tv_usec;\n        } tv = {};\n        if (bpf_probe_read_user(&tv, sizeof(tv), (void *)ctx->args[4]) == 0) {\n            ev->timeout_ns = tv.tv_sec * 1000000000LL + tv.tv_usec * 1000LL;\n        }\n    }\n"
	case "sys_enter_pselect6":
		return "    ev->nfds = (__s32)ctx->args[0];\n    ev->timeout_ns = -1;\n    if (ctx->args[4] != 0) {\n        struct __ior_timespec {\n            __s64 tv_sec;\n            __s64 tv_nsec;\n        } ts = {};\n        if (bpf_probe_read_user(&ts, sizeof(ts), (void *)ctx->args[4]) == 0) {\n            ev->timeout_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;\n        }\n    }\n"
	default:
		return "    ev->nfds = -1;\n    ev->timeout_ns = -1;\n"
	}
}

func generateExtraMem(name string) string {
	switch name {
	case "sys_enter_munmap":
		return "    ev->addr = (__u64)ctx->args[0];\n    ev->length = (__u64)ctx->args[1];\n    ev->length2 = 0;\n    ev->flags = 0;\n"
	case "sys_enter_mremap":
		return "    ev->addr = (__u64)ctx->args[0];\n    ev->length = (__u64)ctx->args[1];\n    ev->length2 = (__u64)ctx->args[2];\n    ev->flags = (__u64)ctx->args[3];\n"
	default:
		return "    ev->addr = 0;\n    ev->length = 0;\n    ev->length2 = 0;\n    ev->flags = 0;\n"
	}
}

func generateExtraSleep(name string) string {
	ptrExpr := "0"
	switch name {
	case "sys_enter_nanosleep":
		ptrExpr = "ctx->args[0]"
	case "sys_enter_clock_nanosleep":
		ptrExpr = "ctx->args[2]"
	}
	return "    ev->requested_ns = -1;\n    if (" + ptrExpr + " != 0) {\n        struct __ior_timespec {\n            __s64 tv_sec;\n            __s64 tv_nsec;\n        } ts = {};\n        if (bpf_probe_read_user(&ts, sizeof(ts), (void *)" + ptrExpr + ") == 0) {\n            ev->requested_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;\n        }\n    }\n"
}

// eventStructName returns the C struct name for a TracepointKind. The mapping
// is driven by kindRegistry so adding a new kind only requires a registry entry.
func eventStructName(kind TracepointKind) string {
	return lookupKind(kind).structName
}

func eventTypeConstant(kind TracepointKind, isEnter bool) string {
	prefix := "EXIT_"
	if isEnter {
		prefix = "ENTER_"
	}
	return prefix + strings.ToUpper(eventStructName(kind))
}
