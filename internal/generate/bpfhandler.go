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

	return renderHandler(handlerSpec{
		name:           f.Name,
		ctxStruct:      ctxStruct,
		eventStruct:    eventStruct,
		comment:        handlerComment(tp, eventStruct),
		eventTypeConst: eventTypeConstant(tp.Classification.Kind, isEnter),
		extra:          generateExtra(tp, isEnter),
		isEnter:        isEnter,
		// Noreturn syscalls (exit, exit_group, rt_sigreturn) get a special
		// enter hook that skips the syscall_enter_state_map write. Their exit
		// handler is suppressed (see codegen.go), so nothing would ever clear a
		// recorded enter-state entry; recording it would only leak stale
		// per-tid entries in the bounded map.
		noreturn: isEnter && isNoreturnSyscall(syscallName(f.Name)),
		// The explicit enter trace ID constant, so an exit handler does not
		// rely on numeric adjacency between kernel-assigned enter/exit IDs.
		enterName: enterConstForHandler(f.Name, isEnter),
		// Only an exit handler recovers a filename, and only for a syscall
		// whose enter side captured one. A sys_exit_* format is always just
		// "long ret", so the exit's own classification cannot tell us that -
		// EnterKind carries it across (see codegen.go).
		recoverFilename: !isEnter && kindRecoversFilename(tp.EnterKind),
	})
}

// handlerComment renders the /// reason line of a handler. It is also the line
// internal/c/generated_tracepoints_result.txt is derived from, so its shape is
// part of the committed artifact contract.
func handlerComment(tp GeneratedTracepoint, eventStruct string) string {
	if tp.Classification.Kind == KindRet {
		return fmt.Sprintf("%s (%s) (kind=%s)", eventStruct, ClassifyRet(tp.Format.Name), tp.Classification.Kind.MetadataName())
	}
	return fmt.Sprintf("%s (kind=%s)", eventStruct, tp.Classification.Kind.MetadataName())
}

// handlerSpec carries everything renderHandler needs for one tracepoint.
type handlerSpec struct {
	name            string
	ctxStruct       string
	eventStruct     string
	comment         string
	eventTypeConst  string
	extra           string
	isEnter         bool
	noreturn        bool
	enterName       string
	recoverFilename bool
}

// enterConstForHandler returns the C #define constant name for the
// corresponding enter tracepoint. For enter handlers it returns
// strings.ToUpper(name) directly; for exit handlers it replaces "EXIT"
// with "ENTER" so the generated code passes the explicit enter ID.
func enterConstForHandler(name string, isEnter bool) string {
	upper := strings.ToUpper(name)
	if isEnter {
		return upper
	}
	return strings.Replace(upper, "SYS_EXIT_", "SYS_ENTER_", 1)
}

// renderHandlerPrologue writes everything ahead of the ring-buffer reserve: the
// scope gate, the per-tid enter/exit hook, and - for the open kinds only - the
// two halves of the faulted-filename recovery. Both recovery lines are
// position-critical, which is why they live here rather than in the kind
// emitters: the take must precede ior_on_syscall_exit (which deletes this tid's
// enter-state entry) and the fixup must precede this handler's own reserve, so
// the ring buffer hands userspace the recovered name while the enter event of
// the same syscall is still pending and unpaired.
func renderHandlerPrologue(b *strings.Builder, h handlerSpec) {
	name, isEnter := h.name, h.isEnter
	fmt.Fprintf(b, "/// %s is a struct %s\n", name, h.comment)
	fmt.Fprintf(b, "SEC(\"tracepoint/syscalls/%s\")\n", name)
	fmt.Fprintf(b, "int handle_%s(struct %s *ctx) {\n", strings.ToLower(name), h.ctxStruct)
	b.WriteString("    __u32 pid, tid;\n")
	b.WriteString("    if (filter(&pid, &tid))\n")
	b.WriteString("        return 0;\n")
	b.WriteString("\n")
	if h.recoverFilename {
		fmt.Fprintf(b, "    __u64 pending_filename = ior_take_pending_filename(tid, %s);\n", h.enterName)
		b.WriteString("\n")
	}
	switch {
	case isEnter && h.noreturn:
		// Noreturn enter: only the sampling decision, no enter-state write. The
		// syscall never returns, so its exit handler is suppressed and nothing
		// would ever look up or delete a recorded enter-state entry. Skipping
		// the write avoids leaking stale per-tid entries in the bounded
		// syscall_enter_state_map; the enter null_event is still emitted below.
		fmt.Fprintf(b, "    if (!ior_on_noreturn_syscall_enter(%s))\n", strings.ToUpper(name))
	case isEnter:
		fmt.Fprintf(b, "    if (!ior_on_syscall_enter(tid, %s))\n", strings.ToUpper(name))
	default:
		fmt.Fprintf(b, "    if (!ior_on_syscall_exit(tid, %s, ctx->ret))\n", h.enterName)
	}
	b.WriteString("        return 0;\n")
	b.WriteString("\n")
	if h.recoverFilename {
		fmt.Fprintf(b, "    ior_emit_open_name_fixup(tid, %s, pending_filename);\n", h.enterName)
		b.WriteString("\n")
	}
}

func renderHandler(h handlerSpec) string {
	var b strings.Builder
	renderHandlerPrologue(&b, h)
	fmt.Fprintf(&b, "    struct %s *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct %s), 0);\n", h.eventStruct, h.eventStruct)
	// A NULL reserve means event_map is full: the event is lost right here.
	// Count it (ior_count_ringbuf_drop, internal/c/filter.c) so kernel-side
	// loss under backpressure is reported instead of vanishing silently
	// (audit findings D2 F1 / D9 Y2).
	b.WriteString("    if (!ev) {\n")
	b.WriteString("        ior_count_ringbuf_drop();\n")
	b.WriteString("        return 0;\n")
	b.WriteString("    }\n")
	b.WriteString("\n")
	fmt.Fprintf(&b, "    ev->event_type = %s;\n", h.eventTypeConst)
	fmt.Fprintf(&b, "    ev->trace_id = %s;\n", strings.ToUpper(h.name))
	b.WriteString("    ev->pid = pid;\n")
	b.WriteString("    ev->tid = tid;\n")
	b.WriteString("    ev->time = bpf_ktime_get_boot_ns();\n")
	if h.extra != "" {
		b.WriteString(h.extra)
	}
	b.WriteString("\n")
	b.WriteString("    bpf_ringbuf_submit(ev, 0);\n")
	b.WriteString("    return 0;\n")
	b.WriteString("}\n")
	return b.String()
}

// extraEmitter produces the kind-specific C body lines for a tracepoint handler.
// Each TracepointKind that needs extra fields registers an emitter in
// extraEmitters. Kinds not registered (or explicitly mapped to nil) emit nothing.
type extraEmitter func(tp GeneratedTracepoint, isEnter bool) string

// extraEmitters maps each TracepointKind to its emitter function.
// Adding a new kind requires only a new entry here plus, if needed, a new
// table-driven helper — no switch statement needs to grow.
var extraEmitters = map[TracepointKind]extraEmitter{
	KindFd:             func(tp GeneratedTracepoint, _ bool) string { return generateExtraFd(tp.Format) },
	KindDup3:           func(_ GeneratedTracepoint, _ bool) string { return generateExtraDup3() },
	KindOpenByHandleAt: func(_ GeneratedTracepoint, _ bool) string { return generateExtraOpenByHandleAt() },
	KindSocket:         func(_ GeneratedTracepoint, _ bool) string { return generateExtraSocket() },
	KindSocketpair:     func(_ GeneratedTracepoint, isEnter bool) string { return generateExtraSocketpair(isEnter) },
	KindAccept:         func(tp GeneratedTracepoint, isEnter bool) string { return generateExtraAccept(tp.Format, isEnter) },
	KindPipe:           func(tp GeneratedTracepoint, isEnter bool) string { return generateExtraPipe(tp.Format, isEnter) },
	KindEventfd:        func(tp GeneratedTracepoint, isEnter bool) string { return generateExtraEventfd(tp.Format, isEnter) },
	KindNamedEventfd:   func(tp GeneratedTracepoint, isEnter bool) string { return generateExtraEventfd(tp.Format, isEnter) },
	KindPidfd:          func(tp GeneratedTracepoint, isEnter bool) string { return generateExtraEventfd(tp.Format, isEnter) },
	KindEpollCtl:       func(_ GeneratedTracepoint, _ bool) string { return generateExtraEpollCtl() },
	KindTwoFd:          func(tp GeneratedTracepoint, _ bool) string { return generateExtraTwoFd(tp.Format.Name) },
	KindPoll:           func(tp GeneratedTracepoint, _ bool) string { return generateExtraPoll(tp.Format.Name) },
	KindMem:            func(tp GeneratedTracepoint, _ bool) string { return generateExtraMem(tp.Format.Name) },
	KindMmap:           func(_ GeneratedTracepoint, _ bool) string { return generateExtraMmap() },
	KindSleep:          func(tp GeneratedTracepoint, _ bool) string { return generateExtraSleep(tp.Format.Name) },
	KindKeyctl:         func(tp GeneratedTracepoint, _ bool) string { return generateExtraKeyctl(tp.Format.Name) },
	KindPtrace:         func(_ GeneratedTracepoint, _ bool) string { return generateExtraPtrace() },
	KindPerfOpen:       func(_ GeneratedTracepoint, _ bool) string { return generateExtraPerfOpen() },
	KindBpf:            func(_ GeneratedTracepoint, _ bool) string { return generateExtraBpf() },
	KindOpen:           func(tp GeneratedTracepoint, _ bool) string { return generateExtraOpen(tp.Format) },
	KindMqOpen:         func(tp GeneratedTracepoint, _ bool) string { return generateExtraMqOpen(tp.Format) },
	KindOpenTree:       func(tp GeneratedTracepoint, _ bool) string { return generateExtraOpen(tp.Format) },
	KindExec:           func(tp GeneratedTracepoint, _ bool) string { return generateExtraExec(tp.Format) },
	KindPathname:       func(tp GeneratedTracepoint, _ bool) string { return generateExtraPathname(tp, tp.Format) },
	KindFdPathname:     func(tp GeneratedTracepoint, _ bool) string { return generateExtraFdPathname(tp.Format) },
	KindName:           func(tp GeneratedTracepoint, _ bool) string { return generateExtraName(tp.Format) },
	KindFcntl:          func(tp GeneratedTracepoint, _ bool) string { return generateExtraFcntl(tp.Format) },
	KindRet:            func(tp GeneratedTracepoint, _ bool) string { return generateExtraRet(tp.Format) },
	// KindNull emits no extra fields — absence from the map means empty output.
}

// generateExtra returns the kind-specific C body lines for a tracepoint handler
// by looking up the emitter registered in extraEmitters. Kinds without a
// registered emitter (e.g. KindNull) produce an empty string.
func generateExtra(tp GeneratedTracepoint, isEnter bool) string {
	if emit, ok := extraEmitters[tp.Classification.Kind]; ok {
		return emit(tp, isEnter)
	}
	return ""
}

// generateExtraRet emits the ret/ret_type capture for exit-side ret events.
func generateExtraRet(f *Format) string {
	return fmt.Sprintf("    ev->ret = ctx->ret;\n    ev->ret_type = %s;\n", ClassifyRet(f.Name))
}

// generateExtraDup3 emits fd and flags from fixed argument positions.
func generateExtraDup3() string {
	return "    ev->fd = (__s32)ctx->args[0];\n    ev->flags = (__s32)ctx->args[2];\n"
}

// generateExtraOpenByHandleAt emits flags from argument position 2.
func generateExtraOpenByHandleAt() string {
	return "    ev->flags = (__s32)ctx->args[2];\n"
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

func generateExtraExec(f *Format) string {
	filenameIdx := f.FieldNumber("filename")
	dirfdIdx := f.FieldNumber("dfd")
	if dirfdIdx < 0 {
		dirfdIdx = f.FieldNumber("fd")
	}
	if dirfdIdx < 0 {
		dirfdIdx = f.FieldNumber("dirfd")
	}
	flagsIdx := f.FieldNumber("flags")
	if filenameIdx < 0 {
		filenameIdx = 0
	}
	var b strings.Builder
	b.WriteString("    __builtin_memset(&(ev->filename), 0, sizeof(ev->filename) + sizeof(ev->comm));\n")
	fmt.Fprintf(&b, "    bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)ctx->args[%d]);\n", filenameIdx)
	b.WriteString("    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));\n")
	if dirfdIdx > -1 {
		fmt.Fprintf(&b, "    ev->dirfd = (__s32)ctx->args[%d];\n", dirfdIdx)
	} else if f.Name == "sys_enter_execveat" {
		b.WriteString("    ev->dirfd = (__s32)ctx->args[0];\n")
	} else {
		b.WriteString("    ev->dirfd = -1;\n")
	}
	if flagsIdx > -1 {
		fmt.Fprintf(&b, "    ev->flags = (__s32)ctx->args[%d];\n", flagsIdx)
	} else {
		b.WriteString("    ev->flags = 0;\n")
	}
	return b.String()
}

func generateExtraOpenWithFields(f *Format, pathnameField, flagsField string) string {
	filenameIdx := f.FieldNumber(pathnameField)
	var b strings.Builder
	b.WriteString("    __builtin_memset(&(ev->filename), 0, sizeof(ev->filename) + sizeof(ev->comm));\n")
	// bpf_probe_read_user_str cannot fault, so it returns -EFAULT whenever the
	// path string's page is not resident yet - routinely the case for the first
	// open a program makes through a freshly mmap'ed library. Stash the pointer
	// on failure; the exit handler re-reads it once the kernel has faulted the
	// page in (ior_take_pending_filename / ior_emit_open_name_fixup in
	// internal/c/filter.c). Without this the row printed "E:name", the
	// descriptor was registered under the empty string, and -path could not
	// match a name that was never captured.
	fmt.Fprintf(&b, "    if (ctx->args[%d] == 0) {\n", filenameIdx)
	b.WriteString("        ev->filename_status = PATH_READ_NULL;\n")
	b.WriteString("    } else {\n")
	b.WriteString("        ev->filename_status = PATH_READ_OK;\n")
	fmt.Fprintf(&b, "        if (bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)ctx->args[%d]) < 0) {\n", filenameIdx)
	b.WriteString("            ev->filename_status = PATH_READ_FAILED;\n")
	fmt.Fprintf(&b, "            ior_stash_pending_filename(tid, ctx->args[%d]);\n", filenameIdx)
	b.WriteString("        }\n")
	b.WriteString("    }\n")
	b.WriteString("    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));\n")
	writeDirfdCapture(&b, f, "dirfd", "dfd", "dirfd")
	b.WriteString("    ev->schema_version = OPEN_EVENT_SCHEMA_VERSION;\n")
	b.WriteString("    ev->schema_reserved = 0;\n")
	writeOpenFlagsCapture(&b, f, flagsField)
	return b.String()
}

// writeOpenFlagsCapture records the open(2) flags word. openat2 is exceptional:
// its flags are the first u64 in the userspace struct open_how at args[2], not
// a direct tracepoint field. Keep the unknown sentinel when the pointer is NULL
// or the nofault read fails.
func writeOpenFlagsCapture(b *strings.Builder, f *Format, flagsField string) {
	if flagsIdx := f.FieldNumber(flagsField); flagsIdx >= 0 {
		fmt.Fprintf(b, "    ev->flags = ctx->args[%d];\n", flagsIdx)
		return
	}

	b.WriteString("    ev->flags = -1;\n")
	if f.Name != "sys_enter_openat2" {
		return
	}
	howIdx := f.FieldNumber("how")
	if howIdx < 0 {
		return
	}
	fmt.Fprintf(b, "    if (ctx->args[%d] != 0) {\n", howIdx)
	b.WriteString("        __u64 open_how_flags = 0;\n")
	fmt.Fprintf(b, "        if (bpf_probe_read_user(&open_how_flags, sizeof(open_how_flags), (void *)ctx->args[%d]) == 0) {\n", howIdx)
	b.WriteString("            ev->flags = (__s32)open_how_flags;\n")
	b.WriteString("        }\n")
	b.WriteString("    }\n")
}

// generateExtraFdPathname preserves both the notification group and its target.
// Mark flags are syscall metadata, never descriptor open flags.
func generateExtraFdPathname(f *Format) string {
	var b strings.Builder
	b.WriteString("    ev->fd = (__s32)ctx->args[0];\n")
	b.WriteString("    __builtin_memset(&(ev->pathname), 0, sizeof(ev->pathname));\n")
	writePathReadCapture(&b, "pathname", "pathname_status", f.FieldNumber("pathname"))
	writeDirfdCapture(&b, f, "dirfd", "dfd")
	if f.Name == "sys_enter_fanotify_mark" {
		writeArgumentCapture(&b, f, "flags", "flags")
	} else {
		b.WriteString("    ev->flags = 0;\n")
	}
	b.WriteString("    ev->schema_version = FD_PATH_EVENT_SCHEMA_VERSION;\n")
	return b.String()
}

// generateExtraPathname returns the pathname capture lines for path-family events.
func generateExtraPathname(tp GeneratedTracepoint, f *Format) string {
	fieldName := tp.Classification.PathnameField
	fieldIdx := f.FieldNumber(fieldName)
	var b strings.Builder
	b.WriteString("    __builtin_memset(&(ev->pathname), 0, sizeof(ev->pathname));\n")
	writePathReadCapture(&b, "pathname", "pathname_status", fieldIdx)
	writeDirfdCapture(&b, f, "dirfd", "dfd", "dirfd")
	writePathFlagsCapture(&b, f)
	writePathTargetCapture(&b, f)
	b.WriteString("    ev->schema_version = PATH_EVENT_SCHEMA_VERSION;\n")
	return b.String()
}

// writePathTargetCapture records whether a successful syscall necessarily
// validated its path target. Most path syscalls do. utimensat is exceptional:
// when both timestamps are UTIME_OMIT the kernel returns success without
// validating the pathname, dirfd, or flags. A nofault read failure is kept
// distinct and fails closed in userspace.
func writePathTargetCapture(b *strings.Builder, f *Format) {
	b.WriteString("    ev->target_status = PATH_TARGET_REQUIRED;\n")
	if f.Name != "sys_enter_utimensat" {
		return
	}
	timesIdx := f.FieldNumber("utimes")
	if timesIdx < 0 {
		timesIdx = f.FieldNumber("times")
	}
	if timesIdx < 0 {
		b.WriteString("    ev->target_status = PATH_TARGET_UNKNOWN; // timespec argument not found\n")
		return
	}
	b.WriteString("    struct __kernel_timespec ior_times[2] = {};\n")
	fmt.Fprintf(b, "    if (ctx->args[%d] != 0) {\n", timesIdx)
	fmt.Fprintf(b, "        if (bpf_probe_read_user(&ior_times, sizeof(ior_times), (void *)ctx->args[%d]) < 0) {\n", timesIdx)
	b.WriteString("            ev->target_status = PATH_TARGET_UNKNOWN;\n")
	b.WriteString("        } else if (IOR_UTIME_OMIT == ior_times[0].tv_nsec &&\n")
	b.WriteString("                   IOR_UTIME_OMIT == ior_times[1].tv_nsec) {\n")
	b.WriteString("            ev->target_status = PATH_TARGET_SKIPPED;\n")
	b.WriteString("        }\n")
	b.WriteString("    }\n")
}

// generateExtraName returns the oldname/newname capture lines for rename/link-family events.
func generateExtraName(f *Format) string {
	oldIdx := f.FieldNumber("oldname")
	newIdx := f.FieldNumber("newname")
	var b strings.Builder
	b.WriteString("    __builtin_memset(&(ev->oldname), 0, sizeof(ev->oldname) + sizeof(ev->newname));\n")
	writePathReadCapture(&b, "oldname", "oldname_status", oldIdx)
	writePathReadCapture(&b, "newname", "newname_status", newIdx)
	writeDirfdCapture(&b, f, "olddirfd", "olddfd", "olddirfd")
	writeDirfdCapture(&b, f, "newdirfd", "newdfd", "newdirfd")
	if f.Name == "sys_enter_linkat" {
		writeArgumentCapture(&b, f, "flags", "flags", "flag")
	} else {
		b.WriteString("    ev->flags = 0;\n")
	}
	b.WriteString("    ev->schema_version = NAME_EVENT_SCHEMA_VERSION;\n")
	return b.String()
}

var pathFlagSyscalls = map[string]struct{}{
	"sys_enter_faccessat2":        {},
	"sys_enter_fchmodat2":         {},
	"sys_enter_fchownat":          {},
	"sys_enter_file_getattr":      {},
	"sys_enter_file_setattr":      {},
	"sys_enter_fspick":            {},
	"sys_enter_getxattrat":        {},
	"sys_enter_listxattrat":       {},
	"sys_enter_mount_setattr":     {},
	"sys_enter_name_to_handle_at": {},
	"sys_enter_newfstatat":        {},
	"sys_enter_removexattrat":     {},
	"sys_enter_setxattrat":        {},
	"sys_enter_statx":             {},
	"sys_enter_utimensat":         {},
}

func writePathFlagsCapture(b *strings.Builder, f *Format) {
	if _, ok := pathFlagSyscalls[f.Name]; !ok {
		b.WriteString("    ev->flags = 0;\n")
		return
	}
	writeArgumentCapture(b, f, "flags", "flags", "flag", "at_flags")
}

func writeArgumentCapture(b *strings.Builder, f *Format, eventField string, formatFields ...string) {
	for _, field := range formatFields {
		if idx := f.FieldNumber(field); idx >= 0 {
			fmt.Fprintf(b, "    ev->%s = (__u32)ctx->args[%d];\n", eventField, idx)
			return
		}
	}
	b.WriteString("    ev->" + eventField + " = 0;\n")
}

// writePathReadCapture distinguishes all three results that otherwise leave a
// zero-filled event string: a valid empty string, an actual NULL pointer, and
// a failed nofault read of a non-NULL pointer. The probe remains directly in an
// if guard so the independent syscall-semantics oracle can verify its source
// argument and destination.
func writePathReadCapture(b *strings.Builder, eventField, statusField string, argIdx int) {
	fmt.Fprintf(b, "    if (ctx->args[%d] == 0) {\n", argIdx)
	fmt.Fprintf(b, "        ev->%s = PATH_READ_NULL;\n", statusField)
	b.WriteString("    } else {\n")
	fmt.Fprintf(b, "        ev->%s = PATH_READ_OK;\n", statusField)
	fmt.Fprintf(b, "        if (bpf_probe_read_user_str(ev->%s, sizeof(ev->%s), (void*)ctx->args[%d]) < 0)\n", eventField, eventField, argIdx)
	fmt.Fprintf(b, "            ev->%s = PATH_READ_FAILED;\n", statusField)
	b.WriteString("    }\n")
}

// writeDirfdCapture emits one directory-fd field, using AT_FDCWD when the
// syscall has no such argument. The sentinel makes ordinary absolute/relative
// path syscalls share the same userspace resolution path without accidentally
// resolving argument zero as a descriptor.
func writeDirfdCapture(b *strings.Builder, f *Format, eventField string, formatFields ...string) {
	for _, field := range formatFields {
		if idx := f.FieldNumber(field); idx >= 0 {
			fmt.Fprintf(b, "    ev->%s = (__s32)ctx->args[%d];\n", eventField, idx)
			return
		}
	}
	fmt.Fprintf(b, "    ev->%s = -100; // AT_FDCWD: no dirfd argument\n", eventField)
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

func generateExtraAccept(f *Format, isEnter bool) string {
	if isEnter {
		flagsExpr := "0"
		if flagsIdx := f.FieldNumber("flags"); flagsIdx >= 0 {
			flagsExpr = fmt.Sprintf("(__s32)ctx->args[%d]", flagsIdx)
		}
		return "    ev->fd = (__s32)ctx->args[0];\n" +
			"    ev->ret = -1;\n" +
			"    ev->flags = " + flagsExpr + ";\n" +
			"    ev->schema_version = ACCEPT_EVENT_SCHEMA_VERSION;\n"
	}
	return "    ev->fd = -1;\n" +
		"    ev->ret = ctx->ret;\n" +
		"    ev->flags = -1;\n" +
		"    ev->schema_version = ACCEPT_EVENT_SCHEMA_VERSION;\n"
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

// eventfdFlagsExpr maps eventfd-family enter syscall names to the C expression
// that captures the flags argument. Syscalls not listed here default to "0".
// To add a new eventfd-like syscall, register its flags expression below.
var eventfdFlagsExpr = map[string]string{
	"sys_enter_epoll_create":            "0", // epoll_create(size) has no flags argument
	"sys_enter_epoll_create1":           "(__s32)ctx->args[0]",
	"sys_enter_inotify_init1":           "(__s32)ctx->args[0]",
	"sys_enter_fanotify_init":           "(__s32)ctx->args[0]",
	"sys_enter_landlock_create_ruleset": "(__s32)ctx->args[2]",
	"sys_enter_eventfd2":                "(__s32)ctx->args[1]",
	"sys_enter_memfd_create":            "(__s32)ctx->args[1]",
	"sys_enter_memfd_secret":            "(__s32)ctx->args[0]",
	"sys_enter_userfaultfd":             "(__s32)ctx->args[0]",
	"sys_enter_signalfd4":               "(__s32)ctx->args[3]",
	"sys_enter_timerfd_create":          "(__s32)ctx->args[1]",
	"sys_enter_pidfd_open":              "(__s32)ctx->args[1]", // pidfd_open(pid, flags): flags at args[1]
	"sys_enter_fsmount":                 "(__s32)ctx->args[1]",
	"sys_enter_fsopen":                  "(__s32)ctx->args[1]",
}

// eventfdFDExpr maps eventfd-family syscalls that can update an existing
// descriptor to the argument carrying that descriptor. The other syscalls
// always create a descriptor and use -1.
var eventfdFDExpr = map[string]string{
	"sys_enter_signalfd":  "(__s32)ctx->args[0]",
	"sys_enter_signalfd4": "(__s32)ctx->args[0]",
	"sys_enter_fsmount":   "(__s32)ctx->args[0]",
}

var eventfdFilenameField = map[string]string{
	"sys_enter_memfd_create": "uname",
	"sys_enter_fsopen":       "_fs_name",
}

// generateExtraEventfd emits the enter/exit body for eventfd-family syscalls.
// Enter: reads the flags expression from eventfdFlagsExpr (defaults to "0"),
// stashes it in eventfd_flags_map, captures an existing descriptor when the
// syscall accepts one, and sets ev->ret = -1. Exit retrieves the stashed flags
// from the map and captures ctx->ret.
func generateExtraEventfd(f *Format, isEnter bool) string {
	if isEnter {
		flagsExpr := eventfdFlagsExpr[f.Name] // empty string if not found
		if flagsExpr == "" {
			flagsExpr = "0"
		}
		fdExpr := eventfdFDExpr[f.Name]
		if fdExpr == "" {
			fdExpr = "-1"
		}
		var b strings.Builder
		b.WriteString("    __builtin_memset(&(ev->filename), 0, sizeof(ev->filename));\n")
		if field := eventfdFilenameField[f.Name]; field != "" {
			idx := f.FieldNumber(field)
			if idx < 0 {
				idx = 0
			}
			fmt.Fprintf(&b, "    if (ctx->args[%d] == 0) {\n", idx)
			b.WriteString("        ev->filename_status = PATH_READ_NULL;\n")
			b.WriteString("    } else {\n")
			b.WriteString("        ev->filename_status = PATH_READ_OK;\n")
			fmt.Fprintf(&b, "        if (bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)ctx->args[%d]) < 0) {\n", idx)
			b.WriteString("            ev->filename_status = PATH_READ_FAILED;\n")
			fmt.Fprintf(&b, "            ior_stash_pending_filename(tid, ctx->args[%d]);\n", idx)
			b.WriteString("        }\n    }\n")
		} else {
			b.WriteString("    ev->filename_status = PATH_READ_NULL;\n")
		}
		b.WriteString("    ev->schema_version = EVENTFD_EVENT_SCHEMA_VERSION;\n")
		fmt.Fprintf(&b, "    __s32 flags = %s;\n", flagsExpr)
		b.WriteString("    bpf_map_update_elem(&eventfd_flags_map, &tid, &flags, BPF_ANY);\n")
		b.WriteString("    ev->flags = flags;\n    ev->ret = -1;\n")
		fmt.Fprintf(&b, "    ev->fd = %s;\n", fdExpr)
		return b.String()
	}
	return "    __builtin_memset(&(ev->filename), 0, sizeof(ev->filename));\n    ev->filename_status = PATH_READ_NULL;\n    ev->schema_version = EVENTFD_EVENT_SCHEMA_VERSION;\n    __s32 flags = 0;\n    __s32 *pending = bpf_map_lookup_elem(&eventfd_flags_map, &tid);\n    if (pending) {\n        flags = *pending;\n        bpf_map_delete_elem(&eventfd_flags_map, &tid);\n    }\n    ev->flags = flags;\n    ev->ret = ctx->ret;\n    ev->fd = -1;\n"
}

func generateExtraEpollCtl() string {
	return "    ev->epfd = (__s32)ctx->args[0];\n    ev->op = (__s32)ctx->args[1];\n    ev->fd = (__s32)ctx->args[2];\n    ev->events = 0;\n    if (ctx->args[3] != 0) {\n        __u32 user_events = 0;\n        if (bpf_probe_read_user(&user_events, sizeof(user_events), (void *)ctx->args[3]) == 0) {\n            ev->events = user_events;\n        }\n    }\n"
}

// twoFdFieldSpec describes argument positions for a two-fd syscall.
// Each expression is a C snippet for the corresponding event field.
type twoFdFieldSpec struct {
	fdA   string // expression for ev->fd_a
	fdB   string // expression for ev->fd_b
	extra string // expression for ev->extra
}

// twoFdOverrides maps syscall names that deviate from the default argument
// layout (args[0], args[1], args[2]). To add a new two-fd syscall with
// non-standard positions, register it here.
var twoFdOverrides = map[string]twoFdFieldSpec{
	"sys_enter_move_mount": {fdA: "(__s32)ctx->args[0]", fdB: "(__s32)ctx->args[2]", extra: "(__u64)ctx->args[4]"},
	// Only KCMP_FILE (0) interprets both indices as descriptors. The primary
	// descriptor belongs to pid1, not necessarily the caller. At sys_enter,
	// compare pid1 with the caller's namespace-local TGID and pack the stable
	// host owner only for a self comparison; userspace must not repeat this
	// lifetime-sensitive proof through /proc. The low word remains the type.
	// Older payloads copied the whole type argument, including unspecified upper
	// bits, so their schema cannot safely attribute a file even when those bits
	// resemble an owner.
	"sys_enter_kcmp": {
		fdA:   "(__u32)ctx->args[2] == 0 ? (__s32)ctx->args[3] : -1",
		fdB:   "(__u32)ctx->args[2] == 0 ? (__s32)ctx->args[4] : -1",
		extra: "((__u64)(ior_kcmp_pid_is_current((__s32)ctx->args[0]) ? pid : 0) << 32) | (__u32)ctx->args[2]",
	},
}

// twoFdDefault is the fallback for two-fd syscalls not in twoFdOverrides.
var twoFdDefault = twoFdFieldSpec{
	fdA:   "(__s32)ctx->args[0]",
	fdB:   "(__s32)ctx->args[1]",
	extra: "(__u64)ctx->args[2]",
}

// generateExtraTwoFd emits the three-field body for two-fd syscalls.
// Syscalls with non-standard argument positions are in twoFdOverrides;
// all others use twoFdDefault.
func generateExtraTwoFd(name string) string {
	spec, ok := twoFdOverrides[name]
	if !ok {
		spec = twoFdDefault
	}
	var b strings.Builder
	fmt.Fprintf(&b, "    ev->fd_a = %s;\n    ev->fd_b = %s;\n    ev->extra = %s;\n",
		spec.fdA, spec.fdB, spec.extra)
	b.WriteString("    __builtin_memset(&(ev->oldname), 0, sizeof(ev->oldname) + sizeof(ev->newname));\n")
	if name == "sys_enter_move_mount" {
		writePathReadCapture(&b, "oldname", "oldname_status", 1)
		writePathReadCapture(&b, "newname", "newname_status", 3)
	} else {
		b.WriteString("    ev->oldname_status = PATH_READ_NULL;\n    ev->newname_status = PATH_READ_NULL;\n")
	}
	b.WriteString("    ev->schema_version = TWO_FD_EVENT_SCHEMA_VERSION;\n")
	return b.String()
}

func generateExtraBpf() string {
	return "    ev->cmd = (__u32)ctx->args[0];\n"
}

// pollTimeoutStyle describes how the poll-family syscall captures its timeout.
type pollTimeoutStyle int

const (
	// pollTimeoutNone means no known timeout capture; emit defaults.
	pollTimeoutNone pollTimeoutStyle = iota
	// pollTimeoutMillis means the timeout is an __s32 millisecond value.
	pollTimeoutMillis
	// pollTimeoutTimespec means the timeout is a pointer to a timespec struct.
	pollTimeoutTimespec
	// pollTimeoutTimeval means the timeout is a pointer to a timeval struct.
	pollTimeoutTimeval
)

// pollFieldSpec describes argument positions and timeout style for a poll
// syscall. nfdsArgIdx is the ctx->args index for nfds; timeoutArgIdx is the
// index for the timeout argument.
type pollFieldSpec struct {
	nfdsArgIdx    int
	timeoutArgIdx int
	timeoutStyle  pollTimeoutStyle
}

// pollOverrides maps poll-family syscall names to their argument layout.
// To add a new poll variant, register it here instead of editing a switch.
var pollOverrides = map[string]pollFieldSpec{
	"sys_enter_poll":     {nfdsArgIdx: 1, timeoutArgIdx: 2, timeoutStyle: pollTimeoutMillis},
	"sys_enter_ppoll":    {nfdsArgIdx: 1, timeoutArgIdx: 2, timeoutStyle: pollTimeoutTimespec},
	"sys_enter_select":   {nfdsArgIdx: 0, timeoutArgIdx: 4, timeoutStyle: pollTimeoutTimeval},
	"sys_enter_pselect6": {nfdsArgIdx: 0, timeoutArgIdx: 4, timeoutStyle: pollTimeoutTimespec},
}

// generateExtraPoll emits the nfds/timeout_ns capture body for poll-family
// syscalls. Unregistered names get sensible defaults (-1, -1).
func generateExtraPoll(name string) string {
	spec, ok := pollOverrides[name]
	if !ok {
		return "    ev->nfds = -1;\n    ev->timeout_ns = -1;\n"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "    ev->nfds = (__s32)ctx->args[%d];\n", spec.nfdsArgIdx)
	b.WriteString("    ev->timeout_ns = -1;\n")
	b.WriteString(pollTimeoutBody(spec.timeoutArgIdx, spec.timeoutStyle))
	return b.String()
}

// pollTimeoutBody returns the C snippet that reads the timeout from the
// specified argument index using the given style (millis, timespec, timeval).
func pollTimeoutBody(argIdx int, style pollTimeoutStyle) string {
	switch style {
	case pollTimeoutMillis:
		return fmt.Sprintf(
			"    __s32 timeout_ms = (__s32)ctx->args[%d];\n"+
				"    if (timeout_ms >= 0) {\n"+
				"        ev->timeout_ns = ((__s64)timeout_ms) * 1000000LL;\n"+
				"    }\n", argIdx)
	case pollTimeoutTimespec:
		return fmt.Sprintf(
			"    if (ctx->args[%d] != 0) {\n"+
				"        struct __ior_timespec {\n"+
				"            __s64 tv_sec;\n"+
				"            __s64 tv_nsec;\n"+
				"        } ts = {};\n"+
				"        if (bpf_probe_read_user(&ts, sizeof(ts), (void *)ctx->args[%d]) == 0) {\n"+
				"            ev->timeout_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;\n"+
				"        }\n"+
				"    }\n", argIdx, argIdx)
	case pollTimeoutTimeval:
		return fmt.Sprintf(
			"    if (ctx->args[%d] != 0) {\n"+
				"        struct __ior_timeval {\n"+
				"            __s64 tv_sec;\n"+
				"            __s64 tv_usec;\n"+
				"        } tv = {};\n"+
				"        if (bpf_probe_read_user(&tv, sizeof(tv), (void *)ctx->args[%d]) == 0) {\n"+
				"            ev->timeout_ns = tv.tv_sec * 1000000000LL + tv.tv_usec * 1000LL;\n"+
				"        }\n"+
				"    }\n", argIdx, argIdx)
	default:
		return ""
	}
}

// memFieldSpec describes the four fields captured for a memory syscall.
// Each expression is a C snippet; empty means the field defaults to "0".
// To add a new memory syscall, register it in memFieldOverrides below.
type memFieldSpec struct {
	addr    string // expression for ev->addr   (default "0")
	length  string // expression for ev->length  (default "0")
	length2 string // expression for ev->length2 (default "0")
	flags   string // expression for ev->flags   (default "0")
}

// memFieldOverrides maps syscall names to per-field C expressions.
// Only syscalls whose arguments differ from all-zeros need an entry;
// the default (unregistered) case emits all zeroes.
var memFieldOverrides = map[string]memFieldSpec{
	"sys_enter_mprotect":         {addr: "(__u64)ctx->args[0]", length: "(__u64)ctx->args[1]", flags: "(__u64)ctx->args[2]"},
	"sys_enter_msync":            {addr: "(__u64)ctx->args[0]", length: "(__u64)ctx->args[1]", flags: "(__u64)ctx->args[2]"},
	"sys_enter_madvise":          {addr: "(__u64)ctx->args[0]", length: "(__u64)ctx->args[1]", flags: "(__u64)ctx->args[2]"},
	"sys_enter_pkey_mprotect":    {addr: "(__u64)ctx->args[0]", length: "(__u64)ctx->args[1]", length2: "(__u64)ctx->args[3]", flags: "(__u64)ctx->args[2]"},
	"sys_enter_brk":              {addr: "(__u64)ctx->args[0]"},
	"sys_enter_munmap":           {addr: "(__u64)ctx->args[0]", length: "(__u64)ctx->args[1]"},
	"sys_enter_mremap":           {addr: "(__u64)ctx->args[0]", length: "(__u64)ctx->args[1]", length2: "(__u64)ctx->args[2]", flags: "(__u64)ctx->args[3]"},
	"sys_enter_mincore":          {addr: "(__u64)ctx->args[0]", length: "(__u64)ctx->args[1]"},
	"sys_enter_remap_file_pages": {addr: "(__u64)ctx->args[0]", length: "(__u64)ctx->args[1]", length2: "(__u64)ctx->args[3]", flags: "(__u64)ctx->args[4]"},
	"sys_enter_mlock":            {addr: "(__u64)ctx->args[0]", length: "(__u64)ctx->args[1]"},
	"sys_enter_mlock2":           {addr: "(__u64)ctx->args[0]", length: "(__u64)ctx->args[1]", flags: "(__u64)ctx->args[2]"},
	"sys_enter_munlock":          {addr: "(__u64)ctx->args[0]", length: "(__u64)ctx->args[1]"},
	"sys_enter_mseal":            {addr: "(__u64)ctx->args[0]", length: "(__u64)ctx->args[1]", flags: "(__u64)ctx->args[2]"},
	"sys_enter_map_shadow_stack": {addr: "(__u64)ctx->args[0]", length: "(__u64)ctx->args[1]", flags: "(__u64)ctx->args[2]"},
}

// generateExtraMem emits the four-field memory event body from memFieldOverrides.
// Unregistered syscalls get all-zero defaults.
func generateExtraMem(name string) string {
	spec := memFieldOverrides[name] // zero-value memFieldSpec if not found
	return fmt.Sprintf("    ev->addr = %s;\n    ev->length = %s;\n    ev->length2 = %s;\n    ev->flags = %s;\n",
		memExpr(spec.addr), memExpr(spec.length), memExpr(spec.length2), memExpr(spec.flags))
}

// generateExtraMmap emits mmap's complete mapping semantics. mmap is the one
// memory-range syscall that also needs descriptor resolution, so it has a
// dedicated event rather than widening every mem_event with fd and prot.
func generateExtraMmap() string {
	return "    ev->addr = (__u64)ctx->args[0];\n" +
		"    ev->length = (__u64)ctx->args[1];\n" +
		"    ev->prot = (__u64)ctx->args[2];\n" +
		"    ev->flags = (__u64)ctx->args[3];\n" +
		"    ev->fd = (__s32)ctx->args[4];\n"
}

// memExpr returns expr if non-empty, otherwise the literal "0".
func memExpr(expr string) string {
	if expr == "" {
		return "0"
	}
	return expr
}

// sleepSpec describes how a sleep-family syscall exposes its requested sleep
// duration.
//
//   - ptr      is the C expression pointing at the user-space timespec struct.
//   - flagsArg is the C expression for the flags argument that may carry
//     TIMER_ABSTIME; it is empty for syscalls whose request is always relative.
type sleepSpec struct {
	ptr      string
	flagsArg string
}

// sleepTimespecPtr maps sleep-family syscall names to their timespec pointer and
// (where applicable) flags-argument expressions. Syscalls not listed default to
// ptr "0" (no pointer), which makes the generated code skip the probe_read_user
// call. To add a new sleep-like syscall, register it here.
//
// nanosleep(const struct timespec *req, struct timespec *rem) is ALWAYS a
// relative sleep, so it has no flagsArg. clock_nanosleep(clockid_t clockid,
// int flags, const struct timespec *request, struct timespec *remain) takes a
// flags argument: when flags & TIMER_ABSTIME is set, *request is an ABSOLUTE
// wakeup time against clockid, not a relative duration — see generateExtraSleep.
var sleepTimespecPtr = map[string]sleepSpec{
	"sys_enter_nanosleep":       {ptr: "ctx->args[0]"},
	"sys_enter_clock_nanosleep": {ptr: "ctx->args[2]", flagsArg: "ctx->args[1]"},
}

// timerAbstimeFlag is the Linux TIMER_ABSTIME flag value (uapi/linux/time.h).
// When set in clock_nanosleep's flags argument, the request timespec is an
// absolute wakeup time rather than a relative duration.
const timerAbstimeFlag = "1 /* TIMER_ABSTIME */"

// generateExtraSleep emits the requested_ns capture body for sleep-family
// syscalls. The timespec pointer (and optional flags) expression come from
// sleepTimespecPtr.
//
// requested_ns defaults to the -1 sentinel (the same value used for a
// null/unreadable timespec pointer). For relative sleeps we overwrite it with
// tv_sec*1e9 + tv_nsec. For an absolute sleep (clock_nanosleep with
// TIMER_ABSTIME set) the request timespec is an absolute clock value, NOT a
// duration; computing tv_sec*1e9 + tv_nsec there would export a bogus
// multi-decade "sleep duration". Deriving the true relative duration would
// require reading the current time of the (variable) clockid in BPF, which is
// racy and clock-dependent. Instead we leave the -1 sentinel so downstream
// consumers (CSV/parquet/stream) report "unknown" rather than a misleading
// value.
func generateExtraSleep(name string) string {
	spec := sleepTimespecPtr[name] // zero value (ptr "") if not found
	ptrExpr := spec.ptr
	if ptrExpr == "" {
		ptrExpr = "0"
	}

	compute := "            ev->requested_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;\n"
	if spec.flagsArg != "" {
		// Absolute sleeps keep the -1 sentinel; only relative sleeps get a
		// computed duration.
		compute = "            if ((" + spec.flagsArg + " & " + timerAbstimeFlag + ") == 0) {\n" +
			"                ev->requested_ns = ts.tv_sec * 1000000000LL + ts.tv_nsec;\n" +
			"            }\n"
	}

	return "    ev->requested_ns = -1;\n    if (" + ptrExpr + " != 0) {\n        struct __ior_timespec {\n            __s64 tv_sec;\n            __s64 tv_nsec;\n        } ts = {};\n        if (bpf_probe_read_user(&ts, sizeof(ts), (void *)" + ptrExpr + ") == 0) {\n" + compute + "        }\n    }\n"
}

// keyctlFieldSpec describes the three fields captured for keyctl-family syscalls.
// Each expression is a C snippet; empty means the field defaults to "0".
type keyctlFieldSpec struct {
	option    string // expression for ev->option    (default "0")
	keySerial string // expression for ev->key_serial (default "0")
	value     string // expression for ev->value      (default "0")
}

// keyctlOverrides maps keyctl-family syscall names to their per-field C
// expressions. To add a new keyctl variant, register it here.
var keyctlOverrides = map[string]keyctlFieldSpec{
	"sys_enter_keyctl":      {option: "(__s32)ctx->args[0]", keySerial: "(__s32)ctx->args[1]", value: "(__u64)ctx->args[2]"},
	"sys_enter_add_key":     {option: "-1", keySerial: "(__s32)ctx->args[4]", value: "(__u64)ctx->args[3]"},
	"sys_enter_request_key": {option: "-2", keySerial: "(__s32)ctx->args[3]"},
}

// generateExtraKeyctl emits the three-field body for keyctl-family syscalls.
// Unregistered syscalls get all-zero defaults.
func generateExtraKeyctl(name string) string {
	spec := keyctlOverrides[name] // zero-value keyctlFieldSpec if not found
	return fmt.Sprintf("    ev->option = %s;\n    ev->key_serial = %s;\n    ev->value = %s;\n",
		memExpr(spec.option), memExpr(spec.keySerial), memExpr(spec.value))
}

// generateExtraPtrace emits the ptrace_event body. _pad is an explicit
// alignment filler between target_pid and data; it must be written, otherwise
// the reserved ring-buffer record keeps whatever 4 bytes the previous record
// left there and the Go decoder surfaces that stale data as PtraceEvent.Pad.
func generateExtraPtrace() string {
	return "    ev->request = (__s64)ctx->args[0];\n    ev->target_pid = (__s32)ctx->args[1];\n    ev->_pad = 0;\n    ev->data = (__u64)ctx->args[3];\n"
}

func generateExtraPerfOpen() string {
	return "    ev->attr_type = 0;\n    ev->attr_size = 0;\n    ev->config = 0;\n    if (ctx->args[0] != 0) {\n        struct __ior_perf_event_attr {\n            __u32 type;\n            __u32 size;\n            __u64 config;\n        } attr = {};\n        if (bpf_probe_read_user(&attr, sizeof(attr), (void *)ctx->args[0]) == 0) {\n            ev->attr_type = attr.type;\n            ev->attr_size = attr.size;\n            ev->config = attr.config;\n        }\n    }\n    ev->target_pid = (__s32)ctx->args[1];\n    ev->cpu = (__s32)ctx->args[2];\n    ev->group_fd = (__s32)ctx->args[3];\n    ev->flags = (__u32)ctx->args[4];\n"
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
