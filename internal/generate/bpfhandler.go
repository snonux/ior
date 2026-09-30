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
		sideMapTake:    generateSideMapTake(tp, isEnter),
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
		outputPathArg:   outputPathArgForHandler(f.Name),
	})
}

// outputPathArgForHandler returns the output-buffer argument index of the
// syscall behind tracepoint name, or -1 when it has none. Both sides need it:
// the enter handler stashes the pointer, the exit handler reads it back.
func outputPathArgForHandler(name string) int {
	if idx, ok := outputPathArgIndex(syscallName(name)); ok {
		return idx
	}
	return -1
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

// clockReadLine is the single clock read of every generated syscall handler.
// bpf_ktime_get_boot_ns is kept deliberately: it keeps counting across
// suspend, so a syscall that spans a suspend reports its true wall duration.
const clockReadLine = "    __u64 now = bpf_ktime_get_boot_ns();\n"

// handlerSpec carries everything renderHandler needs for one tracepoint.
type handlerSpec struct {
	name            string
	ctxStruct       string
	eventStruct     string
	comment         string
	eventTypeConst  string
	extra           string
	sideMapTake     string
	isEnter         bool
	noreturn        bool
	enterName       string
	recoverFilename bool
	// outputPathArg is the argument index of an output path buffer the exit
	// handler captures (outputPathSyscalls), or -1 for every other syscall.
	outputPathArg int
}

// takesPendingFilename reports whether this exit handler takes the pointer the
// enter handler stashed: the faulted-filename recovery and the output-path
// capture share the enter-state slot and the fixup record.
func (h handlerSpec) takesPendingFilename() bool {
	return !h.isEnter && (h.recoverFilename || h.outputPathArg >= 0)
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
// scope gate, the per-tid enter/exit hook, and - for the open kinds and the
// output-path syscalls (outputPathSyscalls) only - the stash/take/emit of a
// user pointer carried on the enter state. Those lines are position-critical,
// which is why they live here rather than in the kind emitters: the enter-side
// stash must follow ior_on_syscall_enter (which creates this tid's enter-state
// entry), the take must precede ior_on_syscall_exit (which deletes it) and the
// fixup must precede this handler's own reserve, so the ring buffer hands
// userspace the name while the enter event of the same syscall is still
// pending and unpaired.
func renderHandlerPrologue(b *strings.Builder, h handlerSpec) {
	name := h.name
	fmt.Fprintf(b, "/// %s is a struct %s\n", name, h.comment)
	fmt.Fprintf(b, "SEC(\"tracepoint/syscalls/%s\")\n", name)
	fmt.Fprintf(b, "int handle_%s(struct %s *ctx) {\n", strings.ToLower(name), h.ctxStruct)
	b.WriteString("    __u32 pid, tid;\n")
	b.WriteString("    if (filter(&pid, &tid))\n")
	b.WriteString("        return 0;\n")
	b.WriteString("\n")
	if h.takesPendingFilename() {
		fmt.Fprintf(b, "    __u64 pending_filename = ior_take_pending_filename(tid, %s);\n", h.enterName)
		b.WriteString("\n")
	}
	renderSyscallHook(b, h)
	b.WriteString("\n")
	renderPendingFilenameUse(b, h)
}

// renderSyscallHook writes the clock read and the per-tid enter/exit hook.
// The handler reads the clock exactly once (clockReadLine) and hands that
// value to the hook and to ev->time, instead of the hook and the body each
// calling bpf_ktime_get_boot_ns(). The hook's duration and the pair's ev->time
// delta are then the same two instants.
func renderSyscallHook(b *strings.Builder, h handlerSpec) {
	switch {
	case h.isEnter && h.noreturn:
		// Noreturn enter: only the sampling decision, no enter-state write. The
		// syscall never returns, so its exit handler is suppressed and nothing
		// would ever look up or delete a recorded enter-state entry. Skipping
		// the write avoids leaking stale per-tid entries in the bounded
		// syscall_enter_state_map; the enter null_event is still emitted below.
		// The hook needs no timestamp, so the clock is read only once the event
		// is known to be emitted, as before.
		fmt.Fprintf(b, "    if (!ior_on_noreturn_syscall_enter(%s))\n", strings.ToUpper(h.name))
		b.WriteString("        return 0;\n")
		b.WriteString("\n")
		b.WriteString(clockReadLine)
	case h.isEnter:
		b.WriteString(clockReadLine)
		fmt.Fprintf(b, "    if (!ior_on_syscall_enter(tid, %s, now))\n", strings.ToUpper(h.name))
		b.WriteString("        return 0;\n")
	default:
		b.WriteString(clockReadLine)
		fmt.Fprintf(b, "    if (!ior_on_syscall_exit(tid, %s, ctx->ret, now))\n", h.enterName)
		b.WriteString("        return 0;\n")
	}
}

// renderPendingFilenameUse writes what follows the hook for the handlers that
// carry a user pointer from sys_enter to sys_exit.
//
// An output-path enter stashes its buffer pointer unconditionally: there is
// nothing to read yet, and only an emitted enter (the hook returned) can ever
// be paired with the fixup. Its exit publishes the buffer only after a
// successful return (ret > 0, the copied byte count including the NUL): on
// failure the kernel wrote nothing, so the buffer holds whatever the caller
// left there. The faulted-filename recovery instead always emits, because its
// pointer is only stashed when the enter-side read failed.
func renderPendingFilenameUse(b *strings.Builder, h handlerSpec) {
	switch {
	case h.isEnter && !h.noreturn && h.outputPathArg >= 0:
		fmt.Fprintf(b, "    ior_stash_pending_filename(tid, ctx->args[%d]);\n", h.outputPathArg)
		b.WriteString("\n")
	case !h.isEnter && h.outputPathArg >= 0:
		b.WriteString("    if (ctx->ret > 0)\n")
		fmt.Fprintf(b, "        ior_emit_open_name_fixup(tid, %s, pending_filename);\n", h.enterName)
		b.WriteString("\n")
	case h.takesPendingFilename():
		fmt.Fprintf(b, "    ior_emit_open_name_fixup(tid, %s, pending_filename);\n", h.enterName)
		b.WriteString("\n")
	}
}

func renderHandler(h handlerSpec) string {
	var b strings.Builder
	renderHandlerPrologue(&b, h)
	// The side-map take (exit handlers of the pipe/socketpair/eventfd kinds)
	// runs before the reserve on purpose: the per-tid side entry must be
	// consumed and deleted whether or not the ring buffer has room, otherwise a
	// failed reserve strands it (see generateSideMapTake).
	if h.sideMapTake != "" {
		b.WriteString(h.sideMapTake)
		b.WriteString("\n")
	}
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
	b.WriteString("    ev->time = now;\n")
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
	KindFdSize:         func(tp GeneratedTracepoint, _ bool) string { return generateExtraFdSize(tp.Format) },
	KindDup3:           func(_ GeneratedTracepoint, _ bool) string { return generateExtraDup3() },
	KindOpenByHandleAt: func(_ GeneratedTracepoint, _ bool) string { return generateExtraOpenByHandleAt() },
	KindSocket:         func(_ GeneratedTracepoint, _ bool) string { return generateExtraSocket() },
	KindSocketpair:     func(_ GeneratedTracepoint, isEnter bool) string { return generateExtraSocketpair(isEnter) },
	KindAccept:         func(tp GeneratedTracepoint, isEnter bool) string { return generateExtraAccept(tp.Format, isEnter) },
	KindPipe:           func(tp GeneratedTracepoint, isEnter bool) string { return generateExtraPipe(tp.Format, isEnter) },
	KindEventfd:        func(tp GeneratedTracepoint, isEnter bool) string { return generateExtraEventfd(tp.Format, isEnter) },
	KindNamedEventfd: func(tp GeneratedTracepoint, isEnter bool) string {
		return generateExtraNamedEventfd(tp.Format, isEnter)
	},
	KindPidfd:      func(tp GeneratedTracepoint, isEnter bool) string { return generateExtraEventfd(tp.Format, isEnter) },
	KindEpollCtl:   func(_ GeneratedTracepoint, _ bool) string { return generateExtraEpollCtl() },
	KindTwoFd:      func(tp GeneratedTracepoint, _ bool) string { return generateExtraTwoFd(tp.Format.Name) },
	KindTwoFdNames: func(tp GeneratedTracepoint, _ bool) string { return generateExtraTwoFdNames(tp.Format.Name) },
	KindPoll:       func(tp GeneratedTracepoint, _ bool) string { return generateExtraPoll(tp.Format.Name) },
	KindMem:        func(tp GeneratedTracepoint, _ bool) string { return generateExtraMem(tp.Format.Name) },
	KindMmap:       func(_ GeneratedTracepoint, _ bool) string { return generateExtraMmap() },
	KindSleep:      func(tp GeneratedTracepoint, _ bool) string { return generateExtraSleep(tp.Format.Name) },
	KindKeyctl:     func(tp GeneratedTracepoint, _ bool) string { return generateExtraKeyctl(tp.Format.Name) },
	KindPtrace:     func(_ GeneratedTracepoint, _ bool) string { return generateExtraPtrace() },
	KindPerfOpen:   func(_ GeneratedTracepoint, _ bool) string { return generateExtraPerfOpen() },
	KindBpf:        func(_ GeneratedTracepoint, _ bool) string { return generateExtraBpf() },
	KindOpen:       func(tp GeneratedTracepoint, _ bool) string { return generateExtraOpen(tp.Format) },
	KindMqOpen:     func(tp GeneratedTracepoint, _ bool) string { return generateExtraMqOpen(tp.Format) },
	KindOpenTree:   func(tp GeneratedTracepoint, _ bool) string { return generateExtraOpen(tp.Format) },
	KindExec:       func(tp GeneratedTracepoint, _ bool) string { return generateExtraExec(tp.Format) },
	KindPathname:   func(tp GeneratedTracepoint, _ bool) string { return generateExtraPathname(tp, tp.Format) },
	KindFdPathname: func(tp GeneratedTracepoint, _ bool) string { return generateExtraFdPathname(tp.Format) },
	KindName:       func(tp GeneratedTracepoint, _ bool) string { return generateExtraName(tp.Format) },
	KindFcntl:      func(tp GeneratedTracepoint, _ bool) string { return generateExtraFcntl(tp.Format) },
	KindRet:        func(tp GeneratedTracepoint, _ bool) string { return generateExtraRet(tp.Format) },
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

// exitSideMapTakers maps the kinds whose enter handler stashes per-tid state
// in a side map (socketpair_ctx_map, pipe_ctx_map, eventfd_flags_map) to the
// exit-side code that consumes and deletes that entry. Each taker declares the
// C locals the kind's exit emitter in extraEmitters then copies into the event,
// so the two halves are a pair and must stay in sync.
var exitSideMapTakers = map[TracepointKind]func() string{
	KindSocketpair:   socketpairExitTake,
	KindPipe:         pipeExitTake,
	KindEventfd:      eventfdExitTake,
	KindNamedEventfd: eventfdExitTake,
	KindPidfd:        eventfdExitTake,
}

// generateSideMapTake returns the exit handler's side-map take, rendered after
// ior_on_syscall_exit and before bpf_ringbuf_reserve (see renderHandler). It
// used to live after the reserve, so a full ring buffer returned early and left
// the entry behind: a later syscall of the same tid whose enter reserve also
// failed read the stale pointer and reported an old call's descriptors, and
// entries of threads that then exited were never reclaimed until the bounded
// (8192) maps filled and new calls lost their descriptors. Taking it first
// deletes the entry on every emitted exit, whatever the ring buffer's state.
// Enter handlers and all other kinds return "".
func generateSideMapTake(tp GeneratedTracepoint, isEnter bool) string {
	if isEnter {
		return ""
	}
	if take, ok := exitSideMapTakers[tp.Classification.Kind]; ok {
		return take()
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

// generateExtraFd returns the fd-capture line for fd-family events.
func generateExtraFd(f *Format) string {
	return fmt.Sprintf("    ev->fd = (__s32)ctx->args[%d];\n", fdArgumentIndex(f))
}

// generateExtraFdSize returns the fd capture plus the requested-size metadata
// of the fd-based xattr reads (fd_size_event).
func generateExtraFdSize(f *Format) string {
	var b strings.Builder
	b.WriteString(generateExtraFd(f))
	writeRequestedSizeCapture(&b, f)
	b.WriteString("    ev->schema_version = FD_SIZE_EVENT_SCHEMA_VERSION;\n")
	return b.String()
}

// fdArgumentIndex selects the argument slot of the one descriptor a single-fd
// payload represents: an explicit override, else the field literally named
// "fd", else args[0].
func fdArgumentIndex(f *Format) int {
	if override, ok := fdArgumentOverrides[f.Name]; ok {
		return override
	}
	if fdIdx := f.FieldNumber("fd"); fdIdx >= 0 {
		return fdIdx
	}
	return 0
}

// fdArgumentOverrides chooses the one descriptor represented by a single-fd
// payload when the syscall has multiple descriptors or names none literally
// "fd". Transfers with two fd endpoints consistently use the destination;
// vmsplice has only one fd endpoint and therefore always uses its pipe fd.
var fdArgumentOverrides = map[string]int{
	"sys_enter_copy_file_range": 2,
	"sys_enter_pidfd_getfd":     0,
	"sys_enter_sendfile64":      0,
	"sys_enter_splice":          2,
	"sys_enter_tee":             1,
	"sys_enter_vmsplice":        0,
}

// requestedSizeArgument records output-buffer capacity only for xattr read
// syscalls. A zero capacity makes these calls size probes: their positive
// return is required capacity, not bytes copied.
var requestedSizeArgument = map[string]int{
	"sys_enter_fgetxattr":   3,
	"sys_enter_flistxattr":  2,
	"sys_enter_getxattr":    3,
	"sys_enter_getxattrat":  4,
	"sys_enter_lgetxattr":   3,
	"sys_enter_listxattr":   2,
	"sys_enter_listxattrat": 4,
	"sys_enter_llistxattr":  2,
}

func writeRequestedSizeCapture(b *strings.Builder, f *Format) {
	b.WriteString("    ev->size_valid = 0;\n")
	b.WriteString("    ev->size = 0;\n")
	if f.Name == "sys_enter_getxattrat" {
		b.WriteString("    if (ctx->args[4] != 0) {\n")
		b.WriteString("        struct { __u64 value; __u32 size; __u32 flags; } ior_xattr_args = {};\n")
		b.WriteString("        if (bpf_probe_read_user(&ior_xattr_args, sizeof(ior_xattr_args), (void *)ctx->args[4]) == 0) {\n")
		b.WriteString("            ev->size = ior_xattr_args.size;\n")
		b.WriteString("            ev->size_valid = 1;\n")
		b.WriteString("        }\n")
		b.WriteString("    }\n")
		return
	}
	if idx, ok := requestedSizeArgument[f.Name]; ok {
		fmt.Fprintf(b, "    ev->size = (__u64)ctx->args[%d];\n", idx)
		b.WriteString("    ev->size_valid = 1;\n")
	}
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
	// The filename carries the three-state read status like the open kinds
	// (task 9p2): an empty name reads the same whether the caller passed ""
	// (AT_EMPTY_PATH execveat, i.e. fexecve) or a pointer the nofault helper
	// could not read, and only the former names the dirfd itself. Unlike
	// open, a failed read is not retried at sys_exit: a successful exec
	// replaces the address space the pointer belonged to.
	writePathReadCapture(&b, "filename", "filename_status", filenameIdx)
	// comm is filled completely by the helper.
	b.WriteString("    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));\n")
	b.WriteString("    ev->schema_version = EXEC_EVENT_SCHEMA_VERSION;\n")
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
	// bpf_probe_read_user_str cannot fault, so it returns -EFAULT whenever the
	// path string's page is not resident yet - routinely the case for the first
	// open a program makes through a freshly mmap'ed library. Stash the pointer
	// on failure; the exit handler re-reads it once the kernel has faulted the
	// page in (ior_take_pending_filename / ior_emit_open_name_fixup in
	// internal/c/filter.c). Without this the row printed "E:name", the
	// descriptor was registered under the empty string, and -path could not
	// match a name that was never captured.
	writeRecoverableFilenameCapture(&b, filenameIdx)
	// bpf_get_current_comm always writes all sizeof(ev->comm) bytes (the name,
	// NUL-padded, or zeros on error), so comm needs no initialization either.
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
	writePathReadCapture(&b, "pathname", "pathname_status", fieldIdx)
	writeDirfdCapture(&b, f, "dirfd", "dfd", "dirfd")
	writePathFlagsCapture(&b, f)
	writePathTargetCapture(&b, f)
	writeRequestedSizeCapture(&b, f)
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

// writePathReadCapture distinguishes all three results that otherwise leave an
// empty event string: a valid empty string, an actual NULL pointer, and a
// failed nofault read of a non-NULL pointer. The probe remains directly in an
// if guard so the independent syscall-semantics oracle can verify its source
// argument and destination. The NULL and failed-read branches each write the
// string's terminator (writeStringTerminator); a successful read terminates it
// itself.
func writePathReadCapture(b *strings.Builder, eventField, statusField string, argIdx int) {
	fmt.Fprintf(b, "    if (ctx->args[%d] == 0) {\n", argIdx)
	writeStringTerminator(b, "        ", eventField)
	fmt.Fprintf(b, "        ev->%s = PATH_READ_NULL;\n", statusField)
	b.WriteString("    } else {\n")
	fmt.Fprintf(b, "        ev->%s = PATH_READ_OK;\n", statusField)
	fmt.Fprintf(b, "        if (bpf_probe_read_user_str(ev->%s, sizeof(ev->%s), (void*)ctx->args[%d]) < 0) {\n", eventField, eventField, argIdx)
	fmt.Fprintf(b, "            ev->%s = PATH_READ_FAILED;\n", statusField)
	writeStringTerminator(b, "            ", eventField)
	b.WriteString("        }\n")
	b.WriteString("    }\n")
}

// writeRecoverableFilenameCapture is writePathReadCapture for ev->filename of
// the kinds whose failed enter-side read is retried at sys_exit: the failed
// branch also stashes the user pointer (ior_stash_pending_filename).
func writeRecoverableFilenameCapture(b *strings.Builder, argIdx int) {
	fmt.Fprintf(b, "    if (ctx->args[%d] == 0) {\n", argIdx)
	writeStringTerminator(b, "        ", "filename")
	b.WriteString("        ev->filename_status = PATH_READ_NULL;\n")
	b.WriteString("    } else {\n")
	b.WriteString("        ev->filename_status = PATH_READ_OK;\n")
	fmt.Fprintf(b, "        if (bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)ctx->args[%d]) < 0) {\n", argIdx)
	b.WriteString("            ev->filename_status = PATH_READ_FAILED;\n")
	writeStringTerminator(b, "            ", "filename")
	fmt.Fprintf(b, "            ior_stash_pending_filename(tid, ctx->args[%d]);\n", argIdx)
	b.WriteString("        }\n")
	b.WriteString("    }\n")
}

// writeStringTerminator empties a ring-buffer string field by writing only its
// first byte. The ring buffer hands out reserved memory unzeroed, so the bytes
// of a string field are stale until written; the handlers used to clear all of
// them with a full-buffer __builtin_memset (256 bytes per string, 32 stores)
// before every read. Userspace only ever reads up to the first NUL
// (types.StringValue), so a string field needs exactly one guarantee: a NUL
// at or before its end. A successful bpf_probe_read_user_str writes one after
// the copied bytes; every other outcome (a NULL pointer, a failed read, a
// field the syscall does not capture) gets this terminator. What follows the
// NUL is never interpreted. Why stale bytes there are acceptable is recorded
// next to ior_emit_open_name_fixup in internal/c/filter.c.
func writeStringTerminator(b *strings.Builder, indent, eventField string) {
	fmt.Fprintf(b, "%sev->%s[0] = 0;\n", indent, eventField)
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

// generateExtraSocketpair emits the socketpair body. Enter stashes the
// user-space sv pointer and the family/type/protocol in socketpair_ctx_map,
// because the descriptors only exist once the syscall has returned. Exit only
// copies the locals socketpairExitTake computed ahead of the reserve.
func generateExtraSocketpair(isEnter bool) string {
	if isEnter {
		return "    struct socketpair_ctx pending;\n    pending.usockvec = ctx->args[3];\n    pending.family = (__s32)ctx->args[0];\n    pending.type = (__s32)ctx->args[1];\n    pending.protocol = (__s32)ctx->args[2];\n    bpf_map_update_elem(&socketpair_ctx_map, &tid, &pending, BPF_ANY);\n    ev->family = pending.family;\n    ev->type = pending.type;\n    ev->protocol = pending.protocol;\n    ev->sv0 = -1;\n    ev->sv1 = -1;\n    ev->ret = 0;\n"
	}
	return "    ev->family = family;\n    ev->type = type;\n    ev->protocol = protocol;\n    ev->sv0 = sv0;\n    ev->sv1 = sv1;\n    ev->ret = ctx->ret;\n"
}

// socketpairExitTake is the pre-reserve half of the socketpair exit: it reads
// the stashed socketpair_ctx, fetches the created descriptors from user memory
// on success, and deletes the entry, leaving the results in locals for
// generateExtraSocketpair.
func socketpairExitTake() string {
	return "    __s32 family = -1;\n    __s32 type = -1;\n    __s32 protocol = -1;\n    __s32 sv0 = -1;\n    __s32 sv1 = -1;\n    struct socketpair_ctx *pending = bpf_map_lookup_elem(&socketpair_ctx_map, &tid);\n    if (pending) {\n        family = pending->family;\n        type = pending->type;\n        protocol = pending->protocol;\n        if (ctx->ret == 0 && pending->usockvec != 0) {\n            int sv[2];\n            if (bpf_probe_read_user(&sv, sizeof(sv), (void *)pending->usockvec) == 0) {\n                sv0 = (__s32)sv[0];\n                sv1 = (__s32)sv[1];\n            }\n        }\n        bpf_map_delete_elem(&socketpair_ctx_map, &tid);\n    }\n"
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

// generateExtraPipe emits the pipe/pipe2 body. Enter stashes the user-space
// pipefd pointer and the flags in pipe_ctx_map, because the descriptors only
// exist once the syscall has returned. Exit only copies the locals
// pipeExitTake computed ahead of the reserve.
func generateExtraPipe(f *Format, isEnter bool) string {
	if isEnter {
		flagsExpr := "0"
		if f.Name == "sys_enter_pipe2" {
			flagsExpr = "(__s32)ctx->args[1]"
		}
		return "    struct pipe_ctx pending;\n    pending.upipefd = ctx->args[0];\n    pending.flags = " + flagsExpr + ";\n    bpf_map_update_elem(&pipe_ctx_map, &tid, &pending, BPF_ANY);\n    ev->flags = pending.flags;\n    ev->fd0 = -1;\n    ev->fd1 = -1;\n    ev->ret = 0;\n"
	}
	return "    ev->flags = flags;\n    ev->fd0 = fd0;\n    ev->fd1 = fd1;\n    ev->ret = ctx->ret;\n"
}

// pipeExitTake is the pre-reserve half of the pipe exit: it reads the stashed
// pipe_ctx, fetches the created descriptors from user memory on success, and
// deletes the entry, leaving the results in locals for generateExtraPipe.
func pipeExitTake() string {
	return "    __s32 flags = 0;\n    __s32 fd0 = -1;\n    __s32 fd1 = -1;\n    struct pipe_ctx *pending = bpf_map_lookup_elem(&pipe_ctx_map, &tid);\n    if (pending) {\n        flags = pending->flags;\n        if (ctx->ret == 0 && pending->upipefd != 0) {\n            int pipefd[2];\n            if (bpf_probe_read_user(&pipefd, sizeof(pipefd), (void *)pending->upipefd) == 0) {\n                fd0 = (__s32)pipefd[0];\n                fd1 = (__s32)pipefd[1];\n            }\n        }\n        bpf_map_delete_elem(&pipe_ctx_map, &tid);\n    }\n"
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
// taken from the map by eventfdExitTake ahead of the reserve and captures
// ctx->ret. Every exit of the family, the named kinds' included, uses this lean
// eventfd_event body.
func generateExtraEventfd(f *Format, isEnter bool) string {
	if isEnter {
		return eventfdEnterCapture(f)
	}
	return "    ev->flags = flags;\n    ev->ret = ctx->ret;\n    ev->fd = -1;\n"
}

// eventfdExitTake is the pre-reserve half of the eventfd-family exit: it reads
// and deletes the flags stashed by eventfdEnterCapture, leaving them in the
// flags local for generateExtraEventfd.
func eventfdExitTake() string {
	return "    __s32 flags = 0;\n    __s32 *pending = bpf_map_lookup_elem(&eventfd_flags_map, &tid);\n    if (pending) {\n        flags = *pending;\n        bpf_map_delete_elem(&eventfd_flags_map, &tid);\n    }\n"
}

// generateExtraNamedEventfd emits the eventfd_name_event enter body of
// memfd_create and fsopen: the identifying name (recovered at sys_exit when
// the enter-side read faults) ahead of the common eventfd capture. Their exits
// classify as KindEventfd and never reach here, but an exit is rendered the
// lean way for safety.
func generateExtraNamedEventfd(f *Format, isEnter bool) string {
	if !isEnter {
		return generateExtraEventfd(f, false)
	}
	idx := 0
	if field := eventfdFilenameField[f.Name]; field != "" {
		if fieldIdx := f.FieldNumber(field); fieldIdx >= 0 {
			idx = fieldIdx
		}
	}
	var b strings.Builder
	writeRecoverableFilenameCapture(&b, idx)
	b.WriteString("    ev->schema_version = EVENTFD_NAME_EVENT_SCHEMA_VERSION;\n")
	b.WriteString(eventfdEnterCapture(f))
	return b.String()
}

// eventfdEnterCapture is the enter body shared by eventfd_event and
// eventfd_name_event: flags (stashed for the exit), ret and the descriptor.
func eventfdEnterCapture(f *Format) string {
	flagsExpr := eventfdFlagsExpr[f.Name] // empty string if not found
	if flagsExpr == "" {
		flagsExpr = "0"
	}
	fdExpr := eventfdFDExpr[f.Name]
	if fdExpr == "" {
		fdExpr = "-1"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "    __s32 flags = %s;\n", flagsExpr)
	b.WriteString("    bpf_map_update_elem(&eventfd_flags_map, &tid, &flags, BPF_ANY);\n")
	b.WriteString("    ev->flags = flags;\n    ev->ret = -1;\n")
	fmt.Fprintf(&b, "    ev->fd = %s;\n", fdExpr)
	return b.String()
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
	var b strings.Builder
	writeTwoFdCapture(&b, name)
	b.WriteString("    ev->schema_version = TWO_FD_EVENT_SCHEMA_VERSION;\n")
	return b.String()
}

// generateExtraTwoFdNames emits the two_fd_names_event body of move_mount:
// the two-fd capture plus its from/to pathnames (args[1] and args[3]).
func generateExtraTwoFdNames(name string) string {
	var b strings.Builder
	writeTwoFdCapture(&b, name)
	writePathReadCapture(&b, "oldname", "oldname_status", 1)
	writePathReadCapture(&b, "newname", "newname_status", 3)
	b.WriteString("    ev->schema_version = TWO_FD_EVENT_SCHEMA_VERSION;\n")
	return b.String()
}

func writeTwoFdCapture(b *strings.Builder, name string) {
	spec, ok := twoFdOverrides[name]
	if !ok {
		spec = twoFdDefault
	}
	fmt.Fprintf(b, "    ev->fd_a = %s;\n    ev->fd_b = %s;\n    ev->extra = %s;\n",
		spec.fdA, spec.fdB, spec.extra)
}

func generateExtraBpf() string {
	return "    ev->cmd = (__u32)ctx->args[0];\n"
}

// pollTimeoutStyle describes how the poll-family syscall captures its timeout.
type pollTimeoutStyle int

const (
	// pollTimeoutNone means no known timeout capture; emit defaults. It is
	// the zero value, so it is only ever used implicitly.
	//lint:ignore U1000 named zero value of pollTimeoutStyle
	pollTimeoutNone pollTimeoutStyle = iota
	// pollTimeoutMillis means the timeout is an __s32 millisecond value.
	pollTimeoutMillis
	// pollTimeoutTimespec means the timeout is a pointer to a timespec struct.
	pollTimeoutTimespec
	// pollTimeoutTimeval means the timeout is a pointer to a timeval struct.
	pollTimeoutTimeval
)

// pollFieldSpec describes argument positions and timeout style for a poll
// syscall. fdArgIdx is -1 when the syscall has no single descriptor;
// nfdsArgIdx and timeoutArgIdx identify the count and timeout arguments.
type pollFieldSpec struct {
	fdArgIdx      int
	nfdsArgIdx    int
	timeoutArgIdx int
	timeoutStyle  pollTimeoutStyle
}

// pollOverrides maps poll-family syscall names to their argument layout.
// To add a new poll variant, register it here instead of editing a switch.
var pollOverrides = map[string]pollFieldSpec{
	"sys_enter_epoll_wait":   {fdArgIdx: 0, nfdsArgIdx: 2, timeoutArgIdx: 3, timeoutStyle: pollTimeoutMillis},
	"sys_enter_epoll_pwait":  {fdArgIdx: 0, nfdsArgIdx: 2, timeoutArgIdx: 3, timeoutStyle: pollTimeoutMillis},
	"sys_enter_epoll_pwait2": {fdArgIdx: 0, nfdsArgIdx: 2, timeoutArgIdx: 3, timeoutStyle: pollTimeoutTimespec},
	"sys_enter_poll":         {fdArgIdx: -1, nfdsArgIdx: 1, timeoutArgIdx: 2, timeoutStyle: pollTimeoutMillis},
	"sys_enter_ppoll":        {fdArgIdx: -1, nfdsArgIdx: 1, timeoutArgIdx: 2, timeoutStyle: pollTimeoutTimespec},
	"sys_enter_select":       {fdArgIdx: -1, nfdsArgIdx: 0, timeoutArgIdx: 4, timeoutStyle: pollTimeoutTimeval},
	"sys_enter_pselect6":     {fdArgIdx: -1, nfdsArgIdx: 0, timeoutArgIdx: 4, timeoutStyle: pollTimeoutTimespec},
}

// generateExtraPoll emits the nfds/timeout_ns capture body for poll-family
// syscalls. Unregistered names get safe unknown defaults.
func generateExtraPoll(name string) string {
	spec, ok := pollOverrides[name]
	if !ok {
		return "    ev->nfds = -1;\n" +
			"    ev->timeout_ns = POLL_TIMEOUT_UNKNOWN_NS;\n" +
			"    ev->fd = -1;\n" +
			"    ev->schema_version = POLL_EVENT_SCHEMA_VERSION;\n"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "    ev->nfds = (__s32)ctx->args[%d];\n", spec.nfdsArgIdx)
	b.WriteString("    ev->timeout_ns = POLL_TIMEOUT_UNKNOWN_NS;\n")
	b.WriteString(pollTimeoutBody(spec.timeoutArgIdx, spec.timeoutStyle))
	if spec.fdArgIdx >= 0 {
		fmt.Fprintf(&b, "    ev->fd = (__s32)ctx->args[%d];\n", spec.fdArgIdx)
	} else {
		b.WriteString("    ev->fd = -1;\n")
	}
	b.WriteString("    ev->schema_version = POLL_EVENT_SCHEMA_VERSION;\n")
	return b.String()
}

// pollTimeoutBody returns the C snippet that reads the timeout from the
// specified argument index using the given style (millis, timespec, timeval).
func pollTimeoutBody(argIdx int, style pollTimeoutStyle) string {
	switch style {
	case pollTimeoutMillis:
		return fmt.Sprintf(
			"    __s32 timeout_ms = (__s32)ctx->args[%d];\n"+
				"    if (timeout_ms < 0) {\n"+
				"        ev->timeout_ns = POLL_TIMEOUT_INFINITE_NS;\n"+
				"    } else {\n"+
				"        ev->timeout_ns = ((__s64)timeout_ms) * 1000000LL;\n"+
				"    }\n", argIdx)
	case pollTimeoutTimespec:
		return fmt.Sprintf(
			"    if (ctx->args[%d] == 0) {\n"+
				"        ev->timeout_ns = POLL_TIMEOUT_INFINITE_NS;\n"+
				"    } else {\n"+
				"        struct __ior_timespec {\n"+
				"            __s64 tv_sec;\n"+
				"            __s64 tv_nsec;\n"+
				"        } ts = {};\n"+
				"        if (bpf_probe_read_user(&ts, sizeof(ts), (void *)ctx->args[%d]) == 0) {\n"+
				"            if ("+timespecValidCond("ts")+" &&\n"+
				"                (ts.tv_sec < "+timespecMaxNsSec+" ||\n"+
				"                 (ts.tv_sec == "+timespecMaxNsSec+" && ts.tv_nsec <= "+timespecMaxNsRem+"))) {\n"+
				"                ev->timeout_ns = "+timespecNsExpr("ts")+";\n"+
				"            }\n"+
				"        }\n"+
				"    }\n", argIdx, argIdx)
	case pollTimeoutTimeval:
		return fmt.Sprintf(
			"    if (ctx->args[%d] == 0) {\n"+
				"        ev->timeout_ns = POLL_TIMEOUT_INFINITE_NS;\n"+
				"    } else {\n"+
				"        struct __ior_timeval {\n"+
				"            __s64 tv_sec;\n"+
				"            __s64 tv_usec;\n"+
				"        } tv = {};\n"+
				"        if (bpf_probe_read_user(&tv, sizeof(tv), (void *)ctx->args[%d]) == 0) {\n"+
				"            if (tv.tv_sec >= 0 && tv.tv_usec >= 0 && tv.tv_usec < 1000000LL &&\n"+
				"                (tv.tv_sec < 9223372036LL ||\n"+
				"                 (tv.tv_sec == 9223372036LL && tv.tv_usec <= 854775LL))) {\n"+
				"                ev->timeout_ns = tv.tv_sec * 1000000000LL + tv.tv_usec * 1000LL;\n"+
				"            }\n"+
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

// Timespec validation shared by the poll-family timeout capture
// (pollTimeoutBody) and the sleep-family request capture (generateExtraSleep).
// Both convert a user-space struct __kernel_timespec into signed 64-bit
// nanoseconds, so both must reject what the kernel rejects and must never let
// tv_sec * 1e9 + tv_nsec wrap around __s64.
const (
	// timespecMaxNsSec and timespecMaxNsRem split S64_MAX
	// (9223372036854775807) into whole seconds and the nanosecond remainder:
	// a valid timespec converts to __s64 nanoseconds without overflow iff
	// tv_sec < timespecMaxNsSec, or tv_sec == timespecMaxNsSec and
	// tv_nsec <= timespecMaxNsRem.
	timespecMaxNsSec = "9223372036LL"
	timespecMaxNsRem = "854775807LL"
	// sleepRequestedNsSaturated is the value a valid sleep request saturates
	// to when its nanoseconds are unrepresentable in __s64 (S64_MAX), e.g.
	// `sleep infinity` passing {LLONG_MAX, 999999999}. The kernel similarly
	// clamps to KTIME_MAX (ktime_set), but already from tv_sec >= KTIME_SEC_MAX
	// (9223372036) regardless of tv_nsec, so values within ~1s of the boundary
	// may differ: {9223372036, 0} sleeps forever in the kernel but is recorded
	// exactly as 9223372036000000000. ior keeps the exact representable-range
	// boundary shared with the poll timeout capture.
	sleepRequestedNsSaturated = "9223372036854775807LL /* S64_MAX */"
)

// timespecValidCond returns the C condition mirroring the kernel's
// timespec64_valid(): tv_sec >= 0 and tv_nsec in [0, 1e9). A timespec failing
// it makes nanosleep/clock_nanosleep/ppoll/pselect6/epoll_pwait2 return
// -EINVAL, so its nanosecond value is meaningless. v names the C struct local.
func timespecValidCond(v string) string {
	return v + ".tv_sec >= 0 && " + v + ".tv_nsec >= 0 && " + v + ".tv_nsec < 1000000000LL"
}

// timespecOverflowCond returns the C condition that is true when a VALID
// timespec (see timespecValidCond) does not fit in __s64 nanoseconds. It is
// the exact negation of the representable range the poll capture accepts.
func timespecOverflowCond(v, indent string) string {
	return v + ".tv_sec > " + timespecMaxNsSec + " ||\n" +
		indent + "(" + v + ".tv_sec == " + timespecMaxNsSec + " && " + v + ".tv_nsec > " + timespecMaxNsRem + ")"
}

// timespecNsExpr returns the C expression converting timespec local v to
// nanoseconds. Callers must guard it with timespecValidCond and a
// representability check; unguarded it wraps for huge tv_sec.
func timespecNsExpr(v string) string {
	return v + ".tv_sec * 1000000000LL + " + v + ".tv_nsec"
}

// generateExtraSleep emits the requested_ns capture body for sleep-family
// syscalls. The timespec pointer (and optional flags) expression come from
// sleepTimespecPtr.
//
// requested_ns defaults to the -1 "unknown" sentinel, which it keeps for:
//   - a null or unreadable timespec pointer;
//   - an invalid timespec (negative tv_sec, tv_nsec outside [0, 1e9)), which
//     the kernel rejects with -EINVAL, so no sleep was requested at all;
//   - an absolute sleep (clock_nanosleep with TIMER_ABSTIME set): the request
//     is an absolute clock value, NOT a duration, and tv_sec*1e9 + tv_nsec
//     would export a bogus multi-decade "sleep duration". Deriving the true
//     relative duration would require reading the current time of the
//     (variable) clockid in BPF, which is racy and clock-dependent.
//
// A valid relative request is converted to nanoseconds. One too large for
// __s64 (e.g. `sleep infinity`) saturates to S64_MAX (the kernel similarly
// clamps to KTIME_MAX, from tv_sec >= KTIME_SEC_MAX; values within ~1s of the
// boundary may differ, see sleepRequestedNsSaturated). Before this range check
// the multiplication wrapped into garbage negative values, and
// {LLONG_MAX, 999999999} landed exactly on -1.
func generateExtraSleep(name string) string {
	spec := sleepTimespecPtr[name] // zero value (ptr "") if not found
	ptrExpr := spec.ptr
	if ptrExpr == "" {
		ptrExpr = "0"
	}

	compute := sleepRequestedNsBody("            ")
	if spec.flagsArg != "" {
		// Absolute sleeps keep the -1 sentinel; only relative sleeps get a
		// computed duration.
		compute = "            if ((" + spec.flagsArg + " & " + timerAbstimeFlag + ") == 0) {\n" +
			sleepRequestedNsBody("                ") +
			"            }\n"
	}

	return "    ev->requested_ns = -1;\n    if (" + ptrExpr + " != 0) {\n        struct __ior_timespec {\n            __s64 tv_sec;\n            __s64 tv_nsec;\n        } ts = {};\n        if (bpf_probe_read_user(&ts, sizeof(ts), (void *)" + ptrExpr + ") == 0) {\n" + compute + "        }\n    }\n"
}

// sleepRequestedNsBody returns the C statements, indented by indent, that set
// requested_ns from the already-read timespec local ts: invalid requests keep
// the -1 sentinel, overflowing ones saturate, the rest convert exactly. The
// saturating branch comes first so the ts-derived assignment is the handler's
// final write to requested_ns, as the syscall semantics oracle requires.
func sleepRequestedNsBody(indent string) string {
	in := indent + "    "
	return indent + "if (" + timespecValidCond("ts") + ") {\n" +
		in + "if (" + timespecOverflowCond("ts", in+"    ") + ") {\n" +
		in + "    ev->requested_ns = " + sleepRequestedNsSaturated + ";\n" +
		in + "} else {\n" +
		in + "    ev->requested_ns = " + timespecNsExpr("ts") + ";\n" +
		in + "}\n" +
		indent + "}\n"
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
