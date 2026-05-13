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

	return renderHandler(f.Name, ctxStruct, eventStruct, comment, eventTypeConst, extra)
}

func renderHandler(name, ctxStruct, eventStruct, comment, eventTypeConst, extra string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "/// %s is a struct %s\n", name, comment)
	fmt.Fprintf(&b, "SEC(\"tracepoint/syscalls/%s\")\n", name)
	fmt.Fprintf(&b, "int handle_%s(struct %s *ctx) {\n", strings.ToLower(name), ctxStruct)
	b.WriteString("    __u32 pid, tid;\n")
	b.WriteString("    if (filter(&pid, &tid))\n")
	b.WriteString("        return 0;\n")
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

func generateExtra(tp GeneratedTracepoint, isEnter bool) string {
	f := tp.Format

	switch tp.Classification.Kind {
	case KindFd:
		if f.Name == "sys_enter_pidfd_getfd" {
			return "    ev->fd = (__s32)ctx->args[0];\n"
		}
		fdIdx := f.FieldNumber("fd")
		if fdIdx >= 0 {
			return fmt.Sprintf("    ev->fd = (__s32)ctx->args[%d];\n", fdIdx)
		}
		return "    ev->fd = (__s32)ctx->args[0];\n"

	case KindDup3:
		return "    ev->fd = (__s32)ctx->args[0];\n    ev->flags = (__s32)ctx->args[2];\n"

	case KindOpenByHandleAt:
		return "    ev->flags = (__s32)ctx->args[2];\n"

	case KindOpen:
		filenameIdx := f.FieldNumber("filename")
		flagsIdx := f.FieldNumber("flags")
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

	case KindPathname:
		fieldName := tp.Classification.PathnameField
		fieldIdx := f.FieldNumber(fieldName)
		var b strings.Builder
		b.WriteString("    __builtin_memset(&(ev->pathname), 0, sizeof(ev->pathname));\n")
		fmt.Fprintf(&b, "    bpf_probe_read_user_str(ev->pathname, sizeof(ev->pathname), (void*)ctx->args[%d]);\n", fieldIdx)
		return b.String()

	case KindName:
		oldIdx := f.FieldNumber("oldname")
		newIdx := f.FieldNumber("newname")
		var b strings.Builder
		b.WriteString("    __builtin_memset(&(ev->oldname), 0, sizeof(ev->oldname) + sizeof(ev->newname));\n")
		fmt.Fprintf(&b, "    bpf_probe_read_user_str(ev->oldname, sizeof(ev->oldname), (void*)ctx->args[%d]);\n", oldIdx)
		fmt.Fprintf(&b, "    bpf_probe_read_user_str(ev->newname, sizeof(ev->newname), (void*)ctx->args[%d]);\n", newIdx)
		return b.String()

	case KindFcntl:
		fdIdx := f.FieldNumber("fd")
		cmdIdx := f.FieldNumber("cmd")
		argIdx := f.FieldNumber("arg")
		return fmt.Sprintf(
			"    ev->fd = ctx->args[%d];\n    ev->cmd = ctx->args[%d];\n    ev->arg = ctx->args[%d];\n",
			fdIdx, cmdIdx, argIdx,
		)

	case KindRet:
		classification := ClassifyRet(f.Name)
		return fmt.Sprintf("    ev->ret = ctx->ret;\n    ev->ret_type = %s;\n", classification)

	case KindNull:
		return ""
	}

	return ""
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
