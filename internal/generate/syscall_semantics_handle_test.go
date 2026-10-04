package generate

import (
	"testing"
)

// semanticMutation is one edit of the committed artifact that the semantics
// oracle must reject.
type semanticMutation struct {
	name   string
	mutate func(*testing.T, string) string
}

const (
	handleStashLine = "    ior_stash_pending_handle(tid, ctx->args[2]);\n"
	handleEmitLines = "    if (ctx->ret == 0)\n        ior_emit_file_handle(pid, tid, SYS_ENTER_NAME_TO_HANDLE_AT, now, enter_ns, pending_handle);\n"
	handleEmitTail  = "SYS_ENTER_NAME_TO_HANDLE_AT, now, enter_ns, pending_handle);"
	handleTakeCall  = "ior_on_syscall_exit_take_handle(tid, SYS_ENTER_NAME_TO_HANDLE_AT, ctx->ret, now, &pending_filename, &pending_handle, &enter_ns)"
	handleReadLine  = "    ev->handle_status = ior_read_file_handle(ctx->args[1], &ev->handle_bytes, &ev->handle_type, ev->f_handle);\n"
)

// outputHandleEnterMutations break the enter half of name_to_handle_at's
// output-handle capture.
func outputHandleEnterMutations() []semanticMutation {
	return []semanticMutation{
		{"output handle stash removed", func(t *testing.T, source string) string {
			return replaceInHandler(t, source, "enter", "name_to_handle_at", handleStashLine, "")
		}},
		{"output handle wrong argument", func(t *testing.T, source string) string {
			return replaceInHandler(t, source, "enter", "name_to_handle_at",
				"ior_stash_pending_handle(tid, ctx->args[2]);", "ior_stash_pending_handle(tid, ctx->args[3]);")
		}},
		{"output handle stashed before the enter hook", func(t *testing.T, source string) string {
			source = replaceInHandler(t, source, "enter", "name_to_handle_at", handleStashLine, "")
			return replaceInHandler(t, source, "enter", "name_to_handle_at",
				"    __u64 now = bpf_ktime_get_boot_ns();\n",
				handleStashLine+"    __u64 now = bpf_ktime_get_boot_ns();\n")
		}},
		{"output handle stashed conditionally", func(t *testing.T, source string) string {
			return replaceInHandler(t, source, "enter", "name_to_handle_at", handleStashLine,
				"    if (ctx->args[2])\n    "+handleStashLine)
		}},
	}
}

// outputHandleExitMutations break the exit half: when the handle is
// published, with which times and pointer, and how they are taken.
func outputHandleExitMutations() []semanticMutation {
	exit := func(old, replacement string) func(*testing.T, string) string {
		return func(t *testing.T, source string) string {
			return replaceInHandler(t, source, "exit", "name_to_handle_at", old, replacement)
		}
	}
	return []semanticMutation{
		{"output handle never published", exit(handleEmitLines, "")},
		{"output handle published on failure", exit("    if (ctx->ret == 0)\n        ior_emit_file_handle", "    if (1)\n        ior_emit_file_handle")},
		{"output handle published for any non-negative return", exit("    if (ctx->ret == 0)\n        ior_emit_file_handle", "    if (ctx->ret >= 0)\n        ior_emit_file_handle")},
		{"output handle stamped with another clock read", exit(handleEmitTail,
			"SYS_ENTER_NAME_TO_HANDLE_AT, bpf_ktime_get_boot_ns(), enter_ns, pending_handle);")},
		{"output handle stamped with the exit time as its enter time", exit(handleEmitTail,
			"SYS_ENTER_NAME_TO_HANDLE_AT, now, now, pending_handle);")},
		{"output handle read through the pathname pointer", exit(handleEmitTail,
			"SYS_ENTER_NAME_TO_HANDLE_AT, now, enter_ns, pending_filename);")},
		{"output handle published for the wrong syscall", exit("ior_emit_file_handle(pid, tid, SYS_ENTER_NAME_TO_HANDLE_AT,", "ior_emit_file_handle(pid, tid, SYS_ENTER_READ,")},
		{"output handle pointer never taken", exit(handleTakeCall,
			"ior_on_syscall_exit_take_filename(tid, SYS_ENTER_NAME_TO_HANDLE_AT, ctx->ret, now, &pending_filename)")},
		{"output handle taken without the enter time", exit(handleTakeCall,
			"ior_on_syscall_exit_take_filenames(tid, SYS_ENTER_NAME_TO_HANDLE_AT, ctx->ret, now, &pending_filename, &pending_handle)")},
		{"output handle taken for the wrong syscall", exit("ior_on_syscall_exit_take_handle(tid, SYS_ENTER_NAME_TO_HANDLE_AT,",
			"ior_on_syscall_exit_take_handle(tid, SYS_ENTER_READ,")},
		{"output handle published before the exit hook", func(t *testing.T, source string) string {
			source = replaceInHandler(t, source, "exit", "name_to_handle_at", handleEmitLines, "")
			return replaceInHandler(t, source, "exit", "name_to_handle_at",
				"    __u64 now = bpf_ktime_get_boot_ns();\n", "    __u64 now = bpf_ktime_get_boot_ns();\n"+handleEmitLines)
		}},
	}
}

// inputHandleMutations break open_by_handle_at's capture of the handle it
// opens.
func inputHandleMutations() []semanticMutation {
	enter := func(replacement string) func(*testing.T, string) string {
		return func(t *testing.T, source string) string {
			return replaceInHandler(t, source, "enter", "open_by_handle_at", handleReadLine, replacement)
		}
	}
	return []semanticMutation{
		{"input handle not read", enter("")},
		{"input handle read from the mount fd argument", enter(
			"    ev->handle_status = ior_read_file_handle(ctx->args[0], &ev->handle_bytes, &ev->handle_type, ev->f_handle);\n")},
		{"input handle status set without a read", enter("    ev->handle_status = FILE_HANDLE_OK;\n")},
		{"input handle bytes left unwritten", enter(
			"    __u8 scratch[IOR_MAX_HANDLE_SZ];\n" +
				"    ev->handle_status = ior_read_file_handle(ctx->args[1], &ev->handle_bytes, &ev->handle_type, scratch);\n")},
		{"input handle status overwritten", enter(handleReadLine + "    ev->handle_status = FILE_HANDLE_OK;\n")},
		{"input handle read twice", enter(handleReadLine +
			"    ior_read_file_handle(ctx->args[2], &ev->handle_bytes, &ev->handle_type, ev->f_handle);\n")},
	}
}

// TestSyscallSemanticsOracleRejectsHandleCaptureMutations keeps the oracle
// honest about the two file-handle captures (task k03): each mutation of the
// committed handlers must fail parsing or the comparison with the reviewed
// rows.
func TestSyscallSemanticsOracleRejectsHandleCaptureMutations(t *testing.T) {
	source, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatalf("read generated tracepoints C: %v", err)
	}
	mutations := append(outputHandleEnterMutations(), outputHandleExitMutations()...)
	mutations = append(mutations, inputHandleMutations()...)
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			actual, err := parseGeneratedSyscallSemantics(mutation.mutate(t, source))
			if err == nil && len(compareSyscallSemantics(syscallSemanticExpectations, actual)) == 0 {
				t.Fatalf("%s mutation did not fail parsing or comparison", mutation.name)
			}
		})
	}
}
