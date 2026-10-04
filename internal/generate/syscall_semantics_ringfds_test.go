package generate

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// The registered-ring capture of io_uring_register (task js2,
// internal/c/iouring.c) in the semantics oracle: what the committed handlers
// must look like, and the mutations of them the oracle must reject.

// ringFdsEnterRE matches the whole enter half: the hook's verdict kept in a
// local, the stash of the opcode and array arguments right behind it with
// that verdict and the handler's clock read, and only then the return of a
// sampled-out enter.
func ringFdsEnterRE(enterConst string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^    int emits = ior_on_syscall_enter\(tid, ` + enterConst + `, now\);\n\n` +
		`    ior_stash_ring_fds\(tid, ` + enterConst + `, now, emits, ctx->args\[([0-9]+)\], ctx->args\[([0-9]+)\]\);\n` +
		`    if \(!emits\)\n        return 0;$`)
}

// ringFdsExitRE matches the whole exit half: both slots taken by the exit
// hook's one lookup, the record published with the handler's clock read, the
// taken opcode and pointer and the return value, and only then the return of
// a sampled-out exit.
func ringFdsExitRE(enterConst string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^    __u64 ring_fds_array;\n    __u64 ring_fds_opcode;\n\n` +
		`    __u64 now = bpf_ktime_get_boot_ns\(\);\n` +
		`    int emits = ior_on_syscall_exit_take_filenames\(tid, ` + enterConst +
		`, ctx->ret, now, &ring_fds_array, &ring_fds_opcode\);\n\n` +
		`    ior_emit_ring_fds\(pid, tid, ` + enterConst + `, now, ring_fds_opcode, ring_fds_array, ctx->ret\);\n` +
		`    if \(!emits\)\n        return 0;$`)
}

// addRingFdsArgSources records the two arguments the registered-ring capture
// parks, when the handlers of name have the capture. They are the
// "ring_fds_opcode" and "ring_fds_array" sources of io_uring_register's row
// in syscallSemanticExpectations: io_uring_register(fd, opcode, arg,
// nr_args) parks args[1] and args[2] next to the fd and opcode its record
// carries.
func addRingFdsArgSources(name, enterBody, exitBody string, result map[string]int) error {
	opcodeArg, arrayArg, ok, err := parseRingFdsCapture(name, enterBody, exitBody)
	if err != nil || !ok {
		return err
	}
	if err := addArgSource(name, result, "ring_fds_opcode", opcodeArg); err != nil {
		return err
	}
	return addArgSource(name, result, "ring_fds_array", arrayArg)
}

// parseRingFdsCapture recognizes the registered-ring capture and returns the
// argument indexes of the opcode and of the array pointer. A handler pair
// that mentions any part of it must have all of it, exactly once, in the
// reviewed shape and ahead of its own ring-buffer reserve: the capture is
// not conditional on the sampling verdict, so its place relative to the
// "if (!emits) return 0;" lines is part of what it means.
func parseRingFdsCapture(name, enterBody, exitBody string) (opcodeArg, arrayArg int, ok bool, err error) {
	if !strings.Contains(enterBody+exitBody, "ring_fds") {
		return 0, 0, false, nil
	}
	enterConst := regexp.QuoteMeta("SYS_ENTER_" + strings.ToUpper(name))
	stashes := ringFdsEnterRE(enterConst).FindAllStringSubmatchIndex(enterBody, -1)
	if len(stashes) != 1 || strings.Count(enterBody, "ior_stash_ring_fds(") != 1 || strings.Count(enterBody, "emits") != 3 {
		return 0, 0, false, fmt.Errorf("sys_enter_%s must stash its ring-fds arguments once, right after its enter hook and whatever that hook decided", name)
	}
	stash := stashes[0]
	if reserve := ringbufReserveRE.FindStringIndex(enterBody); reserve == nil || stash[1] > reserve[0] {
		return 0, 0, false, fmt.Errorf("sys_enter_%s stashes its ring-fds arguments after its reserve", name)
	}
	if strings.Contains(enterBody, "ior_stash_pending_") {
		return 0, 0, false, fmt.Errorf("sys_enter_%s uses the pending slots for a path and for ring fds", name)
	}
	if err := validateRingFdsExit(name, enterConst, exitBody); err != nil {
		return 0, 0, false, err
	}
	return mustArgIndex(enterBody[stash[2]:stash[3]]), mustArgIndex(enterBody[stash[4]:stash[5]]), true, nil
}

// validateRingFdsExit checks the exit half of parseRingFdsCapture.
func validateRingFdsExit(name, enterConst, exitBody string) error {
	emits := ringFdsExitRE(enterConst).FindAllStringIndex(exitBody, -1)
	allHooks := regexp.MustCompile(`\bior_on_syscall_exit\w*\s*\(`).FindAllStringIndex(exitBody, -1)
	if len(emits) != 1 || len(allHooks) != 1 || strings.Count(exitBody, "ior_emit_ring_fds(") != 1 ||
		strings.Count(exitBody, "emits") != 2 || strings.Count(exitBody, "ring_fds_") != 6 {
		return fmt.Errorf("sys_exit_%s must take its ring-fds slots once through its exit hook and publish them once, whatever that hook decided", name)
	}
	if reserve := ringbufReserveRE.FindStringIndex(exitBody); reserve == nil || emits[0][1] > reserve[0] {
		return fmt.Errorf("sys_exit_%s publishes its ring fds after its reserve", name)
	}
	return nil
}

const (
	ringFdsStashLine = "    ior_stash_ring_fds(tid, SYS_ENTER_IO_URING_REGISTER, now, emits, ctx->args[1], ctx->args[2]);\n"
	ringFdsEmitLine  = "    ior_emit_ring_fds(pid, tid, SYS_ENTER_IO_URING_REGISTER, now, ring_fds_opcode, ring_fds_array, ctx->ret);\n"
	ringFdsTakeCall  = "ior_on_syscall_exit_take_filenames(tid, SYS_ENTER_IO_URING_REGISTER, ctx->ret, now, &ring_fds_array, &ring_fds_opcode)"
	ringFdsGateLines = "    if (!emits)\n        return 0;\n"
)

// ringFdsMutation edits one handler of io_uring_register.
func ringFdsMutation(phase, old, replacement string) func(*testing.T, string) string {
	return func(t *testing.T, source string) string {
		return replaceInHandler(t, source, phase, "io_uring_register", old, replacement)
	}
}

// ringFdsEnterMutations break the enter half of the capture.
func ringFdsEnterMutations() []semanticMutation {
	enter := func(old, replacement string) func(*testing.T, string) string {
		return ringFdsMutation("enter", old, replacement)
	}
	return []semanticMutation{
		{"ring fds stash removed", enter(ringFdsStashLine, "")},
		{"ring fds opcode from the fd argument", enter("emits, ctx->args[1], ctx->args[2]);", "emits, ctx->args[0], ctx->args[2]);")},
		{"ring fds array from the count argument", enter("emits, ctx->args[1], ctx->args[2]);", "emits, ctx->args[1], ctx->args[3]);")},
		{"ring fds opcode and array swapped", enter("emits, ctx->args[1], ctx->args[2]);", "emits, ctx->args[2], ctx->args[1]);")},
		{"ring fds stashed only for an emitted enter", enter(ringFdsStashLine+ringFdsGateLines, ringFdsGateLines+ringFdsStashLine)},
		{"ring fds stash told every enter is emitted", enter("now, emits, ctx->args[1]", "now, 1, ctx->args[1]")},
		{"ring fds stashed with another clock read", enter("SYS_ENTER_IO_URING_REGISTER, now, emits,", "SYS_ENTER_IO_URING_REGISTER, bpf_ktime_get_boot_ns(), emits,")},
		{"ring fds stashed for the wrong syscall", enter("ior_stash_ring_fds(tid, SYS_ENTER_IO_URING_REGISTER,", "ior_stash_ring_fds(tid, SYS_ENTER_READ,")},
		{"ring fds stashed before the enter hook", func(t *testing.T, source string) string {
			source = replaceInHandler(t, source, "enter", "io_uring_register", ringFdsStashLine, "")
			return replaceInHandler(t, source, "enter", "io_uring_register",
				"    int emits = ior_on_syscall_enter(", "    int emits = 1;\n"+ringFdsStashLine+"    emits = ior_on_syscall_enter(")
		}},
		{"ring fds stashed twice", enter(ringFdsStashLine, ringFdsStashLine+ringFdsStashLine)},
	}
}

// ringFdsExitMutations break the exit half: whether, when and with what the
// record is published, and how the slots are taken.
func ringFdsExitMutations() []semanticMutation {
	exit := func(old, replacement string) func(*testing.T, string) string {
		return ringFdsMutation("exit", old, replacement)
	}
	return []semanticMutation{
		{"ring fds never published", exit(ringFdsEmitLine, "")},
		{"ring fds published only for an emitted exit", exit(ringFdsEmitLine+ringFdsGateLines, ringFdsGateLines+ringFdsEmitLine)},
		{"ring fds published only for a failed call", exit(ringFdsEmitLine, "    if (ctx->ret < 0)\n    "+ringFdsEmitLine)},
		{"ring fds opcode and array swapped", exit("now, ring_fds_opcode, ring_fds_array, ctx->ret);", "now, ring_fds_array, ring_fds_opcode, ctx->ret);")},
		{"ring fds published without the return value", exit("ring_fds_array, ctx->ret);", "ring_fds_array, 1);")},
		{"ring fds stamped with another clock read", exit("SYS_ENTER_IO_URING_REGISTER, now, ring_fds_opcode,", "SYS_ENTER_IO_URING_REGISTER, bpf_ktime_get_boot_ns(), ring_fds_opcode,")},
		{"ring fds published for the wrong syscall", exit("ior_emit_ring_fds(pid, tid, SYS_ENTER_IO_URING_REGISTER,", "ior_emit_ring_fds(pid, tid, SYS_ENTER_READ,")},
		{"ring fds slots never taken", exit(ringFdsTakeCall, "ior_on_syscall_exit(tid, SYS_ENTER_IO_URING_REGISTER, ctx->ret, now)")},
		{"ring fds slots taken in the other order", exit("&ring_fds_array, &ring_fds_opcode)", "&ring_fds_opcode, &ring_fds_array)")},
		{"ring fds taken for the wrong syscall", exit("ior_on_syscall_exit_take_filenames(tid, SYS_ENTER_IO_URING_REGISTER,", "ior_on_syscall_exit_take_filenames(tid, SYS_ENTER_READ,")},
		{"ring fds published twice", exit(ringFdsEmitLine, ringFdsEmitLine+ringFdsEmitLine)},
	}
}

// ringFdsSpreadMutations give the capture to a syscall that must not have it:
// io_uring_enter is the hot one, and its handlers must not gain work.
func ringFdsSpreadMutations() []semanticMutation {
	return []semanticMutation{
		{"io_uring_enter stashes ring fds", func(t *testing.T, source string) string {
			return replaceInHandler(t, source, "enter", "io_uring_enter",
				"    if (!ior_on_syscall_enter(tid, SYS_ENTER_IO_URING_ENTER, now))\n        return 0;\n",
				"    int emits = ior_on_syscall_enter(tid, SYS_ENTER_IO_URING_ENTER, now);\n\n"+
					"    ior_stash_ring_fds(tid, SYS_ENTER_IO_URING_ENTER, now, emits, ctx->args[1], ctx->args[2]);\n"+ringFdsGateLines)
		}},
		{"io_uring_enter publishes ring fds", func(t *testing.T, source string) string {
			return replaceInHandler(t, source, "exit", "io_uring_enter",
				"    if (!ior_on_syscall_exit(tid, SYS_ENTER_IO_URING_ENTER, ctx->ret, now))\n        return 0;\n",
				"    if (!ior_on_syscall_exit(tid, SYS_ENTER_IO_URING_ENTER, ctx->ret, now))\n        return 0;\n"+
					"    ior_emit_ring_fds(pid, tid, SYS_ENTER_IO_URING_ENTER, now, 20, 0, ctx->ret);\n")
		}},
	}
}

// TestSyscallSemanticsOracleRejectsRingFdsCaptureMutations keeps the oracle
// honest about the registered-ring capture (task js2): each mutation of the
// committed handlers must fail parsing or the comparison with the reviewed
// rows.
func TestSyscallSemanticsOracleRejectsRingFdsCaptureMutations(t *testing.T) {
	source, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatalf("read generated tracepoints C: %v", err)
	}
	mutations := append(ringFdsEnterMutations(), ringFdsExitMutations()...)
	mutations = append(mutations, ringFdsSpreadMutations()...)
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			actual, err := parseGeneratedSyscallSemantics(mutation.mutate(t, source))
			if err == nil && len(compareSyscallSemantics(syscallSemanticExpectations, actual)) == 0 {
				t.Fatalf("%s mutation did not fail parsing or comparison", mutation.name)
			}
		})
	}
}

// TestSyscallSemanticsOracleAcceptsTheCommittedRingFdsCapture is the other
// half: the unmutated artifact has the capture on io_uring_register, with the
// reviewed arguments, and on no other syscall.
func TestSyscallSemanticsOracleAcceptsTheCommittedRingFdsCapture(t *testing.T) {
	source, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatalf("read generated tracepoints C: %v", err)
	}
	if got := strings.Count(source, "ring_fds"); got != 8 {
		t.Errorf("the artifact mentions ring_fds %d times, want the 8 of one handler pair", got)
	}
	handlers := splitGeneratedHandlers(t, source)
	opcodeArg, arrayArg, ok, err := parseRingFdsCapture("io_uring_register",
		handlers["sys_enter_io_uring_register"], handlers["sys_exit_io_uring_register"])
	if err != nil || !ok || opcodeArg != 1 || arrayArg != 2 {
		t.Fatalf("io_uring_register capture: opcode arg %d, array arg %d, present %v, err %v; want 1, 2, true, nil",
			opcodeArg, arrayArg, ok, err)
	}
}
