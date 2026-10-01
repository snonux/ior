package generate

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// clockHelperCall is the BPF clock helper. It is counted by call site: every
// generated syscall handler must call it exactly once and reuse the value for
// both the enter/exit hook and ev->time (task 69; before, the hook and the
// body each read the clock, four helper calls per traced syscall).
const clockHelperCall = "bpf_ktime_get_boot_ns("

// handlerSplit matches the start of every generated syscall handler.
var handlerSplit = regexp.MustCompile(`(?m)^/// (sys_\w+) is a struct `)

// enterHookCall finds an enter hook call of either variant: ior_on_syscall_enter
// or ior_on_syscall_enter_stateful (the handlers that stash a pending filename).
var enterHookCall = regexp.MustCompile(`ior_on_syscall_enter(_stateful)?\(`)

// enterHookWithNow and exitHookWithNow match the enter/exit hook calls that
// are passed the handler's single timestamp. The exit hook has three variants:
// the plain one, and the two that also hand back the pending filename(s) from
// their single enter-state lookup (the argument after now is then an out
// pointer, not the closing parenthesis).
var (
	enterHookWithNow = regexp.MustCompile(`ior_on_syscall_enter(_stateful)?\(tid, \w+, now\)`)
	exitHookCall     = regexp.MustCompile(`ior_on_syscall_exit(_take_filenames?)?\(`)
	exitHookWithNow  = regexp.MustCompile(`ior_on_syscall_exit(_take_filenames?)?\(tid, \w+, ctx->ret, now[,)]`)
)

// splitGeneratedHandlers returns each generated handler body keyed by its
// tracepoint name, from its /// comment through the closing brace.
func splitGeneratedHandlers(t *testing.T, generated string) map[string]string {
	t.Helper()
	locs := handlerSplit.FindAllStringSubmatchIndex(generated, -1)
	handlers := make(map[string]string, len(locs))
	for _, loc := range locs {
		name := generated[loc[2]:loc[3]]
		rest := generated[loc[0]:]
		end := strings.Index(rest, "\n}\n")
		if end < 0 {
			t.Fatalf("handler %s has no closing brace", name)
		}
		handlers[name] = rest[:end+3]
	}
	return handlers
}

// checkHandlerClockRead verifies the single-clock-read contract of one
// generated handler body and returns the first violation, or nil.
func checkHandlerClockRead(name, body string) error {
	if got := strings.Count(body, clockHelperCall); got != 1 {
		return fmt.Errorf("%s: %d %s calls, want exactly 1", name, got, clockHelperCall)
	}
	if got := strings.Count(body, "ev->time = "); got != 1 {
		return fmt.Errorf("%s: %d ev->time assignments, want exactly 1", name, got)
	}
	if !strings.Contains(body, "    ev->time = now;\n") {
		return fmt.Errorf("%s: ev->time must reuse the handler's single clock read", name)
	}

	clockAt := strings.Index(body, clockReadLine)
	if clockAt < 0 {
		return fmt.Errorf("%s: missing %q", name, strings.TrimSpace(clockReadLine))
	}
	if filterAt := strings.Index(body, "if (filter(&pid, &tid))"); filterAt < 0 || filterAt > clockAt {
		return fmt.Errorf("%s: the clock must be read only after filter() accepted the task", name)
	}
	if reserveAt := strings.Index(body, "bpf_ringbuf_reserve("); reserveAt >= 0 && reserveAt < clockAt {
		return fmt.Errorf("%s: the clock is read after the ring-buffer reserve", name)
	}

	switch {
	case strings.Contains(body, "ior_on_noreturn_syscall_enter("):
		// The noreturn hook takes no timestamp; the clock is read only once
		// the event is known to be emitted.
		if strings.Index(body, "ior_on_noreturn_syscall_enter(") > clockAt {
			return fmt.Errorf("%s: noreturn handler reads the clock before its sampling decision", name)
		}
	case enterHookCall.MatchString(body):
		hookAt := enterHookCall.FindStringIndex(body)[0]
		if hookAt < clockAt {
			return fmt.Errorf("%s: enter hook runs before the clock read it needs", name)
		}
		if !enterHookWithNow.MatchString(body) {
			return fmt.Errorf("%s: enter hook must be passed the handler's timestamp", name)
		}
	case exitHookCall.MatchString(body):
		hookAt := exitHookCall.FindStringIndex(body)[0]
		if hookAt < clockAt {
			return fmt.Errorf("%s: exit hook runs before the clock read it needs", name)
		}
		if !exitHookWithNow.MatchString(body) {
			return fmt.Errorf("%s: exit hook must be passed the handler's timestamp", name)
		}
	default:
		return fmt.Errorf("%s: no enter/exit hook call", name)
	}
	return nil
}

// TestGenerateHandlersReadTheClockOnce checks freshly generated output for
// every hook variant: returning enter, exit, noreturn enter and the open
// kinds with faulted-filename recovery.
func TestGenerateHandlersReadTheClockOnce(t *testing.T) {
	pairs := []struct{ enter, exit string }{
		{FormatRead, FormatExitRead},
		{FormatOpenat, FormatExitOpenat},
		{FormatClose, FormatExitClose},
		{FormatMmap, FormatExitMmap},
		{FormatExecve, FormatExitExecve},
		{syntheticEnter("exit_group", 60), syntheticExit("exit_group", 59)},
	}
	var input strings.Builder
	for _, p := range pairs {
		input.WriteString(p.enter + "\n" + p.exit + "\n")
	}
	handlers := splitGeneratedHandlers(t, GenerateTracepointsC(mustParseAll(t, input.String())))

	// exit_group has no exit handler, so one fewer than two per pair.
	if want := 2*len(pairs) - 1; len(handlers) != want {
		t.Fatalf("generated %d handlers, want %d", len(handlers), want)
	}
	if _, ok := handlers["sys_enter_exit_group"]; !ok {
		t.Fatal("noreturn enter handler missing from the fixture")
	}
	for name, body := range handlers {
		if err := checkHandlerClockRead(name, body); err != nil {
			t.Errorf("%v\n%s", err, body)
		}
	}
}

// TestGeneratedArtifactReadsTheClockOnce applies the same contract to every
// handler in the committed internal/c/generated_tracepoints.c, including the
// tracepoints that only exist on the newer generation kernel.
func TestGeneratedArtifactReadsTheClockOnce(t *testing.T) {
	artifact, err := readGeneratedTracepointsC()
	if err != nil {
		t.Fatalf("read generated tracepoints C: %v", err)
	}
	handlers := splitGeneratedHandlers(t, artifact)
	if len(handlers) == 0 {
		t.Fatal("no handlers found in generated_tracepoints.c")
	}
	for name, body := range handlers {
		if err := checkHandlerClockRead(name, body); err != nil {
			t.Error(err)
		}
	}
	if got, want := strings.Count(artifact, clockHelperCall), len(handlers); got != want {
		t.Errorf("%d clock reads in generated_tracepoints.c, want one per handler (%d)", got, want)
	}
}

// TestSyscallHooksDoNotReadTheClock pins the other half: the enter/exit hooks
// in filter.c take the handler's timestamp and must not call the clock helper
// themselves, or a traced syscall is back to two reads per side.
func TestSyscallHooksDoNotReadTheClock(t *testing.T) {
	filterC, err := readCSource("filter.c")
	if err != nil {
		t.Fatalf("read filter.c: %v", err)
	}
	hooks := map[string]string{
		"ior_on_syscall_enter":          "(__u32 tid, __u32 enter_trace_id, __u64 now)",
		"ior_on_syscall_enter_stateful": "(__u32 tid, __u32 enter_trace_id, __u64 now)",
		"ior_on_syscall_enter_impl":     "(__u32 tid, __u32 enter_trace_id, __u64 now, int keep_state)",
		"ior_on_noreturn_syscall_enter": "(__u32 enter_trace_id)",
		"ior_on_syscall_exit":           "(__u32 tid, __u32 enter_trace_id, __s64 ret, __u64 now)",
		"ior_on_syscall_exit_impl": "(__u32 tid, __u32 enter_trace_id, __s64 ret, __u64 now, " +
			"__u64 *pending_filename, __u64 *pending_filename2)",
		"ior_on_syscall_exit_take_filename": "(__u32 tid, __u32 enter_trace_id, __s64 ret, __u64 now, " +
			"__u64 *pending_filename)",
		"ior_on_syscall_exit_take_filenames": "(__u32 tid, __u32 enter_trace_id, __s64 ret, __u64 now, " +
			"__u64 *pending_filename, __u64 *pending_filename2)",
	}
	for hook, params := range hooks {
		re := regexp.MustCompile(`(?s)static __always_inline int ` + hook + `(\(.*?\)) \{\n(.*?)\n\}\n`)
		m := re.FindStringSubmatch(filterC)
		if m == nil {
			t.Errorf("%s not found in filter.c", hook)
			continue
		}
		// A long parameter list is wrapped over several lines in filter.c;
		// compare it as one line.
		if strings.Join(strings.Fields(m[1]), " ") != params {
			t.Errorf("%s parameters = %s, want %s", hook, m[1], params)
		}
		if strings.Contains(m[2], clockHelperCall) {
			t.Errorf("%s reads the clock itself; it must use the handler's timestamp", hook)
		}
	}
	if !strings.Contains(filterC, "    state.start_ns = now;\n") {
		t.Error("ior_on_syscall_enter must record the handler's timestamp as start_ns")
	}
	if !strings.Contains(filterC, "    duration = now > state->start_ns ? now - state->start_ns : 1;\n") {
		t.Error("ior_on_syscall_exit must derive the duration from the handler's timestamp")
	}
}

// TestCheckHandlerClockReadRejectsViolations keeps the checker honest: each
// case is a way the single-read contract can regress, starting with the
// pre-task-69 shape where the body read the clock again for ev->time.
func TestCheckHandlerClockReadRejectsViolations(t *testing.T) {
	good := GenerateTracepointsC(mustParseAll(t, FormatRead+"\n"+FormatExitRead+"\n"+
		FormatOpenat+"\n"+FormatExitOpenat+"\n"+
		syntheticEnter("exit_group", 60)+"\n"+syntheticExit("exit_group", 59)+"\n"))
	handlers := splitGeneratedHandlers(t, good)
	enter, exit := handlers["sys_enter_read"], handlers["sys_exit_read"]
	noreturn := handlers["sys_enter_exit_group"]
	taking := handlers["sys_exit_openat"]
	if enter == "" || exit == "" || noreturn == "" || taking == "" {
		t.Fatal("fixture is missing the enter, exit or noreturn handler")
	}
	for name, body := range handlers {
		if err := checkHandlerClockRead(name, body); err != nil {
			t.Fatalf("fixture is not valid to begin with: %v", err)
		}
	}

	for _, tc := range clockReadViolations(enter, exit, noreturn, taking) {
		t.Run(tc.name, func(t *testing.T) {
			if tc.body == enter || tc.body == exit || tc.body == noreturn || tc.body == taking {
				t.Fatal("mutation did not apply; the fixture shape changed")
			}
			if err := checkHandlerClockRead("mutated", tc.body); err == nil {
				t.Errorf("checker accepted:\n%s", tc.body)
			}
		})
	}
}

// clockReadViolation is one handler body mutated so that it breaks the
// single-clock-read contract checkHandlerClockRead enforces.
type clockReadViolation struct {
	name, body string
}

// clockReadViolations is the mutation table of
// TestCheckHandlerClockReadRejectsViolations, kept apart from the test so the
// test body stays short. Each entry rewrites one of the four valid fixture
// handlers (a plain enter, a plain exit, a noreturn enter and a
// pointer-taking exit) into a shape the checker must reject; a mutation whose
// anchor text no longer matches returns the handler unchanged, which the test
// reports as a fixture change rather than as an accepted violation.
func clockReadViolations(enter, exit, noreturn, taking string) []clockReadViolation {
	return []clockReadViolation{
		{"second read for ev->time", strings.Replace(enter, "ev->time = now;", "ev->time = bpf_ktime_get_boot_ns();", 1)},
		{"no clock read at all", strings.Replace(exit, clockReadLine, "    __u64 now = 0;\n", 1)},
		{"hook not given the timestamp", strings.Replace(exit, "ctx->ret, now)", "ctx->ret)", 1)},
		{"pointer-taking hook not given the timestamp", strings.Replace(taking, "ctx->ret, now, &", "ctx->ret, 0, &", 1)},
		{"pointer-taking hook before the clock read", strings.Replace(
			strings.Replace(taking, clockReadLine, "", 1),
			"&pending_filename))\n        return 0;\n", "&pending_filename))\n        return 0;\n"+clockReadLine, 1)},
		{"enter hook not given the timestamp", strings.Replace(enter, ", now)", ")", 1)},
		{"clock read after the hook", strings.Replace(
			strings.Replace(exit, clockReadLine, "", 1),
			"        return 0;\n\n    struct", "        return 0;\n"+clockReadLine+"\n    struct", 1)},
		{"clock read before filter", strings.Replace(
			strings.Replace(enter, clockReadLine, "", 1),
			"    __u32 pid, tid;\n", "    __u32 pid, tid;\n"+clockReadLine, 1)},
		{"clock read after reserve", strings.Replace(
			strings.Replace(enter, clockReadLine, "", 1),
			"    ev->time = now;\n", clockReadLine+"    ev->time = now;\n", 1)},
		{"noreturn clock read before the sampling decision", strings.Replace(
			strings.Replace(noreturn, "\n"+clockReadLine, "", 1),
			"    if (!ior_on_noreturn_syscall_enter(", clockReadLine+"    if (!ior_on_noreturn_syscall_enter(", 1)},
	}
}
