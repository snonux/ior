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
	case strings.Contains(body, "ior_on_syscall_enter("):
		hookAt := strings.Index(body, "ior_on_syscall_enter(")
		if hookAt < clockAt {
			return fmt.Errorf("%s: enter hook runs before the clock read it needs", name)
		}
		if !regexp.MustCompile(`ior_on_syscall_enter\(tid, \w+, now\)`).MatchString(body) {
			return fmt.Errorf("%s: enter hook must be passed the handler's timestamp", name)
		}
	case strings.Contains(body, "ior_on_syscall_exit("):
		hookAt := strings.Index(body, "ior_on_syscall_exit(")
		if hookAt < clockAt {
			return fmt.Errorf("%s: exit hook runs before the clock read it needs", name)
		}
		if !regexp.MustCompile(`ior_on_syscall_exit\(tid, \w+, ctx->ret, now\)`).MatchString(body) {
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
		"ior_on_noreturn_syscall_enter": "(__u32 enter_trace_id)",
		"ior_on_syscall_exit":           "(__u32 tid, __u32 enter_trace_id, __s64 ret, __u64 now)",
	}
	for hook, params := range hooks {
		re := regexp.MustCompile(`(?s)static __always_inline int ` + hook + `(\(.*?\)) \{\n(.*?)\n\}\n`)
		m := re.FindStringSubmatch(filterC)
		if m == nil {
			t.Errorf("%s not found in filter.c", hook)
			continue
		}
		if m[1] != params {
			t.Errorf("%s parameters = %s, want %s", hook, m[1], params)
		}
		if strings.Contains(m[2], clockHelperCall) {
			t.Errorf("%s reads the clock itself; it must use the handler's timestamp", hook)
		}
	}
	if !strings.Contains(filterC, "    state.start_ns = now;\n") {
		t.Error("ior_on_syscall_enter must record the handler's timestamp as start_ns")
	}
	if !strings.Contains(filterC, "        duration = now - state->start_ns;\n") {
		t.Error("ior_on_syscall_exit must derive the duration from the handler's timestamp")
	}
}

// TestCheckHandlerClockReadRejectsViolations keeps the checker honest: each
// case is a way the single-read contract can regress, starting with the
// pre-task-69 shape where the body read the clock again for ev->time.
func TestCheckHandlerClockReadRejectsViolations(t *testing.T) {
	good := GenerateTracepointsC(mustParseAll(t, FormatRead+"\n"+FormatExitRead+"\n"))
	handlers := splitGeneratedHandlers(t, good)
	enter, exit := handlers["sys_enter_read"], handlers["sys_exit_read"]
	for name, body := range handlers {
		if err := checkHandlerClockRead(name, body); err != nil {
			t.Fatalf("fixture is not valid to begin with: %v", err)
		}
	}

	cases := []struct {
		name, body string
	}{
		{"second read for ev->time", strings.Replace(enter, "ev->time = now;", "ev->time = bpf_ktime_get_boot_ns();", 1)},
		{"no clock read at all", strings.Replace(exit, clockReadLine, "    __u64 now = 0;\n", 1)},
		{"hook not given the timestamp", strings.Replace(exit, "ctx->ret, now)", "ctx->ret)", 1)},
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.body == enter || tc.body == exit {
				t.Fatal("mutation did not apply; the fixture shape changed")
			}
			if err := checkHandlerClockRead("mutated", tc.body); err == nil {
				t.Errorf("checker accepted:\n%s", tc.body)
			}
		})
	}
}
