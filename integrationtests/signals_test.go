package integrationtests

import "testing"

// signalsTraceArgs restricts tracing to the SIGNALS-family syscalls the
// signals-basic workload issues, so the output is dominated by those calls.
// pause (noreturn-blocking) and rt_sigreturn (only reachable via handler
// return) are intentionally absent: the scenario never invokes them.
var signalsTraceArgs = []string{
	"-trace-syscalls",
	"rt_sigaction,rt_sigprocmask,rt_sigpending,sigaltstack,kill,tgkill,tkill,rt_sigqueueinfo,rt_sigtimedwait",
}

// TestSignalsBasic verifies the SIGNALS syscall family is traced end-to-end.
// The signals-basic workload self-directs every call (installs a handler,
// blocks SIGUSR1, sets an alternate stack, sends SIGUSR1 to itself four ways,
// queries pending signals, and reaps one with a short timeout), so it never
// touches another process. Each required syscall must appear as an enter event.
func TestSignalsBasic(t *testing.T) {
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs("signals-basic", defaultDuration, signalsTraceArgs)
	if err != nil {
		t.Fatalf("run scenario signals-basic: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, []ExpectedEvent{
		{Tracepoint: "enter_rt_sigaction", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_rt_sigprocmask", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_rt_sigpending", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_sigaltstack", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_kill", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_tgkill", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_rt_sigtimedwait", Comm: "ioworkload", MinCount: 1},
	})

	// rt_sigtimedwait blocks (briefly) on its timeout, so the paired enter/exit
	// must carry a positive duration — proof the exit tracepoint was correlated.
	assertEventDurationPositive(t, result,
		ExpectedEvent{Tracepoint: "enter_rt_sigtimedwait", Comm: "ioworkload"})
}
