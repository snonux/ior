package integrationtests

import "testing"

const (
	seccompDeniedScenario = "seccomp-denied"
	// seccompDeniedCalls mirrors ioworkload's constant: the fchmod calls
	// the scenario makes under its filter.
	seccompDeniedCalls = 3
)

// TestSeccompDeniedCallsShowAsExitsWithoutEnter pins what ior makes of a call
// a seccomp filter answers itself (task c23). The filter runs before the
// sys_enter tracepoint and the skipped call still fires sys_exit, so each
// denied fchmod is an exit without an enter of a thread ior has seen: no row,
// one count in the "exits without an enter" statistic, and - failed with the
// filter's errno - one in the share that looks like a filter's answer.
//
// The counts are lower bounds here, not exact: a skipped probe run of the
// workload would add a lost half of its own. The one fchmod before the
// filter is the row.
func TestSeccompDeniedCallsShowAsExitsWithoutEnter(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	h.IorOutput = &OutputCapture{}
	result, pid, err := h.RunWithIorArgs(seccompDeniedScenario, defaultDuration,
		[]string{"-trace-syscalls", "fchmod"})
	if err != nil {
		t.Fatalf("run scenario %s: %v", seccompDeniedScenario, err)
	}
	AssertNoUnexpectedPID(t, result, pid)
	AssertEventsPresent(t, result, []ExpectedEvent{
		{Tracepoint: "enter_fchmod", Comm: "ioworkload", MinCount: 1},
	})
	logged := h.IorOutput.String()
	loss, err := ParseKernelLoss(logged)
	if err != nil {
		t.Fatalf("%v:\n%s", err, logged)
	}
	if loss.ExitsWithoutEnter < seccompDeniedCalls || loss.FilterLikeExits < seccompDeniedCalls {
		t.Fatalf("%d exits without an enter, %d of them filter-like, want at least %d each:\n%s",
			loss.ExitsWithoutEnter, loss.FilterLikeExits, seccompDeniedCalls, logged)
	}
	if loss.FilterLikeExits > loss.ExitsWithoutEnter {
		t.Fatalf("the filter-like share %d exceeds its count %d", loss.FilterLikeExits, loss.ExitsWithoutEnter)
	}
}
