package integrationtests

import (
	"regexp"
	"testing"
)

const (
	getppidBurstScenario = "getppid-burst"
	// getppidBurstCalls mirrors ioworkload's constant of the same name.
	getppidBurstCalls = 1_500_000
	// stopAccountingSlack is how many records beyond the getppid ones a run
	// may count: the exit records of the workload's threads, which pass the
	// -pid filter as well. How many of them fall before the stop varies.
	stopAccountingSlack = 64
	// stopAccountingAttempts bounds the reruns after a run in which the
	// kernel skipped probe runs.
	stopAccountingAttempts = 3
)

var (
	tracepointsLine     = regexp.MustCompile(`tracepoints: ([^\n]+)`)
	discardedAtStopLine = regexp.MustCompile(`records discarded at stop: ([^\n]+)`)
	leftInRingLine      = regexp.MustCompile(`records left in the kernel ring buffer at stop: ([^\n]+)`)
)

// stopFigures are the end-of-run figures a record can end up in.
type stopFigures struct {
	tracepoints, discarded, leftInRing uint64
	loss                               KernelLoss
}

// accounted is the number of records the figures account for.
func (f stopFigures) accounted() uint64 {
	return f.tracepoints + f.loss.RingDrops + f.discarded + f.leftInRing
}

// TestStopAccountsForEveryRecord is the accounting identity of task f23, end
// to end: the workload makes a known number of getppid calls and exits, the
// trace stops on that exit, and every record the kernel produced must be in
// exactly one figure - decoded (tracepoints), dropped by the full ring,
// discarded at stop, or left in the kernel ring buffer. The loop outruns
// ior, so the stop usually finds rawCh full and the ring behind it filled;
// before the fix such a run was short of exactly one channel's worth (4096).
//
// What the assertion can and cannot say: ring-buffer drops are counted
// exactly, so they are part of the sum, not a reason to give up. A probe run
// the kernel skipped produced no record and is counted for every task on the
// host, so a run with any is not judged (rerun, then skipped). On a host
// where ior keeps up the sum is just the tracepoints, and the test passes
// without having exercised the lagging stop; the unit tests in
// internal/eventloop_stopaccount_test.go cover that case on every host.
func TestStopAccountsForEveryRecord(t *testing.T) {
	enableParallelIfRequested(t)
	const want = 2 * getppidBurstCalls
	for range stopAccountingAttempts {
		figures := runGetppidBurst(t)
		if figures.loss.SkippedRuns > 0 {
			t.Logf("the kernel skipped %d probe runs; the records produced are not known, rerunning", figures.loss.SkippedRuns)
			continue
		}
		t.Logf("%+v", figures)
		if got := figures.accounted(); got < want || got > want+stopAccountingSlack {
			t.Fatalf("the figures account for %d records, want the %d of %d getppid calls (plus at most %d exit records): %+v",
				got, want, getppidBurstCalls, stopAccountingSlack, figures)
		}
		return
	}
	t.Skipf("the kernel skipped probe runs in each of %d runs; the accounting cannot be judged", stopAccountingAttempts)
}

// runGetppidBurst traces one getppid-burst run and returns its figures.
func runGetppidBurst(t *testing.T) stopFigures {
	t.Helper()
	h := newTestHarness(t)
	h.IorOutput = &OutputCapture{}
	if _, _, err := h.RunWithIorArgs(getppidBurstScenario, defaultDuration, []string{"-trace-syscalls", "getppid"}); err != nil {
		t.Fatalf("run scenario %s: %v", getppidBurstScenario, err)
	}
	logged := h.IorOutput.String()
	loss, err := ParseKernelLoss(logged)
	if err != nil {
		t.Fatalf("%v:\n%s", err, logged)
	}
	tracepoints, err := statFigure(logged, tracepointsLine, "tracepoints")
	if err != nil {
		t.Fatalf("%v:\n%s", err, logged)
	}
	return stopFigures{
		tracepoints: tracepoints,
		discarded:   optionalStatFigure(t, logged, discardedAtStopLine, "records discarded at stop"),
		leftInRing:  optionalStatFigure(t, logged, leftInRingLine, "records left in the kernel ring buffer at stop"),
		loss:        loss,
	}
}

// optionalStatFigure reads a statistics line that ior prints only when its
// figure is not zero.
func optionalStatFigure(t *testing.T, logged string, line *regexp.Regexp, name string) uint64 {
	t.Helper()
	if !line.MatchString(logged) {
		return 0
	}
	n, err := statFigure(logged, line, name)
	if err != nil {
		t.Fatalf("%v:\n%s", err, logged)
	}
	return n
}
