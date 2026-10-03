package integrationtests

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	getppidBurstScenario = "getppid-burst"
	// getppidBurstCalls mirrors ioworkload's constant of the same name.
	getppidBurstCalls = 1_500_000
	// stopAccountingAttempts bounds the runs of the test: it runs again
	// while no run stopped with ior lagging, and after a run in which the
	// kernel skipped probe runs.
	stopAccountingAttempts = 5
	// stopAccountingDelayStep is added to the workload's release delay with
	// every attempt (0, 100, ... 400 ms): the attempts then spread the
	// traced child's exit over ior's 500 ms liveness period.
	stopAccountingDelayStep = 100 * time.Millisecond
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

// lagged reports that the trace stopped with ior behind the kernel: the stop
// left records undecoded, in rawCh or in the kernel ring.
func (f stopFigures) lagged() bool {
	return f.discarded+f.leftInRing > 0
}

// getppidBurstRecords is the number of records the kernel produces for a
// traced getppid-burst child, or counts as dropped: an enter and an exit per
// getppid call and the exit record of the child, which is one thread.
const getppidBurstRecords = 2*getppidBurstCalls + 1

// TestStopAccountsForEveryRecord is the accounting identity of task f23, end
// to end: the traced process makes a known number of getppid calls and exits,
// the trace stops on that exit, and every record the kernel produced must be in
// exactly one figure - decoded (tracepoints), dropped by the full ring,
// discarded at stop, or left in the kernel ring buffer. The identity is
// exact because the traced process is the workload's forked child, a single
// thread that the Go runtime knows nothing of (startGetppidBurstChild in
// cmd/ioworkload): two records per call and its one exit record pass the
// -pid filter, and nothing else can. The workload itself is not traced. Its
// runtime starts threads when it likes, each with records of its own, and
// counting them from /proc while it ran missed one about once in 13 runs.
//
// The case the test is there for is the LAGGING stop: ior's liveness watcher
// sees the target gone while the event loop is still behind, so the stop
// finds rawCh full and the ring behind it filled. Before the fix such a run
// was short of exactly one channel's worth (4096). Whether a run stops that
// way is the host's timing: the loop outruns ior, but when the loop reaches
// the workload's exit record before the watcher's next 500 ms check, the
// trace stops there with everything decoded, and the identity holds without
// having tested anything. With the harness's fixed timing that was every
// run on the development host when it was idle. So every run is judged, each
// logs whether it exercised the lagging stop, and the test runs again with a
// longer release delay (another phase against the watcher) until one did. If
// none did it SKIPS, visibly in `mage integrationTest` (SkipUnexercised): a
// pass would claim the check ran.
//
// A probe run the kernel skipped produced no record and is counted for every
// task on the host, so a run with any is not judged. Ring-buffer drops are
// counted exactly and are part of the sum. The unit tests in
// internal/eventloop_stopaccount_test.go cover the lagging stop on every
// host.
func TestStopAccountsForEveryRecord(t *testing.T) {
	enableParallelIfRequested(t)
	judged := 0
	for attempt := range stopAccountingAttempts {
		delay := time.Duration(attempt) * stopAccountingDelayStep
		figures := runGetppidBurst(t, delay)
		if figures.loss.SkippedRuns > 0 {
			t.Logf("attempt %d: the kernel skipped %d probe runs; the records produced are not known, not judged",
				attempt+1, figures.loss.SkippedRuns)
			continue
		}
		judged++
		t.Logf("attempt %d (release delayed by %v): lagging stop exercised: %s; %+v",
			attempt+1, delay, yesNo(figures.lagged()), figures)
		if got := figures.accounted(); got != getppidBurstRecords {
			t.Fatalf("the figures account for %d records, want %d (2 per getppid call of %d and the exit record): %+v",
				got, getppidBurstRecords, getppidBurstCalls, figures)
		}
		if figures.lagged() {
			return
		}
	}
	SkipUnexercised(t, os.Stdout, fmt.Sprintf(
		"no trace stopped with ior lagging in %d runs (%d judged and accounted for, %d with probe runs the kernel skipped); "+
			"the accounting of a lagging stop was not exercised",
		stopAccountingAttempts, judged, stopAccountingAttempts-judged))
}

func yesNo(yes bool) string {
	if yes {
		return "yes"
	}
	return "no"
}

// runGetppidBurst traces one getppid-burst run, released releaseDelay later
// than the harness does by itself, and returns its figures. The trace is of
// the workload's forked child, whose pid the workload publishes before the
// harness starts ior; the trace stops on the child's exit.
func runGetppidBurst(t *testing.T, releaseDelay time.Duration) stopFigures {
	t.Helper()
	h := newTestHarness(t)
	h.IorOutput = &OutputCapture{}
	h.ReleaseDelay = releaseDelay
	pidFile := filepath.Join(h.OutputDir, "burst-child.pid")
	h.WorkloadEnv = append(h.WorkloadEnv, forkChildPidFileEnv+"="+pidFile)
	// The -pid given here follows the harness's own and overrides it.
	h.IorArgsForPID = func(int) ([]string, error) {
		raw, err := os.ReadFile(pidFile)
		if err != nil {
			return nil, err
		}
		return []string{"-pid", strings.TrimSpace(string(raw))}, nil
	}
	if _, _, err := h.RunWithIorArgs(getppidBurstScenario, defaultDuration, []string{"-trace-syscalls", "getppid"}); err != nil {
		t.Fatalf("run scenario %s: %v", getppidBurstScenario, err)
	}
	return parseStopFigures(t, h.IorOutput.String())
}

// parseStopFigures reads the figures a record can end up in from ior's
// end-of-run statistics.
func parseStopFigures(t *testing.T, logged string) stopFigures {
	t.Helper()
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
