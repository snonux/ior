package integrationtests

import (
	"fmt"
	"io"
	"os"
	"sync"

	"ior/internal/flamegraph"
	"ior/internal/gatecmd"
	iorparquet "ior/internal/parquet"
)

// A test that asserts the presence of specific rows fails when a row is
// missing, and it should: but the kernel skips probe runs for real (task
// 723), and a skipped enter probe takes the whole row of that call with it
// while touching neither the ring-drop nor the lost-half counters. Seen at a
// host load of ~45: TestCloseRangeEmpty lost its single close_range row in a
// run whose statistics said "probe runs skipped by the kernel: 1" (task a33).
// Such a run cannot show what the test wants to see and is no failure of
// ior either. So the presence assertions (AssertRowsPresent and
// AssertEventsPresent) ask, before they fail, whether the run the rows came
// from reported kernel-side loss that can explain what is missing; if it
// can, the scenario is run again, up to rowRunAttempts runs in all, and a
// test none of whose runs could be judged SKIPS visibly (GiveUpOnRows).
//
// What stays a hard failure, exactly as before:
//   - rows missing from a run that reported no kernel-side loss;
//   - more missing rows than the run lost records (shortfall.explainedBy);
//   - a WRONG row: the calls an expectation names were recorded, in the
//     wanted number, and what ior says about them does not match;
//   - rows whose run is not known (runSources), e.g. a filtered copy or a
//     test that drives the harness itself;
//   - every other assertion of the test.

// rowRunAttempts is how often a scenario is run before a test whose rows are
// missing gives up on this host: once, and twice more. Each run is asked on
// its own, so a run that reports no loss ends the retries with a failure.
const rowRunAttempts = 3

// shortfall is what a run's rows lack of a list of expectations.
type shortfall struct {
	// unmet is the number of expectations the rows do not meet.
	unmet int
	// missing is the number of calls the rows hold nothing of, summed over
	// the unmet expectations.
	missing uint64
	// wrong says that an unmet expectation's calls WERE recorded: the trace
	// holds as many rows of that call as wanted, and they do not match. No
	// lost record explains that.
	wrong bool
}

// note adds one unmet expectation that wants want rows, of whose call
// (whatever the rows say about it) recorded rows are in the trace.
func (s *shortfall) note(want, recorded uint64) {
	s.unmet++
	if recorded >= want {
		s.wrong = true
		return
	}
	s.missing += want - recorded
}

// explainedBy reports whether the loss a run reported can account for the
// shortfall: only rows are missing, none is wrong, and no more of them than
// the kernel lost records. A lost record is at most one missing row. Both
// figures count every task on the host, so this is evidence that the run
// cannot be judged, never proof that the row was lost.
func (s shortfall) explainedBy(loss KernelLoss) bool {
	return s.unmet > 0 && !s.wrong && s.missing <= loss.RingDrops+loss.SkippedRuns
}

// judgedRun is one run of a scenario as a presence assertion needs it: its
// rows, everything ior printed (the statistics block included) and the
// workload's pid.
type judgedRun[R any] struct {
	rows   []R
	logged string
	pid    int
}

// rowVerdict is what the judging of a run needs of a test (*testing.T).
type rowVerdict interface {
	foldVerdict
	Logf(format string, args ...any)
}

// rowJudge decides which run of a scenario a presence assertion is made on.
type rowJudge[R any] struct {
	attempts int
	out      io.Writer
	getenv   func(string) string
	// rerun runs the scenario once more.
	rerun func() judgedRun[R]
	// lacking returns what rows lack of the assertion's expectations.
	lacking func(rows []R) shortfall
}

// runToJudge returns the run the assertion is to be made on: run itself
// when its rows meet the expectations, or when they do not and the run's
// kernel-side loss cannot explain it (the assertion then fails as it always
// did); else the first rerun of which the same holds. When attempts runs in
// a row lacked rows their loss can explain, the test is given up on
// (GiveUpOnRows). A run whose statistics state no figures is judged as it
// is: silence is not evidence of loss.
func (j rowJudge[R]) runToJudge(t rowVerdict, run judgedRun[R]) judgedRun[R] {
	t.Helper()
	var lost []KernelLoss
	for {
		short := j.lacking(run.rows)
		if short.unmet == 0 {
			return run
		}
		loss, err := ParseKernelLoss(run.logged)
		if err != nil {
			t.Logf("run %d lacks rows and states no kernel-loss figures (%v): judged as it is", len(lost)+1, err)
			return run
		}
		if !short.explainedBy(loss) {
			return run
		}
		lost = append(lost, loss)
		t.Logf("run %d lacks %d row(s) that its kernel-side loss can explain (%s): not judged",
			len(lost), short.missing, loss)
		if len(lost) == j.attempts {
			GiveUpOnRows(t, j.out, j.getenv, lost)
			return run
		}
		run = j.rerun()
	}
}

// GiveUpOnRows ends a test every one of whose runs lacked expected rows and
// reported kernel-side loss that can explain them (lost, one entry per run).
// By default it SKIPS - the rows were not shown, so it must not pass, and
// the host's doing is no failure - and first prints gatecmd.RowSkipMarker
// with the test and the counts to out (the test binary's standard output),
// because a skip is invisible in `mage integrationTest`, which summarises
// these lines at the end (gatecmd.SkipSummary). With gatecmd.RequireRowsEnv=1
// in the environment getenv reads it FAILS instead: a row that is really
// absent looks the same on a host that loses records in every run.
func GiveUpOnRows(t foldVerdict, out io.Writer, getenv func(string) string, lost []KernelLoss) {
	t.Helper()
	why := fmt.Sprintf("every one of %d runs lacked expected rows and reported kernel-side loss "+
		"that can explain them (last: %s); the rows cannot be judged on this host right now",
		len(lost), lost[len(lost)-1])
	if gatecmd.RowsRequired(getenv) {
		t.Fatalf("%s, and %s=1 requires them", why, gatecmd.RequireRowsEnv)
		return
	}
	_, _ = fmt.Fprintf(out, "%s%s: %s\n", gatecmd.RowSkipMarker, t.Name(), why)
	t.Skipf("%s (set %s=1 to fail instead)", why, gatecmd.RequireRowsEnv)
}

// rememberedRun is a run a presence assertion can be asked about: what it
// printed, and how to run its scenario again.
type rememberedRun[R any] struct {
	run   judgedRun[R]
	rerun func() judgedRun[R]
}

// runSources remembers, for the rows of the scenario runs made through the
// shared helpers (helpers_test.go), the run they came from. The presence
// assertions take bare rows, in many call sites, and the evidence that
// excuses a missing row belongs to the run; keying it by the identity of the
// rows (the address of the first one) ties it to exactly the rows asserted
// on, also in a test that runs several scenarios. Rows it does not know -
// a copy, a filtered subset, a run a test made on its own - are judged as
// they are.
type runSources[R any] struct {
	mu     sync.Mutex
	byRows map[*R]rememberedRun[R]
}

var (
	parquetRunSources runSources[iorparquet.Record]
	eventRunSources   runSources[flamegraph.IterRecord]
)

// remember records where run's rows came from and how to run the scenario
// again, and returns the function that forgets it (for t.Cleanup). A run
// without rows has no identity and is not remembered.
func (s *runSources[R]) remember(run judgedRun[R], rerun func() judgedRun[R]) (forget func()) {
	if len(run.rows) == 0 {
		return func() {}
	}
	key := &run.rows[0]
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byRows == nil {
		s.byRows = make(map[*R]rememberedRun[R])
	}
	s.byRows[key] = rememberedRun[R]{run: run, rerun: rerun}
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.byRows, key)
	}
}

// of returns the remembered run rows came from.
func (s *runSources[R]) of(rows []R) (rememberedRun[R], bool) {
	if len(rows) == 0 {
		return rememberedRun[R]{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	source, ok := s.byRows[&rows[0]]
	return source, ok
}

// judged returns the run a presence assertion over rows is to be made on
// (rowJudge.runToJudge): rows as they are when their run is not remembered.
func (s *runSources[R]) judged(t rowVerdict, rows []R, lacking func([]R) shortfall) judgedRun[R] {
	t.Helper()
	source, ok := s.of(rows)
	if !ok {
		return judgedRun[R]{rows: rows}
	}
	judge := rowJudge[R]{
		attempts: rowRunAttempts,
		out:      os.Stdout,
		getenv:   os.Getenv,
		rerun:    source.rerun,
		lacking:  lacking,
	}
	return judge.runToJudge(t, source.run)
}
