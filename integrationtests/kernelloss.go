package integrationtests

import (
	"fmt"
	"io"
	"regexp"
	"strconv"

	"ior/internal/gatecmd"
)

// The lines of ior's end-of-run statistics that say what the kernel lost:
// the records the full ring buffer refused, and the probe runs the kernel
// skipped (which it counts from Linux 6.7 on, for every task on the host; ior
// prints "not counted" before that); and, as the pairing of this trace's own
// records sees it, the calls that lost their exit or their enter record
// (task c23).
var (
	ringDropsLine         = regexp.MustCompile(`ring buffer drops: ([^\n]+)`)
	skippedRunsLine       = regexp.MustCompile(`probe runs skipped by the kernel: ([^\n]+)`)
	entersWithoutExitLine = regexp.MustCompile(`enters without an exit: ([^\n]+)`)
	exitsWithoutEnterLine = regexp.MustCompile(`exits without an enter: ([^\n]+)`)
	leadingCount          = regexp.MustCompile(`^\d+`)
)

// skippedRunsNotCounted is the figure of the skipped-run line on a kernel
// that does not count them. Nothing can be known there, and it is taken for
// no skipped run.
const skippedRunsNotCounted = "not counted"

// KernelLoss is what one ior run reported in its statistics block about
// records lost in the kernel.
type KernelLoss struct {
	RingDrops   uint64
	SkippedRuns uint64
	// EntersWithoutExit and ExitsWithoutEnter are the calls of this trace
	// whose exit, or enter, record was lost, as ior's pairing found them.
	// They are the trace's own records, where SkippedRuns counts every task
	// on the host.
	EntersWithoutExit uint64
	ExitsWithoutEnter uint64
}

// Any reports whether the run lost a record, or may have: a skipped probe
// run refuses a restart fold like a drop does, whoever's run it was. The
// lost halves are not asked: ior refuses no fold over them, and the loss
// behind one is a drop or a skipped run, which is asked.
func (l KernelLoss) Any() bool {
	return l.RingDrops > 0 || l.SkippedRuns > 0
}

func (l KernelLoss) String() string {
	return fmt.Sprintf("ring buffer drops: %d, probe runs skipped by the kernel: %d, "+
		"enters without an exit: %d, exits without an enter: %d",
		l.RingDrops, l.SkippedRuns, l.EntersWithoutExit, l.ExitsWithoutEnter)
}

// ParseKernelLoss reads the four figures from ior's output. A line that is
// missing, or that states no figure ("unknown ..."), is an error: a test
// that depends on the figures must not take silence for zero. The one
// exception is a skipped-run line that says "not counted", taken for 0.
func ParseKernelLoss(logged string) (KernelLoss, error) {
	var loss KernelLoss
	var err error
	if loss.RingDrops, err = statFigure(logged, ringDropsLine, "ring buffer drops"); err != nil {
		return KernelLoss{}, err
	}
	if m := skippedRunsLine.FindStringSubmatch(logged); m == nil || m[1] != skippedRunsNotCounted {
		loss.SkippedRuns, err = statFigure(logged, skippedRunsLine, "probe runs skipped by the kernel")
		if err != nil {
			return KernelLoss{}, err
		}
	}
	if loss.EntersWithoutExit, err = statFigure(logged, entersWithoutExitLine, "enters without an exit"); err != nil {
		return KernelLoss{}, err
	}
	if loss.ExitsWithoutEnter, err = statFigure(logged, exitsWithoutEnterLine, "exits without an enter"); err != nil {
		return KernelLoss{}, err
	}
	return loss, nil
}

// statFigure returns the count a statistics line begins with.
func statFigure(logged string, line *regexp.Regexp, name string) (uint64, error) {
	m := line.FindStringSubmatch(logged)
	if m == nil {
		return 0, fmt.Errorf("ior output lacks a %q statistics line", name)
	}
	n, err := strconv.ParseUint(leadingCount.FindString(m[1]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("ior's %q line states no figure: %q", name, m[1])
	}
	return n, nil
}

// FirstRunWithoutKernelLoss calls run up to attempts times and returns the
// result of the first run that reported no kernel-side loss, together with
// the losses of the runs before it. When every run reported one, lost has
// attempts entries and result is the zero value: the caller cannot judge
// what it wanted to judge and must say so (skip), never pass.
//
// It exists for tests that require an interrupted call to be FOLDED. ior
// refuses a fold when a record may have been lost in between, and it is
// right to: on a host where a real-time task preempts BPF programs the
// kernel skips probe runs for real (task 723), and such a run is no failure
// of the fold. One retry tells a busy moment from a host that does it all
// the time.
func FirstRunWithoutKernelLoss[T any](attempts int, run func() (T, KernelLoss, error)) (result T, lost []KernelLoss, err error) {
	for range attempts {
		got, loss, err := run()
		if err != nil {
			return result, lost, err
		}
		if !loss.Any() {
			return got, lost, nil
		}
		lost = append(lost, loss)
	}
	return result, lost, nil
}

// foldVerdict is what GiveUpOnFolds needs of a test (*testing.T).
type foldVerdict interface {
	Helper()
	Name() string
	Skipf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// GiveUpOnFolds ends a test that requires folds after every one of its runs
// reported kernel-side loss (lost, from FirstRunWithoutKernelLoss). By
// default it SKIPS, and first prints gatecmd.FoldSkipMarker with the test
// and the counts to out (the test binary's standard output), because a skip
// is invisible in `mage integrationTest`, which runs the binary without
// -test.v and summarises these lines at the end. With
// gatecmd.RequireFoldsEnv=1 in the environment getenv reads it FAILS
// instead: on a host that has to show the folds, a run that cannot is an
// error of the run.
func GiveUpOnFolds(t foldVerdict, out io.Writer, getenv func(string) string, scenario string, lost []KernelLoss) {
	t.Helper()
	why := fmt.Sprintf("scenario %s: every one of %d runs reported kernel-side loss (last: %s); "+
		"folds cannot be shown on this host right now", scenario, len(lost), lost[len(lost)-1])
	if gatecmd.FoldsRequired(getenv) {
		t.Fatalf("%s, and %s=1 requires them", why, gatecmd.RequireFoldsEnv)
		return
	}
	_, _ = fmt.Fprintf(out, "%s%s: %s\n", gatecmd.FoldSkipMarker, t.Name(), why)
	t.Skipf("%s (set %s=1 to fail instead)", why, gatecmd.RequireFoldsEnv)
}
