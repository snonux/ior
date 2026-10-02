package integrationtests

import (
	"fmt"
	"regexp"
	"strconv"
)

// The two lines of ior's end-of-run statistics that say what the kernel
// lost: the records the full ring buffer refused, and the probe runs the
// kernel skipped (which it counts from Linux 6.7 on, for every task on the
// host; ior prints "not counted" before that).
var (
	ringDropsLine   = regexp.MustCompile(`ring buffer drops: ([^\n]+)`)
	skippedRunsLine = regexp.MustCompile(`probe runs skipped by the kernel: ([^\n]+)`)
	leadingCount    = regexp.MustCompile(`^\d+`)
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
}

// Any reports whether the run lost a record, or may have: a skipped probe
// run refuses a restart fold like a drop does, whoever's run it was.
func (l KernelLoss) Any() bool {
	return l.RingDrops > 0 || l.SkippedRuns > 0
}

func (l KernelLoss) String() string {
	return fmt.Sprintf("ring buffer drops: %d, probe runs skipped by the kernel: %d", l.RingDrops, l.SkippedRuns)
}

// ParseKernelLoss reads the two figures from ior's output. A line that is
// missing, or that states no figure ("unknown ..."), is an error: a test
// that depends on the figures must not take silence for zero.
func ParseKernelLoss(logged string) (KernelLoss, error) {
	drops, err := statFigure(logged, ringDropsLine, "ring buffer drops")
	if err != nil {
		return KernelLoss{}, err
	}
	if m := skippedRunsLine.FindStringSubmatch(logged); m != nil && m[1] == skippedRunsNotCounted {
		return KernelLoss{RingDrops: drops}, nil
	}
	skipped, err := statFigure(logged, skippedRunsLine, "probe runs skipped by the kernel")
	if err != nil {
		return KernelLoss{}, err
	}
	return KernelLoss{RingDrops: drops, SkippedRuns: skipped}, nil
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
