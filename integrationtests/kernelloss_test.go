package integrationtests

import (
	"errors"
	"slices"
	"testing"
)

// statsBlock is the part of ior's end-of-run statistics ParseKernelLoss
// reads, with the two figures as given.
func statsBlock(ringDrops, skippedRuns string) string {
	return "Statistics:\n\tring buffer drops: " + ringDrops + "\n" +
		"\tprobe runs skipped by the kernel: " + skippedRuns + "\n\tgroup-dead exits: 1\n"
}

func TestParseKernelLossReadsBothFigures(t *testing.T) {
	const meaning = " (events may be missing; the count includes tasks outside the trace filter)"
	for _, tc := range []struct {
		name, ring, skipped string
		want                KernelLoss
	}{
		{"nothing lost", "0 (0.00/s, 0.00% of events)", "0", KernelLoss{}},
		{"drops", "12 (1.20/s, 0.10% of events)", "0", KernelLoss{RingDrops: 12}},
		{"skipped runs", "0 (0.00/s, 0.00% of events)", "22600" + meaning, KernelLoss{SkippedRuns: 22600}},
		{"a kernel that does not count skips", "3 (0.30/s, 0.01% of events)", "not counted", KernelLoss{RingDrops: 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseKernelLoss(statsBlock(tc.ring, tc.skipped))
			if err != nil || got != tc.want {
				t.Fatalf("ParseKernelLoss = %+v, %v, want %+v", got, err, tc.want)
			}
			if got.Any() != (tc.want.RingDrops+tc.want.SkippedRuns > 0) {
				t.Fatalf("Any() = %v for %+v", got.Any(), got)
			}
		})
	}
}

// A figure that is not there is not zero.
func TestParseKernelLossRefusesAMissingOrUnknownFigure(t *testing.T) {
	for name, logged := range map[string]string{
		"no statistics at all": "Probing for 10 seconds\n",
		"no skipped-run line":  "\tring buffer drops: 0 (0.00/s, 0.00% of events)\n",
		"no ring-buffer line":  "\tprobe runs skipped by the kernel: 0\n",
		"ring drops unknown":   statsBlock("unknown (drop counter unreadable)", "0"),
		"skipped runs unknown": statsBlock("0 (0.00/s, 0.00% of events)", "unknown (counter unreadable)"),
		"skipped runs partly counted": statsBlock("0 (0.00/s, 0.00% of events)",
			"unknown (counter unreadable; 2 counted before the failure)"),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := ParseKernelLoss(logged); err == nil {
				t.Fatalf("ParseKernelLoss = %+v without an error", got)
			}
		})
	}
}

// scriptedRuns returns a run function that reports the given losses in
// turn, with the number of its call as the result, and the number of calls.
func scriptedRuns(losses ...KernelLoss) (run func() (int, KernelLoss, error), calls *int) {
	calls = new(int)
	return func() (int, KernelLoss, error) {
		*calls++
		return *calls, losses[*calls-1], nil
	}, calls
}

func TestFirstRunWithoutKernelLossRetriesAndNeverPassesALossyRun(t *testing.T) {
	skipped, dropped := KernelLoss{SkippedRuns: 2}, KernelLoss{RingDrops: 1}

	run, calls := scriptedRuns(KernelLoss{}, skipped)
	if got, lost, err := FirstRunWithoutKernelLoss(2, run); err != nil || got != 1 || len(lost) != 0 || *calls != 1 {
		t.Fatalf("a clean first run: result %d, lost %v, err %v after %d runs, want run 1 and no retry", got, lost, err, *calls)
	}
	run, calls = scriptedRuns(skipped, KernelLoss{})
	if got, lost, err := FirstRunWithoutKernelLoss(2, run); err != nil || got != 2 || !slices.Equal(lost, []KernelLoss{skipped}) || *calls != 2 {
		t.Fatalf("a clean second run: result %d, lost %v, err %v after %d runs, want run 2 and the first run's loss",
			got, lost, err, *calls)
	}
	run, calls = scriptedRuns(skipped, dropped, KernelLoss{})
	got, lost, err := FirstRunWithoutKernelLoss(2, run)
	if err != nil || got != 0 || !slices.Equal(lost, []KernelLoss{skipped, dropped}) || *calls != 2 {
		t.Fatalf("two lossy runs: result %d, lost %v, err %v after %d runs, want no result, both losses and no third run",
			got, lost, err, *calls)
	}
}

func TestFirstRunWithoutKernelLossStopsAtAnError(t *testing.T) {
	boom := errors.New("boom")
	calls := 0
	_, lost, err := FirstRunWithoutKernelLoss(2, func() (int, KernelLoss, error) {
		calls++
		return 0, KernelLoss{}, boom
	})
	if !errors.Is(err, boom) || len(lost) != 0 || calls != 1 {
		t.Fatalf("err = %v, lost %v after %d runs, want the run's error at once", err, lost, calls)
	}
}
