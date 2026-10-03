package integrationtests

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"ior/internal/gatecmd"
)

// statsBlock is the part of ior's end-of-run statistics ParseKernelLoss
// reads, with the kernel's two figures as given and no lost half.
func statsBlock(ringDrops, skippedRuns string) string {
	return statsBlockWithHalves(ringDrops, skippedRuns, "0", "0 (0 look like a filter's answer)")
}

// statsBlockWithHalves is statsBlock with the two lost-half figures as given.
func statsBlockWithHalves(ringDrops, skippedRuns, entersWithoutExit, exitsWithoutEnter string) string {
	return "Statistics:\n\tsyscalls: 10 (1.00/s) with 0 mismatched enter/exit pairs (0.00%)\n" +
		"\tenters without an exit: " + entersWithoutExit + "\n" +
		"\texits without an enter: " + exitsWithoutEnter + "\n" +
		"\tring buffer drops: " + ringDrops + "\n" +
		"\tprobe runs skipped by the kernel: " + skippedRuns + "\n\tgroup-dead exits: 1\n"
}

// The lost halves are read too, and are not what Any asks about.
func TestParseKernelLossReadsTheLostHalves(t *testing.T) {
	const zero = "0 (0.00/s, 0.00% of events)"
	logged := statsBlockWithHalves(zero, "0",
		"12 (superseded by the thread's next enter: exit record lost)",
		"7 (thread seen before: enter record lost, or a call a seccomp filter answered; "+
			"2 look like a filter's answer: an error or the syscall's own number)")
	got, err := ParseKernelLoss(logged)
	want := KernelLoss{EntersWithoutExit: 12, ExitsWithoutEnter: 7, FilterLikeExits: 2}
	if err != nil || got != want {
		t.Fatalf("ParseKernelLoss = %+v, %v, want %+v", got, err, want)
	}
	if got.Any() {
		t.Fatalf("Any() = true for lost halves alone: %+v", got)
	}
	for name, logged := range map[string]string{
		"no enter line": strings.Replace(logged, "enters without an exit", "x", 1),
		"no exit line":  strings.Replace(logged, "exits without an enter", "x", 1),
		"no figure":     statsBlockWithHalves(zero, "0", "many", "0 (0 look like a filter's answer)"),
		"no share":      statsBlockWithHalves(zero, "0", "0", "7 (2 returned an error)"),
	} {
		if got, err := ParseKernelLoss(logged); err == nil {
			t.Fatalf("%s: ParseKernelLoss = %+v without an error", name, got)
		}
	}
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

// recordingVerdict is a foldVerdict that records how the test ended.
type recordingVerdict struct {
	skipped, failed string
}

func (v *recordingVerdict) Helper()      {}
func (v *recordingVerdict) Name() string { return "TestFold" }
func (v *recordingVerdict) Skipf(format string, args ...any) {
	v.skipped = fmt.Sprintf(format, args...)
}
func (v *recordingVerdict) Fatalf(format string, args ...any) {
	v.failed = fmt.Sprintf(format, args...)
}

// TestGiveUpOnFoldsSkipsVisiblyOrFailsOnRequest: by default a fold test
// whose runs all lost records skips, and prints the marked line mage
// summarises; with IOR_REQUIRE_FOLDS=1 it fails and prints nothing.
func TestGiveUpOnFoldsSkipsVisiblyOrFailsOnRequest(t *testing.T) {
	lost := []KernelLoss{{SkippedRuns: 3}, {RingDrops: 1}}
	for value, wantFail := range map[string]bool{"": false, "1": true} {
		var out strings.Builder
		verdict := &recordingVerdict{}
		getenv := func(name string) string {
			if name == gatecmd.RequireFoldsEnv {
				return value
			}
			return ""
		}
		GiveUpOnFolds(verdict, &out, getenv, "restart-read", lost)
		if failed := verdict.failed != ""; failed != wantFail || (verdict.skipped != "") == wantFail {
			t.Fatalf("%s=%q: failed %q, skipped %q", gatecmd.RequireFoldsEnv, value, verdict.failed, verdict.skipped)
		}
		marked := gatecmd.SkippedFoldTests(out.String())
		if wantFail != (len(marked) == 0) || (!wantFail && !strings.HasPrefix(marked[0], "TestFold: scenario restart-read")) {
			t.Fatalf("%s=%q: printed %q", gatecmd.RequireFoldsEnv, value, out.String())
		}
		if !strings.Contains(verdict.failed+verdict.skipped, "ring buffer drops: 1") {
			t.Fatalf("the verdict does not give the last run's counts: %q", verdict.failed+verdict.skipped)
		}
	}
}
