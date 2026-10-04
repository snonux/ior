package integrationtests

import (
	"fmt"
	"strings"
	"testing"

	"ior/internal/flamegraph"
	"ior/internal/gatecmd"
	iorparquet "ior/internal/parquet"
	"ior/internal/types"
)

// TestShortfallIsExplainedOnlyByEnoughLossAndNoWrongRow: loss excuses rows
// that are missing, up to the number of records lost, and nothing else.
func TestShortfallIsExplainedOnlyByEnoughLossAndNoWrongRow(t *testing.T) {
	for _, tc := range []struct {
		name  string
		short shortfall
		loss  KernelLoss
		want  bool
	}{
		{"nothing lacking", shortfall{}, KernelLoss{SkippedRuns: 5}, false},
		{"missing, no loss", shortfall{unmet: 1, missing: 1}, KernelLoss{}, false},
		{"missing, lost halves alone", shortfall{unmet: 1, missing: 1}, KernelLoss{EntersWithoutExit: 3, ExitsWithoutEnter: 3}, false},
		{"missing, one skipped run", shortfall{unmet: 1, missing: 1}, KernelLoss{SkippedRuns: 1}, true},
		{"missing, one ring drop", shortfall{unmet: 1, missing: 1}, KernelLoss{RingDrops: 1}, true},
		{"more missing than lost", shortfall{unmet: 2, missing: 3}, KernelLoss{SkippedRuns: 1, RingDrops: 1}, false},
		{"as many missing as lost", shortfall{unmet: 2, missing: 2}, KernelLoss{SkippedRuns: 1, RingDrops: 1}, true},
		{"a wrong row", shortfall{unmet: 1, wrong: true}, KernelLoss{SkippedRuns: 100}, false},
		{"a wrong row beside a missing one", shortfall{unmet: 2, missing: 1, wrong: true}, KernelLoss{SkippedRuns: 100}, false},
	} {
		if got := tc.short.explainedBy(tc.loss); got != tc.want {
			t.Errorf("%s: explainedBy = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestRowShortfallTellsAMissingRowFromAWrongOne: rows of the expected call
// that do not match are wrong; only a call with no row at all is missing.
func TestRowShortfallTellsAMissingRowFromAWrongOne(t *testing.T) {
	want := ExpectedRow{Syscall: "close_range", Comm: "ioworkload", FD: ptrTo(int32(9000)), RetVal: ptrTo(int64(0))}
	other := iorparquet.Record{Syscall: "close", Comm: "ioworkload", FD: 3}
	for _, tc := range []struct {
		name string
		rows []iorparquet.Record
		exp  ExpectedRow
		want shortfall
	}{
		{"present", []iorparquet.Record{other, {Syscall: "close_range", FD: 9000}}, want, shortfall{}},
		{"absent", []iorparquet.Record{other}, want, shortfall{unmet: 1, missing: 1}},
		{"wrong return value", []iorparquet.Record{{Syscall: "close_range", FD: 9000, Ret: -9}}, want, shortfall{unmet: 1, wrong: true}},
		{"another descriptor's call", []iorparquet.Record{{Syscall: "close_range", FD: 7}}, want, shortfall{unmet: 1, missing: 1}},
		{"two of three", []iorparquet.Record{other, other}, ExpectedRow{Syscall: "close", MinCount: 3}, shortfall{unmet: 1, missing: 1}},
		{"three wrong of three", []iorparquet.Record{other, other, other},
			ExpectedRow{Syscall: "close", FileContains: "x.txt", MinCount: 3}, shortfall{unmet: 1, wrong: true}},
	} {
		if got := rowShortfall(tc.rows, []ExpectedRow{tc.exp}); got != tc.want {
			t.Errorf("%s: rowShortfall = %+v, want %+v", tc.name, got, tc.want)
		}
	}
	both := rowShortfall([]iorparquet.Record{other}, []ExpectedRow{want, {Syscall: "fsync"}, {Syscall: "close"}})
	if both != (shortfall{unmet: 2, missing: 2}) {
		t.Errorf("two absent calls beside a present one: %+v", both)
	}
}

// TestEventShortfallTellsAMissingEventFromAWrongOne is the same for the
// flamegraph records, whose counts are summed.
func TestEventShortfallTellsAMissingEventFromAWrongOne(t *testing.T) {
	closeRange := flamegraph.IterRecord{TraceID: types.SYS_ENTER_CLOSE_RANGE, Path: "/tmp/a", Cnt: flamegraph.Counter{Count: 2}}
	for _, tc := range []struct {
		name    string
		records []flamegraph.IterRecord
		exp     ExpectedEvent
		want    shortfall
	}{
		{"present", []flamegraph.IterRecord{closeRange}, ExpectedEvent{Tracepoint: "enter_close_range", MinCount: 2}, shortfall{}},
		{"absent", []flamegraph.IterRecord{closeRange}, ExpectedEvent{Tracepoint: "enter_fsync"}, shortfall{unmet: 1, missing: 1}},
		{"too few", []flamegraph.IterRecord{closeRange}, ExpectedEvent{Tracepoint: "enter_close_range", MinCount: 5},
			shortfall{unmet: 1, missing: 3}},
		{"wrong path", []flamegraph.IterRecord{closeRange}, ExpectedEvent{Tracepoint: "enter_close_range", PathContains: "/tmp/b", MinCount: 2},
			shortfall{unmet: 1, wrong: true}},
	} {
		if got := eventShortfall(tc.records, []ExpectedEvent{tc.exp}); got != tc.want {
			t.Errorf("%s: eventShortfall = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

const noRingDrops = "0 (0.00/s, 0.00% of events)"

// scriptedJudge returns a rowJudge over runs whose rows are a single int:
// the number of rows the run lacks. first is the run handed to runToJudge,
// reruns are returned by rerun in turn; calls counts the reruns.
func scriptedJudge(out *strings.Builder, require string, reruns ...judgedRun[int]) (judge rowJudge[int], calls *int) {
	calls = new(int)
	return rowJudge[int]{
		attempts: 3,
		out:      out,
		getenv: func(name string) string {
			if name == gatecmd.RequireRowsEnv {
				return require
			}
			return ""
		},
		rerun: func() judgedRun[int] {
			*calls++
			return reruns[*calls-1]
		},
		lacking: func(rows []int) shortfall {
			if rows[0] == 0 {
				return shortfall{}
			}
			return shortfall{unmet: 1, missing: uint64(rows[0])}
		},
	}, calls
}

// lackingRun is a run that lacks missing rows and whose statistics report
// skipped probe runs; pid tells the runs apart.
func lackingRun(pid, missing int, skipped string) judgedRun[int] {
	return judgedRun[int]{rows: []int{missing}, logged: statsBlock(noRingDrops, skipped), pid: pid}
}

// TestRunToJudgeNeverExcusesARunWithoutEvidence: a run is only passed over
// when it lacks rows AND reports enough loss; every other run is the one
// the assertion is made on, at once and without a rerun.
func TestRunToJudgeNeverExcusesARunWithoutEvidence(t *testing.T) {
	for name, first := range map[string]judgedRun[int]{
		"complete, no loss":        lackingRun(1, 0, "0"),
		"complete, loss":           lackingRun(1, 0, "7"),
		"lacking, no loss":         lackingRun(1, 1, "0"),
		"lacking, skips uncounted": lackingRun(1, 1, "not counted"),
		"lacking more than lost":   lackingRun(1, 3, "2"),
		"lacking, no statistics":   {rows: []int{1}, logged: "Probing for 10 seconds\n", pid: 1},
	} {
		var out strings.Builder
		verdict := &recordingVerdict{}
		judge, calls := scriptedJudge(&out, "")
		got := judge.runToJudge(verdict, first)
		if got.pid != 1 || *calls != 0 || verdict.skipped != "" || verdict.failed != "" || out.Len() != 0 {
			t.Errorf("%s: judged run %d after %d reruns, skipped %q, failed %q, printed %q",
				name, got.pid, *calls, verdict.skipped, verdict.failed, out.String())
		}
	}
}

// TestRunToJudgeRerunsALossyRunThatLacksRows: the first run that is
// complete, or lacking without loss to explain it, is the one judged.
func TestRunToJudgeRerunsALossyRunThatLacksRows(t *testing.T) {
	for name, tc := range map[string]struct {
		reruns    []judgedRun[int]
		wantPID   int
		wantCalls int
	}{
		"complete second run":       {[]judgedRun[int]{lackingRun(2, 0, "4")}, 2, 1},
		"second run lacks, no loss": {[]judgedRun[int]{lackingRun(2, 1, "0")}, 2, 1},
		"complete third run":        {[]judgedRun[int]{lackingRun(2, 1, "1"), lackingRun(3, 0, "0")}, 3, 2},
	} {
		var out strings.Builder
		verdict := &recordingVerdict{}
		judge, calls := scriptedJudge(&out, "", tc.reruns...)
		got := judge.runToJudge(verdict, lackingRun(1, 1, "1"))
		if got.pid != tc.wantPID || *calls != tc.wantCalls || verdict.skipped != "" || verdict.failed != "" || out.Len() != 0 {
			t.Errorf("%s: judged run %d after %d reruns, skipped %q, failed %q, printed %q",
				name, got.pid, *calls, verdict.skipped, verdict.failed, out.String())
		}
	}
}

// TestRunToJudgeGivesUpVisiblyOrFailsOnRequest: when every run lacked rows
// its loss can explain, the test skips after the last attempt and prints the
// line mage summarises; with IOR_REQUIRE_ROWS=1 it fails and prints nothing.
func TestRunToJudgeGivesUpVisiblyOrFailsOnRequest(t *testing.T) {
	for require, wantFail := range map[string]bool{"": false, "1": true} {
		var out strings.Builder
		verdict := &recordingVerdict{}
		judge, calls := scriptedJudge(&out, require, lackingRun(2, 1, "2"), lackingRun(3, 1, "9"))
		judge.runToJudge(verdict, lackingRun(1, 1, "1"))
		if failed := verdict.failed != ""; failed != wantFail || (verdict.skipped != "") == wantFail || *calls != 2 {
			t.Fatalf("%s=%q: failed %q, skipped %q after %d reruns", gatecmd.RequireRowsEnv, require, verdict.failed, verdict.skipped, *calls)
		}
		marked := gatecmd.SkippedRowTests(out.String())
		if wantFail != (len(marked) == 0) || (!wantFail && !strings.HasPrefix(marked[0], "TestFold: every one of 3 runs")) {
			t.Fatalf("%s=%q: printed %q", gatecmd.RequireRowsEnv, require, out.String())
		}
		if !strings.Contains(verdict.failed+verdict.skipped, "probe runs skipped by the kernel: 9") {
			t.Fatalf("the verdict does not give the last run's counts: %q", verdict.failed+verdict.skipped)
		}
		if summary := gatecmd.SkipSummary(out.String()); !wantFail && len(summary) != 2 {
			t.Fatalf("summary = %q, want a count and the test", summary)
		}
	}
}

// TestRunSourcesKnowOnlyTheRowsTheyWereGiven: the evidence of a run excuses
// the rows of that run and no others, and is forgotten with the test.
func TestRunSourcesKnowOnlyTheRowsTheyWereGiven(t *testing.T) {
	var sources runSources[int]
	lacking := func(rows []int) shortfall { return shortfall{unmet: 1, missing: uint64(rows[0])} }
	rerun := func() judgedRun[int] { return lackingRun(2, 1, "0") }
	first := lackingRun(1, 1, "1")
	forget := sources.remember(first, rerun)
	sources.remember(judgedRun[int]{}, rerun)()

	verdict := &recordingVerdict{}
	if got := sources.judged(verdict, first.rows, lacking); got.pid != 2 {
		t.Fatalf("remembered rows: judged run %d, want the rerun", got.pid)
	}
	copied := append([]int(nil), first.rows...)
	if got := sources.judged(verdict, copied, lacking); got.pid != 0 || fmt.Sprint(got.rows) != "[1]" {
		t.Fatalf("a copy of the rows: judged %+v, want the copy as it is", got)
	}
	if got := sources.judged(verdict, nil, lacking); got.rows != nil {
		t.Fatalf("no rows: judged %+v", got)
	}
	forget()
	if got := sources.judged(verdict, first.rows, lacking); got.pid != 0 {
		t.Fatalf("forgotten rows: judged run %d, want the rows as they are", got.pid)
	}
}
