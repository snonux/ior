package gatecmd

import (
	"slices"
	"strings"
	"testing"
)

func TestFoldsRequiredOnlyForOne(t *testing.T) {
	for value, want := range map[string]bool{"1": true, "": false, "0": false, "true": false, " 1": false} {
		getenv := func(name string) string {
			if name != RequireFoldsEnv {
				t.Fatalf("getenv(%q), want %q", name, RequireFoldsEnv)
			}
			return value
		}
		if got := FoldsRequired(getenv); got != want {
			t.Errorf("FoldsRequired with %s=%q = %v, want %v", RequireFoldsEnv, value, got, want)
		}
	}
}

// Only lines that begin with the marker count: the same text indented, as
// a t.Log of another test would print it, is no skip.
func TestFoldSkipSummaryListsTheMarkedLines(t *testing.T) {
	output := "=== RUN TestA\n" + FoldSkipMarker + "TestA: scenario a: lost\n" +
		"    helpers_test.go:1: " + FoldSkipMarker + "TestX: quoted\n" +
		"ok\n" + FoldSkipMarker + "TestB: scenario b: lost"
	if got, want := SkippedFoldTests(output), []string{"TestA: scenario a: lost", "TestB: scenario b: lost"}; !slices.Equal(got, want) {
		t.Fatalf("SkippedFoldTests = %q, want %q", got, want)
	}
	summary := FoldSkipSummary(output)
	if len(summary) != 3 || !strings.HasPrefix(summary[0], "2 fold test(s) SKIPPED") ||
		!strings.Contains(summary[0], RequireFoldsEnv+"=1") || summary[2] != "  TestB: scenario b: lost" {
		t.Fatalf("FoldSkipSummary = %q", summary)
	}
	if got := FoldSkipSummary("ok\nPASS\n"); got != nil {
		t.Fatalf("FoldSkipSummary without a skip = %q, want nothing", got)
	}
}

// A test whose case was not exercised is listed under its own heading, after
// the fold tests (and after any row-presence skips; see
// TestRowSkipSummaryListsTheMarkedLines).
func TestSkipSummaryListsUnexercisedTestsBehindTheFoldTests(t *testing.T) {
	output := UnexercisedSkipMarker + "TestStop: no lagging stop in 5 runs\n" +
		"    stop_test.go:1: " + UnexercisedSkipMarker + "TestX: quoted\n" +
		FoldSkipMarker + "TestA: scenario a: lost\nok\n"
	if got, want := SkippedUnexercisedTests(output), []string{"TestStop: no lagging stop in 5 runs"}; !slices.Equal(got, want) {
		t.Fatalf("SkippedUnexercisedTests = %q, want %q", got, want)
	}
	summary := SkipSummary(output)
	if len(summary) != 4 || !strings.HasPrefix(summary[0], "1 fold test(s) SKIPPED") || summary[1] != "  TestA: scenario a: lost" ||
		!strings.HasPrefix(summary[2], "1 test(s) SKIPPED because no run exercised") || summary[3] != "  TestStop: no lagging stop in 5 runs" {
		t.Fatalf("SkipSummary = %q", summary)
	}
	if got := SkipSummary(FoldSkipMarker + "TestA: lost\n"); len(got) != 2 {
		t.Fatalf("SkipSummary with only a fold skip = %q, want its two lines", got)
	}
	if got := SkipSummary("ok\nPASS\n"); len(got) != 0 {
		t.Fatalf("SkipSummary without a skip = %q, want nothing", got)
	}
}

// TestRowSkipSummaryListsTheMarkedLines: a row test's skip is listed with
// the way to make it fail, between the fold tests and the unexercised ones,
// and only IOR_REQUIRE_ROWS=1 asks for the failure.
func TestRowSkipSummaryListsTheMarkedLines(t *testing.T) {
	output := UnexercisedSkipMarker + "TestStop: no lagging stop\n" +
		RowSkipMarker + "TestCloseRangeEmpty: 3 runs\n" +
		"    close_test.go:1: " + RowSkipMarker + "TestX: quoted\n" +
		FoldSkipMarker + "TestA: scenario a: lost\nok\n"
	if got, want := SkippedRowTests(output), []string{"TestCloseRangeEmpty: 3 runs"}; !slices.Equal(got, want) {
		t.Fatalf("SkippedRowTests = %q, want %q", got, want)
	}
	summary := SkipSummary(output)
	if len(summary) != 6 || !strings.HasPrefix(summary[2], "1 row test(s) SKIPPED") ||
		!strings.Contains(summary[2], RequireRowsEnv+"=1") || summary[3] != "  TestCloseRangeEmpty: 3 runs" {
		t.Fatalf("SkipSummary = %q", summary)
	}
	if got := RowSkipSummary("ok\nPASS\n"); got != nil {
		t.Fatalf("RowSkipSummary without a skip = %q, want nothing", got)
	}
	for value, want := range map[string]bool{"": false, "0": false, "true": false, "1": true} {
		getenv := func(name string) string {
			if name != RequireRowsEnv {
				t.Fatalf("getenv(%q), want %q", name, RequireRowsEnv)
			}
			return value
		}
		if got := RowsRequired(getenv); got != want {
			t.Errorf("RowsRequired with %s=%q = %v, want %v", RequireRowsEnv, value, got, want)
		}
	}
}
