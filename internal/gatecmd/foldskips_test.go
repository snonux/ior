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
