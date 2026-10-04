package gatecmd

import (
	"fmt"
	"strings"
)

// The integration tests that require an interrupted call to come out folded
// (runFoldScenarioRows in integrationtests/helpers_test.go) cannot show it
// when the kernel lost, or may have lost, a record of the run: ior refuses
// the fold then, and rightly (task 723). Such a test retries once and then
// skips. `mage integrationTest` runs the test binary without -test.v, which
// prints no skip at all, so a host that skips them every time would look
// green. Two things are here for that:
//
//   - RequireFoldsEnv: set to 1, the test fails instead of skipping. It is
//     read by the test binary, which `mage integrationTest` starts with its
//     own environment (sudo -E), so `IOR_REQUIRE_FOLDS=1 mage
//     integrationTest` is all it takes.
//   - FoldSkipMarker: a test that skips prints one line beginning with it to
//     its standard output, at once and whatever the verbosity, and the mage
//     target ends its run with SkipSummary over what the binary printed,
//     which includes FoldSkipSummary.

// RequireFoldsEnv names the environment variable that turns a fold test
// none of whose runs could show the fold into a failure.
const RequireFoldsEnv = "IOR_REQUIRE_FOLDS"

// FoldSkipMarker begins the line a fold test prints when it skips; the rest
// of the line names the test and why.
const FoldSkipMarker = "ior-integration: fold test skipped: "

// FoldsRequired reports whether getenv (os.Getenv, or a test's) asks for
// fold tests to fail rather than skip: RequireFoldsEnv set to exactly 1.
func FoldsRequired(getenv func(string) string) bool {
	return getenv(RequireFoldsEnv) == "1"
}

// SkippedFoldTests returns what follows FoldSkipMarker on each line of
// output that begins with it, in order.
func SkippedFoldTests(output string) []string {
	return markedLines(output, FoldSkipMarker)
}

// markedLines returns what follows marker on each line of output that begins
// with it, in order. Only the beginning of a line counts: the same text
// indented, as a t.Log of another test would print it, is no skip.
func markedLines(output, marker string) []string {
	var marked []string
	for line := range strings.SplitSeq(output, "\n") {
		if rest, ok := strings.CutPrefix(line, marker); ok {
			marked = append(marked, rest)
		}
	}
	return marked
}

// FoldSkipSummary returns the lines `mage integrationTest` prints after the
// run about the fold tests (as part of SkipSummary): none when no fold test
// skipped, else a count with the way to make
// them fail, and one line per test. The count is the plausibility check a
// reader needs: one skip is a busy moment of the host, most of them a host
// whose real-time tasks preempt BPF programs all the time, where the folds
// go untested until the run is repeated elsewhere or required.
func FoldSkipSummary(output string) []string {
	skipped := SkippedFoldTests(output)
	if len(skipped) == 0 {
		return nil
	}
	lines := []string{fmt.Sprintf("%d fold test(s) SKIPPED because every run reported kernel-side loss "+
		"(set %s=1 to fail them instead):", len(skipped), RequireFoldsEnv)}
	for _, test := range skipped {
		lines = append(lines, "  "+test)
	}
	return lines
}
