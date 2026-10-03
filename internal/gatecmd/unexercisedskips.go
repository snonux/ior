package gatecmd

import "fmt"

// Some integration tests can judge a run but cannot make the run take the
// path they are there for: whether a trace stops while ior lags behind the
// kernel (TestStopAccountsForEveryRecord, task f23) is decided by the host's
// timing. Such a test retries, and when none of its runs took the path it
// skips rather than pass: a pass would claim a check that never ran. Like a
// fold test's skip (foldskips.go) that skip is invisible in `mage
// integrationTest`, so the test prints one line beginning with
// UnexercisedSkipMarker and the target's closing summary (SkipSummary) lists
// it.

// UnexercisedSkipMarker begins the line a test prints when it skips because
// no run exercised the case it tests; the rest of the line names the test
// and why.
const UnexercisedSkipMarker = "ior-integration: test skipped, case not exercised: "

// SkippedUnexercisedTests returns what follows UnexercisedSkipMarker on each
// line of output that begins with it, in order.
func SkippedUnexercisedTests(output string) []string {
	return markedLines(output, UnexercisedSkipMarker)
}

// UnexercisedSkipSummary returns the summary lines for the tests that skipped
// because their case was not exercised: none when there are none, else a
// count and one line per test.
func UnexercisedSkipSummary(output string) []string {
	skipped := SkippedUnexercisedTests(output)
	if len(skipped) == 0 {
		return nil
	}
	lines := []string{fmt.Sprintf("%d test(s) SKIPPED because no run exercised the case they test "+
		"(what they check went unchecked on this host):", len(skipped))}
	for _, test := range skipped {
		lines = append(lines, "  "+test)
	}
	return lines
}

// SkipSummary returns the lines `mage integrationTest` prints after the run
// about every test that skipped for a reason the host decides: the fold
// tests (FoldSkipSummary), then the tests whose case was not exercised
// (UnexercisedSkipSummary). Nothing when none skipped.
func SkipSummary(output string) []string {
	return append(FoldSkipSummary(output), UnexercisedSkipSummary(output)...)
}
