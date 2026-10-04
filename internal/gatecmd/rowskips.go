package gatecmd

import "fmt"

// The integration tests that assert the presence of specific rows (through
// AssertRowsPresent and AssertEventsPresent, integrationtests/expectations.go)
// cannot judge a run whose rows are missing while the kernel reported that
// it lost, or may have lost, as many records: a probe run the kernel skipped
// takes a call's row with it and leaves no other trace (task a33). Such a
// test runs its scenario again, and when every run was like that it skips
// rather than fail for what the host did. As with the fold tests
// (foldskips.go) the skip is invisible in `mage integrationTest`, so:
//
//   - RequireRowsEnv: set to 1, the test fails instead of skipping.
//   - RowSkipMarker: a test that skips prints one line beginning with it to
//     its standard output, and the target's closing summary (SkipSummary)
//     lists it.

// RequireRowsEnv names the environment variable that turns a row test none
// of whose runs could be judged into a failure.
const RequireRowsEnv = "IOR_REQUIRE_ROWS"

// RowSkipMarker begins the line a row test prints when it skips; the rest of
// the line names the test and why.
const RowSkipMarker = "ior-integration: row test skipped: "

// RowsRequired reports whether getenv (os.Getenv, or a test's) asks for row
// tests to fail rather than skip: RequireRowsEnv set to exactly 1.
func RowsRequired(getenv func(string) string) bool {
	return getenv(RequireRowsEnv) == "1"
}

// SkippedRowTests returns what follows RowSkipMarker on each line of output
// that begins with it, in order.
func SkippedRowTests(output string) []string {
	return markedLines(output, RowSkipMarker)
}

// RowSkipSummary returns the summary lines for the row tests that skipped:
// none when there are none, else a count with the way to make them fail, and
// one line per test. One skip is a busy moment of the host; many of them
// mean rows went unchecked there, or that a row is really absent on a host
// too busy to tell.
func RowSkipSummary(output string) []string {
	skipped := SkippedRowTests(output)
	if len(skipped) == 0 {
		return nil
	}
	lines := []string{fmt.Sprintf("%d row test(s) SKIPPED because every run lacked rows that the "+
		"kernel-side loss it reported can explain (set %s=1 to fail them instead):", len(skipped), RequireRowsEnv)}
	for _, test := range skipped {
		lines = append(lines, "  "+test)
	}
	return lines
}
