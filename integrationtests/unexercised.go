package integrationtests

import (
	"fmt"
	"io"

	"ior/internal/gatecmd"
)

// skipVerdict is what SkipUnexercised needs of a test (*testing.T).
type skipVerdict interface {
	Helper()
	Name() string
	Skipf(format string, args ...any)
}

// SkipUnexercised ends a test none of whose runs took the path it is there
// to check, which the host's timing decides and the test cannot force. It
// SKIPS - a pass would claim a check that never ran - and first prints
// gatecmd.UnexercisedSkipMarker with the test and why to out (the test
// binary's standard output), because a skip is invisible in `mage
// integrationTest`, which runs the binary without -test.v and summarises
// these lines at the end (gatecmd.SkipSummary).
func SkipUnexercised(t skipVerdict, out io.Writer, why string) {
	t.Helper()
	_, _ = fmt.Fprintf(out, "%s%s: %s\n", gatecmd.UnexercisedSkipMarker, t.Name(), why)
	t.Skipf("%s", why)
}
