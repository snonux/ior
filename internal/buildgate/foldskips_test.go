package buildgate

import (
	"go/ast"
	"testing"
)

// TestIntegrationRunSummarisesSkippedFoldTests pins the one place a fold
// test's skip becomes visible in `mage integrationTest` (task 723): the
// binary runs without -test.v, which prints no skip, so the run of the
// integration test binary must end with gatecmd.FoldSkipSummary over its
// output.
func TestIntegrationRunSummarisesSkippedFoldTests(t *testing.T) {
	body := funcDecl(t, parseMagefile(t), integrationRun).Body
	if !contains(body, func(n ast.Node) bool { return isGatecmdCall(n, "FoldSkipSummary") }) {
		t.Errorf("%s() does not print gatecmd.FoldSkipSummary: skipped fold tests would go unseen", integrationRun)
	}
}
