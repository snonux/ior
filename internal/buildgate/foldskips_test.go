package buildgate

import (
	"go/ast"
	"go/token"
	"testing"
)

// TestIntegrationRunSummarisesSkippedFoldTests pins the one place a fold
// test's skip becomes visible in `mage integrationTest` (task 723), and the
// skip of a test whose case no run exercised (task f23): the binary runs
// without -test.v, which prints no skip, so the run of the integration test
// binary must end with gatecmd.SkipSummary (both lists) over its output.
// "Its output" is pinned too: the summary reads `<buf>.String()` of a buffer
// the run's writer copies into (an `io.MultiWriter(..., &<buf>)` argument of
// runRootTestBinary). A summary over anything else - an empty string,
// another buffer - would print nothing and pass the old check.
func TestIntegrationRunSummarisesSkippedFoldTests(t *testing.T) {
	file := parseMagefile(t)
	var summaries []*ast.CallExpr
	ast.Inspect(funcDecl(t, file, integrationRun).Body, func(n ast.Node) bool {
		if isGatecmdCall(n, "SkipSummary") {
			summaries = append(summaries, n.(*ast.CallExpr))
		}
		return true
	})
	if len(summaries) != 1 {
		t.Fatalf("%s() calls gatecmd.SkipSummary %d times, want once: skipped tests would go unseen", integrationRun, len(summaries))
	}
	buffer := stringOfIdent(summaries[0])
	if buffer == "" {
		t.Fatalf("gatecmd.SkipSummary is not called with <buffer>.String()")
	}
	runs := callsTo(t, file, integrationRun, rootBinaryRunner)
	if len(runs) != 1 || len(runs[0].Args) < 3 || !copiesInto(runs[0].Args[2], buffer) {
		t.Errorf("the output of %s() in %s() is not copied into %s, the buffer gatecmd.SkipSummary reads", rootBinaryRunner, integrationRun, buffer)
	}
}

// stringOfIdent returns the name of the buffer in a call `f(<name>.String())`
// that has that one argument, or "".
func stringOfIdent(call *ast.CallExpr) string {
	if len(call.Args) != 1 {
		return ""
	}
	inner, ok := call.Args[0].(*ast.CallExpr)
	if !ok || len(inner.Args) != 0 {
		return ""
	}
	sel, ok := inner.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "String" {
		return ""
	}
	if ident, ok := sel.X.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// copiesInto reports whether writer is `io.MultiWriter(...)` with `&<buffer>`
// among its arguments.
func copiesInto(writer ast.Expr, buffer string) bool {
	call, ok := writer.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "MultiWriter" || !isIdent(sel.X, "io") {
		return false
	}
	for _, arg := range call.Args {
		if ref, ok := arg.(*ast.UnaryExpr); ok && ref.Op == token.AND && isIdent(ref.X, buffer) {
			return true
		}
	}
	return false
}
