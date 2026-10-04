package buildgate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ior/internal/gatecmd"
)

// rootLinkTestFile holds the tests that need root and a real BPF module: what
// libbpfgo does with a link whose Destroy failed (task 123). They skip for
// anybody else, so no unprivileged gate can tell whether they still pass.
const rootLinkTestFile = "internal/ior_bpflink_root_test.go"

// rootLinkHelperTest is the child process of those tests, not a test by
// itself: they re-execute the test binary with it.
const rootLinkHelperTest = "TestLibbpfLinkHelperProcess"

// testFunctionsIn returns the names of the top-level Test functions of the Go
// file at the repository path rel.
func testFunctionsIn(t *testing.T, rel string) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(repoRoot(t), rel), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	var names []string
	for _, declaration := range file.Decls {
		decl, ok := declaration.(*ast.FuncDecl)
		if ok && decl.Recv == nil && strings.HasPrefix(decl.Name.Name, "Test") {
			names = append(names, decl.Name.Name)
		}
	}
	return names
}

// The names of the step's functions in Magefile.go.
const (
	integrationTarget  = "runIntegrationTests"
	rootLinkStep       = "runRootLinkTests"
	rootBinaryRunner   = "runRootTestBinary"
	integrationCompile = "compileIntegrationTestBinary"
	integrationRun     = "runIntegrationTestBinary"
)

// callsTo returns the calls in the body of the Magefile function fn whose
// callee is the plain identifier callee, in source order.
func callsTo(t *testing.T, file *ast.File, fn, callee string) []*ast.CallExpr {
	t.Helper()
	var calls []*ast.CallExpr
	ast.Inspect(funcDecl(t, file, fn).Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == callee {
				calls = append(calls, call)
			}
		}
		return true
	})
	return calls
}

// isGatecmdCall reports whether expr is the call `gatecmd.<name>(...)`.
func isGatecmdCall(expr ast.Node, name string) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "gatecmd"
}

// contains reports whether match holds for a node of the tree below root.
func contains(root ast.Node, match func(ast.Node) bool) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if n != nil && match(n) {
			found = true
		}
		return !found
	})
	return found
}

// TestIntegrationTestRunsTheRootLinkTests pins the one gate that runs the
// root link tests (task 223): `mage integrationTest` and its serial twin run
// them as root, stop when they fail, and do so before the integration test
// binary is built. The order is load-bearing: the step builds the test
// binary of ./internal at the path of the integration test binary. Run after
// the integration compile, it would leave its own binary there for the
// integration run - three tests of ./internal, the integration flags, exit 0
// and not one integration test run. (The step also removes its binary, see
// TestRootLinkStepCleansUpAndBelievesOnlyReportedPasses, which turns that
// into sudo's "command not found"; this pin fails first, and without root.)
func TestIntegrationTestRunsTheRootLinkTests(t *testing.T) {
	file := parseMagefile(t)
	if !slices.Contains(calleesOf(t, file, integrationTarget), rootLinkStep) {
		t.Fatalf("%s() does not run %s(): no mage target runs the root link tests any more", integrationTarget, rootLinkStep)
	}
	if !failsOn(t, file, integrationTarget, rootLinkStep) {
		t.Errorf("%s() runs %s() but does not return when it fails", integrationTarget, rootLinkStep)
	}

	order := []string{rootLinkStep, integrationCompile, integrationRun}
	var last token.Pos
	for _, callee := range order {
		calls := callsTo(t, file, integrationTarget, callee)
		if len(calls) != 1 {
			t.Fatalf("%s() calls %s() %d times, want once", integrationTarget, callee, len(calls))
		}
		if calls[0].Pos() < last {
			t.Errorf("%s() calls %s() out of order, want %v: the root link step shares the binary path and must be over before the integration test binary is built",
				integrationTarget, callee, order)
		}
		last = calls[0].Pos()
	}
}

// TestRootLinkStepRunsTheListedTests pins what the step runs: the argv of
// gatecmd, handed to the root runner whole, in the package directory. With
// any other -test.run pattern the binary runs other tests or none, and a
// test binary that ran nothing exits 0.
func TestRootLinkStepRunsTheListedTests(t *testing.T) {
	file := parseMagefile(t)
	runs := callsTo(t, file, rootLinkStep, rootBinaryRunner)
	if len(runs) != 1 {
		t.Fatalf("%s() calls %s() %d times, want once", rootLinkStep, rootBinaryRunner, len(runs))
	}
	if !failsOn(t, file, rootLinkStep, rootBinaryRunner) {
		t.Errorf("%s() does not return when the test binary fails", rootLinkStep)
	}
	// (env, dir, stdout, args...): the fourth is the binary's whole argv.
	args := runs[0].Args
	if len(args) != 4 || !runs[0].Ellipsis.IsValid() || !isGatecmdCall(args[3], "RootLinkTestArgs") {
		t.Errorf("%s() does not hand %s() exactly gatecmd.RootLinkTestArgs()... as the arguments of the test binary",
			rootLinkStep, rootBinaryRunner)
	}
	if dir, ok := args[1].(*ast.BasicLit); !ok || dir.Value != `"internal"` {
		t.Errorf("%s() does not run the test binary in internal/, the package directory", rootLinkStep)
	}

	pattern := "^(" + strings.Join(gatecmd.RootLinkTests(), "|") + ")$"
	assertArgvAllowed(t, "RootLinkTestArgs", gatecmd.RootLinkTestArgs(),
		[]string{"-test.run", pattern, "-test.timeout=5m", "-test.count=1", "-test.v"})
}

// TestRootLinkTestsAreTheTestsOfTheFile compares the listed names with the
// tests the file declares, both ways. A test renamed in the file would match
// nothing in the -test.run pattern; a test added to it would never run as
// root.
func TestRootLinkTestsAreTheTestsOfTheFile(t *testing.T) {
	listed := gatecmd.RootLinkTests()
	declared := slices.DeleteFunc(testFunctionsIn(t, rootLinkTestFile), func(name string) bool {
		return name == rootLinkHelperTest
	})
	slices.Sort(listed)
	slices.Sort(declared)
	if len(declared) == 0 || !slices.Equal(listed, declared) {
		t.Errorf("gatecmd.RootLinkTests() = %v, but %s declares %v: the two must name the same tests",
			listed, rootLinkTestFile, declared)
	}
}

// TestRootLinkStepCleansUpAndBelievesOnlyReportedPasses pins the two things
// that keep the step from being, or causing, a green no-op. It fails unless
// every listed test is reported as passed, whatever the exit status. And it
// removes its binary in a defer - on every way out - so that the path of the
// integration test binary never holds the test binary of ./internal for the
// integration run to pick up.
func TestRootLinkStepCleansUpAndBelievesOnlyReportedPasses(t *testing.T) {
	file := parseMagefile(t)
	body := funcDecl(t, file, rootLinkStep).Body

	checked := contains(body, func(n ast.Node) bool {
		stmt, ok := n.(*ast.IfStmt)
		if !ok || stmt.Init == nil || !propagatesError(stmt.Body) {
			return false
		}
		cond, ok := stmt.Cond.(*ast.BinaryExpr)
		return ok && cond.Op == token.NEQ && contains(stmt.Init, func(n ast.Node) bool {
			return isGatecmdCall(n, "RootLinkTestsNotPassed")
		})
	})
	if !checked {
		t.Errorf("%s() does not fail when gatecmd.RootLinkTestsNotPassed names a test", rootLinkStep)
	}

	removed := contains(body, func(n ast.Node) bool {
		stmt, ok := n.(*ast.DeferStmt)
		return ok && contains(stmt, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			return ok && len(call.Args) == 1 && isIdent(call.Fun, "removeFilesByPath") &&
				isIdent(call.Args[0], "integrationTestBinaryName")
		})
	})
	if !removed {
		t.Errorf("%s() does not defer the removal of its test binary (removeFilesByPath(integrationTestBinaryName))", rootLinkStep)
	}
}

// isIdent reports whether expr is the plain identifier name.
func isIdent(expr ast.Expr, name string) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == name
}

// rootLinkOutputs are -test.v outputs of the test binary, each with the
// tests it does not report as passed: none, the first of
// gatecmd.RootLinkTests, or all of them. PASSES is replaced by a passed line
// for every listed test but the first, and FIRST by the name of the first.
var rootLinkOutputs = []struct {
	name, output string
	missing      string
}{
	{"all passed", "=== RUN   FIRST\n--- PASS: FIRST (0.31s)\nPASSES\nPASS\n", "none"},
	{"no test matched the pattern", "testing: warning: no tests to run\nPASS\n", "all"},
	{"one skipped, as for anybody but root", "--- SKIP: FIRST (0.00s)\nPASSES\nPASS\n", "first"},
	{"one failed", "--- FAIL: FIRST (0.10s)\nPASSES\nFAIL\n", "first"},
	{"a subtest's verdict is not the test's", "    --- PASS: FIRST (0.00s)\nPASSES\nPASS\n", "first"},
	{"a longer name is another test", "--- PASS: FIRSTAndMore (0.00s)\nPASSES\nPASS\n", "first"},
	{"nothing at all", "", "all"},
}

// TestRootLinkTestsNotPassed runs the check the step relies on against the
// outputs that exit 0 without the tests having passed, and those that must
// not trip it.
func TestRootLinkTestsNotPassed(t *testing.T) {
	names := gatecmd.RootLinkTests()
	if len(names) < 2 {
		t.Fatalf("gatecmd.RootLinkTests() = %v, want at least two names to tell one missing from all", names)
	}
	var passes []string
	for _, name := range names[1:] {
		passes = append(passes, "=== RUN   "+name, "--- PASS: "+name+" (1.20s)")
	}
	replace := strings.NewReplacer("PASSES", strings.Join(passes, "\n"), "FIRST", names[0])
	want := map[string][]string{"none": nil, "first": names[:1], "all": names}
	for _, tc := range rootLinkOutputs {
		t.Run(tc.name, func(t *testing.T) {
			if got := gatecmd.RootLinkTestsNotPassed(replace.Replace(tc.output)); !slices.Equal(got, want[tc.missing]) {
				t.Errorf("RootLinkTestsNotPassed() = %v, want %v", got, want[tc.missing])
			}
		})
	}
}
