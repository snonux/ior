package buildgate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// rootLinkTestFile holds the tests that need root and a real BPF module: what
// libbpfgo does with a link whose Destroy failed (task 123). They skip for
// anybody else, so no unprivileged gate can tell whether they still pass.
const rootLinkTestFile = "internal/ior_bpflink_root_test.go"

// rootLinkHelperTest is the child process of those tests, not a test by
// itself: they re-execute the test binary with it.
const rootLinkHelperTest = "TestLibbpfLinkHelperProcess"

// magefileStringList returns the string literals of the top-level variable
// name in Magefile.go, a []string composite literal.
func magefileStringList(t *testing.T, file *ast.File, name string) []string {
	t.Helper()
	for _, declaration := range file.Decls {
		decl, ok := declaration.(*ast.GenDecl)
		if !ok || decl.Tok != token.VAR {
			continue
		}
		for _, spec := range decl.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || value.Names[0].Name != name || len(value.Values) != 1 {
				continue
			}
			return stringElements(t, name, value.Values[0])
		}
	}
	t.Fatalf("Magefile.go declares no top-level variable %s", name)
	return nil
}

// stringElements returns the elements of expr, a composite literal of string
// literals, which is the value of the Magefile variable name.
func stringElements(t *testing.T, name string, expr ast.Expr) []string {
	t.Helper()
	list, ok := expr.(*ast.CompositeLit)
	if !ok {
		t.Fatalf("%s in Magefile.go is not a composite literal", name)
	}
	var elements []string
	for _, element := range list.Elts {
		literal, ok := element.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			t.Fatalf("%s in Magefile.go has an element that is not a string literal", name)
		}
		text, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatalf("unquote %s: %v", literal.Value, err)
		}
		elements = append(elements, text)
	}
	return elements
}

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

// TestIntegrationTestRunsTheRootLinkTests pins the one gate that runs the
// root link tests (task 223): `mage integrationTest` and its serial twin run
// them as root before the integration tests, stop when they fail, and name
// every test of the file. The names are compared both ways. A test renamed
// in the file would match nothing in the -test.run pattern, and a test binary
// that ran nothing exits 0; a test added to the file would never run as root.
func TestIntegrationTestRunsTheRootLinkTests(t *testing.T) {
	file := parseMagefile(t)
	const target, step = "runIntegrationTests", "runRootLinkTests"
	if !slices.Contains(calleesOf(t, file, target), step) {
		t.Errorf("%s() does not run %s(): no mage target runs the root link tests any more", target, step)
	} else if !failsOn(t, file, target, step) {
		t.Errorf("%s() runs %s() but does not return when it fails", target, step)
	}
	if callees := calleesOf(t, file, step); !slices.Contains(callees, "runRootTestBinary") {
		t.Errorf("%s() does not run the test binary as root (it calls %v)", step, callees)
	}

	listed := magefileStringList(t, file, "rootLinkTests")
	declared := slices.DeleteFunc(testFunctionsIn(t, rootLinkTestFile), func(name string) bool {
		return name == rootLinkHelperTest
	})
	slices.Sort(listed)
	slices.Sort(declared)
	if len(declared) == 0 || !slices.Equal(listed, declared) {
		t.Errorf("Magefile.go's rootLinkTests = %v, but %s declares %v: the two must name the same tests",
			listed, rootLinkTestFile, declared)
	}
}
