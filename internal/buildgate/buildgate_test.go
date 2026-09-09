package buildgate

import (
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// repoRoot returns the repository root, resolved from this test's own location
// so the test does not depend on the working directory `go test` happens to use.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Join(wd, "..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("go.mod not found at resolved repo root %s: %v", root, err)
	}
	return root
}

// parseMagefile parses Magefile.go. It is behind `//go:build mage`, so it is
// parsed directly rather than through the package loader, which would exclude
// it.
func parseMagefile(t *testing.T) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(repoRoot(t), "Magefile.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse Magefile.go: %v", err)
	}
	return file
}

// funcDecl returns the top-level (non-method) declaration of fn.
func funcDecl(t *testing.T, file *ast.File, fn string) *ast.FuncDecl {
	t.Helper()
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == fn {
			return fd
		}
	}
	t.Fatalf("Magefile.go declares no top-level func %s", fn)
	return nil
}

// toolCall is one invocation of an external tool from a Mage target: the
// literal arguments it was given, and whether its result reaches a return.
type toolCall struct {
	args     []string
	returned bool
}

// shRunners are the sh helpers that actually execute something. A target that
// calls none of them runs no tool, whatever its body says.
var shRunners = []string{"Run", "RunV", "RunWith", "RunWithV", "Output", "OutputWith"}

// toolCallsIn returns every `sh.Run*(...)` invocation in the body of fn.
//
// This models what a gate has to do - run a tool and fail when it fails -
// rather than what its source happens to contain. Asserting on the text was
// tried and lost repeatedly: a `fmt.Println(goEnv(), "run", "./...")` body
// satisfies a check for those literals while running nothing, a helper that
// wraps the call moves the discard out of the function being inspected, and an
// argument supplied by a top-level const never appears in the body at all.
// Each of those left `mage lint` exiting 0 with real findings present.
func toolCallsIn(t *testing.T, file *ast.File, fn string) []toolCall {
	t.Helper()
	decl := funcDecl(t, file, fn)

	isRunner := func(call *ast.CallExpr) bool {
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		pkg, ok := sel.X.(*ast.Ident)
		return ok && pkg.Name == "sh" && slices.Contains(shRunners, sel.Sel.Name)
	}
	// String literals, plus identifiers that resolve to a top-level string
	// constant - routing a flag through a const is otherwise a way to keep it
	// out of the body entirely. Anything still unreadable is recorded as the
	// empty string, which the allow-list rejects: an argument this test cannot
	// read is one it cannot vouch for.
	argsOf := func(call *ast.CallExpr) []string {
		var args []string
		for _, arg := range call.Args {
			switch a := arg.(type) {
			case *ast.BasicLit:
				if a.Kind != token.STRING {
					args = append(args, "")
					continue
				}
				unquoted, err := strconv.Unquote(a.Value)
				if err != nil {
					args = append(args, "")
					continue
				}
				args = append(args, unquoted)
			case *ast.Ident:
				if value, ok := lookupConstString(file, a.Name); ok {
					args = append(args, value)
					continue
				}
				// A slice built up in the body (Vet's package list) is covered
				// by that target's own assertions rather than here.
				if a.Name == "packages" || a.Name == "args" {
					continue
				}
				args = append(args, "")
			case *ast.CallExpr:
				continue // goEnv(), append(...) and friends supply no flags
			default:
				args = append(args, "")
			}
		}
		return args
	}

	var calls []toolCall
	var walk func(n ast.Node, returned bool)
	walk = func(n ast.Node, returned bool) {
		ast.Inspect(n, func(n ast.Node) bool {
			switch stmt := n.(type) {
			case *ast.ReturnStmt:
				for _, res := range stmt.Results {
					if call, ok := res.(*ast.CallExpr); ok && isRunner(call) {
						calls = append(calls, toolCall{args: argsOf(call), returned: true})
						return false
					}
				}
			case *ast.IfStmt:
				// if err := sh.Run...(); err != nil { ... return err ... }
				if stmt.Init != nil {
					assign, ok := stmt.Init.(*ast.AssignStmt)
					if ok {
						for _, rhs := range assign.Rhs {
							call, ok := rhs.(*ast.CallExpr)
							if !ok || !isRunner(call) {
								continue
							}
							calls = append(calls, toolCall{args: argsOf(call), returned: propagatesError(stmt.Body)})
						}
					}
				}
			case *ast.AssignStmt:
				// `err := sh.Run...()` outside an if-init. Gated when that
				// variable is returned later, which is an ordinary way to
				// write it; ungated for `_ = sh.Run...()`, which is not.
				for i, rhs := range stmt.Rhs {
					call, ok := rhs.(*ast.CallExpr)
					if !ok || !isRunner(call) {
						continue
					}
					name := ""
					if i < len(stmt.Lhs) {
						if ident, ok := stmt.Lhs[i].(*ast.Ident); ok {
							name = ident.Name
						}
					}
					calls = append(calls, toolCall{
						args:     argsOf(call),
						returned: name != "" && name != "_" && returnsIdent(decl.Body, name, stmt.Pos()),
					})
				}
			}
			return true
		})
	}
	walk(decl.Body, false)
	return calls
}

// returnsIdent reports whether body has a `return name` (possibly among other
// results, as in `return nil, err`) that appears *after* pos.
//
// The position matters. Lint assigns err twice - once for the config
// pre-flight, once for the run - and searching the whole body for any
// `return err` let the pre-flight's return vouch for a later
// `err := sh.Run...(); _ = err; return nil`, which is the same any-versus-every
// mistake this file has now made three times.
func returnsIdent(body ast.Node, name string, pos token.Pos) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || ret.Pos() <= pos {
			return true
		}
		for _, res := range ret.Results {
			if ident, ok := res.(*ast.Ident); ok && ident.Name == name {
				found = true
			}
		}
		return true
	})
	return found
}

// propagatesError reports whether the branch taken when a call failed returns
// something other than a bare nil. `return nil` there, or no return at all,
// means the failure was swallowed and the caller succeeds anyway.
func propagatesError(body ast.Node) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		if len(ret.Results) == 0 {
			return true
		}
		for _, res := range ret.Results {
			if ident, ok := res.(*ast.Ident); ok && ident.Name == "nil" {
				continue
			}
			found = true
		}
		return true
	})
	return found
}

// failsOn reports whether a failure of gate() makes fn stop: the gate called
// in an if-statement whose branch propagates a non-nil error, `return gate()`,
// or mg.Deps/mg.SerialDeps, which abort the run on any dependency failure.
func failsOn(t *testing.T, file *ast.File, fn, gate string) bool {
	t.Helper()
	callsGate := func(n ast.Node) bool {
		found := false
		ast.Inspect(n, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == gate {
				found = true
			}
			return true
		})
		return found
	}

	fails := false
	ast.Inspect(funcDecl(t, file, fn).Body, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.ReturnStmt:
			for _, res := range stmt.Results {
				if callsGate(res) {
					fails = true
				}
			}
		case *ast.IfStmt:
			if stmt.Init != nil && callsGate(stmt.Init) && propagatesError(stmt.Body) {
				fails = true
			}
		case *ast.CallExpr:
			// mg.Deps(Vet, Lint) / mg.SerialDeps(...) abort on failure.
			sel, ok := stmt.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "mg" || !strings.HasSuffix(sel.Sel.Name, "Deps") {
				return true
			}
			for _, arg := range stmt.Args {
				if ident, ok := arg.(*ast.Ident); ok && ident.Name == gate {
					fails = true
				}
			}
		}
		return true
	})
	return fails
}

// calleesOf returns the names of the functions the top-level function fn calls
// directly. Arguments to mg.Deps are counted as callees too: `mg.Deps(Vet)` is
// how Mage declares a dependency and runs it, and is interchangeable with a
// plain `Vet()` call for the purposes of these tests.
func calleesOf(t *testing.T, file *ast.File, fn string) []string {
	t.Helper()
	decl := funcDecl(t, file, fn)
	var callees []string
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			callees = append(callees, fun.Name)
		case *ast.SelectorExpr:
			// mg.Deps(Vet, Lint) / mg.SerialDeps(...) run their arguments.
			pkg, ok := fun.X.(*ast.Ident)
			if !ok || pkg.Name != "mg" || !strings.HasSuffix(fun.Sel.Name, "Deps") {
				return true
			}
			for _, arg := range call.Args {
				if ident, ok := arg.(*ast.Ident); ok {
					callees = append(callees, ident.Name)
				}
			}
		}
		return true
	})
	return callees
}

// goFilesOutside returns every Go file in the repository whose path does not
// start with prefix, relative to the repo root and slash-separated, which is
// the form golangci-lint matches an exclusion rule's `path` regex against.
func goFilesOutside(t *testing.T, prefix string) []string {
	t.Helper()
	root := repoRoot(t)
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !strings.HasPrefix(rel, prefix) {
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(files) == 0 {
		t.Fatalf("found no Go files outside %s; the walk is broken and every scope assertion would pass vacuously", prefix)
	}
	return files
}

// TestNoNegatedMageConstraint underwrites Lint running a single pass. `mage
// lint` passes --build-tags mage, which covers every package plus Magefile.go
// only while nothing is excluded *by* that tag. A file that builds without the
// tag but not with it would never be linted at all.
//
// The constraint is evaluated rather than pattern-matched. Three rounds of
// regex each missed a spelling the toolchain accepts - `!mage`, then `!(mage)`
// and `! mage`, then `!(linux && mage)` - and there is no reason to expect the
// fourth to be the last. go/build/constraint answers the actual question:
// is there a file the default build includes and the tagged build drops?
func TestNoNegatedMageConstraint(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range goFilesOutside(t, "\x00") {
		src, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		line, expr := buildConstraint(t, rel, string(src))
		if expr == nil {
			continue
		}
		withTag := expr.Eval(func(tag string) bool { return tag == "mage" || tag == "linux" || tag == "amd64" })
		withoutTag := expr.Eval(func(tag string) bool { return tag == "linux" || tag == "amd64" })
		if withoutTag && !withTag {
			t.Errorf("%s:%d is excluded by the mage build tag (%s); `mage lint` runs a single pass with -tags mage, so this file would not be linted at all", rel, line, strings.TrimSpace(constraintText(string(src))))
		}
	}
}

// buildConstraint returns the parsed //go:build expression of a file, or nil
// when it has none.
func buildConstraint(t *testing.T, rel, src string) (int, constraint.Expr) {
	t.Helper()
	for i, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(line, "package ") {
			return 0, nil // constraints must precede the package clause
		}
		if !constraint.IsGoBuild(line) {
			continue
		}
		expr, err := constraint.Parse(line)
		if err != nil {
			t.Errorf("%s:%d has an unparseable build constraint %q: %v", rel, i+1, line, err)
			return 0, nil
		}
		return i + 1, expr
	}
	return 0, nil
}

// constraintText returns the //go:build line of a file, for error messages.
func constraintText(src string) string {
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(line, "package ") {
			return ""
		}
		if constraint.IsGoBuild(line) {
			return line
		}
	}
	return ""
}

// TestNoNestedModules underwrites every `./...` in this repository. A go.mod
// below the root cuts its whole subtree out of the main module, so `mage
// lint`, `mage vet` and `mage test` all stop seeing it at once and all three
// keep reporting success.
func TestNoNestedModules(t *testing.T) {
	root := repoRoot(t)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "go.mod" || filepath.Dir(path) == root {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		t.Errorf("%s is a nested module; everything under %s drops out of ./... , so lint, vet and test all stop covering it while still reporting success", rel, filepath.Dir(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}

// TestWorldRunsTheStaticAnalysisGates pins the wiring this package exists for.
// Vet, Lint and FmtCheck are useful only if something runs them; before they
// were part of World their findings accumulated between the occasions somebody
// ran them by hand. PrReview inherits all three through World.
func TestWorldRunsTheStaticAnalysisGates(t *testing.T) {
	file := parseMagefile(t)

	worldCalls := calleesOf(t, file, "World")
	// Test is in this list for a reason that is easy to miss: everything else
	// in this package is a test, so a World that stops running the suite - or
	// a Test narrowed to a subset of packages - switches every assertion here
	// off in one edit while the gate keeps reporting success.
	for _, gate := range []string{"FmtCheck", "Vet", "Lint", "Test"} {
		if !slices.Contains(worldCalls, gate) {
			t.Errorf("World() does not run %s(); that gate is unwired (World runs: %v)", gate, worldCalls)
			continue
		}
		// Calling a gate is not enough, and neither is checking that its error
		// is not thrown away with `_ =`. The natural way to make a gate
		// advisory is to keep the `if err != nil` and log instead of
		// returning, which is errcheck-clean and reads like real code:
		//
		//	if err := Lint(); err != nil {
		//		fmt.Println("World: lint findings (non-fatal):", err)
		//	}
		//
		// So what is asserted is that World stops: the gate's error has to
		// reach a return statement.
		if !failsOn(t, file, "World", gate) {
			t.Errorf("World() runs %s() but does not return when it fails; its findings are reported and World succeeds anyway", gate)
		}
	}

	prCalls := calleesOf(t, file, "PrReview")
	if !slices.Contains(prCalls, "World") {
		t.Errorf("PrReview() does not run World(), so it no longer inherits the static-analysis gates (PrReview runs: %v)", prCalls)
	} else if !failsOn(t, file, "PrReview", "World") {
		t.Error("PrReview() runs World() but does not return when it fails; the gates run but no longer fail it")
	}
}

// stringLiteralsIn returns every string literal in the body of the top-level
// function fn. Working from the AST rather than the source text is what makes
// this resistant to the obvious dodges: a commented-out invocation left in the
// body no longer satisfies the assertions below.
func stringLiteralsIn(t *testing.T, file *ast.File, fn string) []string {
	t.Helper()
	decl := funcDecl(t, file, fn)
	var lits []string
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			unquoted, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			lits = append(lits, unquoted)
		}
		return true
	})
	return lits
}

// lookupConstString returns the value of the top-level string constant name.
func lookupConstString(file *ast.File, name string) (string, bool) {
	for _, d := range file.Decls {
		gen, ok := d.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if ident.Name != name || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				unquoted, err := strconv.Unquote(lit.Value)
				if err != nil {
					return "", false
				}
				return unquoted, true
			}
		}
	}
	return "", false
}

// constString returns the value of the top-level string constant name.
func constString(t *testing.T, file *ast.File, name string) string {
	t.Helper()
	for _, d := range file.Decls {
		gen, ok := d.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if ident.Name != name || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				unquoted, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("const %s is not a plain string: %v", name, err)
				}
				return unquoted
			}
		}
	}
	t.Fatalf("Magefile.go declares no top-level string const %s", name)
	return ""
}

// allowedToolArgs lists, per Mage target, every literal argument it may pass
// to an external tool. It is an allow-list because blocklisting lost by one
// character twice: --issues-exit-code was banned and --issues-exit-code=0
// walked past it, --config was banned and --new-from-rev, --new, -D and
// --enable-only were never on the list at all. Each of those makes the linter
// report findings and exit 0, or hides them outright.
//
// An argument this test cannot read as a string literal is recorded as "" and
// rejected here too, so routing a flag through a const or a variable does not
// evade the list.
var allowedToolArgs = map[string][]string{
	"Lint": {
		"golangci-lint",    // the binary, via golangciLintBin
		"config", "verify", // pre-flight: reject a config `run` would half-ignore
		"run",          // the gate itself
		"--build-tags", // so Magefile.go is inside its own gate
		"mage",
		"./...", // the whole module
	},
	"Vet": {
		"go", // the binary
		"vet",
		"-unsafeptr=false", // the one scoped analyzer exemption
		vetUnsafeptrExempt,
	},
}

// vetUnsafeptrExempt is the single package vetted with unsafeptr disabled. It
// is duplicated from Magefile.go rather than imported because that file is
// behind the mage build tag; TestVetExemptionStaysScoped keeps them in step.
const vetUnsafeptrExempt = "ior/cmd/ioworkload"

// requiredToolArgs are arguments each target must pass, as opposed to merely
// being allowed to.
var requiredToolArgs = map[string][]string{
	"Lint": {"run", "--build-tags", "mage", "./..."},
	"Vet":  {"vet"},
}

// TestGatesActuallyRunTheirTool is the structural half of the gate's guarantee:
// each target has to invoke a tool, over the whole module, and stop when it
// fails.
//
// Every assertion here is on the *call* rather than on the text of the
// function, because the text has been a poor proxy. A body of
// `fmt.Println(goEnv(), "run", "./...")` contains every required literal and
// runs nothing; a helper wrapping the invocation moves the swallowed error out
// of the function; a flag supplied by a top-level const never appears in the
// body. All three left `mage lint` reporting success with real findings
// present.
func TestGatesActuallyRunTheirTool(t *testing.T) {
	file := parseMagefile(t)

	if bin := constString(t, file, "golangciLintBin"); bin != "golangci-lint" {
		t.Errorf("golangciLintBin is %q, not \"golangci-lint\"; Lint runs something else", bin)
	}

	for _, target := range []string{"Lint", "Vet"} {
		calls := toolCallsIn(t, file, target)
		if len(calls) == 0 {
			t.Errorf("%s() makes no sh.Run* call; it runs no tool at all, whatever its body says", target)
			continue
		}

		var seen []string
		// Every invocation has to be gated, not just one of them. Lint makes
		// two - the config pre-flight and the run - and accepting "any" let
		// the pre-flight's `return err` vouch for a run whose error was
		// printed and dropped.
		ungated := 0
		for _, call := range calls {
			seen = append(seen, call.args...)
			if !call.returned {
				ungated++
			}
			for _, arg := range call.args {
				if arg == "" {
					t.Errorf("%s() passes a non-literal argument this test cannot read; route flags through literals so the allow-list can vouch for them", target)
					continue
				}
				if !slices.Contains(allowedToolArgs[target], arg) {
					t.Errorf("%s() passes an unreviewed argument %q. Flags here can make the tool exit 0 with findings (--issues-exit-code=0), limit what it looks at (--new-from-rev, --new), turn a linter off (-D, --enable-only) or point it at another config (--config=...). Review it, then add it to allowedToolArgs (args seen: %v).", target, arg, seen)
				}
			}
		}
		if ungated != 0 {
			t.Errorf("%s() makes %d sh.Run* call(s) whose error never reaches a return; that tool's findings are printed and the target succeeds anyway (args seen: %v)", target, ungated, seen)
		}
		for _, want := range requiredToolArgs[target] {
			if !slices.Contains(seen, want) {
				t.Errorf("%s() passes no %q argument (args seen: %v)", target, want, seen)
			}
		}
	}

	// FmtCheck walks the tree itself rather than shelling out, so it is pinned
	// by the weaker property that it can fail at all.
	if !returnsAnError(t, file, "FmtCheck") {
		t.Error("FmtCheck() has no return statement that can be non-nil; it reports formatting drift and succeeds anyway")
	}

	if testArgs := toolCallsIn(t, file, "Test"); len(testArgs) == 0 {
		t.Error("Test() makes no sh.Run* call; it runs no tests at all")
	} else {
		var seen []string
		for _, call := range testArgs {
			seen = append(seen, call.args...)
		}
		if !slices.Contains(seen, "./...") {
			t.Errorf("Test() does not run ./... ; narrowing it drops packages out of `mage world` - internal/buildgate included, which would disable every assertion in this file (args seen: %v)", seen)
		}
	}

	if !slices.Contains(calleesOf(t, file, "Lint"), "goEnv") {
		t.Error("Lint() does not use goEnv(); without the libbpfgo cgo environment every package that imports libbpfgo fails to typecheck and the linter reports a missing bpf/bpf.h instead of any real finding")
	}
}

// TestVetExemptionStaysScoped pins the one analyzer exemption to one package.
// Widening it (to "./..." , say) disables unsafeptr module-wide while `mage
// vet` keeps exiting 0, and the constant lives in Magefile.go where no other
// test reads it.
func TestVetExemptionStaysScoped(t *testing.T) {
	if got := constString(t, parseMagefile(t), "vetUnsafeptrExempt"); got != vetUnsafeptrExempt {
		t.Errorf("vetUnsafeptrExempt is %q, want %q. It disables the unsafeptr analyzer for whatever it names; see the comment above it in Magefile.go for why exactly one package needs that.", got, vetUnsafeptrExempt)
	}
}

// returnsAnError reports whether fn has any return statement that is not a
// bare `nil`, i.e. whether it can fail at all.
func returnsAnError(t *testing.T, file *ast.File, fn string) bool {
	t.Helper()
	found := false
	ast.Inspect(funcDecl(t, file, fn).Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for _, res := range ret.Results {
			if ident, ok := res.(*ast.Ident); ok && ident.Name == "nil" {
				continue
			}
			found = true
		}
		return true
	})
	return found
}

// golangciConfig models .golangci.yml as raw maps on purpose, all the way
// down. Typed fields would let yaml.Unmarshal silently drop any key the struct
// does not name, and every way this gate has been found to be defeatable was a
// *different* key from the one the tests were watching: `linters.disable`
// beats `enable`, `exclusions.paths` and `.presets` beat `exclusions.rules`,
// `settings.errcheck.exclude-functions` exempts a function module-wide, and
// `run.issues-exit-code: 0` / `run.tests: false` silence the gate from a
// section none of it appears in. So the tests below work from the whole
// document and treat an unreviewed key as a failure.
type golangciConfig map[string]any

// section returns cfg[key] as a mapping, or nil when it is absent. It fails
// the test when the key is present but not a mapping this code can walk.
//
// That case is not hypothetical: yaml.v3 decodes a mapping into the named type
// golangciConfig only while every key in it is a string. A single non-string
// key - `true: 1` is enough - makes it a map[any]any instead, and a silent
// type assertion would hand back nil, which assertOnlyKnownKeys would then
// walk to a clean pass. One stray key would blind the check on that whole
// section.
func (c golangciConfig) section(t *testing.T, key string) golangciConfig {
	t.Helper()
	raw, present := c[key]
	if !present || raw == nil {
		return nil
	}
	m, ok := raw.(golangciConfig)
	if !ok {
		t.Fatalf("%q in .golangci.yml is %T, not a mapping this test can inspect; a non-string key inside it would otherwise silently disable every assertion about that section", key, raw)
	}
	return m
}

// mapStrings returns m[key] as a []string, tolerating a scalar.
func mapStrings(m golangciConfig, key string) []string {
	switch v := m[key].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, fmt.Sprint(item))
		}
		return out
	case nil:
		return nil
	default:
		return []string{fmt.Sprint(v)}
	}
}

// assertOnlyKnownKeys fails for any key in m that is not in known. This is the
// deny-by-default rule the config assertions rest on.
func assertOnlyKnownKeys(t *testing.T, where string, m golangciConfig, known ...string) {
	t.Helper()
	for key := range m {
		if !slices.Contains(known, key) {
			t.Errorf("unreviewed %s key %q in .golangci.yml. Keys here can silence the gate without touching anything the other tests watch (e.g. linters.disable, linters.exclusions.paths, run.issues-exit-code). Review what it does, then add it to the known set in %s.", where, key, "buildgate_test.go")
		}
	}
}

// configNames are every filename golangci-lint will load as its configuration.
// It prefers .golangci.yaml/.toml/.json over the .golangci.yml this suite
// asserts on, so an added sibling would shadow the reviewed config entirely
// while every assertion below kept passing against a file no longer in use.
var configNames = []string{
	".golangci.yml", ".golangci.yaml", ".golangci.toml", ".golangci.json",
}

// TestOnlyOneLintConfig fails if a second configuration file appears beside
// the reviewed one.
func TestOnlyOneLintConfig(t *testing.T) {
	root := repoRoot(t)
	for _, name := range configNames {
		if name == ".golangci.yml" {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			t.Errorf("%s exists and shadows .golangci.yml, which every other assertion in this package reads; golangci-lint would use %s instead", name, name)
		}
	}
}

func loadGolangciConfig(t *testing.T) golangciConfig {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".golangci.yml"))
	if err != nil {
		t.Fatalf("read .golangci.yml: %v", err)
	}
	var cfg golangciConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parse .golangci.yml: %v", err)
	}
	return cfg
}

// TestLintConfigHasNoUnreviewedSections walks the whole document and fails on
// any key that has not been looked at. `run` in particular contains
// issues-exit-code (which makes the linter exit 0 with findings present) and
// tests (which removes every _test.go file from the gate).
func TestLintConfigHasNoUnreviewedSections(t *testing.T) {
	cfg := loadGolangciConfig(t)
	assertOnlyKnownKeys(t, "top-level", cfg, "version", "linters", "issues")

	linters := cfg.section(t, "linters")
	settings := linters.section(t, "settings")
	exclusions := linters.section(t, "exclusions")
	assertOnlyKnownKeys(t, "linters", linters, "default", "enable", "settings", "exclusions")
	assertOnlyKnownKeys(t, "linters.settings", settings, "staticcheck")
	assertOnlyKnownKeys(t, "linters.exclusions", exclusions, "generated", "rules")
	// The value matters, not just the key. Under golangci-lint's default
	// `lax`, prefixing any file with "// Code generated by hand. DO NOT EDIT."
	// removes it from the gate exactly the way //nolint does - and //nolint is
	// banned outright for that reason. `strict` does not help: it matches that
	// header too. Only `disable` closes it, and it costs nothing, because the
	// repository's two generated Go files have no findings under any setting.
	if generated, _ := exclusions["generated"].(string); generated != "disable" {
		t.Errorf("linters.exclusions.generated is %q, want \"disable\". Any other value lets a hand-written \"Code generated\" header take a file out of the gate.", generated)
	}
	assertOnlyKnownKeys(t, "issues", cfg.section(t, "issues"), "max-issues-per-linter", "max-same-issues")
}

// The behavioural test above subsumes two assertions that used to live here:
// that errcheck and staticcheck are named under `linters.enable`, and that
// staticcheck's SA family is not switched off. Both were spelling checks for
// conditions TestLintConfigRejectsAKnownDefect detects directly, and detects
// better - it also catches a linter that is enabled and inert, which naming
// alone cannot. They were deleted rather than kept as belt and braces, since
// the whole argument of this file is that spelling assertions lose.

// reviewedExclusionText is the exact `text` regex of the one exclusion rule in
// .golangci.yml, kept here so a change to it fails loudly instead of being
// judged by whichever function names this test happens to probe.
const reviewedExclusionText = "Error return value of `(syscall\\.(Close|Munmap|Chdir)|os\\.RemoveAll)` is not checked"

// errcheckMessage renders the message errcheck emits for an unchecked call to
// fn, which is what an exclusion rule's `text` regex is matched against.
func errcheckMessage(fn string) string {
	return fmt.Sprintf("Error return value of `%s` is not checked", fn)
}

// TestErrcheckExclusionsStayScopedToTheStimulusBinary is the negative test for
// the one exclusion in .golangci.yml. Unchecked errors are tolerated in
// cmd/ioworkload because that binary exists to emit syscalls, not to handle
// their teardown errors. Nothing else may claim that exemption, and not even
// cmd/ioworkload may claim it for anything but those teardown calls: a rule
// that also matched internal/, or that matched every message, would silently
// reopen the gap while `mage lint` still reported "0 issues".
func TestErrcheckExclusionsStayScopedToTheStimulusBinary(t *testing.T) {
	cfg := loadGolangciConfig(t)

	// Every Go file in the tree, so the path regex is checked against what the
	// repository actually contains rather than a hand-written sample. A rule
	// scoped to some package nobody thought to list is the whole failure mode
	// here.
	protected := goFilesOutside(t, "cmd/ioworkload/")
	// A path inside the stimulus binary, to prove the rule is not vacuous: if
	// no rule matches it, the exclusion has been removed or misspelled and the
	// assertions below would pass for the wrong reason.
	const stimulus = "cmd/ioworkload/scenario_dup.go"
	// Teardown calls the exemption is for, and calls it must not cover. An
	// ioworkload scenario that drops the error of the syscall it exists to
	// exercise is still a bug.
	exempt := []string{"syscall.Close", "syscall.Munmap", "syscall.Chdir", "os.RemoveAll"}
	notExempt := []string{"os.Chmod", "syscall.Unlink", "unix.Getrandom", "f.Write"}

	rules, _ := cfg.section(t, "linters").section(t, "exclusions")["rules"].([]any)
	stimulusExempt := map[string]bool{}
	for i, raw := range rules {
		rule, ok := raw.(golangciConfig)
		if !ok {
			t.Fatalf("exclusion rule %d is %T, want a mapping", i, raw)
		}
		names := mapStrings(rule, "linters")
		// A rule naming no linters silences every one of them, and a rule
		// naming staticcheck silences the correctness half of the gate just as
		// effectively as one naming errcheck. Both have to be scoped.
		if len(names) != 0 && !slices.Contains(names, "errcheck") && !slices.Contains(names, "staticcheck") {
			continue
		}
		path, _ := rule["path"].(string)
		if path == "" {
			t.Errorf("exclusion rule %d disables errcheck with no path scope at all", i)
			continue
		}
		pathRe, err := regexp.Compile(path)
		if err != nil {
			t.Fatalf("exclusion rule %d has an invalid path regex %q: %v", i, path, err)
		}
		for _, p := range protected {
			if pathRe.MatchString(p) {
				t.Errorf("exclusion rule %d (path %q) exempts %s from errcheck; only cmd/ioworkload may be exempt", i, path, p)
				break // one example is enough; the regex is the bug
			}
		}
		if !pathRe.MatchString(stimulus) {
			continue
		}
		text, _ := rule["text"].(string)
		if text == "" {
			t.Errorf("exclusion rule %d exempts all of cmd/ioworkload from errcheck; it must name the teardown calls it covers via `text`", i)
			continue
		}
		// Compared literally, not sampled. Probing a handful of function names
		// only proves the regex does not cover *those*: widening it to
		// `…|.*\.(Close|Sync)` exempted every Close and Sync in the package
		// while every probe still passed. The reviewed exemption is four named
		// calls, so the regex that expresses it is pinned as a whole.
		if text != reviewedExclusionText {
			t.Errorf("exclusion rule %d's text regex has changed.\n  is:   %s\n  want: %s\nThe exemption covers four teardown calls; any other regex is a different exemption and needs reviewing, not just matching.", i, text, reviewedExclusionText)
			continue
		}
		textRe, err := regexp.Compile(text)
		if err != nil {
			t.Fatalf("exclusion rule %d has an invalid text regex %q: %v", i, text, err)
		}
		for _, fn := range exempt {
			if textRe.MatchString(errcheckMessage(fn)) {
				stimulusExempt[fn] = true
			}
		}
		// Kept as a cross-check on reviewedExclusionText itself: if that
		// constant is ever updated to something broader, these still fail.
		for _, fn := range notExempt {
			if textRe.MatchString(errcheckMessage(fn)) {
				t.Errorf("exclusion rule %d (text %q) also exempts %s in cmd/ioworkload; the exemption is for teardown calls, not for the syscalls a scenario exists to exercise", i, text, fn)
			}
		}
	}
	// Deliberately not "every one of the four must be covered". Deleting the
	// exclusion and checking all 160 call sites instead is a strengthening,
	// and `mage lint` would fail loudly if it were done by halves - so that
	// direction needs no guard here. What this catches is the exclusion
	// silently ceasing to match what it names while still being present: some
	// covered, some not, which is drift rather than a decision.
	if len(stimulusExempt) != 0 && len(stimulusExempt) != len(exempt) {
		var missing []string
		for _, fn := range exempt {
			if !stimulusExempt[fn] {
				missing = append(missing, fn)
			}
		}
		t.Errorf("the cmd/ioworkload exclusion covers some of its teardown calls but not %v; its regexes have drifted from the set they are documented to cover", missing)
	}
}

// TestNoNolintDirectives enforces the rule in AGENTS.md ("Code Style"): a
// deliberately discarded error is written as an explicit `_ =`, and the single
// blanket exemption lives in .golangci.yml where it is stated once with its
// reasoning.
//
// This is the regression the lint gate was added to prevent, and the gate
// cannot catch it itself: golangci-lint honours //nolint by construction, so
// one comment silently removes a file from the gate while `mage lint` keeps
// reporting "0 issues" - which is exactly how 24 of them accumulated before.
func TestNoNolintDirectives(t *testing.T) {
	root := repoRoot(t)
	// Assembled rather than written out so this test does not report itself,
	// and skip this file outright: its documentation names the directive.
	// The spacing is deliberate: golangci-lint honours `// nolint` with any
	// run of spaces after the slashes exactly as it honours `//nolint`, so
	// matching the tight form alone left the ban one keystroke wide.
	// golangci-lint trims the cutset "/ " after the comment marker before it
	// looks for the directive, so `// /nolint` and `//  /  nolint` are honoured
	// exactly as `//nolint` is - and a pattern matching only spaces left the
	// ban one character wide for the second time. A tab is *not* trimmed, so
	// `//\tnolint` does not suppress anything; it is matched anyway, because a
	// directive that looks live and is not is worse than one that is banned.
	needle := regexp.MustCompile(`//[/ \t]*` + "nolint")
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not identify this test file")
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || path == self {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		for i, line := range strings.Split(string(src), "\n") {
			if needle.MatchString(line) {
				t.Errorf("%s:%d has a %v directive: %s\nUse an explicit `_ =` for a deliberate discard, or add the case to .golangci.yml where the exemption is stated once with its reasoning (AGENTS.md, Code Style).", rel, i+1, needle, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}

// lintFixture is a package that violates exactly the two linters this gate
// exists to run: an unchecked error (errcheck) and a dead store (staticcheck
// SA4006). It is written to a temp directory rather than committed, so it
// cannot itself be caught by the gate it is used to test.
const lintFixture = `package fixture

import (
	"fmt"
	"os"
)

func Fixture() string {
	os.Remove("/nonexistent/lint-gate-fixture")
	s := fmt.Sprintf("dead %d", 1)
	s = fmt.Sprintf("live %d", 2)
	return s
}
`

// lintFixtureTest puts the same unchecked error in a test file.
const lintFixtureTest = `package fixture

import "os"

func helper() {
	os.Remove("/nonexistent/lint-gate-fixture-test")
}
`

// TestLintConfigRejectsAKnownDefect runs the repository's own .golangci.yml
// against a package that is known to violate both enabled linters, and
// requires it to be reported.
//
// Every other test in this file pins the gate by its *spelling* - which key is
// set, which argument is passed - and each round of review has found another
// spelling that turns it off. This one asks the only question that finally
// matters: given this configuration, does a real defect still fail? It is what
// catches a config that is individually plausible key by key and collectively
// inert.
//
// Skipped when golangci-lint is not installed, so `go test ./...` still works
// on a machine that has never run `mage lint`.
func TestLintConfigRejectsAKnownDefect(t *testing.T) {
	bin, err := exec.LookPath("golangci-lint")
	if err != nil {
		t.Skip("golangci-lint not on PATH; `mage lint` would report the same")
	}

	// The fixture lives in its own module so the linter does not try to load
	// the real one, which needs the libbpfgo cgo environment to typecheck.
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("go.mod", "module lintfixture\n\ngo 1.26.0\n")
	write("fixture.go", lintFixture)
	// A defect in a _test.go file too, so `run.tests: false` - which removes
	// every test file in the repository from the gate, and most of what this
	// gate has caught lives in test files - fails here as well.
	write("fixture_test.go", lintFixtureTest)

	cfg, err := os.ReadFile(filepath.Join(repoRoot(t), ".golangci.yml"))
	if err != nil {
		t.Fatalf("read .golangci.yml: %v", err)
	}
	write(".golangci.yml", string(cfg))

	cmd := exec.Command(bin, "run", "--output.text.path", "stdout", "./...")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	report := string(out)

	if err == nil {
		t.Errorf("the configured linter accepted a package with an unchecked error and a dead store; the gate reports nothing and would pass any tree.\n%s", report)
	}
	for _, want := range []struct{ what, marker string }{
		{"errcheck", "fixture.go"},
		{"staticcheck", "SA4006"},
		{"errcheck in a _test.go file", "fixture_test.go"},
	} {
		if !strings.Contains(report, want.marker) {
			t.Errorf("%s reported nothing for the fixture (looked for %q); it is enabled in name only.\n%s", want.what, want.marker, report)
		}
	}
}
