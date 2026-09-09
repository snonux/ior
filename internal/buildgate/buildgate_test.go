package buildgate

import (
	"bytes"
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
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"ior/internal/gatecmd"
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

// propagatesError reports whether the branch taken when a call failed hands a
// real error back. `return nil` there means the failure was swallowed, and so
// does `return errors.Join()` - which is nil - or returning a variable that
// was just cleared. Only an identifier or a call with arguments counts, so the
// nil-valued dodges have to be spelled as something this cannot mistake for an
// error.
func propagatesError(body ast.Node) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			return true
		}
		for _, res := range ret.Results {
			switch r := res.(type) {
			case *ast.Ident:
				if r.Name != "nil" {
					found = true
				}
			case *ast.CallExpr:
				// fmt.Errorf(...) wraps; errors.Join() with no arguments is nil.
				if len(r.Args) != 0 {
					found = true
				}
			}
		}
		return true
	})
	return found
}

// checksForFailure reports whether cond is the `err != nil` test. A gate whose
// branch is entered on `err == nil` runs the tool, returns its (nil) error and
// reports success - the condition is as load-bearing as the branch.
func checksForFailure(cond ast.Expr) bool {
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	if bin.Op != token.NEQ {
		return false
	}
	ident, ok := bin.Y.(*ast.Ident)
	return ok && ident.Name == "nil"
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
			if stmt.Init != nil && callsGate(stmt.Init) && checksForFailure(stmt.Cond) && propagatesError(stmt.Body) {
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
	// One level further down: `checks` is the key that decides which analyses
	// actually run, and `checks: [SA4006]` leaves staticcheck enabled while
	// switching off everything the fixture does not happen to trigger.
	assertOnlyKnownKeys(t, "linters.settings.staticcheck", settings.section(t, "staticcheck"), "checks")
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

func Printf(format string) {
	fmt.Printf(format)
}
`

// lintFixtureTest puts the same unchecked error in a test file.
const lintFixtureTest = `package fixture

import "os"

func helper() {
	os.Remove("/nonexistent/lint-gate-fixture-test")
}
`

// The gates' command lines live in internal/gatecmd rather than in
// Magefile.go, which is behind the mage build tag and so unreachable from any
// test. That put several rounds of review into a losing pattern: each
// assertion about what `mage lint` runs had to be made against the *source
// text* of a function nothing could call, and each was walked around - a body
// that merely mentions the right strings, a flag routed through a constant, a
// helper wrapping the invocation, a guard clause returning before the call.
//
// Asserting on data, and then running it, replaces all of that.

// TestLintArgvCoversTheWholeModule pins the lint command line itself.
func TestLintArgvCoversTheWholeModule(t *testing.T) {
	if got := gatecmd.GolangciLintBin; got != "golangci-lint" {
		t.Errorf("GolangciLintBin is %q; the gate runs something else", got)
	}
	assertArgvAllowed(t, "LintConfigVerify", gatecmd.LintConfigVerify(),
		[]string{"golangci-lint", "config", "verify"})
	assertArgvAllowed(t, "LintRun", gatecmd.LintRun(),
		[]string{"golangci-lint", "run", "--build-tags", "mage", "./..."})

	for _, want := range []string{"run", "--build-tags", "mage", "./..."} {
		if !slices.Contains(gatecmd.LintRun(), want) {
			t.Errorf("LintRun() omits %q; it must lint the whole module with the mage build tag (%v)", want, gatecmd.LintRun())
		}
	}
}

// TestVetArgvCoversTheWholeModule pins vet's two passes, including that the
// unsafeptr exemption names exactly one package. Widening it disables the
// analyzer module-wide while `mage vet` keeps exiting 0.
func TestVetArgvCoversTheWholeModule(t *testing.T) {
	if got := gatecmd.VetUnsafeptrExempt; got != "ior/cmd/ioworkload" {
		t.Errorf("VetUnsafeptrExempt is %q, want \"ior/cmd/ioworkload\"; it disables the unsafeptr analyzer for whatever it names", got)
	}
	assertArgvAllowed(t, "VetUnsafeptrExempted", gatecmd.VetUnsafeptrExempted(),
		[]string{"go", "vet", "-unsafeptr=false", gatecmd.VetUnsafeptrExempt})

	// The full-analyzer pass takes the package list as an argument, so what is
	// pinned is that it adds nothing but `go vet` to it: an extra
	// `-printf=false` here would switch an analyzer off module-wide, and it is
	// the one argument slot no literal assertion used to see.
	packages := []string{"ior/internal", "ior/cmd/ior"}
	assertArgvAllowed(t, "VetAll", gatecmd.VetAll(packages),
		append([]string{"go", "vet"}, packages...))
}

// TestTestArgvRunsEverything pins the suite that carries every assertion in
// this package. Narrowing it, or filtering it with -run, switches all of them
// off in one edit while `mage world` keeps reporting success.
func TestTestArgvRunsEverything(t *testing.T) {
	assertArgvAllowed(t, "TestAll", gatecmd.TestAll(),
		[]string{"go", "test", "./...", "-failfast", "-timeout=90m"})
	if !slices.Contains(gatecmd.TestAll(), "./...") {
		t.Errorf("TestAll() does not run ./... ; packages dropped from it leave mage world silently, internal/buildgate included (%v)", gatecmd.TestAll())
	}
	assertArgvAllowed(t, "CleanTestCache", gatecmd.CleanTestCache(),
		[]string{"go", "clean", "-testcache"})
}

// assertArgvAllowed compares an argv against the reviewed one exactly.
//
// An allow-list rather than a list of flags known to be bad, because
// blocklisting lost by one character twice: --issues-exit-code was banned and
// --issues-exit-code=0 walked past it; --config was banned while
// --new-from-rev, --new, -D and --enable-only were never on the list. Each
// makes a tool report findings and exit 0, or hides them outright.
func assertArgvAllowed(t *testing.T, name string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("gatecmd.%s() has changed.\n  is:   %v\n  want: %v\nArguments here can make a tool exit 0 with findings (--issues-exit-code=0), limit what it looks at (--new-from-rev, -run), turn a linter off (-D) or point it at another config (--config=...). Review the change, then update the expected argv.", name, got, want)
	}
}

// TestLintArgvRejectsAKnownDefect runs the lint gate's real command line - the
// argv `mage lint` runs, with the repository's own .golangci.yml - against a
// package containing an unchecked error and two dead stores, and requires all
// of them to be reported.
//
// This is the assertion the config- and argv-level ones exist to support: it
// asks what the gate *does*. A configuration that is plausible key by key and
// collectively inert fails here regardless of how it was spelled.
func TestLintArgvRejectsAKnownDefect(t *testing.T) {
	bin, err := exec.LookPath(gatecmd.GolangciLintBin)
	if err != nil {
		t.Skipf("%s not on PATH; `mage lint` would fail the same way", gatecmd.GolangciLintBin)
	}

	// The fixture is its own module so the linter does not try to load the
	// real one, which needs the libbpfgo cgo environment to typecheck.
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	// An old language version on purpose: the fixture needs nothing modern,
	// and naming the repository's own would break this test on any machine
	// whose golangci-lint was built with an older Go than go.mod requires.
	write("go.mod", "module lintfixture\n\ngo 1.21\n")
	write("fixture.go", lintFixture)
	// A defect in a _test.go file too, so `run.tests: false` - which drops
	// every test file in the repository, where most of what this gate has
	// caught lives - fails here as well.
	write("fixture_test.go", lintFixtureTest)

	cfg, err := os.ReadFile(filepath.Join(repoRoot(t), ".golangci.yml"))
	if err != nil {
		t.Fatalf("read .golangci.yml: %v", err)
	}
	write(".golangci.yml", string(cfg))

	argv := gatecmd.LintRun()
	cmd := exec.Command(bin, append(argv[1:], "--output.text.path", "stdout")...)
	cmd.Dir = dir
	out, runErr := cmd.CombinedOutput()
	report := string(out)

	if runErr == nil {
		t.Errorf("the lint gate accepted a package with an unchecked error and two dead stores; it reports nothing and would pass any tree.\n%s", report)
	}
	// Two different SA checks, because pinning one lets `checks: [SA4006]`
	// disable the rest of the family while this test still passes.
	for _, want := range []struct{ what, marker string }{
		{"errcheck", "fixture.go"},
		{"errcheck in a _test.go file", "fixture_test.go"},
		{"staticcheck SA4006", "SA4006"},
		{"staticcheck SA1006", "SA1006"},
	} {
		if !strings.Contains(report, want.marker) {
			t.Errorf("%s reported nothing for the fixture (looked for %q); it is enabled in name only.\n%s", want.what, want.marker, report)
		}
	}
}

// TestMageLintFailsOnAPlantedDefect runs `mage lint` itself, in a copy of the
// repository with an unchecked error added, and requires it to fail.
//
// It is the only assertion that covers the Mage target as a whole rather than
// the pieces it is built from. Everything else here checks an argv or a config
// key, and a target can satisfy all of those and still not run: an early
// `if os.Getenv("SKIP_LINT") != "" { return nil }`, or clearing the error
// (`if err != nil { log(err); err = nil }; return err`), leaves every other
// test in this package passing while `mage lint` reports success on a tree
// full of findings.
//
// Cost is a git archive plus a BPF build, around 20s. That is why it is
// skipped under -short; `mage test` does not pass -short, so the gate's own
// gate runs in the suite that matters.
func TestMageLintFailsOnAPlantedDefect(t *testing.T) {
	if testing.Short() {
		t.Skip("copies the repo and runs a BPF build; ~20s")
	}
	for _, bin := range []string{"mage", "git", gatecmd.GolangciLintBin} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH", bin)
		}
	}
	libbpfgo := os.Getenv("LIBBPFGO")
	if libbpfgo == "" {
		libbpfgo = filepath.Join(repoRoot(t), "..", "libbpfgo")
	}
	if _, err := os.Stat(filepath.Join(libbpfgo, "output", "libbpf", "libbpf.a")); err != nil {
		t.Skipf("libbpfgo not built at %s; `mage lint` cannot run here either", libbpfgo)
	}

	// git archive rather than a recursive copy: tracked files only, no build
	// artifacts, and it fails loudly on a dirty index rather than silently
	// testing something other than HEAD.
	root := repoRoot(t)
	dir := t.TempDir()
	archive := exec.Command("git", "archive", "--format=tar", "HEAD")
	archive.Dir = root
	tarball, err := archive.Output()
	if err != nil {
		t.Fatalf("git archive HEAD: %v", err)
	}
	untar := exec.Command("tar", "-x", "-C", dir)
	untar.Stdin = bytes.NewReader(tarball)
	if out, err := untar.CombinedOutput(); err != nil {
		t.Fatalf("untar: %v\n%s", err, out)
	}

	// A defect the gate is configured to catch, in a package the
	// cmd/ioworkload exclusion does not cover. internal/ is used because it
	// is certain to exist in any revision this runs against.
	planted := filepath.Join(dir, "internal", "planted_defect.go")
	const defect = `package internal

import "os"

func plantedDefect() {
	os.Remove("/nonexistent/planted-defect")
}
`
	if err := os.WriteFile(planted, []byte(defect), 0o644); err != nil {
		t.Fatalf("plant defect: %v", err)
	}

	cmd := exec.Command("mage", "lint")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "LIBBPFGO="+mustAbs(t, libbpfgo))
	out, runErr := cmd.CombinedOutput()
	if runErr == nil {
		t.Errorf("`mage lint` succeeded on a tree containing an unchecked error; the target does not fail on findings, whatever its argv says.\n%s", out)
	}
	if !strings.Contains(string(out), "planted_defect.go") {
		t.Errorf("`mage lint` failed, but not because of the planted defect - it never reported planted_defect.go, so something else broke and this test proves nothing.\n%s", out)
	}
}

// mustAbs resolves p to an absolute path, since the command runs elsewhere.
func mustAbs(t *testing.T, p string) string {
	t.Helper()
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("abs %s: %v", p, err)
	}
	return abs
}
