package buildgate

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
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

// discardedCallsIn returns the names of functions whose result is thrown away
// with `_ = f()` in the body of fn.
func discardedCallsIn(t *testing.T, file *ast.File, fn string) []string {
	t.Helper()
	var discarded []string
	ast.Inspect(funcDecl(t, file, fn).Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); !ok || ident.Name != "_" {
				return true
			}
		}
		for _, rhs := range assign.Rhs {
			if call, ok := rhs.(*ast.CallExpr); ok {
				if ident, ok := call.Fun.(*ast.Ident); ok {
					discarded = append(discarded, ident.Name)
				}
			}
		}
		return true
	})
	return discarded
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
// only while nothing is excluded *by* that tag. A `!mage` constraint would
// drop a file out of the one pass that runs.
func TestNoNegatedMageConstraint(t *testing.T) {
	root := repoRoot(t)
	negated := regexp.MustCompile(`^//\s*(go:build|\+build).*!mage`)
	for _, rel := range goFilesOutside(t, "\x00") {
		src, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.HasPrefix(line, "package ") {
				break // build constraints must precede the package clause
			}
			if negated.MatchString(line) {
				t.Errorf("%s:%d has a !mage build constraint (%s); `mage lint` runs a single pass with -tags mage, so this file would not be linted at all", rel, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// TestWorldRunsTheStaticAnalysisGates pins the wiring this package exists for.
// Vet, Lint and FmtCheck are useful only if something runs them; before they
// were part of World their findings accumulated between the occasions somebody
// ran them by hand. PrReview inherits all three through World.
func TestWorldRunsTheStaticAnalysisGates(t *testing.T) {
	file := parseMagefile(t)

	worldCalls := calleesOf(t, file, "World")
	// A gate whose error is discarded still runs and still prints its
	// findings, and World still succeeds - so calling it is not enough.
	worldDiscards := discardedCallsIn(t, file, "World")
	for _, gate := range []string{"FmtCheck", "Vet", "Lint"} {
		if !slices.Contains(worldCalls, gate) {
			t.Errorf("World() does not run %s(); that gate is unwired (World runs: %v)", gate, worldCalls)
			continue
		}
		if slices.Contains(worldDiscards, gate) {
			t.Errorf("World() discards the result of %s() with `_ =`; its findings are printed but no longer fail the build", gate)
		}
	}

	prCalls := calleesOf(t, file, "PrReview")
	if !slices.Contains(prCalls, "World") {
		t.Errorf("PrReview() does not run World(), so it no longer inherits the static-analysis gates (PrReview runs: %v)", prCalls)
	}
	if slices.Contains(discardedCallsIn(t, file, "PrReview"), "World") {
		t.Error("PrReview() discards the result of World(); the gates run but no longer fail it")
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

// TestLintTargetActuallyRunsTheLinter guards the half of the wiring World
// cannot see. World can call Lint() faithfully while Lint has been narrowed to
// a subset of packages, pointed at a different binary, told to exit 0
// regardless, or stubbed out entirely - and every one of those leaves `mage
// lint` printing a reassuring "0 issues".
func TestLintTargetActuallyRunsTheLinter(t *testing.T) {
	file := parseMagefile(t)

	if bin := constString(t, file, "golangciLintBin"); bin != "golangci-lint" {
		t.Errorf("golangciLintBin is %q, not \"golangci-lint\"; Lint runs something else", bin)
	}

	lits := stringLiteralsIn(t, file, "Lint")
	// "mage" is required because Lint runs a single pass carrying that build
	// tag, which is the only reason Magefile.go is inside its own gate.
	for _, want := range []string{"run", "./...", "--build-tags", "mage"} {
		if !slices.Contains(lits, want) {
			t.Errorf("Lint() passes no %q argument; it must run the linter over the whole module with the mage build tag (args seen: %v)", want, lits)
		}
	}
	// Flags that would make the linter report findings and still succeed.
	for _, banned := range []string{"--issues-exit-code", "--no-config", "-c", "--config"} {
		if slices.Contains(lits, banned) {
			t.Errorf("Lint() passes %q; the gate must fail the build on a finding and must use the repository's own .golangci.yml (args seen: %v)", banned, lits)
		}
	}

	callees := calleesOf(t, file, "Lint")
	if !slices.Contains(callees, "goEnv") {
		t.Errorf("Lint() does not use goEnv(); without the libbpfgo cgo environment every package that imports libbpfgo fails to typecheck and the linter reports a missing bpf/bpf.h instead of any real finding (calls: %v)", callees)
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

// section returns cfg[key] as a mapping, or nil when it is absent. yaml.v3
// decodes nested mappings into the named type, not a bare map[string]any, so
// the assertion has to name golangciConfig.
func (c golangciConfig) section(key string) golangciConfig {
	m, _ := c[key].(golangciConfig)
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

	linters := cfg.section("linters")
	settings := linters.section("settings")
	exclusions := linters.section("exclusions")
	assertOnlyKnownKeys(t, "linters", linters, "default", "enable", "settings", "exclusions")
	assertOnlyKnownKeys(t, "linters.settings", settings, "staticcheck")
	assertOnlyKnownKeys(t, "linters.exclusions", exclusions, "generated", "rules")
	assertOnlyKnownKeys(t, "issues", cfg.section("issues"), "max-issues-per-linter", "max-same-issues")
}

// TestLintConfigEnablesErrcheckAndStaticcheck fails if a linter is dropped from
// the enabled set, which would make `mage lint` pass while the findings it was
// added for come back.
func TestLintConfigEnablesErrcheckAndStaticcheck(t *testing.T) {
	linters := loadGolangciConfig(t).section("linters")
	enabled := mapStrings(linters, "enable")
	disabled := mapStrings(linters, "disable")
	for _, want := range []string{"errcheck", "staticcheck"} {
		if !slices.Contains(enabled, want) {
			t.Errorf("%s is not enabled in .golangci.yml (enabled: %v)", want, enabled)
		}
		// `disable` wins over `enable`, so naming a linter in both leaves it
		// listed as enabled and reporting nothing.
		if slices.Contains(disabled, want) {
			t.Errorf("%s appears in linters.disable, which overrides linters.enable; it reports nothing", want)
		}
	}
}

// TestStaticcheckKeepsItsCorrectnessChecks guards the settings side of the
// same question. Naming staticcheck under `enable` says nothing about which of
// its analyses run: `checks: [all, -SA*]` leaves it enabled and silent, which
// is indistinguishable from a passing gate.
func TestStaticcheckKeepsItsCorrectnessChecks(t *testing.T) {
	settings := loadGolangciConfig(t).section("linters").section("settings")
	if settings == nil {
		return // no settings block: golangci-lint's default check set applies
	}
	staticcheck := settings.section("staticcheck")
	if staticcheck == nil {
		return
	}
	checks := mapStrings(staticcheck, "checks")
	if len(checks) == 0 {
		return
	}
	if !slices.Contains(checks, "all") {
		t.Errorf("staticcheck.checks does not start from `all` (%v); the SA correctness checks may not be running", checks)
	}
	for _, check := range checks {
		// The SA family is the bug-finding half of staticcheck and the reason
		// it is in this gate at all. Disabling ST/QF/S is deliberate.
		if strings.HasPrefix(check, "-SA") {
			t.Errorf("staticcheck.checks disables %q; the SA correctness checks are the reason staticcheck is enabled (checks: %v)", check, checks)
		}
	}
}

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

	rules, _ := cfg.section("linters").section("exclusions")["rules"].([]any)
	stimulusExempt := map[string]bool{}
	for i, raw := range rules {
		rule, ok := raw.(golangciConfig)
		if !ok {
			t.Fatalf("exclusion rule %d is %T, want a mapping", i, raw)
		}
		linters, _ := rule["linters"].([]any)
		var names []string
		for _, l := range linters {
			names = append(names, fmt.Sprint(l))
		}
		if len(names) != 0 && !slices.Contains(names, "errcheck") {
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
		textRe, err := regexp.Compile(text)
		if err != nil {
			t.Fatalf("exclusion rule %d has an invalid text regex %q: %v", i, text, err)
		}
		for _, fn := range exempt {
			if textRe.MatchString(errcheckMessage(fn)) {
				stimulusExempt[fn] = true
			}
		}
		for _, fn := range notExempt {
			if textRe.MatchString(errcheckMessage(fn)) {
				t.Errorf("exclusion rule %d (text %q) also exempts %s in cmd/ioworkload; the exemption is for teardown calls, not for the syscalls a scenario exists to exercise", i, text, fn)
			}
		}
	}
	for _, fn := range exempt {
		if !stimulusExempt[fn] {
			t.Errorf("no errcheck exclusion covers %s in %s; either the stimulus-binary exclusion was removed (and `mage lint` now fails) or its regexes no longer match", fn, stimulus)
		}
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
	needle := regexp.MustCompile(`//[ \t]*` + "nolint")
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
