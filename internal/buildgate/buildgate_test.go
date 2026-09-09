package buildgate

import (
	"fmt"
	"go/ast"
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

// hasBlankDiscard reports whether fn throws away any call result with `_ =`.
// In a gate function that is always a bug: `_ = sh.RunWithV(...)` runs the
// tool, prints every finding, and returns nil.
func hasBlankDiscard(t *testing.T, file *ast.File, fn string) bool {
	t.Helper()
	found := false
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
		found = true
		return true
	})
	return found
}

// failsOn reports whether a failure of gate() makes fn stop. It looks for the
// `if err := gate(); err != nil { ... return ... }` shape: the gate called in
// an if-statement's init, and a return somewhere in the branch taken when it
// errored. A bare `return gate()` counts too.
//
// Checking for a return rather than for the absence of `_ =` is deliberate:
// logging the error and carrying on is the more natural way to make a gate
// advisory, it passes errcheck, and it leaves every other assertion here
// happy.
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
	hasReturn := func(n ast.Node) bool {
		found := false
		ast.Inspect(n, func(n ast.Node) bool {
			if _, ok := n.(*ast.ReturnStmt); ok {
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
			// return gate()
			for _, res := range stmt.Results {
				if callsGate(res) {
					fails = true
				}
			}
		case *ast.IfStmt:
			// if err := gate(); err != nil { ... return ... }
			if stmt.Init != nil && callsGate(stmt.Init) && hasReturn(stmt.Body) {
				fails = true
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
// only while nothing is excluded *by* that tag. A `!mage` constraint would
// drop a file out of the one pass that runs.
func TestNoNegatedMageConstraint(t *testing.T) {
	root := repoRoot(t)
	// `!(mage)` and `! mage` are both accepted by the toolchain and exclude
	// the file just as thoroughly as `!mage`, so match a negation followed by
	// anything but a word character before the tag.
	negated := regexp.MustCompile(`^//\s*(go:build|\+build).*![\s(]*mage\b`)
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
	for _, gate := range []string{"FmtCheck", "Vet", "Lint"} {
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
	// "config"/"verify" are the pre-flight that rejects a config golangci-lint
	// would otherwise silently half-ignore.
	for _, want := range []string{"config", "verify", "run", "./...", "--build-tags", "mage"} {
		if !slices.Contains(lits, want) {
			t.Errorf("Lint() passes no %q argument; it must verify the config and then run the linter over the whole module with the mage build tag (args seen: %v)", want, lits)
		}
	}
	// Deny-by-default, not a list of flags known to be bad. Blocklisting was
	// tried and lost by one character every time: --issues-exit-code was
	// banned and --issues-exit-code=0 walked past it, --config was banned and
	// --new-from-rev, --new, -D and --enable-only were never on the list at
	// all. Each of those makes the linter report findings and exit 0, or hides
	// findings outright, and every one of them has to be spelled somewhere in
	// this function to take effect.
	for _, lit := range lits {
		if !slices.Contains(allowedLintArgs, lit) {
			t.Errorf("Lint() passes an unreviewed argument %q. Flags here can make the linter exit 0 with findings (--issues-exit-code=0), limit what it looks at (--new-from-rev, --new), turn a linter off (-D, --enable-only) or point it at another config (--config=...). Review it, then add it to allowedLintArgs (args seen: %v).", lit, lits)
		}
	}

	callees := calleesOf(t, file, "Lint")
	if !slices.Contains(callees, "goEnv") {
		t.Errorf("Lint() does not use goEnv(); without the libbpfgo cgo environment every package that imports libbpfgo fails to typecheck and the linter reports a missing bpf/bpf.h instead of any real finding (calls: %v)", callees)
	}

	// A gate that runs its tool and drops the result reports every finding and
	// still exits 0. World checking Lint's error does not help if Lint never
	// produces one, so each gate has to be able to fail on its own.
	for _, gate := range []string{"Lint", "Vet", "FmtCheck"} {
		if !returnsAnError(t, file, gate) {
			t.Errorf("%s() has no return statement that can be non-nil; the gate runs its tool and succeeds whatever it reports", gate)
		}
		// Checking only for a non-nil return is not enough: Lint's config
		// pre-flight already supplies one, so `_ = sh.RunWithV(..., "run", ...)`
		// followed by `return nil` kept that assertion happy while the run
		// itself became advisory.
		if hasBlankDiscard(t, file, gate) {
			t.Errorf("%s() throws away a call result with `_ =`; a gate that discards what its tool returned reports findings and still succeeds", gate)
		}
	}
}

// allowedLintArgs is every string literal Lint may pass. Adding one is a
// deliberate act: see TestLintTargetActuallyRunsTheLinter for why this is an
// allow-list rather than a list of flags known to be dangerous.
var allowedLintArgs = []string{
	"config", "verify", // pre-flight: reject a config `run` would half-ignore
	"run",          // the gate itself
	"--build-tags", //
	"mage",         // so Magefile.go is inside its own gate
	"./...",        // the whole module
	// Diagnostics, not behaviour.
	"%s not on PATH; install it with `go install %s`",
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
	assertOnlyKnownKeys(t, "issues", cfg.section(t, "issues"), "max-issues-per-linter", "max-same-issues")
}

// TestLintConfigEnablesErrcheckAndStaticcheck fails if a linter is dropped from
// the enabled set, which would make `mage lint` pass while the findings it was
// added for come back.
func TestLintConfigEnablesErrcheckAndStaticcheck(t *testing.T) {
	linters := loadGolangciConfig(t).section(t, "linters")
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
	settings := loadGolangciConfig(t).section(t, "linters").section(t, "settings")
	if settings == nil {
		return // no settings block: golangci-lint's default check set applies
	}
	staticcheck := settings.section(t, "staticcheck")
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
	// Deny-by-default again: `-SA*` was the only spelling rejected, and `-*`
	// walked straight past it while disabling the SA family just as
	// thoroughly. Only the three reviewed style-family negations are allowed.
	reviewedNegations := []string{"-ST*", "-QF*", "-S1*"}
	for _, check := range checks {
		if !strings.HasPrefix(check, "-") {
			continue
		}
		if !slices.Contains(reviewedNegations, check) {
			t.Errorf("staticcheck.checks disables %q, which is not one of the reviewed style-family negations %v. The SA correctness checks are the reason staticcheck is in this gate (checks: %v)", check, reviewedNegations, checks)
		}
	}
}

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
