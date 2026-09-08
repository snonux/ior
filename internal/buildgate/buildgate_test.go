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

// calleesOf returns the names of the functions the top-level function fn calls
// directly. Arguments to mg.Deps are counted as callees too: `mg.Deps(Vet)` is
// how Mage declares a dependency and runs it, and is interchangeable with a
// plain `Vet()` call for the purposes of these tests.
func calleesOf(t *testing.T, file *ast.File, fn string) []string {
	t.Helper()
	var decl *ast.FuncDecl
	for _, d := range file.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if ok && fd.Recv == nil && fd.Name.Name == fn {
			decl = fd
			break
		}
	}
	if decl == nil {
		t.Fatalf("Magefile.go declares no top-level func %s", fn)
	}
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

// TestWorldRunsTheStaticAnalysisGates pins the wiring this package exists for.
// Vet, Lint and FmtCheck are useful only if something runs them; before they
// were part of World their findings accumulated between the occasions somebody
// ran them by hand. PrReview inherits all three through World.
func TestWorldRunsTheStaticAnalysisGates(t *testing.T) {
	fset := token.NewFileSet()
	// Magefile.go is behind `//go:build mage`, so it is parsed directly rather
	// than through the package loader, which would exclude it.
	file, err := parser.ParseFile(fset, filepath.Join(repoRoot(t), "Magefile.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse Magefile.go: %v", err)
	}

	worldCalls := calleesOf(t, file, "World")
	for _, gate := range []string{"Vet", "Lint", "FmtCheck"} {
		if !slices.Contains(worldCalls, gate) {
			t.Errorf("World() does not run %s(); that gate is unwired (World runs: %v)", gate, worldCalls)
		}
	}

	if prCalls := calleesOf(t, file, "PrReview"); !slices.Contains(prCalls, "World") {
		t.Errorf("PrReview() does not run World(), so it no longer inherits the static-analysis gates (PrReview runs: %v)", prCalls)
	}
}

// TestLintTargetLintsTheWholeModule guards the other half of the wiring: World
// can call Lint faithfully while Lint itself has been narrowed to a subset of
// packages, or stubbed out entirely.
func TestLintTargetLintsTheWholeModule(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "Magefile.go"))
	if err != nil {
		t.Fatalf("read Magefile.go: %v", err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "Magefile.go", src, 0)
	if err != nil {
		t.Fatalf("parse Magefile.go: %v", err)
	}
	var body string
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "Lint" {
			body = string(src[fset.Position(fd.Pos()).Offset:fset.Position(fd.End()).Offset])
		}
	}
	if body == "" {
		t.Fatal("Magefile.go declares no top-level func Lint")
	}
	for _, want := range []string{`"run"`, `"./..."`, "goEnv()"} {
		if !strings.Contains(body, want) {
			t.Errorf("Lint() no longer contains %s; it must run the linter over the whole module with the libbpfgo cgo environment:\n%s", want, body)
		}
	}
}

// golangciConfig models .golangci.yml loosely on purpose. The exclusion and
// settings sections are kept as raw maps so an unrecognized key is visible to
// the tests below instead of being silently dropped by the decoder: every way
// this gate has been found to be defeatable was a *different* key from the one
// the tests were watching.
type golangciConfig struct {
	Linters struct {
		Default    string         `yaml:"default"`
		Enable     []string       `yaml:"enable"`
		Settings   map[string]any `yaml:"settings"`
		Exclusions map[string]any `yaml:"exclusions"`
	} `yaml:"linters"`
	Issues map[string]any `yaml:"issues"`
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

// TestLintConfigEnablesErrcheckAndStaticcheck fails if a linter is dropped from
// the enabled set, which would make `mage lint` pass while the findings it was
// added for come back.
func TestLintConfigEnablesErrcheckAndStaticcheck(t *testing.T) {
	cfg := loadGolangciConfig(t)
	for _, want := range []string{"errcheck", "staticcheck"} {
		if !slices.Contains(cfg.Linters.Enable, want) {
			t.Errorf("%s is not enabled in .golangci.yml (enabled: %v)", want, cfg.Linters.Enable)
		}
	}
}

// TestStaticcheckKeepsItsCorrectnessChecks guards the settings side of the
// same question. Naming staticcheck under `enable` says nothing about which of
// its analyses run: `checks: [all, -SA*]` leaves it enabled and silent, which
// is indistinguishable from a passing gate.
func TestStaticcheckKeepsItsCorrectnessChecks(t *testing.T) {
	cfg := loadGolangciConfig(t)
	settings, ok := cfg.Linters.Settings["staticcheck"].(map[string]any)
	if !ok {
		return // no settings block: golangci-lint's default check set applies
	}
	raw, ok := settings["checks"]
	if !ok {
		return
	}
	items, ok := raw.([]any)
	if !ok {
		t.Fatalf("staticcheck.checks is %T, want a list", raw)
	}
	var checks []string
	for _, item := range items {
		checks = append(checks, fmt.Sprint(item))
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

	// Only these exclusion keys have been reviewed. `paths` and `presets` in
	// particular can silence errcheck across the whole tree without touching
	// `rules`, so a new key fails here rather than passing unnoticed.
	const reviewedKeys = "generated, rules"
	for key := range cfg.Linters.Exclusions {
		if key != "generated" && key != "rules" {
			t.Errorf("unreviewed linters.exclusions key %q in .golangci.yml; only %s have been reviewed, and keys like `paths`/`presets` can silence errcheck tree-wide. Review it, then add it here.", key, reviewedKeys)
		}
	}
	// The same applies to per-linter settings: errcheck.exclude-functions
	// exempts a function everywhere, and disable-default-exclusions changes
	// the baseline in the other direction.
	for key := range cfg.Linters.Settings {
		if key != "staticcheck" {
			t.Errorf("unreviewed linters.settings key %q in .golangci.yml; an errcheck settings block can exempt functions module-wide. Review it, then add it here.", key)
		}
	}

	// Paths that must never be exempt from errcheck.
	protected := []string{
		"internal/ior.go",
		"internal/eventloop.go",
		"internal/ior_bpfsetup.go",
		"internal/probemanager/manager.go",
		"internal/tui/dashboard/model.go",
		"cmd/ior/main.go",
		"cmd/filewriter/main.go",
		"audit/check/flameroundtrip/main.go",
		"integrationtests/harness.go",
	}
	// A path inside the stimulus binary, to prove the rule is not vacuous: if
	// no rule matches it, the exclusion has been removed or misspelled and the
	// assertions above would pass for the wrong reason.
	const stimulus = "cmd/ioworkload/scenario_dup.go"
	// Teardown calls the exemption is for, and calls it must not cover. An
	// ioworkload scenario that drops the error of the syscall it exists to
	// exercise is still a bug.
	exempt := []string{"syscall.Close", "syscall.Munmap", "syscall.Chdir", "os.RemoveAll"}
	notExempt := []string{"os.Chmod", "syscall.Unlink", "unix.Getrandom", "f.Write"}

	rules, _ := cfg.Linters.Exclusions["rules"].([]any)
	stimulusExempt := map[string]bool{}
	for i, raw := range rules {
		rule, ok := raw.(map[string]any)
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
	needle := "//" + "nolint"
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
			if strings.Contains(line, needle) {
				t.Errorf("%s:%d has a %s directive: %s\nUse an explicit `_ =` for a deliberate discard, or add the case to .golangci.yml where the exemption is stated once with its reasoning (AGENTS.md, Code Style).", rel, i+1, needle, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}
