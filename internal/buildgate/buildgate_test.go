package buildgate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// repoRoot returns the repository root, resolved from this test's own
// location so the test does not depend on the working directory `go test`
// happens to use.
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

// calleesOf returns the names of every function called directly in the body of
// the top-level function fn in the parsed file.
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
		if ident, ok := call.Fun.(*ast.Ident); ok {
			callees = append(callees, ident.Name)
		}
		return true
	})
	return callees
}

// TestWorldRunsTheStaticAnalysisGates pins the wiring this package exists for.
// Vet and Lint are useful only if something runs them; before they were part
// of World their findings accumulated between the occasions somebody ran them
// by hand. PrReview inherits both through World, which the second half checks.
func TestWorldRunsTheStaticAnalysisGates(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	// Magefile.go is behind `//go:build mage`, so it is parsed directly rather
	// than through the package loader, which would exclude it.
	file, err := parser.ParseFile(fset, filepath.Join(root, "Magefile.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse Magefile.go: %v", err)
	}

	worldCalls := calleesOf(t, file, "World")
	for _, gate := range []string{"Vet", "Lint"} {
		if !slices.Contains(worldCalls, gate) {
			t.Errorf("World() does not call %s(); the static-analysis gate is unwired (World calls: %v)", gate, worldCalls)
		}
	}

	if prCalls := calleesOf(t, file, "PrReview"); !slices.Contains(prCalls, "World") {
		t.Errorf("PrReview() does not call World(), so it no longer inherits the vet/lint gates (PrReview calls: %v)", prCalls)
	}
}

// golangciConfig is the subset of .golangci.yml this test asserts on.
type golangciConfig struct {
	Linters struct {
		Enable     []string `yaml:"enable"`
		Exclusions struct {
			Rules []struct {
				Path    string   `yaml:"path"`
				Linters []string `yaml:"linters"`
				Text    string   `yaml:"text"`
			} `yaml:"rules"`
		} `yaml:"exclusions"`
	} `yaml:"linters"`
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

// TestLintConfigEnablesErrcheck fails if errcheck is dropped from the enabled
// set, which would make `mage lint` pass while the findings it was added for
// come back.
func TestLintConfigEnablesErrcheck(t *testing.T) {
	cfg := loadGolangciConfig(t)
	for _, want := range []string{"errcheck", "staticcheck"} {
		if !slices.Contains(cfg.Linters.Enable, want) {
			t.Errorf("%s is not enabled in .golangci.yml (enabled: %v)", want, cfg.Linters.Enable)
		}
	}
}

// TestErrcheckExclusionsStayScopedToTheStimulusBinary is the negative test for
// the one exclusion in .golangci.yml. Unchecked errors are tolerated in
// cmd/ioworkload because that binary exists to emit syscalls, not to handle
// their teardown errors. Nothing else may claim that exemption: an exclusion
// that also matched internal/ or cmd/ior would silently reopen the gap in the
// code the tracer is actually made of, and `mage lint` would still report
// "0 issues".
func TestErrcheckExclusionsStayScopedToTheStimulusBinary(t *testing.T) {
	cfg := loadGolangciConfig(t)

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
	// A path inside the stimulus binary, to prove the rule is not vacuous:
	// if no rule matches it, the exclusion has been removed or misspelled and
	// the assertions above would pass for the wrong reason.
	const stimulus = "cmd/ioworkload/scenario_dup.go"

	stimulusExempt := false
	for i, rule := range cfg.Linters.Exclusions.Rules {
		if len(rule.Linters) != 0 && !slices.Contains(rule.Linters, "errcheck") {
			continue
		}
		if rule.Path == "" {
			t.Errorf("exclusion rule %d disables errcheck with no path scope at all", i)
			continue
		}
		re, err := regexp.Compile(rule.Path)
		if err != nil {
			t.Fatalf("exclusion rule %d has an invalid path regex %q: %v", i, rule.Path, err)
		}
		for _, p := range protected {
			if re.MatchString(p) {
				t.Errorf("exclusion rule %d (path %q) exempts %s from errcheck; only cmd/ioworkload may be exempt", i, rule.Path, p)
			}
		}
		if re.MatchString(stimulus) {
			stimulusExempt = true
		}
	}
	if !stimulusExempt {
		t.Errorf("no errcheck exclusion matches %s; either the stimulus-binary exclusion was removed (and `mage lint` now fails) or its path regex no longer matches", stimulus)
	}
}
