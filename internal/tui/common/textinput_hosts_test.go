package common

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const textinputImportPath = "charm.land/bubbles/v2/textinput"

// directTextInputUpdateAllowed lists the files (relative to internal/tui)
// that may call a textinput's Update directly. Only UpdateTextInput itself
// does; every host goes through it (task kz2). An entry the scan never hits
// fails the test too, which keeps the list honest and proves the scan still
// finds direct calls.
var directTextInputUpdateAllowed = map[string]bool{
	"common/textinput.go": true,
}

// TestTextInputHostsUseUpdateTextInput fails when a non-test file under
// internal/tui calls Update on a bubbles textinput.Model directly instead of
// through UpdateTextInput, which would bring back the Alt+D panic of task
// kz2 for that input.
//
// The scan is syntactic, not type-checked: per package directory it collects
// the names declared with type textinput.Model (struct fields, variables,
// parameters) or assigned from textinput.New(), then flags every x.Update(...)
// call whose receiver is one of those names (ti.Update, m.input.Update). It
// misses an input reached under another name (a method value, an embedded
// field, a getter); such code should not exist, and a name shared with some
// other type's Update only causes a false alarm that the helper fixes too.
func TestTextInputHostsUseUpdateTextInput(t *testing.T) {
	pkgs := parseTUIPackages(t, "..")
	hits := map[string]bool{}
	var offenders []string
	for _, files := range pkgs {
		names := textInputNames(files)
		for _, f := range files {
			for _, line := range directUpdateCalls(f, names) {
				if directTextInputUpdateAllowed[f.rel] {
					hits[f.rel] = true
					continue
				}
				offenders = append(offenders, f.rel+":"+strconv.Itoa(line))
			}
		}
	}
	sort.Strings(offenders)
	for _, o := range offenders {
		t.Errorf("%s calls textinput Update directly; use common.UpdateTextInput", o)
	}
	for rel := range directTextInputUpdateAllowed {
		if !hits[rel] {
			t.Errorf("allow-listed %s has no direct textinput Update call: "+
				"drop it from the list, or the scan no longer works", rel)
		}
	}
}

// tuiFile is one parsed non-test Go file, its path relative to the root and
// the file set its positions belong to.
type tuiFile struct {
	rel  string
	ast  *ast.File
	fset *token.FileSet
}

// parseTUIPackages parses every non-test .go file under root and groups the
// files by directory (one package each).
func parseTUIPackages(t *testing.T, root string) map[string][]tuiFile {
	t.Helper()
	fset := token.NewFileSet()
	pkgs := map[string][]tuiFile{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		dir := filepath.Dir(rel)
		pkgs[dir] = append(pkgs[dir], tuiFile{rel: filepath.ToSlash(rel), ast: f, fset: fset})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return pkgs
}

// textinputImportName is the name file f refers to the textinput package by,
// or "" when f does not import it.
func textinputImportName(f *ast.File) string {
	for _, imp := range f.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p == textinputImportPath {
			if imp.Name != nil {
				return imp.Name.Name
			}
			return "textinput"
		}
	}
	return ""
}

// textInputNames collects, over all files of one package, the identifiers
// declared as textinput.Model or assigned from textinput.New().
func textInputNames(files []tuiFile) map[string]bool {
	names := map[string]bool{}
	for _, f := range files {
		pkg := textinputImportName(f.ast)
		if pkg == "" {
			continue
		}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.Field:
				addIdentsIf(names, n.Names, isPkgSelector(n.Type, pkg, "Model"))
			case *ast.ValueSpec:
				addIdentsIf(names, n.Names, isPkgSelector(n.Type, pkg, "Model") || callsNew(n.Values, pkg))
			case *ast.AssignStmt:
				for i, rhs := range n.Rhs {
					if i >= len(n.Lhs) {
						break
					}
					if id, ok := n.Lhs[i].(*ast.Ident); ok && callsNew([]ast.Expr{rhs}, pkg) {
						names[id.Name] = true
					}
				}
			}
			return true
		})
	}
	return names
}

func addIdentsIf(names map[string]bool, idents []*ast.Ident, ok bool) {
	if !ok {
		return
	}
	for _, id := range idents {
		names[id.Name] = true
	}
}

// isPkgSelector reports whether e is pkg.sel.
func isPkgSelector(e ast.Expr, pkg, sel string) bool {
	s, ok := e.(*ast.SelectorExpr)
	if !ok || s.Sel.Name != sel {
		return false
	}
	id, ok := s.X.(*ast.Ident)
	return ok && id.Name == pkg
}

// callsNew reports whether any of values is a call of pkg.New.
func callsNew(values []ast.Expr, pkg string) bool {
	for _, v := range values {
		if call, ok := v.(*ast.CallExpr); ok && isPkgSelector(call.Fun, pkg, "New") {
			return true
		}
	}
	return false
}

// directUpdateCalls returns the lines of f that call Update on a receiver
// named in names (x.Update or y.x.Update with x in names).
func directUpdateCalls(f tuiFile, names map[string]bool) []int {
	var lines []int
	ast.Inspect(f.ast, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fun, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || fun.Sel.Name != "Update" {
			return true
		}
		if recv := receiverName(fun.X); recv != "" && names[recv] {
			lines = append(lines, f.fset.Position(call.Pos()).Line)
		}
		return true
	})
	return lines
}

// receiverName is the last identifier of a receiver expression: "ti" for ti,
// "input" for m.input.
func receiverName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}
