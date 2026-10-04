package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
)

const textinputImportPath = "charm.land/bubbles/v2/textinput"

// directTextInputUpdateAllowed lists the files (relative to internal/tui)
// that may use a textinput's Update method directly. Only UpdateTextInput
// itself does; every host goes through it (task kz2). An entry the scan
// never hits fails the test too, which keeps the list honest and proves the
// scan still finds direct uses.
var directTextInputUpdateAllowed = map[string]bool{
	"common/textinput.go": true,
}

// TestTextInputHostsUseUpdateTextInput fails when a non-test file under
// internal/tui uses the Update method of a bubbles textinput.Model directly
// instead of going through UpdateTextInput, which would bring back the Alt+D
// panic of task kz2 for that input.
//
// The scan is type-checked: every package under internal/tui is type-checked
// from source (its imports come from the export data `go list -export`
// leaves in the build cache), and every identifier the type checker resolves
// to textinput.Model's Update method is flagged. That covers any expression
// of type textinput.Model or *textinput.Model, however it is reached: fields,
// pointer fields, parameters, locals and copies, slice/map elements, getter
// results, embedded (promoted) fields, method values (f := ti.Update) and
// method expressions (textinput.Model.Update). The only way past it is
// dynamic dispatch: calling Update through an interface value that holds a
// textinput.Model, or through reflection; such code should not exist.
func TestTextInputHostsUseUpdateTextInput(t *testing.T) {
	hits := map[string]bool{}
	var offenders []string
	for _, use := range directTextInputUpdateUses(t, "..") {
		if directTextInputUpdateAllowed[use.rel] {
			hits[use.rel] = true
			continue
		}
		offenders = append(offenders, use.rel+":"+strconv.Itoa(use.line))
	}
	sort.Strings(offenders)
	for _, o := range offenders {
		t.Errorf("%s uses textinput Update directly; use common.UpdateTextInput", o)
	}
	for rel := range directTextInputUpdateAllowed {
		if !hits[rel] {
			t.Errorf("allow-listed %s has no direct textinput Update use: "+
				"drop it from the list, or the scan no longer works", rel)
		}
	}
}

// listedPackage is the part of `go list -json` output the scan needs.
type listedPackage struct {
	ImportPath string
	Dir        string
	Export     string
	GoFiles    []string
	CgoFiles   []string
	DepOnly    bool
}

// updateUse is one direct use of textinput.Model.Update: the file relative
// to the internal/tui root and the line.
type updateUse struct {
	rel  string
	line int
}

// directTextInputUpdateUses type-checks every package under root (the
// internal/tui directory) and returns each use of textinput.Model's Update
// method in their non-test files.
func directTextInputUpdateUses(t *testing.T, root string) []updateUse {
	t.Helper()
	absRoot, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	pkgs := goListExport(t, absRoot)
	exports := map[string]string{}
	for _, p := range pkgs {
		exports[p.ImportPath] = p.Export
	}
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		if exports[path] == "" {
			return nil, errors.New("no export data for " + path)
		}
		return os.Open(exports[path])
	})
	var uses []updateUse
	for _, p := range pkgs {
		if p.DepOnly {
			continue
		}
		if len(p.CgoFiles) > 0 {
			// Not type-checkable from the plain files; none exist today.
			t.Fatalf("%s has cgo files; teach the scan to handle them", p.ImportPath)
		}
		uses = append(uses, packageUpdateUses(t, fset, imp, absRoot, p)...)
	}
	return uses
}

// goListExport runs `go list -export -deps -json` on every package under
// absRoot, which builds them (cached) and reports their export data files.
func goListExport(t *testing.T, absRoot string) []listedPackage {
	t.Helper()
	cmd := exec.Command("go", "list", "-export", "-deps",
		"-json=ImportPath,Dir,Export,GoFiles,CgoFiles,DepOnly", "./...")
	cmd.Dir = absRoot
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}
	var pkgs []listedPackage
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var p listedPackage
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// packageUpdateUses parses and type-checks the non-test files of p and
// returns the uses of textinput.Model's Update method in them.
func packageUpdateUses(t *testing.T, fset *token.FileSet, imp types.Importer, absRoot string, p listedPackage) []updateUse {
	t.Helper()
	files := make([]*ast.File, 0, len(p.GoFiles))
	for _, name := range p.GoFiles {
		f, err := parser.ParseFile(fset, filepath.Join(p.Dir, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}}
	conf := types.Config{Importer: imp}
	if _, err := conf.Check(p.ImportPath, fset, files, info); err != nil {
		t.Fatalf("type-check %s: %v", p.ImportPath, err)
	}
	var uses []updateUse
	for id, obj := range info.Uses {
		if !isTextInputUpdate(obj) {
			continue
		}
		pos := fset.Position(id.Pos())
		rel, err := filepath.Rel(absRoot, pos.Filename)
		if err != nil {
			t.Fatal(err)
		}
		uses = append(uses, updateUse{rel: filepath.ToSlash(rel), line: pos.Line})
	}
	return uses
}

// isTextInputUpdate reports whether obj is the Update method of
// textinput.Model (whichever receiver form bubbles declares it with).
func isTextInputUpdate(obj types.Object) bool {
	fn, ok := obj.(*types.Func)
	if !ok || fn.Name() != "Update" || fn.Pkg() == nil || fn.Pkg().Path() != textinputImportPath {
		return false
	}
	recv := fn.Signature().Recv()
	if recv == nil {
		return false
	}
	rt := recv.Type()
	if ptr, ok := rt.(*types.Pointer); ok {
		rt = ptr.Elem()
	}
	named, ok := rt.(*types.Named)
	return ok && named.Obj().Name() == "Model"
}
