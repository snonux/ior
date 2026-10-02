package internal

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

// These tests drive libbpfLink without a kernel: destroyBPFLink is replaced,
// and the BPFLink is one no attach made. What libbpfgo and libbpf really do
// with a link whose Destroy fails is in ior_bpflink_root_test.go.

// errDetachFailed is what the stubbed destroy of these tests reports.
var errDetachFailed = errors.New("perf event disable failed")

// stubDestroyBPFLink replaces destroyBPFLink for the test with a destroy that
// returns err, and returns the number of calls it got.
func stubDestroyBPFLink(t *testing.T, err error) *atomic.Int32 {
	t.Helper()
	calls := &atomic.Int32{}
	orig := destroyBPFLink
	destroyBPFLink = func(*bpf.BPFLink) error {
		calls.Add(1)
		return err
	}
	t.Cleanup(func() { destroyBPFLink = orig })
	return calls
}

// markedBPFLink returns a BPFLink that differs from the zero value, so a test
// can see whether Destroy zeroed it. No attach made it and its C pointer is
// nil; the mark is the private eventName, set through its address because a
// BPFLink has no exported field and no constructor.
func markedBPFLink(t *testing.T) *bpf.BPFLink {
	t.Helper()
	link := &bpf.BPFLink{}
	field := reflect.ValueOf(link).Elem().FieldByName("eventName")
	if !field.IsValid() || field.Kind() != reflect.String {
		t.Fatal("bpf.BPFLink has no string field eventName any more: mark another field")
	}
	*(*string)(unsafe.Pointer(field.UnsafeAddr())) = "marked"
	if *link == (bpf.BPFLink{}) {
		t.Fatal("the marked BPFLink still equals the zero value")
	}
	return link
}

// A Destroy that reports an error is the case libbpfLink exists for: the error
// is passed on and the BPFLink is zeroed, which is what clears the pointer
// libbpfgo's Module.Close looks at.
func TestLibbpfLinkZeroesTheLinkAndPassesTheErrorOnWhenDestroyFailed(t *testing.T) {
	calls := stubDestroyBPFLink(t, errDetachFailed)
	inner := markedBPFLink(t)
	link, err := newLibbpfLink(inner, nil)
	if err != nil {
		t.Fatalf("newLibbpfLink() = %v", err)
	}

	if err := link.Destroy(); !errors.Is(err, errDetachFailed) {
		t.Fatalf("Destroy() = %v, want %v", err, errDetachFailed)
	}
	if *inner != (bpf.BPFLink{}) {
		t.Fatalf("the BPFLink was not zeroed after a failed Destroy: %+v", *inner)
	}
	if err := link.Destroy(); err != nil {
		t.Fatalf("second Destroy() = %v, want nil", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("libbpfgo's Destroy was called %d times, want once", got)
	}
}

// A Destroy that succeeded needs no help: libbpfgo cleared its pointer, and
// the wrapper leaves the struct as libbpfgo left it.
func TestLibbpfLinkLeavesTheLinkAloneWhenDestroySucceeded(t *testing.T) {
	calls := stubDestroyBPFLink(t, nil)
	inner := markedBPFLink(t)
	before := *inner
	link, err := newLibbpfLink(inner, nil)
	if err != nil {
		t.Fatalf("newLibbpfLink() = %v", err)
	}

	for i := range 2 {
		if err := link.Destroy(); err != nil {
			t.Fatalf("Destroy() number %d = %v, want nil", i+1, err)
		}
	}
	if *inner != before {
		t.Fatalf("the BPFLink changed although Destroy succeeded: %+v", *inner)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("libbpfgo's Destroy was called %d times, want once", got)
	}
}

// Destroy reaches libbpfgo once however many goroutines call it. The probe
// manager and the hand probes' release closures promise one call already; the
// wrapper does not depend on it. Run under -race it also shows that the swap
// is the only shared state.
func TestLibbpfLinkDestroysOnceUnderConcurrentCalls(t *testing.T) {
	calls := stubDestroyBPFLink(t, errDetachFailed)
	link, err := newLibbpfLink(markedBPFLink(t), nil)
	if err != nil {
		t.Fatalf("newLibbpfLink() = %v", err)
	}

	var failed atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if link.Destroy() != nil {
				failed.Add(1)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 || failed.Load() != 1 {
		t.Fatalf("libbpfgo's Destroy was called %d times and %d callers got its error, want one each",
			calls.Load(), failed.Load())
	}
}

// A nil wrapper and one without a link have nothing to destroy and must not
// hand libbpfgo a nil link.
func TestLibbpfLinkDestroyWithoutALinkDoesNothing(t *testing.T) {
	calls := stubDestroyBPFLink(t, errDetachFailed)
	var none *libbpfLink
	if err := none.Destroy(); err != nil {
		t.Fatalf("Destroy() on a nil wrapper = %v, want nil", err)
	}
	if err := (&libbpfLink{}).Destroy(); err != nil {
		t.Fatalf("Destroy() on an empty wrapper = %v, want nil", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("libbpfgo's Destroy was called %d times, want never", got)
	}
}

// A failed attach hands out no link at all. The interface must be an untyped
// nil: libbpfgo returns a nil *bpf.BPFLink with the error, and a wrapper
// around it would be a link whose Destroy quietly does nothing.
func TestNewLibbpfLinkHandsOutNoLinkWithoutOne(t *testing.T) {
	attachFailed := errors.New("no such tracepoint")
	for _, tc := range []struct {
		name  string
		inner *bpf.BPFLink
		err   error
		want  error
	}{
		{"a failed attach", nil, attachFailed, attachFailed},
		{"a link together with an error", &bpf.BPFLink{}, attachFailed, attachFailed},
		{"neither a link nor an error", nil, nil, errNoLibbpfLink},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link, err := newLibbpfLink(tc.inner, tc.err)
			if link != nil {
				t.Fatalf("newLibbpfLink() link = %#v, want an untyped nil", link)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("newLibbpfLink() error = %v, want %v", err, tc.want)
			}
		})
	}
}

// The unstubbed destroy is libbpfgo's. A BPFLink no attach made has a nil C
// pointer, which bpf_link__destroy accepts (it returns 0 for NULL), so this
// much of the real call needs neither root nor a kernel with BPF.
func TestLibbpfLinkDestroysThroughLibbpfgo(t *testing.T) {
	if got, want := reflect.ValueOf(destroyBPFLink).Pointer(), reflect.ValueOf((*bpf.BPFLink).Destroy).Pointer(); got != want {
		t.Fatal("destroyBPFLink is not libbpfgo's BPFLink.Destroy")
	}
	link, err := newLibbpfLink(&bpf.BPFLink{}, nil)
	if err != nil {
		t.Fatalf("newLibbpfLink() = %v", err)
	}
	if err := link.Destroy(); err != nil {
		t.Fatalf("Destroy() of a link without a C pointer = %v, want nil", err)
	}
}

// libbpfTracepointProgram is the one place ior attaches through libbpfgo, and
// every link it returns has to be a libbpfLink. Its methods are therefore
// pinned to the one-line form `return newLibbpfLink(p.prog.Attach...(...))`:
// a method that returned the *bpf.BPFLink itself would compile (it has a
// Destroy) and bring the double destroy back. The root tests check the same
// on real links; this one runs unprivileged.
func TestLibbpfTracepointProgramHandsOutOnlyWrappedLinks(t *testing.T) {
	parsed := parseRepoFile(t, filepath.Join(repoRoot(t), "internal", "ior_bpfsetup.go"))
	methods := 0
	for _, declaration := range parsed.Decls {
		decl, ok := declaration.(*ast.FuncDecl)
		if !ok || receiverTypeName(decl) != "libbpfTracepointProgram" {
			continue
		}
		methods++
		if !returnsOnlyAWrappedAttach(decl) {
			t.Errorf("libbpfTracepointProgram.%s is not `return newLibbpfLink(p.prog.Attach...(...))`", decl.Name.Name)
		}
	}
	// AttachTracepoint and AttachRawTracepoint: fewer means the scan lost them.
	if methods < 2 {
		t.Fatalf("found %d methods of libbpfTracepointProgram, want at least 2", methods)
	}
}

// receiverTypeName returns the name of decl's receiver type, without a
// pointer star, or "" for a function.
func receiverTypeName(decl *ast.FuncDecl) string {
	if decl.Recv == nil || len(decl.Recv.List) != 1 {
		return ""
	}
	expr := decl.Recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// returnsOnlyAWrappedAttach reports whether decl's body is the single
// statement `return newLibbpfLink(<x>.prog.Attach<...>(...))`.
func returnsOnlyAWrappedAttach(decl *ast.FuncDecl) bool {
	if decl.Body == nil || len(decl.Body.List) != 1 {
		return false
	}
	ret, ok := decl.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	wrap, ok := ret.Results[0].(*ast.CallExpr)
	if !ok || !isIdentifier(wrap.Fun, "newLibbpfLink") || len(wrap.Args) != 1 {
		return false
	}
	attach, ok := wrap.Args[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	method, ok := attach.Fun.(*ast.SelectorExpr)
	if !ok || !strings.HasPrefix(method.Sel.Name, "Attach") {
		return false
	}
	field, ok := method.X.(*ast.SelectorExpr)
	return ok && field.Sel.Name == "prog"
}

// moduleWideLinkCalls are the two libbpfgo Module methods ior must not call
// once it zeroes a link whose Destroy failed (libbpfLink): AttachPrograms
// walks the module's links through linkExist, which dereferences the nil prog
// of a zeroed link (module.go, lines 460-468), and DetachPrograms (lines
// 499-520) destroys every link of the module itself, behind the back of the
// wrappers that own them: a link whose Destroy failed there keeps its pointer
// and is destroyed again by its wrapper.
var moduleWideLinkCalls = []string{"AttachPrograms", "DetachPrograms"}

// TestIorNeverCallsTheModuleWideAttachOrDetach scans every Go file of the
// repository, tests included, for a selector with one of those names. It goes
// by name, not by type, so a method of that name on any other type trips it
// too: rename that method, or narrow this test.
func TestIorNeverCallsTheModuleWideAttachOrDetach(t *testing.T) {
	root := repoRoot(t)
	files := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && path != root && strings.HasPrefix(entry.Name(), ".") {
			return filepath.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		files++
		for _, found := range selectorsNamed(parseRepoFile(t, path), moduleWideLinkCalls...) {
			t.Errorf("%s uses %s: libbpfgo's module-wide attach and detach are not safe with ior's links (libbpfLink)", path, found)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	// This package alone has far more files; fewer means the walk went wrong.
	if files < 100 {
		t.Fatalf("scanned %d Go files under %s, want the whole repository", files, root)
	}
}

// The scan above is only worth something if it finds such a call.
func TestSelectorsNamedFindsAModuleWideCall(t *testing.T) {
	src := `package p
// AttachPrograms in a comment and "DetachPrograms" in a string are not calls.
func f(m module) { _ = "DetachPrograms"; m.inner.AttachPrograms(); g(m.DetachPrograms) }`
	parsed, err := parser.ParseFile(token.NewFileSet(), "p.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := selectorsNamed(parsed, moduleWideLinkCalls...)
	if want := []string{"AttachPrograms", "DetachPrograms"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selectorsNamed() = %q, want %q", got, want)
	}
}

// selectorsNamed returns the selected names (the x.NAME of a selector
// expression) in file that are one of names, in source order.
func selectorsNamed(file *ast.File, names ...string) []string {
	var found []string
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		for _, name := range names {
			if selector.Sel.Name == name {
				found = append(found, name)
			}
		}
		return true
	})
	return found
}

// repoRoot returns the repository root, the parent of this package's
// directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate this test file")
	}
	return filepath.Dir(filepath.Dir(thisFile))
}

// parseRepoFile parses the Go file at path.
func parseRepoFile(t *testing.T, path string) *ast.File {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return parsed
}
