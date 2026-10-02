package internal

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"ior/internal/probemanager"

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
// every link it returns has to be a libbpfLink attached under libbpfAttachMu.
// Its two methods are therefore pinned to the one-line
// form `return attachLibbpf...(p.prog, ...)`, and the attach functions behind
// them to a single return, `return newLibbpfLink(attachBPF...(...))`: a
// method that returned the *bpf.BPFLink itself would compile (it has a
// Destroy) and bring the double destroy back. The root tests check the same
// on real links; this one runs unprivileged. That nothing attaches beside
// these four functions is TestOnlyTheLibbpfSeamUsesLibbpfgoProgramsAndLinks.
func TestLibbpfTracepointProgramHandsOutOnlyWrappedLinks(t *testing.T) {
	root := repoRoot(t)
	methods := 0
	for _, decl := range funcDecls(parseRepoFile(t, filepath.Join(root, "internal", "ior_bpfsetup.go"))) {
		if receiverTypeName(decl) != "libbpfTracepointProgram" {
			continue
		}
		methods++
		if call := onlyReturnedCall(decl); call == nil || !callsIdentWithPrefix(call, "attachLibbpf") || !passesProgField(call) {
			t.Errorf("libbpfTracepointProgram.%s is not `return attachLibbpf...(p.prog, ...)`", decl.Name.Name)
		}
	}
	// AttachTracepoint and AttachRawTracepoint: fewer means the scan lost them.
	if methods < 2 {
		t.Fatalf("found %d methods of libbpfTracepointProgram, want at least 2", methods)
	}
	attaches := 0
	for _, decl := range funcDecls(parseRepoFile(t, filepath.Join(root, "internal", "ior_bpflink.go"))) {
		if !strings.HasPrefix(decl.Name.Name, "attachLibbpf") {
			continue
		}
		attaches++
		if !returnsOnlyAWrappedAttach(decl) {
			t.Errorf("%s does not end in its only return, `return newLibbpfLink(attachBPF...(...))`", decl.Name.Name)
		}
	}
	if attaches < 2 {
		t.Fatalf("found %d attachLibbpf... functions in ior_bpflink.go, want at least 2", attaches)
	}
}

// funcDecls returns the function and method declarations of file.
func funcDecls(file *ast.File) []*ast.FuncDecl {
	var decls []*ast.FuncDecl
	for _, declaration := range file.Decls {
		if decl, ok := declaration.(*ast.FuncDecl); ok {
			decls = append(decls, decl)
		}
	}
	return decls
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

// onlyReturnedCall returns the call of `return <call>` when that statement is
// decl's whole body, and nil otherwise.
func onlyReturnedCall(decl *ast.FuncDecl) *ast.CallExpr {
	if decl.Body == nil || len(decl.Body.List) != 1 {
		return nil
	}
	return returnedCall(decl.Body.List[0])
}

// returnedCall returns the call of stmt when stmt is `return <call>`, and nil
// otherwise.
func returnedCall(stmt ast.Stmt) *ast.CallExpr {
	ret, ok := stmt.(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return nil
	}
	call, _ := ret.Results[0].(*ast.CallExpr)
	return call
}

// callsIdentWithPrefix reports whether call calls a plain identifier (no
// selector) whose name begins with prefix.
func callsIdentWithPrefix(call *ast.CallExpr, prefix string) bool {
	ident, ok := call.Fun.(*ast.Ident)
	return ok && strings.HasPrefix(ident.Name, prefix)
}

// passesProgField reports whether call's first argument is `<x>.prog`.
func passesProgField(call *ast.CallExpr) bool {
	if len(call.Args) == 0 {
		return false
	}
	field, ok := call.Args[0].(*ast.SelectorExpr)
	return ok && field.Sel.Name == "prog"
}

// returnsOnlyAWrappedAttach reports whether decl has exactly one return
// statement, its last statement, of the form
// `return newLibbpfLink(attachBPF<...>(...))`.
func returnsOnlyAWrappedAttach(decl *ast.FuncDecl) bool {
	if decl.Body == nil || len(decl.Body.List) == 0 {
		return false
	}
	returns := 0
	ast.Inspect(decl.Body, func(node ast.Node) bool {
		if _, ok := node.(*ast.ReturnStmt); ok {
			returns++
		}
		return true
	})
	wrap := returnedCall(decl.Body.List[len(decl.Body.List)-1])
	if returns != 1 || wrap == nil || !isIdentifier(wrap.Fun, "newLibbpfLink") || len(wrap.Args) != 1 {
		return false
	}
	attach, ok := wrap.Args[0].(*ast.CallExpr)
	return ok && callsIdentWithPrefix(attach, "attachBPF")
}

// libbpfSeamNames are the names through which Go code gets at a libbpfgo
// program or link, each with the places that may use it as a selector
// (x.NAME): a repository path and the top-level declarations in it, by
// function name, "Type.Method" or type name; "*" is the whole file.
//
//   - GetProgram is libbpfgo's Module.GetProgram, which hands out the
//     *bpf.BPFProg, in libbpfTracepointModule.GetProgram alone. The scan goes
//     by name, so the two calls of probemanager.Attacher's GetProgram are
//     listed too.
//   - BPFProg and BPFLink are the types. ior_bpflink.go wraps and destroys
//     the links and makes the attach calls; beyond it only the field of
//     libbpfTracepointProgram names the program type.
//   - prog is that field: only the two methods read it, to pass it on.
//
// Anything else is a way around the wrapper (libbpfLink: a bare link whose
// Destroy failed is destroyed again by Module.Close) or around the attach
// mutex (libbpfAttachMu). What the scan cannot see: a program reached without
// any of these names, such as through libbpfgo's Module.Iterator.
var libbpfSeamNames = map[string]map[string][]string{
	"GetProgram": {
		"internal/ior_bpfsetup.go":         {"libbpfTracepointModule.GetProgram", "attachHandProbe"},
		"internal/probemanager/manager.go": {"attachOne"},
	},
	"BPFProg": {
		"internal/ior_bpflink.go":  {"*"},
		"internal/ior_bpfsetup.go": {"libbpfTracepointProgram"},
	},
	"BPFLink": {
		"internal/ior_bpflink.go": {"*"},
	},
	"prog": {
		"internal/ior_bpfsetup.go": {
			"libbpfTracepointProgram.AttachTracepoint", "libbpfTracepointProgram.AttachRawTracepoint",
		},
	},
}

// TestOnlyTheLibbpfSeamUsesLibbpfgoProgramsAndLinks scans every non-test Go
// file of the repository for the names of libbpfSeamNames outside the places
// listed there (task 223). The pin on libbpfTracepointProgram's methods alone
// left every other function free to call GetProgram on the module, attach
// the program and hand out the bare link.
func TestOnlyTheLibbpfSeamUsesLibbpfgoProgramsAndLinks(t *testing.T) {
	scanned := 0
	walkRepoGoFiles(t, func(rel string, file *ast.File) {
		if strings.HasSuffix(rel, "_test.go") {
			return
		}
		scanned++
		for _, violation := range libbpfSeamViolations(rel, file) {
			t.Error(violation)
		}
	})
	if scanned < 100 {
		t.Fatalf("scanned %d non-test Go files, want the whole repository", scanned)
	}
}

// libbpfSeamViolations returns one message for every selector in file, the
// file at the repository path rel, that libbpfSeamNames does not allow there.
func libbpfSeamViolations(rel string, file *ast.File) []string {
	var violations []string
	for _, declaration := range file.Decls {
		for _, in := range declNames(declaration) {
			ast.Inspect(in.node, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				places, pinned := libbpfSeamNames[selector.Sel.Name]
				allowed := places[rel]
				if pinned && !slices.Contains(allowed, "*") && !slices.Contains(allowed, in.name) {
					violations = append(violations, fmt.Sprintf(
						"%s: %q uses .%s outside the libbpf seam (libbpfSeamNames)", rel, in.name, selector.Sel.Name))
				}
				return true
			})
		}
	}
	return violations
}

// namedDecl is one top-level declaration and the name libbpfSeamNames knows
// it by.
type namedDecl struct {
	name string
	node ast.Node
}

// declNames splits a top-level declaration into its named parts: a function
// ("name" or "Type.method"), or each type, variable and constant of a
// declaration group, under its own name.
func declNames(declaration ast.Decl) []namedDecl {
	switch decl := declaration.(type) {
	case *ast.FuncDecl:
		name := decl.Name.Name
		if receiver := receiverTypeName(decl); receiver != "" {
			name = receiver + "." + name
		}
		return []namedDecl{{name: name, node: decl}}
	case *ast.GenDecl:
		var parts []namedDecl
		for _, spec := range decl.Specs {
			switch spec := spec.(type) {
			case *ast.TypeSpec:
				parts = append(parts, namedDecl{name: spec.Name.Name, node: spec})
			case *ast.ValueSpec:
				parts = append(parts, namedDecl{name: spec.Names[0].Name, node: spec})
			}
		}
		return parts
	}
	return nil
}

// libbpfSeamSources are sources for the scan to judge, each as if it were the
// file at rel, with the names it must report. The first three are ways around
// the seam: a method that attaches by itself and hands out the bare link, a
// function that reaches for the program field, and a file elsewhere that
// names libbpfgo's types. The last is the seam as it stands.
var libbpfSeamSources = []struct {
	name, rel, src string
	want           []string
}{
	{"a module method that attaches by itself", "internal/ior_bpfsetup.go", `package p
func (m libbpfTracepointModule) attachBare(n string) (probemanager.Link, error) {
	prog, _ := m.module.GetProgram(n)
	return prog.AttachTracepoint("syscalls", n)
}`, []string{"GetProgram"}},
	{"a function that reads the program field", "internal/ior_bpfsetup.go", `package p
func bare(p libbpfTracepointProgram) probemanager.Link {
	link, _ := p.prog.AttachRawTracepoint("task_rename")
	return link
}`, []string{"prog"}},
	{"the types named in another file", "internal/ior.go", `package p
var keep []*bpf.BPFLink
type holder struct{ prog *bpf.BPFProg }`, []string{"BPFLink", "BPFProg"}},
	{"the seam as it is", "internal/ior_bpfsetup.go", `package p
type libbpfTracepointProgram struct{ prog *bpf.BPFProg }
func (p libbpfTracepointProgram) AttachTracepoint(c, n string) (probemanager.Link, error) {
	return attachLibbpfTracepoint(p.prog, c, n)
}
func (m libbpfTracepointModule) GetProgram(n string) (probemanager.Program, error) {
	prog, err := m.module.GetProgram(n)
	return libbpfTracepointProgram{prog: prog}, err
}`, nil},
}

// The scan above is only worth something if it finds a bypass, and leaves the
// seam itself alone.
func TestLibbpfSeamViolationsFindsABypass(t *testing.T) {
	for _, tc := range libbpfSeamSources {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parser.ParseFile(token.NewFileSet(), "p.go", tc.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := libbpfSeamViolations(tc.rel, parsed)
			if len(got) != len(tc.want) {
				t.Fatalf("violations = %q, want one each for %q", got, tc.want)
			}
			for i, name := range tc.want {
				if !strings.Contains(got[i], "uses ."+name+" ") {
					t.Errorf("violation %d = %q, want it to name .%s", i, got[i], name)
				}
			}
		})
	}
}

// attachOverlap stands in for libbpfgo's two attach calls. Like the real ones
// it appends every link to one list without a lock (Module.links), and it
// counts the calls that found another one inside.
type attachOverlap struct {
	inFlight atomic.Int32
	overlaps atomic.Int32
	// links is unsynchronised on purpose: under -race two attaches at once
	// fail the test by themselves.
	links []*bpf.BPFLink
}

func (o *attachOverlap) attach() (*bpf.BPFLink, error) {
	if o.inFlight.Add(1) > 1 {
		o.overlaps.Add(1)
	}
	defer o.inFlight.Add(-1)
	link := &bpf.BPFLink{}
	o.links = append(o.links, link)
	// Long enough for a second attach to arrive while this one is inside.
	time.Sleep(time.Millisecond)
	return link, nil
}

// stubBPFAttaches replaces libbpfgo's two attach calls for the test with an
// attachOverlap, and its destroy with one that succeeds.
func stubBPFAttaches(t *testing.T) *attachOverlap {
	t.Helper()
	overlap := &attachOverlap{}
	origClassic, origRaw := attachBPFTracepoint, attachBPFRawTracepoint
	attachBPFTracepoint = func(*bpf.BPFProg, string, string) (*bpf.BPFLink, error) { return overlap.attach() }
	attachBPFRawTracepoint = func(*bpf.BPFProg, string) (*bpf.BPFLink, error) { return overlap.attach() }
	t.Cleanup(func() { attachBPFTracepoint, attachBPFRawTracepoint = origClassic, origRaw })
	stubDestroyBPFLink(t, nil)
	return overlap
}

// seamAttacher hands out ior's real program wrapper, around no program: the
// attach calls behind it are stubbed.
type seamAttacher struct{}

func (seamAttacher) GetProgram(string) (probemanager.Program, error) {
	return libbpfTracepointProgram{}, nil
}

// TestAttachesOfDifferentSyscallsNeverOverlapInLibbpfgo: the probe manager
// lets probes of different syscalls attach at the same time, which is what
// two quick toggles in the probes modal are, and libbpfgo's attach is not
// safe for that (libbpfAttachMu). Sixteen syscalls are attached at once
// through a real manager and ior's real seam, beside raw attaches, and no two
// calls may be inside libbpfgo together. Run it under -race.
func TestAttachesOfDifferentSyscallsNeverOverlapInLibbpfgo(t *testing.T) {
	overlap := stubBPFAttaches(t)
	mgr := probemanager.NewManager(seamAttacher{})
	const syscalls = 16
	var wg sync.WaitGroup
	for i := range syscalls {
		name := fmt.Sprintf("sc%d", i)
		mgr.Register(name, probemanager.TracepointPair{Enter: "sys_enter_" + name, Exit: "sys_exit_" + name})
		wg.Go(func() {
			if err := mgr.Attach(name); err != nil {
				t.Errorf("Attach(%s): %v", name, err)
			}
		})
		wg.Go(func() {
			if _, err := (libbpfTracepointProgram{}).AttachRawTracepoint(name); err != nil {
				t.Errorf("AttachRawTracepoint(%s): %v", name, err)
			}
		})
	}
	wg.Wait()
	if got := overlap.overlaps.Load(); got != 0 {
		t.Fatalf("%d attaches ran inside libbpfgo while another one was there, want none", got)
	}
	if got, want := len(overlap.links), 3*syscalls; got != want {
		t.Fatalf("libbpfgo's list holds %d links, want %d: enter, exit and raw of every syscall", got, want)
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
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
	files := walkRepoGoFiles(t, func(rel string, file *ast.File) {
		for _, found := range selectorsNamed(file, moduleWideLinkCalls...) {
			t.Errorf("%s uses %s: libbpfgo's module-wide attach and detach are not safe with ior's links (libbpfLink)", rel, found)
		}
	})
	// This package alone has far more files; fewer means the walk went wrong.
	if files < 100 {
		t.Fatalf("scanned %d Go files, want the whole repository", files)
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

// walkRepoGoFiles parses every Go file of the repository, tests included,
// and calls visit with its slash-separated path below the repository root.
// It returns the number of files visited. Directories whose name begins with
// a dot (.git and the like) are skipped.
func walkRepoGoFiles(t *testing.T, visit func(rel string, file *ast.File)) int {
	t.Helper()
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
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files++
		visit(filepath.ToSlash(rel), parseRepoFile(t, path))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return files
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
