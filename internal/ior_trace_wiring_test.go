package internal

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"strings"
	"testing"

	"ior/internal/globalfilter"
	"ior/internal/statsengine"
	"ior/internal/types"
)

// newTraceEventLoop is what -plain and -flamegraph (and the TUI) run, so the
// kernel counts of a sampled run reach their drain loop only if it stores the
// source it opened. A nil module is the smallest seam: openAggregateSource is
// faked, and the drop-counter lookup on a nil module fails the way an older BPF
// object does, which is non-fatal and reported through warnSetup.
func TestNewTraceEventLoopWiresTheAggregateSource(t *testing.T) {
	stub := &aggregateSourceStub{rows: [][]statsengine.SyscallAggregate{
		{{TraceID: types.SYS_ENTER_READ, Count: 90}},
	}}
	opened := useAggregateSource(t, stub, nil)

	var warnings []string
	el, err := newTraceEventLoop(mustParseArgs(t, "-plain", "-syscall-sampling-syscalls", "read=10"), nil,
		func(args ...any) { warnings = append(warnings, fmt.Sprint(args...)) })
	if err != nil {
		t.Fatalf("newTraceEventLoop() error = %v, want nil", err)
	}
	defer el.shutdownCommResolver()

	if *opened != 1 {
		t.Fatalf("aggregate source opened %d times, want once", *opened)
	}
	// Identity, not just non-nil: a different source would drain other counts.
	if el.aggregateSrc != syscallAggregateSource(stub) {
		t.Fatalf("el.aggregateSrc = %v, want the source openAggregateSource returned", el.aggregateSrc)
	}
	// The missing drop counter stays a warning, never a failure or a half-wired loop.
	if el.dropSrc != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "drop counter unavailable") {
		t.Fatalf("dropSrc = %v, warnings = %q; want no drop source and one drop-counter warning", el.dropSrc, warnings)
	}
}

// When the source cannot be opened the loop is not handed out at all: a run
// that asked for exact totals must not start without the counts.
func TestNewTraceEventLoopFailsWithoutTheAggregateSource(t *testing.T) {
	boom := errors.New("no syscall_aggregate_map")
	useAggregateSource(t, nil, boom)

	el, err := newTraceEventLoop(mustParseArgs(t, "-plain"), nil, func(...any) {})
	if !errors.Is(err, boom) {
		t.Fatalf("newTraceEventLoop() error = %v, want it to wrap %v", err, boom)
	}
	if el != nil {
		t.Fatalf("newTraceEventLoop() returned a loop alongside the error: %v", el)
	}
}

// The sampling report lists only syscalls whose probe really attached, by
// asking the probe manager. This drives a real probemanager.Manager (fake
// attacher, only openat attaches) through the exact method value the setup
// passes, so a manager-side change in how IsActive names syscalls breaks it.
func TestRestrictSamplingToActiveWithARealProbeManager(t *testing.T) {
	el := sampledLoop(t, "-plain", "-syscall-sampling-syscalls", "read=10,openat=10")
	attacher := &fakeProbeAttacher{prog: &fakeProbeProgram{link: &fakeProbeLink{}}}
	onlyOpenat := func(tp string) bool { return strings.HasSuffix(tp, "_openat") }
	mgr, err := attachSyscallProbes(attacher, onlyOpenat, syscallPairNames("openat", "read"), failOnLog(t))
	if err != nil {
		t.Fatalf("attachSyscallProbes() error = %v", err)
	}
	defer func() { _ = mgr.Close() }()

	el.restrictSamplingToActive(mgr.IsActive)

	if got := el.samplingPlan().Rates(); got != "openat=10" {
		t.Fatalf("plan rates = %q, want only the attached openat=10", got)
	}
}

// The call that connects the two - setupTraceInfraWithEventLoop handing the
// manager's IsActive to the loop - cannot run without a kernel, so it is pinned
// structurally, like the other setup-order pins in ior_setup_test.go: replacing
// it by `_ = infra.mgr`, or by an always-true func, silently turns the stats
// and footers of a run that traced fewer syscalls than it sampled into reports
// of syscalls that were never measured.
func TestSetupTraceInfraRestrictsSamplingToAttachedProbes(t *testing.T) {
	decl, fset := parseInternalFunction(t, "ior.go", "runTraceSetup")

	restrict := callsNamed(decl, "restrictSamplingToActive")
	if len(restrict) != 1 {
		t.Fatalf("shared trace setup calls restrictSamplingToActive %d times, want exactly once", len(restrict))
	}
	call := restrict[0]
	receiver, isSelector := call.Fun.(*ast.SelectorExpr)
	if !isSelector || !isIdentifier(receiver.X, "el") {
		t.Fatal("restrictSamplingToActive must be called on the event loop el")
	}
	// A method value of the real manager, not a literal that could say yes to all.
	assertCallArguments(t, call, []string{"infra.mgr.IsActive"})
	// Position and arguments alone stay green if the call is wrapped in a
	// closure nobody invokes, deferred, or hidden behind `if false`.
	assertRunsUnconditionallyOnceManagerExists(t, decl, call, "infra.mgr != nil")

	wire := firstCallPosition(decl, "wireEventLoopLogging")
	signal := firstCallPosition(decl, "signalTraceStarted")
	if !wire.IsValid() || !signal.IsValid() {
		t.Fatal("shared trace setup lost wireEventLoopLogging or signalTraceStarted")
	}
	// After the probes attached (infra.mgr is set by setupTraceInfraBPF, before
	// the loop is built) and before the loop can run; nothing fallible may follow
	// the start signal, and the report must be final by then.
	if call.Pos() < wire {
		t.Fatalf("restrictSamplingToActive at %s precedes wireEventLoopLogging at %s", fset.Position(call.Pos()), fset.Position(wire))
	}
	if call.End() >= signal {
		t.Fatalf("restrictSamplingToActive at %s must precede the start signal at %s", fset.Position(call.Pos()), fset.Position(signal))
	}
}

// TestWatchProbeChangesWithARealProbeManager drives the loop's probe-change
// hook through a real probemanager.Manager (fake attacher), with the exact
// method value the setup passes (task o03): a probe detached and attached
// again at runtime clears the kernel's pending restarts and moves the loop's
// change stamp each time, and the startup attach, which ran before the loop
// listened, is covered by the stamp taken when the hook was installed.
func TestWatchProbeChangesWithARealProbeManager(t *testing.T) {
	attacher := &fakeProbeAttacher{prog: &fakeProbeProgram{link: &fakeProbeLink{}}}
	mgr, err := attachSyscallProbes(attacher, nil, syscallPairNames("read"), failOnLog(t))
	if err != nil {
		t.Fatalf("attachSyscallProbes() error = %v", err)
	}
	defer func() { _ = mgr.Close() }()
	f := newReexecFixture(t, globalfilter.Filter{})
	pending := &scriptedPendingClearer{}
	f.el.restartPending = pending

	f.clockAt(100)
	f.el.watchProbeChanges(mgr.SetChangeHook)
	if stamp, clears := f.el.restarts.probes.changedAt.Load(), pending.clears.Load(); stamp != 100 || clears != 0 {
		t.Fatalf("after installing the hook: stamp=%d clears=%d, want the install stamp 100 and no clear", stamp, clears)
	}
	for i, change := range []func(string) error{mgr.Detach, mgr.Attach} {
		at := uint64(200 + 100*i)
		f.clockAt(at)
		if err := change("read"); err != nil {
			t.Fatalf("probe change %d: %v", i, err)
		}
		if stamp, clears := f.el.restarts.probes.changedAt.Load(), pending.clears.Load(); stamp != at || clears != int64(i+1) {
			t.Fatalf("after probe change %d: stamp=%d clears=%d, want %d and %d", i, stamp, clears, at, i+1)
		}
	}
}

// TestSetupTraceInfraReportsProbeChangesToTheLoop pins the call that connects
// the two, structurally like its sibling above: without it the TUI's probes
// modal changes probes and the loop keeps folding into rows whose continuation
// ran unseen (task o03). It must hand the loop the real manager's
// SetChangeHook, on every setup that has a manager, before the loop can run.
func TestSetupTraceInfraReportsProbeChangesToTheLoop(t *testing.T) {
	decl, fset := parseInternalFunction(t, "ior.go", "runTraceSetup")
	watch := callsNamed(decl, "watchProbeChanges")
	if len(watch) != 1 {
		t.Fatalf("shared trace setup calls watchProbeChanges %d times, want exactly once", len(watch))
	}
	call := watch[0]
	receiver, isSelector := call.Fun.(*ast.SelectorExpr)
	if !isSelector || !isIdentifier(receiver.X, "el") {
		t.Fatal("watchProbeChanges must be called on the event loop el")
	}
	assertCallArguments(t, call, []string{"infra.mgr.SetChangeHook"})
	assertRunsUnconditionallyOnceManagerExists(t, decl, call, "infra.mgr != nil")
	if signal := firstCallPosition(decl, "signalTraceStarted"); !signal.IsValid() || call.End() >= signal {
		t.Fatalf("watchProbeChanges at %s must precede the start signal", fset.Position(call.Pos()))
	}
}

// assertRunsUnconditionallyOnceManagerExists requires call to execute on every
// pass of the setup that has a probe manager: it must be an expression
// statement that is either a direct statement of the function body, or the
// direct statement of the body of an `if <guard>` that has no init and no else.
// Any other nesting - an unsent closure (`_ = func(){...}`), go/defer, a
// different or inverted condition such as `if false` - does not match, because
// the statement holding the call is then not an ExprStmt of those two shapes
// (or the guard text differs and the test fails on it). The failure names the
// method call is a call of.
func assertRunsUnconditionallyOnceManagerExists(t *testing.T, decl *ast.FuncDecl, call *ast.CallExpr, guard string) {
	t.Helper()
	name := "the call"
	if method, isSelector := call.Fun.(*ast.SelectorExpr); isSelector {
		name = method.Sel.Name
	}
	isCallStatement := func(statement ast.Stmt) bool {
		expression, ok := statement.(*ast.ExprStmt)
		return ok && expression.X == call
	}
	for _, statement := range decl.Body.List {
		if isCallStatement(statement) {
			return // unguarded: runs on every pass, a superset of the guarded case
		}
		guarded, ok := statement.(*ast.IfStmt)
		if !ok || guarded.Init != nil || guarded.Else != nil {
			continue
		}
		for _, inner := range guarded.Body.List {
			if !isCallStatement(inner) {
				continue
			}
			var condition bytes.Buffer
			if err := printer.Fprint(&condition, token.NewFileSet(), guarded.Cond); err != nil {
				t.Fatalf("render guard condition: %v", err)
			}
			if condition.String() != guard {
				t.Fatalf("%s is guarded by %q, want %q", name, condition.String(), guard)
			}
			return
		}
	}
	t.Fatal(name + " must be a plain statement of the setup body or of an `if " + guard +
		"` directly in it, not inside a closure, go/defer, or another construct")
}
