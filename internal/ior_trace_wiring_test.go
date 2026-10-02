package internal

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"slices"
	"strings"
	"testing"

	"ior/internal/globalfilter"
	"ior/internal/probemanager"
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
// change stamp at each report - one for the detach, two for the attach - and
// the startup attach, which ran before the loop listened, is covered by the
// clear and the stamp taken when the hook was installed.
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
	if stamp, clears := f.el.restarts.probes.changedAt.Load(), pending.clears.Load(); stamp != 100 || clears != 1 {
		t.Fatalf("after installing the hook: stamp=%d clears=%d, want the install stamp 100 and one clear", stamp, clears)
	}
	wantClears := []int64{2, 4} // the install, the detach, the attach twice
	for i, change := range []func(string) error{mgr.Detach, mgr.Attach} {
		at := uint64(200 + 100*i)
		f.clockAt(at)
		if err := change("read"); err != nil {
			t.Fatalf("probe change %d: %v", i, err)
		}
		if stamp, clears := f.el.restarts.probes.changedAt.Load(), pending.clears.Load(); stamp != at || clears != wantClears[i] {
			t.Fatalf("after probe change %d: stamp=%d clears=%d, want %d and %d", i, stamp, clears, at, wantClears[i])
		}
	}
}

// attachWindowProgram is a probe program whose attach first runs a callback:
// what the traced host does while the manager is attaching a pair.
type attachWindowProgram struct {
	fakeProbeProgram
	during func(tracepoint string)
}

func (p *attachWindowProgram) AttachTracepoint(category, name string) (probemanager.Link, error) {
	if p.during != nil {
		p.during(name)
	}
	return p.fakeProbeProgram.AttachTracepoint(category, name)
}

// TestCallStoppedDuringAnAttachIsNotFoldedWithALaterRestartSyscall: the two
// tracepoints of a pair are attached one after the other, after the attach was
// reported. While restart_syscall's are being attached a traced sleep is
// stopped - after that report, so its row is held and its task pending - and
// resumed before the enter tracepoint is there: its restart_syscall is never
// seen. The restart_syscall BPF announces later, from the entry that outlived
// it, resumes another stopped call of the thread, one that left no record.
// With the attach reported only beforehand it was folded into the held sleep;
// the report after the attach is younger than that row, so RESUME releases it
// and the restart_syscall is a row of its own.
func TestCallStoppedDuringAnAttachIsNotFoldedWithALaterRestartSyscall(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	prog := &attachWindowProgram{fakeProbeProgram: fakeProbeProgram{link: &fakeProbeLink{}}}
	none := func(string) bool { return false }
	mgr, err := attachSyscallProbes(&fakeProbeAttacher{prog: prog}, none, syscallPairNames("restart_syscall"), failOnLog(t))
	if err != nil {
		t.Fatalf("attachSyscallProbes() error = %v", err)
	}
	defer func() { _ = mgr.Close() }()
	f.clockAt(restartBase - 1000)
	f.el.watchProbeChanges(mgr.SetChangeHook)

	prog.during = func(tracepoint string) {
		if tracepoint != "sys_enter_restart_syscall" {
			return
		}
		f.interrupt(restartBase, restartTid) // held: interrupted after the first report
		f.clockAt(restartBase + 1000)        // and resumed unseen before this attach returns
	}
	f.clockAt(restartBase - 100)
	if err := mgr.Attach("restart_syscall"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if stamp := f.el.restarts.probes.changedAt.Load(); stamp != restartBase+1000 {
		t.Fatalf("change stamp = %d after the attach, want %d: a report once both tracepoints are attached", stamp, restartBase+1000)
	}

	rows := f.foldSleepFrom(restartBase)
	requireSleepAndRestartRows(t, rows, restartBase, restartBase+1500, restartBase+3000, 0)
	f.requireNothingHeld()
}

// TestSetupTraceInfraReportsProbeChangesToTheLoop pins the call that connects
// the two, structurally like its sibling above: without it the TUI's probes
// modal changes probes and the loop keeps folding into rows whose continuation
// ran unseen (task o03). It must hand the loop the real manager's
// SetChangeHook, on every setup that published its manager to a TUI, before
// the loop can run. On those only: a headless run changes no probe, and
// listening starts with a stamp that refuses the folds of the calls interrupted
// before it - in a time namespace with a positive boottime offset, where the
// stamp lies in the records' future, every fold for the length of the offset.
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
	assertRunsUnconditionallyOnceManagerExists(t, decl, call, "infra.mgr != nil && hooks.probes != nil")
	if signal := firstCallPosition(decl, "signalTraceStarted"); !signal.IsValid() || call.End() >= signal {
		t.Fatalf("watchProbeChanges at %s must precede the start signal", fset.Position(call.Pos()))
	}
}

// TestTraceSetIsFinalWithARealProbeManager drives traceSetIsFinal through a
// real probemanager.Manager (fake attacher), with the exact method value the
// setup passes (task u13): the loop stops holding -516 rows exactly when the
// manager has no restart_syscall probe attached. A manager-side change in how
// IsActive names syscalls would otherwise call restart_syscall inactive in
// every headless run and silently end the stopped-sleep fold there.
func TestTraceSetIsFinalWithARealProbeManager(t *testing.T) {
	for _, tc := range []struct {
		name         string
		attach       func(tracepoint string) bool
		wantUntraced bool
	}{
		{"restart_syscall attached", nil, false},
		{"only the sleep attached", func(tp string) bool { return strings.HasSuffix(tp, "_clock_nanosleep") }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attacher := &fakeProbeAttacher{prog: &fakeProbeProgram{link: &fakeProbeLink{}}}
			mgr, err := attachSyscallProbes(attacher, tc.attach,
				syscallPairNames("clock_nanosleep", "restart_syscall"), failOnLog(t))
			if err != nil {
				t.Fatalf("attachSyscallProbes() error = %v", err)
			}
			defer func() { _ = mgr.Close() }()
			f := newRestartFixture(t, globalfilter.Filter{})

			f.el.traceSetIsFinal(mgr.IsActive)

			if got := f.el.restarts.restartSyscallUntraced; got != tc.wantUntraced {
				t.Fatalf("restartSyscallUntraced = %t, want %t", got, tc.wantUntraced)
			}
		})
	}
}

// TestSetupTraceInfraTellsAHeadlessLoopItsTraceSetIsFinal pins the call that
// connects the two, structurally like its siblings above (task u13). It must
// hand the loop the real manager's IsActive, before the loop can run, and on
// the setups that published their manager to nobody - on those only: a TUI's
// probes modal attaches restart_syscall while the loop runs, and a loop told
// at startup that it is not traced would never fold a stopped sleep again.
func TestSetupTraceInfraTellsAHeadlessLoopItsTraceSetIsFinal(t *testing.T) {
	decl, fset := parseInternalFunction(t, "ior.go", "runTraceSetup")
	final := callsNamed(decl, "traceSetIsFinal")
	if len(final) != 1 {
		t.Fatalf("shared trace setup calls traceSetIsFinal %d times, want exactly once", len(final))
	}
	call := final[0]
	receiver, isSelector := call.Fun.(*ast.SelectorExpr)
	if !isSelector || !isIdentifier(receiver.X, "el") {
		t.Fatal("traceSetIsFinal must be called on the event loop el")
	}
	assertCallArguments(t, call, []string{"infra.mgr.IsActive"})
	assertRunsUnconditionallyOnceManagerExists(t, decl, call, "infra.mgr != nil && hooks.probes == nil")
	// That helper also accepts a call no condition guards, which here is the
	// defect itself: a TUI's loop told that its trace set is final.
	for _, statement := range decl.Body.List {
		if expression, ok := statement.(*ast.ExprStmt); ok && expression.X == call {
			t.Fatal("traceSetIsFinal must not run for a manager that was published to a TUI")
		}
	}
	if signal := firstCallPosition(decl, "signalTraceStarted"); !signal.IsValid() || call.End() >= signal {
		t.Fatalf("traceSetIsFinal at %s must precede the start signal", fset.Position(call.Pos()))
	}
}

// TestNewTraceEventLoopHandsTheLoopTheRestartPendingMap pins, structurally
// again, the statement that gives the loop the kernel's restart_pending_map to
// clear at a probe change (task o03). It needs a loaded BPF module to do
// anything, so no test without root reaches it, and without it nothing fails
// loudly: the loop's time rule still refuses the folds, and only the cases the
// clear exists for - a stamp the records cannot be compared with - go wrong.
func TestNewTraceEventLoopHandsTheLoopTheRestartPendingMap(t *testing.T) {
	decl, _ := parseInternalFunction(t, "ior.go", "newTraceEventLoop")
	attach := callsNamed(decl, "attachRestartPendingMap")
	if len(attach) != 1 {
		t.Fatalf("newTraceEventLoop calls attachRestartPendingMap %d times, want exactly once", len(attach))
	}
	assertCallArguments(t, attach[0], []string{"el", "bpfModule"})
	// A plain statement of the body: not behind a condition, in a closure
	// nobody calls, or deferred past the return of the loop.
	plain := slices.ContainsFunc(decl.Body.List, func(statement ast.Stmt) bool {
		expression, ok := statement.(*ast.ExprStmt)
		return ok && expression.X == attach[0]
	})
	if !plain {
		t.Fatal("attachRestartPendingMap must be a plain statement of newTraceEventLoop's body")
	}
}

// TestAttachRestartPendingMapWithoutAMapLeavesTheLoopWithout: an object
// without restart_pending_map (here: no module at all) is not an error and
// leaves a loop that guards the folds by time alone.
func TestAttachRestartPendingMapWithoutAMapLeavesTheLoopWithout(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	attachRestartPendingMap(f.el, nil)
	if f.el.restartPending != nil {
		t.Fatalf("restartPending = %v without a module, want nil", f.el.restartPending)
	}
	f.changeProbes(restartBase)
	if got := f.el.restarts.probes.changedAt.Load(); got != restartBase {
		t.Fatalf("change stamp = %d without a map to clear, want %d", got, restartBase)
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
