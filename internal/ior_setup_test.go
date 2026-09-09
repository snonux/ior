package internal

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"strings"
	"testing"

	"ior/internal/flags"
	"ior/internal/globalfilter"
	"ior/internal/types"

	bpf "github.com/aquasecurity/libbpfgo"
)

func TestSetupBPFModuleErrorWrapsStage(t *testing.T) {
	cause := errors.New("boom")

	err := setupBPFModuleError("load object", cause)
	if err == nil {
		t.Fatalf("expected wrapped error")
	}
	if got, want := err.Error(), "setup BPF module: load object: boom"; got != want {
		t.Fatalf("wrapped error = %q, want %q", got, want)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("expected wrapped error to retain original cause")
	}
}

func TestSetupBPFModuleErrorNil(t *testing.T) {
	if err := setupBPFModuleError("attach probes", nil); err != nil {
		t.Fatalf("expected nil error passthrough, got %v", err)
	}
}

func TestLoadBPFModuleUsesEmbeddedObjectByDefault(t *testing.T) {
	origFile := newBPFModuleFromFile
	origBuffer := newBPFModuleFromBuffer
	origOverride, hadOverride := os.LookupEnv(bpfObjectOverrideEnv)
	t.Cleanup(func() {
		newBPFModuleFromFile = origFile
		newBPFModuleFromBuffer = origBuffer
		if hadOverride {
			_ = os.Setenv(bpfObjectOverrideEnv, origOverride)
			return
		}
		_ = os.Unsetenv(bpfObjectOverrideEnv)
	})
	_ = os.Unsetenv(bpfObjectOverrideEnv)

	wantErr := errors.New("buffer load failed")
	newBPFModuleFromFile = func(string) (*bpf.Module, error) {
		t.Fatal("expected embedded loader, not file loader")
		return nil, nil
	}

	var gotBytes []byte
	var gotName string
	newBPFModuleFromBuffer = func(data []byte, name string) (*bpf.Module, error) {
		gotBytes = append([]byte(nil), data...)
		gotName = name
		return nil, wantErr
	}

	module, stage, err := loadBPFModule()
	if module != nil {
		t.Fatalf("expected nil module from stubbed loader, got %v", module)
	}
	if got, want := stage, "load embedded module"; got != want {
		t.Fatalf("stage = %q, want %q", got, want)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected embedded loader error, got %v", err)
	}
	if !bytes.Equal(gotBytes, embeddedBPFObject) {
		t.Fatalf("embedded loader received unexpected object bytes")
	}
	if got, want := gotName, embeddedBPFObjectName; got != want {
		t.Fatalf("embedded loader name = %q, want %q", got, want)
	}
}

func TestLoadBPFModuleUsesOverridePathWhenConfigured(t *testing.T) {
	origFile := newBPFModuleFromFile
	origBuffer := newBPFModuleFromBuffer
	origOverride, hadOverride := os.LookupEnv(bpfObjectOverrideEnv)
	t.Cleanup(func() {
		newBPFModuleFromFile = origFile
		newBPFModuleFromBuffer = origBuffer
		if hadOverride {
			_ = os.Setenv(bpfObjectOverrideEnv, origOverride)
			return
		}
		_ = os.Unsetenv(bpfObjectOverrideEnv)
	})

	overridePath := "/tmp/custom-ior.bpf.o"
	if err := os.Setenv(bpfObjectOverrideEnv, overridePath); err != nil {
		t.Fatalf("set override env: %v", err)
	}

	wantErr := errors.New("file load failed")
	newBPFModuleFromBuffer = func([]byte, string) (*bpf.Module, error) {
		t.Fatal("expected file loader, not embedded loader")
		return nil, nil
	}

	var gotPath string
	newBPFModuleFromFile = func(path string) (*bpf.Module, error) {
		gotPath = path
		return nil, wantErr
	}

	module, stage, err := loadBPFModule()
	if module != nil {
		t.Fatalf("expected nil module from stubbed loader, got %v", module)
	}
	if got, want := stage, "load module from override file"; got != want {
		t.Fatalf("stage = %q, want %q", got, want)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected override loader error, got %v", err)
	}
	if got, want := gotPath, overridePath; got != want {
		t.Fatalf("override path = %q, want %q", got, want)
	}
}

// TestSetupTraceInfraRejectsAnUnusableFilterBeforeAnyBPFSetup pins the
// contract the TUI trace starter depends on: the started channel is closed
// only for a trace that is really running. A comm pattern longer than the
// kernel's fixed-size comm field can never match, so setup must reject it and
// leave the signal unsent - the TUI reads a closed channel as "attached" and
// stops listening for errors, so a failure after that point is invisible.
//
// The name says "before any BPF setup" rather than "before signalling start"
// because that is the stronger thing this actually pins when run unprivileged:
// setupBPFModule fails first on rlimit for a normal user, so the only way to
// see the filter error here is for validation to precede it. As root the
// started-channel assertion below is the one that carries the test. Both are
// worth having - the ordering also means an unusable filter costs no probe
// attach/detach cycle.
func TestSetupTraceInfraRejectsAnUnusableFilterBeforeAnyBPFSetup(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.GlobalFilter = globalfilter.Filter{
		Comm: &globalfilter.StringFilter{
			Pattern: strings.Repeat("a", types.MAX_PROGNAME_LENGTH+1),
		},
	}

	started := make(chan struct{})
	infra, err := setupTraceInfra(context.Background(), cfg, started, func(...any) {})
	// Close is nil-safe: a rejected filter builds no infrastructure at all, so
	// there is nothing to release and infra is nil.
	infra.Close()

	if err == nil {
		t.Fatal("setupTraceInfra accepted a comm filter longer than the kernel comm field")
	}
	if !strings.Contains(err.Error(), "comm filter max size") {
		t.Fatalf("setupTraceInfra error = %v, want the comm-filter length rejection", err)
	}
	select {
	case <-started:
		t.Fatal("setupTraceInfra signalled trace start for a trace it could not start")
	default:
	}
}

// TestNewTraceEventLoopPropagatesAnAggregateConsumerFailure covers the other
// half of the defect setupTraceInfra's signal ordering exists for. The reported
// trigger was an over-long comm filter, which fails in newEventLoop; a stale
// IOR_BPF_OBJECT without syscall_aggregate_map fails one step later, in
// newSyscallAggregateConsumer. Both used to happen after the TUI had been told
// the trace was running.
//
// What is pinned here is that newTraceEventLoop hands that second failure back
// rather than swallowing it, and returns no event loop alongside it. The
// specific missing-map error is deliberately NOT what this reaches: a nil
// module trips newSyscallAggregateConsumer's own nil guard first, so the error
// asserted below is "nil bpf module", not "get syscall_aggregate_map". Getting
// to the GetMap branch would mean loading a real BPF object built without that
// map, which is not worth a kernel dependency for one error path - but the
// assertion names the error it actually gets, so this test cannot quietly
// start passing because some earlier step began failing instead.
func TestNewTraceEventLoopPropagatesAnAggregateConsumerFailure(t *testing.T) {
	el, err := newTraceEventLoop(flags.NewFlags(), nil, func(...any) {})
	if err == nil {
		t.Fatal("newTraceEventLoop accepted a nil BPF module")
	}
	if !strings.Contains(err.Error(), "nil bpf module") {
		t.Fatalf("newTraceEventLoop error = %v, want the aggregate consumer's nil-module rejection", err)
	}
	if el != nil {
		t.Errorf("newTraceEventLoop returned an event loop alongside its error: %v", el)
	}
}

// TestNewTraceEventLoopRejectsAnUnusableFilter is the first half of the same
// pair: newEventLoop validates the filter, and its failure has to reach
// setupTraceInfra rather than being reported as a running trace.
func TestNewTraceEventLoopRejectsAnUnusableFilter(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.GlobalFilter = globalfilter.Filter{
		Comm: &globalfilter.StringFilter{
			Pattern: strings.Repeat("a", types.MAX_PROGNAME_LENGTH+1),
		},
	}

	el, err := newTraceEventLoop(cfg, nil, func(...any) {})
	if err == nil {
		t.Fatal("newTraceEventLoop accepted a comm filter longer than the kernel comm field")
	}
	if !strings.Contains(err.Error(), "comm filter max size") {
		t.Fatalf("newTraceEventLoop error = %v, want the comm-filter length rejection", err)
	}
	if el != nil {
		t.Errorf("newTraceEventLoop returned an event loop alongside its error: %v", el)
	}
}

// TestSetupTraceInfraSignalsStartAfterEveryFallibleStep pins the ordering the
// whole trace-start contract rests on, structurally, because behaviour cannot
// reach it: every step that could fail after the signal needs either root or a
// deliberately broken BPF object, so the suite stays green with the defect
// reintroduced. Moving signalTraceStarted back above newTraceEventLoop - the
// exact regression - is invisible to every other test in this package.
//
// The repo already pins structural properties this way; see
// streamrow.TestNewCoversEveryRetCarryingEventType.
//
// The rule: after signalTraceStarted, setupTraceInfra may not return an error.
// In TUI mode that signal is what makes the starter report success, so an
// error returned afterwards has no caller left to receive it and the dashboard
// shows a live-looking, permanently empty session.
//
// setupTraceInfra returns (*traceInfra, error), so "returns an error" is read
// off the last result of every return statement below the signal: the success
// return is the only one allowed, and it spells its error result as a literal
// nil. The signature check above it is what keeps that reading honest - if the
// error result were ever dropped or moved, a nil last result would stop
// meaning "no error" and this test would pass for the wrong reason.
func TestSetupTraceInfraSignalsStartAfterEveryFallibleStep(t *testing.T) {
	_, thisFile, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate this test file")
	}
	path := filepath.Join(filepath.Dir(thisFile), "ior.go")
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse ior.go: %v", err)
	}

	var decl *ast.FuncDecl
	for _, d := range parsed.Decls {
		if fd, isFunc := d.(*ast.FuncDecl); isFunc && fd.Recv == nil && fd.Name.Name == "setupTraceInfra" {
			decl = fd
			break
		}
	}
	if decl == nil {
		t.Fatal("internal/ior.go declares no func setupTraceInfra")
	}
	results := decl.Type.Results
	if results == nil || len(results.List) == 0 {
		t.Fatal("setupTraceInfra returns nothing; it must still hand its setup failures back")
	}
	lastResult := results.List[len(results.List)-1].Type
	if ident, isIdent := lastResult.(*ast.Ident); !isIdent || ident.Name != "error" {
		t.Fatalf(
			"setupTraceInfra's last result is %T, want error: the check below reads the last "+
				"result of every return to decide whether it carries a failure",
			lastResult,
		)
	}

	var signalPos token.Pos
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		// The *first* signal is the binding one: from the moment the started
		// channel is closed the starter has reported success, so a second
		// call further down would not make an error in between reachable
		// again (it would panic on the closed channel anyway).
		if ident, isIdent := call.Fun.(*ast.Ident); isIdent && ident.Name == "signalTraceStarted" && !signalPos.IsValid() {
			signalPos = call.Pos()
		}
		return true
	})
	if !signalPos.IsValid() {
		t.Fatal("setupTraceInfra no longer calls signalTraceStarted; the TUI would never leave the attaching overlay")
	}

	// A return whose last result is a bare nil is the success return. Anything
	// else after the signal is an error the caller can no longer be told about
	// - `return nil, err` and `return infra, wrap(err)` alike, and also a naked
	// `return`, which named results (the shape this function used to have)
	// would make perfectly capable of carrying a non-nil err.
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		ret, isReturn := n.(*ast.ReturnStmt)
		if !isReturn || ret.Pos() <= signalPos {
			return true
		}
		if len(ret.Results) != 0 {
			last := ret.Results[len(ret.Results)-1]
			if ident, isIdent := last.(*ast.Ident); isIdent && ident.Name == "nil" {
				return true
			}
		}
		t.Errorf(
			"setupTraceInfra returns an error at %s, after signalTraceStarted at %s.\n"+
				"In TUI mode closing the started channel is what makes the trace starter report success, "+
				"so an error returned after it reaches nobody and the dashboard shows a live-looking, empty trace. "+
				"Move the fallible step above the signal (newTraceEventLoop is where the others live).",
			fset.Position(ret.Pos()), fset.Position(signalPos),
		)
		return true
	})
}

// TestTraceInfraCloseRunsEveryCleanupLIFO pins the two properties Close has to
// hold for the teardown stack to be equivalent to the hand-written arms it
// replaced.
//
// Order, because each step is built on the one before it: a cleanup must run
// before the cleanup of the step it depends on. And isolation, because Close
// replaced three separate deferred calls in runTraceWithContext - Go keeps
// running deferred calls while a panic unwinds, so a panic in profiling.stop
// still let the probes detach and the BPF module close. A plain loop would
// have silently dropped that.
func TestTraceInfraCloseRunsEveryCleanupLIFO(t *testing.T) {
	t.Run("reverse registration order", func(t *testing.T) {
		var order []string
		infra := &traceInfra{}
		infra.onClose(func() { order = append(order, "first") })
		infra.onClose(func() { order = append(order, "second") })
		infra.Close()

		if want := []string{"second", "first"}; !slices.Equal(order, want) {
			t.Errorf("cleanup order = %v, want %v", order, want)
		}
	})

	t.Run("a panicking cleanup does not strand the others", func(t *testing.T) {
		var ran []string
		infra := &traceInfra{}
		infra.onClose(func() { ran = append(ran, "bpf teardown") })
		infra.onClose(func() { panic("profiling blew up") })

		func() {
			defer func() {
				if recover() == nil {
					t.Error("Close swallowed a cleanup panic; it must propagate")
				}
			}()
			infra.Close()
		}()

		if want := []string{"bpf teardown"}; !slices.Equal(ran, want) {
			t.Errorf("cleanups run = %v, want %v: a panicking cleanup must not take the ones below it with it", ran, want)
		}
	})

	t.Run("second Close repeats no cleanup", func(t *testing.T) {
		calls := 0
		infra := &traceInfra{}
		infra.onClose(func() { calls++ })
		infra.Close()
		infra.Close()

		if calls != 1 {
			t.Errorf("cleanup ran %d times across two Close calls, want 1: a repeated probe detach or module close is not safe", calls)
		}
	})

	t.Run("nil receiver", func(t *testing.T) {
		var infra *traceInfra
		infra.Close() // must not panic: a rejected filter returns no infra
	})
}
