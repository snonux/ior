package internal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"strings"
	"testing"

	"ior/internal/flags"
	"ior/internal/globalfilter"
	"ior/internal/runtime"
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

// TestTraceInfraSetupsRejectAnUnusableFilterBeforeAnyBPFSetup pins the shared
// pre-attach validation through both mode entry points. A comm pattern longer
// than the kernel's fixed-size comm field can never match, so setup must reject
// it without depending on whether BPF setup would succeed on this host.
//
// The name says "before any BPF setup" rather than "before signalling start"
// because that is the stronger thing this actually pins when run unprivileged:
// setupBPFModule fails first on rlimit for a normal user, so the only way to
// see the filter error here is for validation to precede it. As root the
// started-channel assertion below is the one that carries the test. Both are
// worth having - the structural ordering test below makes the same assertion
// independent of the user's privileges.
func TestTraceInfraSetupsRejectAnUnusableFilterBeforeAnyBPFSetup(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.GlobalFilter = globalfilter.Filter{
		Comm: &globalfilter.StringFilter{
			Pattern: strings.Repeat("a", types.MAX_PROGNAME_LENGTH+1),
		},
	}

	setups := []struct {
		name  string
		setup func(chan<- struct{}) (*traceInfra, error)
	}{
		{
			name: "regular trace",
			setup: func(started chan<- struct{}) (*traceInfra, error) {
				return setupTraceInfra(context.Background(), cfg, started, traceSetupHooks{}, func(...any) {})
			},
		},
		{
			name: "headless parquet",
			setup: func(chan<- struct{}) (*traceInfra, error) {
				return setupHeadlessParquetInfra(cfg, func(...any) {})
			},
		},
	}

	for _, tc := range setups {
		t.Run(tc.name, func(t *testing.T) {
			started := make(chan struct{})
			infra, err := tc.setup(started)
			// Close is nil-safe: a rejected filter builds no infrastructure.
			infra.Close()

			if err == nil {
				t.Fatal("setup accepted a comm filter longer than the kernel comm field")
			}
			if !strings.Contains(err.Error(), "comm filter max size") {
				t.Fatalf("setup error = %v, want the comm-filter length rejection", err)
			}
			select {
			case <-started:
				t.Fatal("setup signalled trace start for a trace it could not start")
			default:
			}
		})
	}
}

// TestSharedTraceInfraSetupValidatesFilterBeforeBPFSetup makes the pre-attach
// ordering deterministic even when the tests run as root. Both mode setup
// paths are required below to delegate to this shared function.
func TestSharedTraceInfraSetupValidatesFilterBeforeBPFSetup(t *testing.T) {
	decl, fset := parseInternalFunction(t, "ior.go", "setupTraceInfraWithEventLoop")
	guardIndex, validationCall := exactValidationGuard(t, decl)
	bpfSetupPos := firstCallPosition(decl, "setupBPFModule")
	if !bpfSetupPos.IsValid() {
		t.Fatal("shared trace setup no longer calls setupBPFModule")
	}
	guardPos := decl.Body.List[guardIndex].Pos()
	if guardPos >= bpfSetupPos {
		t.Fatalf(
			"filter validation at %s must precede BPF setup at %s",
			fset.Position(guardPos), fset.Position(bpfSetupPos),
		)
	}
	validationCalls := callsNamed(decl, "ValidateTracepointFields")
	if len(validationCalls) != 1 || validationCalls[0] != validationCall {
		t.Fatalf("shared trace setup has %d validation calls, want only the guarded call", len(validationCalls))
	}
}

// TestSharedTraceInfraSetupBuildsSelectedEventLoopBeforeSignallingStart pins
// the factory seam that preserves the intentional regular/headless difference.
// The selected factory must finish successfully before the TUI sees startup.
func TestSharedTraceInfraSetupBuildsSelectedEventLoopBeforeSignallingStart(t *testing.T) {
	decl, fset := parseInternalFunction(t, "ior.go", "setupTraceInfraWithEventLoop")
	sequenceIndex, buildCall := exactEventLoopBuildSequence(t, decl)
	buildCalls := callsNamed(decl, "buildEventLoop")
	if len(buildCalls) != 1 || buildCalls[0] != buildCall {
		t.Fatalf("shared trace setup has %d factory calls, want only the guarded assignment", len(buildCalls))
	}
	signalCall := singleBareCall(t, decl, "signalTraceStarted")
	assertCallArguments(t, signalCall, []string{"started"})
	sequenceEnd := decl.Body.List[sequenceIndex+2].End()
	if sequenceEnd >= signalCall.Pos() {
		t.Fatalf(
			"event-loop setup sequence ending at %s must precede start signal at %s",
			fset.Position(sequenceEnd), fset.Position(signalCall.Pos()),
		)
	}
}

// TestTraceInfraEntryPointsUseSharedSetup prevents either mode from growing a
// second copy of the fallible lifecycle and missing the ordering guards again.
func TestTraceInfraEntryPointsUseSharedSetup(t *testing.T) {
	tests := []struct {
		file string
		name string
		args []string
	}{
		{
			file: "ior.go",
			name: "setupTraceInfra",
			args: []string{"parentCtx", "cfg", "started", "hooks", "logln", "newTraceEventLoop"},
		},
		{
			file: "ior_parquet_sink.go",
			name: "setupHeadlessParquetInfra",
			args: []string{"context.Background()", "cfg", "nil", "traceSetupHooks{}", "logln", "newHeadlessParquetEventLoop"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decl, _ := parseInternalFunction(t, tc.file, tc.name)
			call := singleDelegatingCall(t, decl, "setupTraceInfraWithEventLoop")
			assertCallArguments(t, call, tc.args)
		})
	}
}

// TestTraceSetupPassesSessionHooksExplicitly pins where the TUI session's
// collaborators go once the starter has handed them to the trace run: the
// run passes its hooks to setup, setup gives the probe publisher to BPF setup
// (which registers the probe manager with it) and the shutdown reporter to
// the infra's progress wiring. setupBPFModule cannot run unprivileged, so the
// wiring is checked structurally; the behaviour on either side is pinned by
// TestTuiTraceStarterHandsRequestBindingsDownToSetup and
// TestNewTraceInfraReportsShutdownProgress.
func TestTraceSetupPassesSessionHooksExplicitly(t *testing.T) {
	run, _ := parseInternalFunction(t, "ior.go", "runTraceWithContext")
	assertCallArguments(t, singleBareCall(t, run, "setupTraceInfra"),
		[]string{"parentCtx", "cfg", "started", "hooks", "logln"})

	setup, _ := parseInternalFunction(t, "ior.go", "setupTraceInfraWithEventLoop")
	bpfSetup := singleBareCall(t, setup, "setupBPFModule")
	if got := renderedArgument(t, bpfSetup, 1); got != "hooks.probes" {
		t.Fatalf("setupBPFModule probe publisher argument = %q, want hooks.probes", got)
	}
	assertCallArguments(t, singleBareCall(t, setup, "newTraceInfra"),
		[]string{"mgr", "hooks.shutdown", "logln"})
}

func renderedArgument(t *testing.T, call *ast.CallExpr, index int) string {
	t.Helper()
	if index >= len(call.Args) {
		t.Fatalf("call has %d arguments, want at least %d", len(call.Args), index+1)
	}
	var rendered bytes.Buffer
	if err := printer.Fprint(&rendered, token.NewFileSet(), call.Args[index]); err != nil {
		t.Fatalf("render argument %d: %v", index, err)
	}
	return rendered.String()
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
// reintroduced. Moving signalTraceStarted above the event-loop factory is
// invisible to every other test in this package.
//
// The repo already pins structural properties this way; see
// streamrow.TestNewCoversEveryRetCarryingEventType.
//
// The rule: signalTraceStarted is the final statement before the success
// return, and the shared setup may not return an error after it. In TUI mode
// that signal is what makes the starter report success, so an error returned
// afterwards has no caller left to receive it and the dashboard shows a
// live-looking, permanently empty session.
//
// The shared setup returns (*traceInfra, error), so "returns an error" is read
// off the last result of every return statement below the signal. The signature
// check keeps that reading honest if the results are ever rearranged.
func TestSetupTraceInfraSignalsStartAfterEveryFallibleStep(t *testing.T) {
	decl, fset := parseInternalFunction(t, "ior.go", "setupTraceInfraWithEventLoop")
	results := decl.Type.Results
	if results == nil || len(results.List) == 0 {
		t.Fatal("shared trace setup returns nothing; it must still hand its setup failures back")
	}
	lastResult := results.List[len(results.List)-1].Type
	if ident, isIdent := lastResult.(*ast.Ident); !isIdent || ident.Name != "error" {
		t.Fatalf(
			"shared trace setup's last result is %T, want error: the check below reads the last "+
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
		t.Fatal("shared trace setup no longer calls signalTraceStarted; the TUI would never leave the attaching overlay")
	}
	assertSignalImmediatelyPrecedesSuccessReturn(t, decl, signalPos, fset)

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
			"shared trace setup returns an error at %s, after signalTraceStarted at %s.\n"+
				"In TUI mode closing the started channel is what makes the trace starter report success, "+
				"so an error returned after it reaches nobody and the dashboard shows a live-looking, empty trace. "+
				"Move the fallible step above the signal (the event-loop factory is where the others live).",
			fset.Position(ret.Pos()), fset.Position(signalPos),
		)
		return true
	})
}

func TestHeadlessParquetEventLoopLeavesAggregateSourceUnwired(t *testing.T) {
	logCount := 0
	el, err := newHeadlessParquetEventLoop(flags.NewFlags(), nil, func(...any) { logCount++ })
	if err != nil {
		t.Fatalf("newHeadlessParquetEventLoop() error = %v, want nil", err)
	}
	defer el.shutdownCommResolver()
	if el.aggregateSrc != nil {
		t.Fatal("headless Parquet event loop wired an aggregate source without an aggregate sink")
	}
	if logCount != 1 {
		t.Fatalf("drop-counter degradation logs = %d, want 1 for the nil test module", logCount)
	}
}

// TestTraceInfraCloseRunsEveryCleanupLIFO pins the properties Close has to hold
// for the teardown stack to be equivalent to the hand-written arms it
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
		var logs []string
		infra := &traceInfra{shutdownLog: func(args ...any) {
			logs = append(logs, fmt.Sprint(args...))
		}}
		infra.onClose(func() { ran = append(ran, "bpf teardown") })
		infra.onClose(func() { panic("profiling blew up") })

		func() {
			defer func() {
				if r := recover(); r != "profiling blew up" {
					t.Errorf("recovered %v, want the cleanup's own panic to propagate", r)
				}
			}()
			infra.Close()
		}()

		if want := []string{"bpf teardown"}; !slices.Equal(ran, want) {
			t.Errorf("cleanups run = %v, want %v: a panicking cleanup must not take the ones below it with it", ran, want)
		}
		if len(logs) != 0 {
			t.Errorf("shutdown logs = %v, want none: a panicking cleanup must not claim completion", logs)
		}
	})

	t.Run("second Close repeats no cleanup", func(t *testing.T) {
		var order []string
		infra := &traceInfra{shutdownLog: func(args ...any) {
			order = append(order, fmt.Sprint(args...))
		}}
		infra.onClose(func() { order = append(order, "cleanup") })
		infra.Close()
		infra.Close()

		want := []string{"cleanup", "Shutdown complete."}
		if !slices.Equal(order, want) {
			t.Errorf("close order = %v, want %v: completion must follow real cleanup and neither may repeat", order, want)
		}
	})

	t.Run("cancel runs first and strands nothing when it panics", func(t *testing.T) {
		var order []string
		infra := &traceInfra{cancel: func() { order = append(order, "cancel") }}
		infra.onClose(func() { order = append(order, "cleanup") })
		infra.Close()
		if want := []string{"cancel", "cleanup"}; !slices.Equal(order, want) {
			t.Errorf("order = %v, want %v: goroutines watching the context must be told to stop before what they touch goes away", order, want)
		}

		// cancel is a teardown step like any other, so a panic in it must not
		// strand the cleanups either.
		var ran []string
		panicky := &traceInfra{cancel: func() { panic("cancel blew up") }}
		panicky.onClose(func() { ran = append(ran, "cleanup") })
		func() {
			defer func() { _ = recover() }()
			panicky.Close()
		}()
		if want := []string{"cleanup"}; !slices.Equal(ran, want) {
			t.Errorf("cleanups run = %v, want %v: a panicking cancel must not strand them", ran, want)
		}
	})

	t.Run("nil receiver", func(t *testing.T) {
		var infra *traceInfra
		infra.Close() // must not panic: a rejected filter returns no infra
	})
}

func parseInternalFunction(t *testing.T, filename, function string) (*ast.FuncDecl, *token.FileSet) {
	t.Helper()
	_, thisFile, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate this test file")
	}
	path := filepath.Join(filepath.Dir(thisFile), filename)
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	for _, declaration := range parsed.Decls {
		decl, isFunction := declaration.(*ast.FuncDecl)
		if isFunction && decl.Recv == nil && decl.Name.Name == function {
			return decl, fset
		}
	}
	t.Fatalf("internal/%s declares no func %s", filename, function)
	return nil, nil
}

func firstCallPosition(decl *ast.FuncDecl, function string) token.Pos {
	calls := callsNamed(decl, function)
	if len(calls) == 0 {
		return token.NoPos
	}
	return calls[0].Pos()
}

func callsNamed(decl *ast.FuncDecl, function string) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(decl.Body, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if isCall && calledFunctionName(call) == function {
			calls = append(calls, call)
		}
		return true
	})
	return calls
}

func calledFunctionName(call *ast.CallExpr) string {
	switch function := call.Fun.(type) {
	case *ast.Ident:
		return function.Name
	case *ast.SelectorExpr:
		return function.Sel.Name
	default:
		return ""
	}
}

func singleBareCall(t *testing.T, decl *ast.FuncDecl, function string) *ast.CallExpr {
	t.Helper()
	calls := callsNamed(decl, function)
	if len(calls) != 1 {
		t.Fatalf("%s calls %s %d times, want exactly once", decl.Name, function, len(calls))
	}
	callee, isIdentifier := calls[0].Fun.(*ast.Ident)
	if !isIdentifier || callee.Name != function {
		t.Fatalf("%s must call %s as a bare identifier", decl.Name, function)
	}
	return calls[0]
}

func exactValidationGuard(t *testing.T, decl *ast.FuncDecl) (int, *ast.CallExpr) {
	t.Helper()
	guardIndex := -1
	var validationCall *ast.CallExpr
	for i, statement := range decl.Body.List {
		call, matches := validationCallFromGuard(statement)
		if !matches {
			continue
		}
		if guardIndex >= 0 {
			t.Fatal("shared trace setup has more than one exact validation guard")
		}
		guardIndex, validationCall = i, call
	}
	if guardIndex < 0 {
		t.Fatal("shared trace setup must contain the exact top-level fixed-field validation guard")
	}
	return guardIndex, validationCall
}

func validationCallFromGuard(statement ast.Stmt) (*ast.CallExpr, bool) {
	guard, ok := statement.(*ast.IfStmt)
	if !ok || guard.Else != nil || !isErrNotNil(guard.Cond) || len(guard.Body.List) != 1 {
		return nil, false
	}
	init, ok := guard.Init.(*ast.AssignStmt)
	if !ok || init.Tok != token.DEFINE || !identifiersMatch(init.Lhs, "err") || len(init.Rhs) != 1 {
		return nil, false
	}
	validationCall, ok := init.Rhs[0].(*ast.CallExpr)
	if !ok || len(validationCall.Args) != 0 {
		return nil, false
	}
	selector, ok := validationCall.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "ValidateTracepointFields" ||
		!isBareCallWithIdentifierArgs(selector.X, "traceFilterFromConfig", "cfg") {
		return nil, false
	}
	if !isReturnIdentifiers(guard.Body.List[0], "nil", "err") {
		return nil, false
	}
	return validationCall, true
}

func exactEventLoopBuildSequence(t *testing.T, decl *ast.FuncDecl) (int, *ast.CallExpr) {
	t.Helper()
	sequenceIndex := -1
	var buildCall *ast.CallExpr
	for i, statement := range decl.Body.List {
		call, matches := eventLoopBuildCallFromAssignment(statement)
		if !matches {
			continue
		}
		if sequenceIndex >= 0 {
			t.Fatal("shared trace setup has more than one exact event-loop factory assignment")
		}
		sequenceIndex, buildCall = i, call
	}
	if sequenceIndex < 0 {
		t.Fatal("shared trace setup must assign the selected event-loop factory result to el, err")
	}
	if sequenceIndex+2 >= len(decl.Body.List) ||
		!isEventLoopBuildErrorGuard(decl.Body.List[sequenceIndex+1]) ||
		!isEventLoopFieldAssignment(decl.Body.List[sequenceIndex+2]) {
		t.Fatal("event-loop factory assignment must be followed by its exact error guard and `infra.el = el`")
	}
	return sequenceIndex, buildCall
}

func eventLoopBuildCallFromAssignment(statement ast.Stmt) (*ast.CallExpr, bool) {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.DEFINE ||
		!identifiersMatch(assignment.Lhs, "el", "err") || len(assignment.Rhs) != 1 {
		return nil, false
	}
	call, ok := assignment.Rhs[0].(*ast.CallExpr)
	if !ok || !isBareCallWithIdentifierArgs(call, "buildEventLoop", "cfg", "bpfModule", "warnSetup") {
		return nil, false
	}
	return call, true
}

func isEventLoopBuildErrorGuard(statement ast.Stmt) bool {
	guard, ok := statement.(*ast.IfStmt)
	if !ok || guard.Init != nil || guard.Else != nil ||
		!isErrNotNil(guard.Cond) || len(guard.Body.List) != 2 {
		return false
	}
	closeStatement, ok := guard.Body.List[0].(*ast.ExprStmt)
	if !ok || !isSelectorCall(closeStatement.X, "infra", "Close") {
		return false
	}
	return isReturnIdentifiers(guard.Body.List[1], "nil", "err")
}

func isEventLoopFieldAssignment(statement ast.Stmt) bool {
	assignment, ok := statement.(*ast.AssignStmt)
	if !ok || assignment.Tok != token.ASSIGN || len(assignment.Lhs) != 1 ||
		!identifiersMatch(assignment.Rhs, "el") {
		return false
	}
	field, ok := assignment.Lhs[0].(*ast.SelectorExpr)
	return ok && field.Sel.Name == "el" && isIdentifier(field.X, "infra")
}

func isErrNotNil(expression ast.Expr) bool {
	comparison, ok := expression.(*ast.BinaryExpr)
	return ok && comparison.Op == token.NEQ &&
		isIdentifier(comparison.X, "err") && isIdentifier(comparison.Y, "nil")
}

func isBareCallWithIdentifierArgs(expression ast.Expr, function string, args ...string) bool {
	call, ok := expression.(*ast.CallExpr)
	if !ok || !isIdentifier(call.Fun, function) {
		return false
	}
	return identifiersMatch(call.Args, args...)
}

func isSelectorCall(expression ast.Expr, receiver, method string) bool {
	call, ok := expression.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == method && isIdentifier(selector.X, receiver)
}

func isReturnIdentifiers(statement ast.Stmt, names ...string) bool {
	ret, ok := statement.(*ast.ReturnStmt)
	return ok && identifiersMatch(ret.Results, names...)
}

func identifiersMatch(expressions []ast.Expr, names ...string) bool {
	if len(expressions) != len(names) {
		return false
	}
	for i, expression := range expressions {
		if !isIdentifier(expression, names[i]) {
			return false
		}
	}
	return true
}

func isIdentifier(expression ast.Expr, name string) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == name
}

func singleDelegatingCall(t *testing.T, decl *ast.FuncDecl, function string) *ast.CallExpr {
	t.Helper()
	if len(decl.Body.List) != 1 {
		t.Fatalf("%s has %d statements, want one return delegating the whole lifecycle", decl.Name, len(decl.Body.List))
	}
	ret, ok := decl.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		t.Fatalf("%s must contain one explicit delegating return", decl.Name)
	}
	call, ok := ret.Results[0].(*ast.CallExpr)
	if !ok {
		t.Fatalf("%s must delegate directly to %s", decl.Name, function)
	}
	callee, isIdentifier := call.Fun.(*ast.Ident)
	if !isIdentifier || callee.Name != function {
		t.Fatalf("%s must delegate directly to %s", decl.Name, function)
	}
	return call
}

func assertCallArguments(t *testing.T, call *ast.CallExpr, want []string) {
	t.Helper()
	if len(call.Args) != len(want) {
		t.Fatalf("delegate arguments = %d, want %d", len(call.Args), len(want))
	}
	for i, arg := range call.Args {
		var rendered bytes.Buffer
		if err := printer.Fprint(&rendered, token.NewFileSet(), arg); err != nil {
			t.Fatalf("render delegate argument %d: %v", i, err)
		}
		if got := rendered.String(); got != want[i] {
			t.Fatalf("delegate argument %d = %q, want %q", i, got, want[i])
		}
	}
}

func assertSignalImmediatelyPrecedesSuccessReturn(
	t *testing.T,
	decl *ast.FuncDecl,
	signalPos token.Pos,
	fset *token.FileSet,
) {
	t.Helper()
	signalIndex := -1
	for i, statement := range decl.Body.List {
		if statement.Pos() <= signalPos && signalPos <= statement.End() {
			signalIndex = i
			break
		}
	}
	if signalIndex != len(decl.Body.List)-2 {
		t.Fatalf("signal at %s must be the final statement before the success return", fset.Position(signalPos))
	}
	signalStatement, ok := decl.Body.List[signalIndex].(*ast.ExprStmt)
	if !ok || signalStatement.X.Pos() != signalPos {
		t.Fatalf("signal at %s must be its own top-level statement", fset.Position(signalPos))
	}
	successReturn, ok := decl.Body.List[len(decl.Body.List)-1].(*ast.ReturnStmt)
	if !ok || len(successReturn.Results) != 2 {
		t.Fatal("shared trace setup must end with exactly `return infra, nil`")
	}
	infra, infraIsIdent := successReturn.Results[0].(*ast.Ident)
	nilError, nilIsIdent := successReturn.Results[1].(*ast.Ident)
	if !infraIsIdent || infra.Name != "infra" || !nilIsIdent || nilError.Name != "nil" {
		t.Fatalf(
			"shared trace setup's final return at %s must be exactly `return infra, nil`",
			fset.Position(successReturn.Pos()),
		)
	}
}

// TestNewTraceInfraReportsShutdownProgress pins the shutdown-progress wiring
// the shared setup gives every mode: each phase is logged, and published when
// the session hands setup a TUI reporter. Without one - the headless modes
// - the same callbacks must only log.
func TestNewTraceInfraReportsShutdownProgress(t *testing.T) {
	reporter := runtime.NewTraceShutdownReporter()
	var logs []string
	logln := func(args ...any) { logs = append(logs, strings.TrimSuffix(fmt.Sprintln(args...), "\n")) }

	infra := newTraceInfra(nil, reporter, logln)
	infra.progress(0, 3)
	if got := <-reporter.Updates(); got.Phase != runtime.TraceShutdownDetaching || got.Total != 3 || got.Completed != 0 {
		t.Fatalf("detach progress = %+v, want detaching 0/3", got)
	}
	infra.progress(2, 3)
	if got := <-reporter.Updates(); got.Completed != 2 {
		t.Fatalf("detach progress = %+v, want detaching 2/3", got)
	}
	infra.releasing()
	if got := <-reporter.Updates(); got.Phase != runtime.TraceShutdownReleasing {
		t.Fatalf("release progress = %+v, want releasing", got)
	}
	wantLogs := []string{"Detaching 3 active BPF probe pairs...", "Releasing remaining BPF resources..."}
	if !slices.Equal(logs, wantLogs) {
		t.Fatalf("shutdown logs = %q, want %q (the detach line only once, at the start)", logs, wantLogs)
	}

	logs = nil
	headless := newTraceInfra(nil, nil, logln)
	headless.progress(0, 1)
	headless.releasing()
	if len(logs) != 2 {
		t.Fatalf("headless shutdown logs = %q, want both phases logged without a reporter", logs)
	}
}
