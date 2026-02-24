package internal

import (
	"context"
	"errors"
	"testing"
	"time"

	"ior/internal/flags"
	"ior/internal/tui"
)

func TestShouldRunTraceMode(t *testing.T) {
	base := flags.Flags{}

	if shouldRunTraceMode(base) {
		t.Fatalf("expected default mode to use TUI")
	}

	withPlain := base
	withPlain.PlainMode = true
	if !shouldRunTraceMode(withPlain) {
		t.Fatalf("expected plain mode to use trace mode")
	}

	withFlamegraph := base
	withFlamegraph.FlamegraphEnable = true
	if !shouldRunTraceMode(withFlamegraph) {
		t.Fatalf("expected flamegraph mode to use trace mode")
	}

	withPprof := base
	withPprof.PprofEnable = true
	if !shouldRunTraceMode(withPprof) {
		t.Fatalf("expected pprof mode to use trace mode")
	}
}

func TestDispatchRunUsesTraceModeWhenRequested(t *testing.T) {
	origRunTrace := runTraceFn
	origRunTUI := runTUIFn
	defer func() {
		runTraceFn = origRunTrace
		runTUIFn = origRunTUI
	}()

	traceCalled := false
	tuiCalled := false
	runTraceFn = func() error {
		traceCalled = true
		return nil
	}
	runTUIFn = func(tui.TraceStarter) error {
		tuiCalled = true
		return nil
	}

	cfg := flags.Flags{PlainMode: true}
	if err := dispatchRun(cfg); err != nil {
		t.Fatalf("dispatchRun returned error: %v", err)
	}
	if !traceCalled {
		t.Fatalf("expected runTraceFn to be called")
	}
	if tuiCalled {
		t.Fatalf("did not expect runTUIFn to be called")
	}
}

func TestDispatchRunUsesTUIStarterWhenNotPlain(t *testing.T) {
	origRunTraceWithContext := runTraceWithContextFn
	origRunTUI := runTUIFn
	defer func() {
		runTraceWithContextFn = origRunTraceWithContext
		runTUIFn = origRunTUI
	}()

	traceDone := make(chan struct{}, 1)
	runTraceWithContextFn = func(_ context.Context, started chan<- struct{}, configure func(*eventLoop)) error {
		if configure != nil {
			configure(&eventLoop{})
		}
		close(started)
		traceDone <- struct{}{}
		return nil
	}

	tuiCalled := false
	runTUIFn = func(starter tui.TraceStarter) error {
		tuiCalled = true
		if starter == nil {
			t.Fatalf("expected non-nil starter")
		}
		if err := starter(context.Background()); err != nil {
			t.Fatalf("starter returned error: %v", err)
		}
		return nil
	}

	cfg := flags.Flags{}
	if err := dispatchRun(cfg); err != nil {
		t.Fatalf("dispatchRun returned error: %v", err)
	}
	if !tuiCalled {
		t.Fatalf("expected runTUIFn to be called")
	}

	select {
	case <-traceDone:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("expected starter to launch runTraceWithContextFn")
	}
}

func TestTuiTraceStarterFromRunTracePropagatesError(t *testing.T) {
	starter := tuiTraceStarterFromRunTrace(
		func(context.Context, chan<- struct{}, func(*eventLoop)) error { return errors.New("startup failed") },
	)

	err := starter(context.Background())
	if err == nil || err.Error() != "startup failed" {
		t.Fatalf("expected startup error, got %v", err)
	}
}

func TestTuiTraceStarterFromRunTraceRespectsCancel(t *testing.T) {
	starter := tuiTraceStarterFromRunTrace(
		func(ctx context.Context, _ chan<- struct{}, _ func(*eventLoop)) error {
			<-ctx.Done()
			return ctx.Err()
		},
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := starter(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}
