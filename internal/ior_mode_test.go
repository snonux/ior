package internal

import (
	"bytes"
	"context"
	"encoding/json"
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
	if shouldRunTraceMode(withPprof) {
		t.Fatalf("expected pprof flag alone to keep TUI mode")
	}

	withLive := base
	withLive.LiveFlamegraph = true
	if !shouldRunTraceMode(withLive) {
		t.Fatalf("expected live mode to use trace mode")
	}

	withTestFlames := base
	withTestFlames.TestFlames = true
	if shouldRunTraceMode(withTestFlames) {
		t.Fatalf("expected --testflames to stay in TUI mode")
	}

	withTestLiveFlames := base
	withTestLiveFlames.TestLiveFlames = true
	if shouldRunTraceMode(withTestLiveFlames) {
		t.Fatalf("expected --testliveflames to stay in TUI mode")
	}
}

func TestShouldAutoStopByDuration(t *testing.T) {
	base := flags.Flags{}
	if shouldAutoStopByDuration(base) {
		t.Fatalf("expected default TUI mode not to auto-stop by duration")
	}

	withPlain := base
	withPlain.PlainMode = true
	if !shouldAutoStopByDuration(withPlain) {
		t.Fatalf("expected plain mode to auto-stop by duration")
	}

	withFlamegraph := base
	withFlamegraph.FlamegraphEnable = true
	if !shouldAutoStopByDuration(withFlamegraph) {
		t.Fatalf("expected flamegraph mode to auto-stop by duration")
	}

	withPprof := base
	withPprof.PprofEnable = true
	if shouldAutoStopByDuration(withPprof) {
		t.Fatalf("expected pprof flag alone not to auto-stop by duration")
	}

	withLive := base
	withLive.LiveFlamegraph = true
	if !shouldAutoStopByDuration(withLive) {
		t.Fatalf("expected live mode to auto-stop by duration")
	}
}

func TestDispatchRunUsesTraceModeWhenRequested(t *testing.T) {
	origRunTrace := runTraceFn
	origRunTUI := runTUIFn
	origRunTUITestFlames := runTUITestFlamesFn
	origRunTUITestLiveFlames := runTUITestLiveFlamesFn
	defer func() {
		runTraceFn = origRunTrace
		runTUIFn = origRunTUI
		runTUITestFlamesFn = origRunTUITestFlames
		runTUITestLiveFlamesFn = origRunTUITestLiveFlames
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
	runTUITestFlamesFn = func(tui.TraceStarter) error {
		t.Fatalf("runTUITestFlamesFn should not be called in trace mode")
		return nil
	}
	runTUITestLiveFlamesFn = func(tui.TraceStarter) error {
		t.Fatalf("runTUITestLiveFlamesFn should not be called in trace mode")
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

func TestDispatchRunUsesTUIWhenOnlyPprofEnabled(t *testing.T) {
	origRunTrace := runTraceFn
	origRunTUI := runTUIFn
	origRunTUITestFlames := runTUITestFlamesFn
	origRunTUITestLiveFlames := runTUITestLiveFlamesFn
	defer func() {
		runTraceFn = origRunTrace
		runTUIFn = origRunTUI
		runTUITestFlamesFn = origRunTUITestFlames
		runTUITestLiveFlamesFn = origRunTUITestLiveFlames
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
	runTUITestFlamesFn = func(tui.TraceStarter) error {
		t.Fatalf("runTUITestFlamesFn should not be called for regular TUI mode")
		return nil
	}
	runTUITestLiveFlamesFn = func(tui.TraceStarter) error {
		t.Fatalf("runTUITestLiveFlamesFn should not be called for regular TUI mode")
		return nil
	}

	cfg := flags.Flags{PprofEnable: true}
	if err := dispatchRun(cfg); err != nil {
		t.Fatalf("dispatchRun returned error: %v", err)
	}
	if traceCalled {
		t.Fatalf("did not expect runTraceFn when only -pprof is enabled")
	}
	if !tuiCalled {
		t.Fatalf("expected runTUIFn to be called")
	}
}

func TestDispatchRunUsesTUIStarterWhenNotPlain(t *testing.T) {
	origRunTraceWithContext := runTraceWithContextFn
	origRunTUI := runTUIFn
	origRunTUITestFlames := runTUITestFlamesFn
	origRunTUITestLiveFlames := runTUITestLiveFlamesFn
	defer func() {
		runTraceWithContextFn = origRunTraceWithContext
		runTUIFn = origRunTUI
		runTUITestFlamesFn = origRunTUITestFlames
		runTUITestLiveFlamesFn = origRunTUITestLiveFlames
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
	runTUITestFlamesFn = func(tui.TraceStarter) error {
		t.Fatalf("runTUITestFlamesFn should not be called for normal starter path")
		return nil
	}
	runTUITestLiveFlamesFn = func(tui.TraceStarter) error {
		t.Fatalf("runTUITestLiveFlamesFn should not be called for normal starter path")
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

func TestDispatchRunRejectsLiveAndFlamegraph(t *testing.T) {
	origRunTrace := runTraceFn
	origRunTUI := runTUIFn
	origRunTUITestFlames := runTUITestFlamesFn
	origRunTUITestLiveFlames := runTUITestLiveFlamesFn
	defer func() {
		runTraceFn = origRunTrace
		runTUIFn = origRunTUI
		runTUITestFlamesFn = origRunTUITestFlames
		runTUITestLiveFlamesFn = origRunTUITestLiveFlames
	}()

	runTraceFn = func() error {
		t.Fatalf("runTraceFn should not be called for invalid flag combos")
		return nil
	}
	runTUIFn = func(tui.TraceStarter) error {
		t.Fatalf("runTUIFn should not be called for invalid flag combos")
		return nil
	}
	runTUITestFlamesFn = func(tui.TraceStarter) error {
		t.Fatalf("runTUITestFlamesFn should not be called for invalid flag combos")
		return nil
	}
	runTUITestLiveFlamesFn = func(tui.TraceStarter) error {
		t.Fatalf("runTUITestLiveFlamesFn should not be called for invalid flag combos")
		return nil
	}

	cfg := flags.Flags{LiveFlamegraph: true, FlamegraphEnable: true}
	err := dispatchRun(cfg)
	if err == nil {
		t.Fatalf("expected error for -live with -flamegraph")
	}
	if err.Error() != "-live and -flamegraph are mutually exclusive" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDispatchRunUsesTestFlamesModeWhenRequested(t *testing.T) {
	origRunTrace := runTraceFn
	origRunTUI := runTUIFn
	origRunTUITestFlames := runTUITestFlamesFn
	origRunTUITestLiveFlames := runTUITestLiveFlamesFn
	defer func() {
		runTraceFn = origRunTrace
		runTUIFn = origRunTUI
		runTUITestFlamesFn = origRunTUITestFlames
		runTUITestLiveFlamesFn = origRunTUITestLiveFlames
	}()

	traceCalled := false
	regularTUICalled := false
	testFlamesCalled := false
	runTraceFn = func() error {
		traceCalled = true
		return nil
	}
	runTUIFn = func(tui.TraceStarter) error {
		regularTUICalled = true
		return nil
	}
	runTUITestFlamesFn = func(starter tui.TraceStarter) error {
		testFlamesCalled = true
		if starter == nil {
			t.Fatalf("expected non-nil starter for test flames mode")
		}
		return starter(context.Background())
	}
	runTUITestLiveFlamesFn = func(tui.TraceStarter) error {
		t.Fatalf("runTUITestLiveFlamesFn should not be called for --testflames")
		return nil
	}

	cfg := flags.Flags{TestFlames: true}
	if err := dispatchRun(cfg); err != nil {
		t.Fatalf("dispatchRun returned error: %v", err)
	}
	if traceCalled {
		t.Fatalf("did not expect runTraceFn for test flames mode")
	}
	if regularTUICalled {
		t.Fatalf("did not expect runTUIFn for test flames mode")
	}
	if !testFlamesCalled {
		t.Fatalf("expected runTUITestFlamesFn to be called")
	}
}

func TestDispatchRunUsesTestLiveFlamesModeWhenRequested(t *testing.T) {
	origRunTrace := runTraceFn
	origRunTUI := runTUIFn
	origRunTUITestFlames := runTUITestFlamesFn
	origRunTUITestLiveFlames := runTUITestLiveFlamesFn
	defer func() {
		runTraceFn = origRunTrace
		runTUIFn = origRunTUI
		runTUITestFlamesFn = origRunTUITestFlames
		runTUITestLiveFlamesFn = origRunTUITestLiveFlames
	}()

	traceCalled := false
	regularTUICalled := false
	testLiveFlamesCalled := false
	runTraceFn = func() error {
		traceCalled = true
		return nil
	}
	runTUIFn = func(tui.TraceStarter) error {
		regularTUICalled = true
		return nil
	}
	runTUITestFlamesFn = func(tui.TraceStarter) error {
		t.Fatalf("runTUITestFlamesFn should not be called for --testliveflames")
		return nil
	}
	runTUITestLiveFlamesFn = func(starter tui.TraceStarter) error {
		testLiveFlamesCalled = true
		if starter == nil {
			t.Fatalf("expected non-nil starter for test live flames mode")
		}
		return starter(context.Background())
	}

	cfg := flags.Flags{TestLiveFlames: true}
	if err := dispatchRun(cfg); err != nil {
		t.Fatalf("dispatchRun returned error: %v", err)
	}
	if traceCalled {
		t.Fatalf("did not expect runTraceFn for test live flames mode")
	}
	if regularTUICalled {
		t.Fatalf("did not expect runTUIFn for test live flames mode")
	}
	if !testLiveFlamesCalled {
		t.Fatalf("expected runTUITestLiveFlamesFn to be called")
	}
}

func TestValidateRunConfigRejectsIorWatchWithoutIor(t *testing.T) {
	cfg := flags.Flags{IorWatchInterval: time.Second}
	err := validateRunConfig(cfg)
	if err == nil {
		t.Fatalf("expected error for -iorWatchInterval without -ior")
	}
	if err.Error() != "-iorWatchInterval requires -ior" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRunConfigRejectsNegativeIorWatchInterval(t *testing.T) {
	cfg := flags.Flags{IorWatchInterval: -time.Second}
	err := validateRunConfig(cfg)
	if err == nil {
		t.Fatalf("expected error for negative -iorWatchInterval")
	}
	if err.Error() != "-iorWatchInterval must be >= 0" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRunConfigRejectsTestFlamesWithTraceFlags(t *testing.T) {
	cfg := flags.Flags{TestFlames: true, PlainMode: true}
	err := validateRunConfig(cfg)
	if err == nil {
		t.Fatalf("expected error for --testflames with trace-mode flags")
	}
	if err.Error() != "--testflames cannot be combined with -plain, -flamegraph, or -live" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRunConfigRejectsTestLiveFlamesWithTraceFlags(t *testing.T) {
	cfg := flags.Flags{TestLiveFlames: true, PlainMode: true}
	err := validateRunConfig(cfg)
	if err == nil {
		t.Fatalf("expected error for --testliveflames with trace-mode flags")
	}
	if err.Error() != "--testliveflames cannot be combined with -plain, -flamegraph, or -live" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRunConfigRejectsBothTestModes(t *testing.T) {
	cfg := flags.Flags{TestFlames: true, TestLiveFlames: true}
	err := validateRunConfig(cfg)
	if err == nil {
		t.Fatalf("expected error when both test flame modes are enabled")
	}
	if err.Error() != "--testflames and --testliveflames are mutually exclusive" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildTestFlamesRuntimeSeedsLiveTrie(t *testing.T) {
	cfg := flags.NewFlags()
	_, streamBuf, liveTrie := buildTestFlamesRuntime(cfg)
	if streamBuf == nil {
		t.Fatalf("expected stream buffer in test flames runtime")
	}
	if liveTrie == nil {
		t.Fatalf("expected live trie in test flames runtime")
	}
	if liveTrie.Version() == 0 {
		t.Fatalf("expected seeded live trie version to be non-zero")
	}

	payload, _ := liveTrie.SnapshotJSON()
	var snap map[string]any
	if err := json.Unmarshal(payload, &snap); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	total, ok := snap["t"].(float64)
	if !ok || total <= 0 {
		t.Fatalf("expected seeded snapshot total > 0, got %v", snap["t"])
	}
}

func TestBuildTestLiveFlamesRuntimeContinuouslyUpdatesLiveTrie(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.LiveInterval = 15 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, streamBuf, liveTrie := buildTestLiveFlamesRuntime(ctx, cfg)
	if streamBuf == nil {
		t.Fatalf("expected stream buffer in test live flames runtime")
	}
	if liveTrie == nil {
		t.Fatalf("expected live trie in test live flames runtime")
	}

	initialVersion := liveTrie.Version()
	if initialVersion == 0 {
		t.Fatalf("expected seeded live trie version to be non-zero")
	}
	initialSnapshot, _ := liveTrie.SnapshotJSON()

	sawUpdate := false
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if liveTrie.Version() <= initialVersion {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		currentSnapshot, _ := liveTrie.SnapshotJSON()
		if !bytes.Equal(initialSnapshot, currentSnapshot) {
			sawUpdate = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !sawUpdate {
		t.Fatalf("expected test live flames snapshot shape to change over time (version > %d)", initialVersion)
	}
}

func TestRunTraceWithContextRequiresRoot(t *testing.T) {
	origGetEUID := getEUID
	defer func() { getEUID = origGetEUID }()

	getEUID = func() int { return 1000 }
	err := runTraceWithContext(context.Background(), nil, nil)
	if !errors.Is(err, errRootPrivilegesRequired) {
		t.Fatalf("expected root-required error, got %v", err)
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

func TestProfilingFilesForMode(t *testing.T) {
	cpu, mem, execTrace, duration := profilingFilesForMode(false)
	if cpu != "ior.cpuprofile" || mem != "ior.memprofile" {
		t.Fatalf("unexpected trace-mode profiling file names: cpu=%q mem=%q", cpu, mem)
	}
	if execTrace != "" || duration != 0 {
		t.Fatalf("expected trace-mode execution tracing to be disabled, got trace=%q duration=%s", execTrace, duration)
	}

	cpu, mem, execTrace, duration = profilingFilesForMode(true)
	if cpu != "ior-tui-cpu.prof" || mem != "ior-tui-mem.prof" || execTrace != "ior-tui-trace.out" {
		t.Fatalf("unexpected TUI profiling file names: cpu=%q mem=%q trace=%q", cpu, mem, execTrace)
	}
	if duration != 10*time.Second {
		t.Fatalf("expected 10s TUI execution trace duration, got %s", duration)
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
