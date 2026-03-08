package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/flags"
	"ior/internal/globalfilter"
	"ior/internal/tui"
	"ior/internal/types"
)

func TestShouldRunTraceMode(t *testing.T) {
	base := flags.Config{}

	if shouldRunTraceMode(base) {
		t.Fatalf("expected default mode to use TUI")
	}

	withPlain := base
	withPlain.PlainMode = true
	if !shouldRunTraceMode(withPlain) {
		t.Fatalf("expected plain mode to use trace mode")
	}

	withPprof := base
	withPprof.PprofEnable = true
	if shouldRunTraceMode(withPprof) {
		t.Fatalf("expected pprof flag alone to keep TUI mode")
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
	base := flags.Config{}
	if shouldAutoStopByDuration(base) {
		t.Fatalf("expected default TUI mode not to auto-stop by duration")
	}

	withPlain := base
	withPlain.PlainMode = true
	if !shouldAutoStopByDuration(withPlain) {
		t.Fatalf("expected plain mode to auto-stop by duration")
	}

	withPprof := base
	withPprof.PprofEnable = true
	if shouldAutoStopByDuration(withPprof) {
		t.Fatalf("expected pprof flag alone not to auto-stop by duration")
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
	runTraceFn = func(flags.Config) error {
		traceCalled = true
		return nil
	}
	runTUIFn = func(flags.Config, tui.TraceStarter) error {
		tuiCalled = true
		return nil
	}
	runTUITestFlamesFn = func(flags.Config, tui.TraceStarter) error {
		t.Fatalf("runTUITestFlamesFn should not be called in trace mode")
		return nil
	}
	runTUITestLiveFlamesFn = func(flags.Config, tui.TraceStarter) error {
		t.Fatalf("runTUITestLiveFlamesFn should not be called in trace mode")
		return nil
	}

	cfg := flags.Config{PlainMode: true}
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
	runTraceFn = func(flags.Config) error {
		traceCalled = true
		return nil
	}
	runTUIFn = func(flags.Config, tui.TraceStarter) error {
		tuiCalled = true
		return nil
	}
	runTUITestFlamesFn = func(flags.Config, tui.TraceStarter) error {
		t.Fatalf("runTUITestFlamesFn should not be called for regular TUI mode")
		return nil
	}
	runTUITestLiveFlamesFn = func(flags.Config, tui.TraceStarter) error {
		t.Fatalf("runTUITestLiveFlamesFn should not be called for regular TUI mode")
		return nil
	}

	cfg := flags.Config{PprofEnable: true}
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
	runTraceWithContextFn = func(_ context.Context, _ flags.Config, started chan<- struct{}, configure func(*eventLoop)) error {
		if configure != nil {
			configure(&eventLoop{})
		}
		close(started)
		traceDone <- struct{}{}
		return nil
	}

	tuiCalled := false
	runTUIFn = func(_ flags.Config, starter tui.TraceStarter) error {
		tuiCalled = true
		if starter == nil {
			t.Fatalf("expected non-nil starter")
		}
		if err := starter(context.Background()); err != nil {
			t.Fatalf("starter returned error: %v", err)
		}
		return nil
	}
	runTUITestFlamesFn = func(flags.Config, tui.TraceStarter) error {
		t.Fatalf("runTUITestFlamesFn should not be called for normal starter path")
		return nil
	}
	runTUITestLiveFlamesFn = func(flags.Config, tui.TraceStarter) error {
		t.Fatalf("runTUITestLiveFlamesFn should not be called for normal starter path")
		return nil
	}

	cfg := flags.Config{}
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
	runTraceFn = func(flags.Config) error {
		traceCalled = true
		return nil
	}
	runTUIFn = func(flags.Config, tui.TraceStarter) error {
		regularTUICalled = true
		return nil
	}
	runTUITestFlamesFn = func(_ flags.Config, starter tui.TraceStarter) error {
		testFlamesCalled = true
		if starter == nil {
			t.Fatalf("expected non-nil starter for test flames mode")
		}
		return starter(context.Background())
	}
	runTUITestLiveFlamesFn = func(flags.Config, tui.TraceStarter) error {
		t.Fatalf("runTUITestLiveFlamesFn should not be called for --testflames")
		return nil
	}

	cfg := flags.Config{TestFlames: true}
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
	runTraceFn = func(flags.Config) error {
		traceCalled = true
		return nil
	}
	runTUIFn = func(flags.Config, tui.TraceStarter) error {
		regularTUICalled = true
		return nil
	}
	runTUITestFlamesFn = func(flags.Config, tui.TraceStarter) error {
		t.Fatalf("runTUITestFlamesFn should not be called for --testliveflames")
		return nil
	}
	runTUITestLiveFlamesFn = func(_ flags.Config, starter tui.TraceStarter) error {
		testLiveFlamesCalled = true
		if starter == nil {
			t.Fatalf("expected non-nil starter for test live flames mode")
		}
		return starter(context.Background())
	}

	cfg := flags.Config{TestLiveFlames: true}
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

func TestValidateRunConfigRejectsTestFlamesWithTraceFlags(t *testing.T) {
	cfg := flags.Config{TestFlames: true, PlainMode: true}
	err := validateRunConfig(cfg)
	if err == nil {
		t.Fatalf("expected error for --testflames with trace-mode flags")
	}
	if err.Error() != "--testflames cannot be combined with -plain" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRunConfigRejectsTestLiveFlamesWithTraceFlags(t *testing.T) {
	cfg := flags.Config{TestLiveFlames: true, PlainMode: true}
	err := validateRunConfig(cfg)
	if err == nil {
		t.Fatalf("expected error for --testliveflames with trace-mode flags")
	}
	if err.Error() != "--testliveflames cannot be combined with -plain" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRunConfigRejectsBothTestModes(t *testing.T) {
	cfg := flags.Config{TestFlames: true, TestLiveFlames: true}
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
	synctest.Test(t, func(t *testing.T) {
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

		time.Sleep(cfg.LiveInterval + time.Nanosecond)
		synctest.Wait()

		if liveTrie.Version() <= initialVersion {
			t.Fatalf("expected live trie version to advance beyond %d", initialVersion)
		}
		currentSnapshot, _ := liveTrie.SnapshotJSON()
		if bytes.Equal(initialSnapshot, currentSnapshot) {
			t.Fatalf("expected test live flames snapshot shape to change over time")
		}
	})
}

func TestRunTraceWithContextRequiresRoot(t *testing.T) {
	origGetEUID := getEUID
	defer func() { getEUID = origGetEUID }()

	getEUID = func() int { return 1000 }
	err := runTraceWithContext(context.Background(), flags.NewFlags(), nil, nil)
	if !errors.Is(err, errRootPrivilegesRequired) {
		t.Fatalf("expected root-required error, got %v", err)
	}
}

func TestTuiTraceStarterFromRunTracePropagatesError(t *testing.T) {
	starter := tuiTraceStarterFromRunTrace(
		flags.NewFlags(),
		func(context.Context, flags.Config, chan<- struct{}, func(*eventLoop)) error {
			return errors.New("startup failed")
		},
	)

	err := starter(context.Background())
	if err == nil || err.Error() != "startup failed" {
		t.Fatalf("expected startup error, got %v", err)
	}
}

func TestTuiTraceStarterFromRunTraceUsesContextFilters(t *testing.T) {
	base := flags.NewFlags()
	base.PidFilter = 11
	base.TidFilter = 12

	var gotCfg flags.Config
	starter := tuiTraceStarterFromRunTrace(
		base,
		func(_ context.Context, cfg flags.Config, started chan<- struct{}, _ func(*eventLoop)) error {
			gotCfg = cfg
			close(started)
			return nil
		},
	)

	ctx := tui.ContextWithTraceFilters(context.Background(), globalfilter.Filter{
		PID:     &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 2222},
		TID:     &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 3333},
		Comm:    &globalfilter.StringFilter{Pattern: "nginx"},
		File:    &globalfilter.StringFilter{Pattern: "/var/log"},
		Syscall: &globalfilter.StringFilter{Pattern: "read"},
		FD:      &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 7},
	})
	if err := starter(ctx); err != nil {
		t.Fatalf("starter returned error: %v", err)
	}
	if gotCfg.PidFilter != 2222 {
		t.Fatalf("expected pid filter from context, got %d", gotCfg.PidFilter)
	}
	if gotCfg.TidFilter != 3333 {
		t.Fatalf("expected tid filter from context, got %d", gotCfg.TidFilter)
	}
	if gotCfg.CommFilter != "nginx" {
		t.Fatalf("expected comm filter from context, got %q", gotCfg.CommFilter)
	}
	if gotCfg.PathFilter != "/var/log" {
		t.Fatalf("expected path filter from context, got %q", gotCfg.PathFilter)
	}
	if gotCfg.GlobalFilter.Syscall == nil || gotCfg.GlobalFilter.Syscall.Pattern != "read" {
		t.Fatalf("expected syscall preserved in global filter payload, got %+v", gotCfg.GlobalFilter.Syscall)
	}
	if gotCfg.GlobalFilter.FD == nil || gotCfg.GlobalFilter.FD.Value != 7 {
		t.Fatalf("expected fd preserved in global filter payload, got %+v", gotCfg.GlobalFilter.FD)
	}
}

func TestShouldIngestTracePairAppliesFullGlobalFilter(t *testing.T) {
	pair := &event.Pair{
		EnterEv:        &types.RetEvent{TraceId: types.SYS_ENTER_READ, Pid: 1234, Tid: 1235},
		ExitEv:         &types.RetEvent{TraceId: types.SYS_EXIT_READ, Pid: 1234, Tid: 1235, Ret: -1},
		Comm:           "nginx",
		File:           file.NewFd(7, "/var/log/access.log", 0),
		Duration:       1_500_000,
		DurationToPrev: 12_000,
		Bytes:          4_096,
	}

	filter := globalfilter.Filter{
		Syscall:    &globalfilter.StringFilter{Pattern: "rea"},
		Comm:       &globalfilter.StringFilter{Pattern: "ngi"},
		File:       &globalfilter.StringFilter{Pattern: "access"},
		PID:        &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 1234},
		TID:        &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 1235},
		FD:         &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 7},
		LatencyNs:  &globalfilter.NumericFilter{Op: globalfilter.OpGt, Value: 1_000_000},
		GapNs:      &globalfilter.NumericFilter{Op: globalfilter.OpLte, Value: 12_000},
		Bytes:      &globalfilter.NumericFilter{Op: globalfilter.OpLt, Value: 8_192},
		RetVal:     &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: -1},
		ErrorsOnly: true,
	}

	if !shouldIngestTracePair(filter, pair) {
		t.Fatalf("expected full filter to accept matching pair")
	}
	if shouldIngestTracePair(globalfilter.Filter{Syscall: &globalfilter.StringFilter{Pattern: "write"}}, pair) {
		t.Fatalf("expected syscall mismatch to reject pair")
	}
	if shouldIngestTracePair(globalfilter.Filter{FD: &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 99}}, pair) {
		t.Fatalf("expected fd mismatch to reject pair")
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
		flags.NewFlags(),
		func(ctx context.Context, _ flags.Config, _ chan<- struct{}, _ func(*eventLoop)) error {
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
