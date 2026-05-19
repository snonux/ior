package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/flags"
	"ior/internal/globalfilter"
	"ior/internal/parquet"
	"ior/internal/runtime"
	"ior/internal/streamrow"
	"ior/internal/types"

	parquetgo "github.com/parquet-go/parquet-go"
)

// stubDeps returns a runnerDeps with safe no-op stubs for every function
// field. Individual tests override only the functions they care about,
// keeping test setup concise and making it easy to add new fields without
// updating every test.
func stubDeps() runnerDeps {
	return runnerDeps{
		getEUID:              func() int { return 0 },
		runTrace:             func(flags.Config) error { return nil },
		runParquet:           func(flags.Config) error { return nil },
		runTraceWithContext:  func(context.Context, flags.Config, chan<- struct{}, func(*eventLoop)) error { return nil },
		runTUI:               func(flags.Config, runtime.TraceStarter) error { return nil },
		runTUITestFlames:     func(flags.Config, runtime.TraceStarter) error { return nil },
		runTUITestLiveFlames: func(flags.Config, runtime.TraceStarter) error { return nil },
	}
}

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

	withParquet := base
	withParquet.ParquetPath = "trace.parquet"
	if !shouldRunTraceMode(withParquet) {
		t.Fatalf("expected parquet mode to use trace mode")
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

	withParquet := base
	withParquet.ParquetPath = "trace.parquet"
	if !shouldAutoStopByDuration(withParquet) {
		t.Fatalf("expected parquet mode to auto-stop by duration")
	}

	withPprof := base
	withPprof.PprofEnable = true
	if shouldAutoStopByDuration(withPprof) {
		t.Fatalf("expected pprof flag alone not to auto-stop by duration")
	}
}

func TestDispatchRunUsesTraceModeWhenRequested(t *testing.T) {
	traceCalled := false
	deps := stubDeps()
	deps.runTrace = func(flags.Config) error {
		traceCalled = true
		return nil
	}
	deps.runParquet = func(flags.Config) error {
		t.Fatalf("runParquet should not be called in plain trace mode")
		return nil
	}
	tuiCalled := false
	deps.runTUI = func(flags.Config, runtime.TraceStarter) error {
		tuiCalled = true
		return nil
	}
	deps.runTUITestFlames = func(flags.Config, runtime.TraceStarter) error {
		t.Fatalf("runTUITestFlames should not be called in trace mode")
		return nil
	}
	deps.runTUITestLiveFlames = func(flags.Config, runtime.TraceStarter) error {
		t.Fatalf("runTUITestLiveFlames should not be called in trace mode")
		return nil
	}

	cfg := flags.Config{PlainMode: true}
	if err := dispatchRunWithDeps(cfg, deps); err != nil {
		t.Fatalf("dispatchRunWithDeps returned error: %v", err)
	}
	if !traceCalled {
		t.Fatalf("expected runTrace to be called")
	}
	if tuiCalled {
		t.Fatalf("did not expect runTUI to be called")
	}
}

func TestDispatchRunUsesHeadlessParquetModeWhenRequested(t *testing.T) {
	traceCalled := false
	parquetCalled := false
	tuiCalled := false
	deps := stubDeps()
	deps.runTrace = func(flags.Config) error {
		traceCalled = true
		return nil
	}
	deps.runParquet = func(flags.Config) error {
		parquetCalled = true
		return nil
	}
	deps.runTUI = func(flags.Config, runtime.TraceStarter) error {
		tuiCalled = true
		return nil
	}
	deps.runTUITestFlames = func(flags.Config, runtime.TraceStarter) error {
		t.Fatalf("runTUITestFlames should not be called in parquet mode")
		return nil
	}
	deps.runTUITestLiveFlames = func(flags.Config, runtime.TraceStarter) error {
		t.Fatalf("runTUITestLiveFlames should not be called in parquet mode")
		return nil
	}

	cfg := flags.Config{ParquetPath: "trace.parquet"}
	if err := dispatchRunWithDeps(cfg, deps); err != nil {
		t.Fatalf("dispatchRunWithDeps returned error: %v", err)
	}
	if !parquetCalled {
		t.Fatalf("expected runParquet to be called")
	}
	if traceCalled {
		t.Fatalf("did not expect runTrace to be called")
	}
	if tuiCalled {
		t.Fatalf("did not expect runTUI to be called")
	}
}

func TestDispatchRunUsesTUIWhenOnlyPprofEnabled(t *testing.T) {
	traceCalled := false
	tuiCalled := false
	deps := stubDeps()
	deps.runTrace = func(flags.Config) error {
		traceCalled = true
		return nil
	}
	deps.runTUI = func(flags.Config, runtime.TraceStarter) error {
		tuiCalled = true
		return nil
	}
	deps.runTUITestFlames = func(flags.Config, runtime.TraceStarter) error {
		t.Fatalf("runTUITestFlames should not be called for regular TUI mode")
		return nil
	}
	deps.runTUITestLiveFlames = func(flags.Config, runtime.TraceStarter) error {
		t.Fatalf("runTUITestLiveFlames should not be called for regular TUI mode")
		return nil
	}

	cfg := flags.Config{PprofEnable: true}
	if err := dispatchRunWithDeps(cfg, deps); err != nil {
		t.Fatalf("dispatchRunWithDeps returned error: %v", err)
	}
	if traceCalled {
		t.Fatalf("did not expect runTrace when only -pprof is enabled")
	}
	if !tuiCalled {
		t.Fatalf("expected runTUI to be called")
	}
}

func TestDispatchRunUsesTUIStarterWhenNotPlain(t *testing.T) {
	traceDone := make(chan struct{}, 1)
	deps := stubDeps()
	deps.runTraceWithContext = func(_ context.Context, _ flags.Config, started chan<- struct{}, configure func(*eventLoop)) error {
		if configure != nil {
			configure(&eventLoop{})
		}
		close(started)
		traceDone <- struct{}{}
		return nil
	}

	tuiCalled := false
	deps.runTUI = func(_ flags.Config, starter runtime.TraceStarter) error {
		tuiCalled = true
		if starter == nil {
			t.Fatalf("expected non-nil starter")
		}
		if err := starter(context.Background()); err != nil {
			t.Fatalf("starter returned error: %v", err)
		}
		return nil
	}
	deps.runTUITestFlames = func(flags.Config, runtime.TraceStarter) error {
		t.Fatalf("runTUITestFlames should not be called for normal starter path")
		return nil
	}
	deps.runTUITestLiveFlames = func(flags.Config, runtime.TraceStarter) error {
		t.Fatalf("runTUITestLiveFlames should not be called for normal starter path")
		return nil
	}

	cfg := flags.Config{}
	if err := dispatchRunWithDeps(cfg, deps); err != nil {
		t.Fatalf("dispatchRunWithDeps returned error: %v", err)
	}
	if !tuiCalled {
		t.Fatalf("expected runTUI to be called")
	}

	select {
	case <-traceDone:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("expected starter to launch runTraceWithContext")
	}
}

func TestDispatchRunUsesTestFlamesModeWhenRequested(t *testing.T) {
	traceCalled := false
	regularTUICalled := false
	testFlamesCalled := false
	deps := stubDeps()
	deps.runTrace = func(flags.Config) error {
		traceCalled = true
		return nil
	}
	deps.runTUI = func(flags.Config, runtime.TraceStarter) error {
		regularTUICalled = true
		return nil
	}
	deps.runTUITestFlames = func(_ flags.Config, starter runtime.TraceStarter) error {
		testFlamesCalled = true
		if starter == nil {
			t.Fatalf("expected non-nil starter for test flames mode")
		}
		return starter(context.Background())
	}
	deps.runTUITestLiveFlames = func(flags.Config, runtime.TraceStarter) error {
		t.Fatalf("runTUITestLiveFlames should not be called for --testflames")
		return nil
	}

	cfg := flags.Config{TestFlames: true}
	if err := dispatchRunWithDeps(cfg, deps); err != nil {
		t.Fatalf("dispatchRunWithDeps returned error: %v", err)
	}
	if traceCalled {
		t.Fatalf("did not expect runTrace for test flames mode")
	}
	if regularTUICalled {
		t.Fatalf("did not expect runTUI for test flames mode")
	}
	if !testFlamesCalled {
		t.Fatalf("expected runTUITestFlames to be called")
	}
}

func TestDispatchRunUsesTestLiveFlamesModeWhenRequested(t *testing.T) {
	traceCalled := false
	regularTUICalled := false
	testLiveFlamesCalled := false
	deps := stubDeps()
	deps.runTrace = func(flags.Config) error {
		traceCalled = true
		return nil
	}
	deps.runTUI = func(flags.Config, runtime.TraceStarter) error {
		regularTUICalled = true
		return nil
	}
	deps.runTUITestFlames = func(flags.Config, runtime.TraceStarter) error {
		t.Fatalf("runTUITestFlames should not be called for --testliveflames")
		return nil
	}
	deps.runTUITestLiveFlames = func(_ flags.Config, starter runtime.TraceStarter) error {
		testLiveFlamesCalled = true
		if starter == nil {
			t.Fatalf("expected non-nil starter for test live flames mode")
		}
		return starter(context.Background())
	}

	cfg := flags.Config{TestLiveFlames: true}
	if err := dispatchRunWithDeps(cfg, deps); err != nil {
		t.Fatalf("dispatchRunWithDeps returned error: %v", err)
	}
	if traceCalled {
		t.Fatalf("did not expect runTrace for test live flames mode")
	}
	if regularTUICalled {
		t.Fatalf("did not expect runTUI for test live flames mode")
	}
	if !testLiveFlamesCalled {
		t.Fatalf("expected runTUITestLiveFlames to be called")
	}
}

// TestDispatchRunRequiresRootForTUI verifies that the TUI mode handler
// enforces the root-privilege gate via deps.getEUID.
func TestDispatchRunRequiresRootForTUI(t *testing.T) {
	deps := stubDeps()
	deps.getEUID = func() int { return 1000 } // non-root
	deps.runTUI = func(flags.Config, runtime.TraceStarter) error {
		t.Fatalf("runTUI must not be called when not root")
		return nil
	}

	cfg := flags.Config{}
	err := dispatchRunWithDeps(cfg, deps)
	if !errors.Is(err, errRootPrivilegesRequired) {
		t.Fatalf("expected root-required error, got %v", err)
	}
}

// TestDispatchRunRequiresRootForPlainTrace verifies that the plain trace
// mode handler enforces the root-privilege gate via deps.getEUID.
func TestDispatchRunRequiresRootForPlainTrace(t *testing.T) {
	deps := stubDeps()
	deps.getEUID = func() int { return 1000 } // non-root
	deps.runTrace = func(flags.Config) error {
		t.Fatalf("runTrace must not be called when not root")
		return nil
	}

	cfg := flags.Config{PlainMode: true}
	err := dispatchRunWithDeps(cfg, deps)
	if !errors.Is(err, errRootPrivilegesRequired) {
		t.Fatalf("expected root-required error, got %v", err)
	}
}

// TestDispatchRunRequiresRootForParquet verifies that the headless Parquet
// mode handler enforces the root-privilege gate via deps.getEUID.
func TestDispatchRunRequiresRootForParquet(t *testing.T) {
	deps := stubDeps()
	deps.getEUID = func() int { return 1000 } // non-root
	deps.runParquet = func(flags.Config) error {
		t.Fatalf("runParquet must not be called when not root")
		return nil
	}

	cfg := flags.Config{ParquetPath: "trace.parquet"}
	err := dispatchRunWithDeps(cfg, deps)
	if !errors.Is(err, errRootPrivilegesRequired) {
		t.Fatalf("expected root-required error, got %v", err)
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

func TestValidateRunConfigRejectsParquetWithPlain(t *testing.T) {
	cfg := flags.Config{ParquetPath: "trace.parquet", PlainMode: true}
	err := validateRunConfig(cfg)
	if err == nil {
		t.Fatalf("expected error for -parquet with -plain")
	}
	if err.Error() != "-parquet and -plain are mutually exclusive" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRunConfigRejectsParquetWithContentFilters(t *testing.T) {
	cfg := flags.Config{
		ParquetPath: "trace.parquet",
		CommFilter:  "nginx",
	}
	err := validateRunConfig(cfg)
	if err == nil {
		t.Fatalf("expected error for -parquet with content filters")
	}
	if err.Error() != "-parquet cannot be combined with content filters (-comm, -path, -tid)" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRunConfigAllowsParquetWithPIDFilter(t *testing.T) {
	cfg := flags.Config{ParquetPath: "trace.parquet", PidFilter: 42}
	if err := validateRunConfig(cfg); err != nil {
		t.Fatalf("expected -parquet with -pid to be accepted, got %v", err)
	}
}

func TestValidateRunConfigRejectsParquetWithGlobalFilter(t *testing.T) {
	cfg := flags.Config{
		ParquetPath: "trace.parquet",
		GlobalFilter: globalfilter.Filter{
			Syscall: &globalfilter.StringFilter{Pattern: "read"},
		},
	}
	err := validateRunConfig(cfg)
	if err == nil {
		t.Fatalf("expected error for -parquet with global filter")
	}
	if err.Error() != "-parquet cannot be combined with content filters (-comm, -path, -tid)" {
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

	ctx := runtime.ContextWithTraceFilters(context.Background(), globalfilter.Filter{
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
	if gotCfg.CommFilter != "" {
		t.Fatalf("expected legacy comm filter to remain unused, got %q", gotCfg.CommFilter)
	}
	if gotCfg.PathFilter != "" {
		t.Fatalf("expected legacy path filter to remain unused, got %q", gotCfg.PathFilter)
	}
	if gotCfg.GlobalFilter.Comm == nil || gotCfg.GlobalFilter.Comm.Pattern != "nginx" {
		t.Fatalf("expected comm preserved in global filter payload, got %+v", gotCfg.GlobalFilter.Comm)
	}
	if gotCfg.GlobalFilter.File == nil || gotCfg.GlobalFilter.File.Pattern != "/var/log" {
		t.Fatalf("expected file preserved in global filter payload, got %+v", gotCfg.GlobalFilter.File)
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

func TestHeadlessParquetTraceConfigPreservesPIDAndClearsContentFilters(t *testing.T) {
	cfg := flags.Config{
		ParquetPath: "trace.parquet",
		PidFilter:   1234,
		TidFilter:   5678,
		CommFilter:  "nginx",
		PathFilter:  "/var/log",
		GlobalFilter: globalfilter.Filter{
			Syscall: &globalfilter.StringFilter{Pattern: "read"},
		},
	}

	got := headlessParquetTraceConfig(cfg)
	if got.PidFilter != 1234 || got.TidFilter != -1 {
		t.Fatalf("pid/tid filters = %d/%d, want 1234/-1", got.PidFilter, got.TidFilter)
	}
	if got.CommFilter != "" || got.PathFilter != "" {
		t.Fatalf("comm/path filters = %q/%q, want empty", got.CommFilter, got.PathFilter)
	}
	if got.GlobalFilter.IsActive() {
		t.Fatalf("expected sanitized global filter to be empty, got %+v", got.GlobalFilter)
	}
}

func TestHeadlessParquetSinkRecordsRows(t *testing.T) {
	recorder := parquet.NewRecorder(parquet.RecorderConfig{
		BatchSize:     1,
		FlushInterval: time.Hour,
	})
	path := filepath.Join(t.TempDir(), "headless.parquet")
	if err := recorder.Start(path, parquet.StartOptions{
		Metadata: parquet.FileMetadata{Mode: "headless"},
	}); err != nil {
		t.Fatalf("recorder.Start() error = %v", err)
	}

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	sink := newHeadlessParquetSink(recorder, cancel)
	el := &eventLoop{}
	sink.configure(el)

	el.printCb(testTracePair(1, "keep"))
	el.printCb(testTracePair(2, "keep"))

	if err := recorder.Stop(); err != nil {
		t.Fatalf("recorder.Stop() error = %v", err)
	}
	if err := sink.err(); err != nil {
		t.Fatalf("sink.err() = %v, want nil", err)
	}

	rows := readRecordedParquet(t, path)
	if len(rows) != 2 {
		t.Fatalf("recorded rows = %d, want 2", len(rows))
	}
	if rows[0].Seq != 1 || rows[1].Seq != 2 {
		t.Fatalf("recorded seq = %d,%d, want 1,2", rows[0].Seq, rows[1].Seq)
	}
	if rows[0].FilterEpoch != 0 || rows[1].FilterEpoch != 0 {
		t.Fatalf("recorded filter epochs = %d,%d, want 0,0", rows[0].FilterEpoch, rows[1].FilterEpoch)
	}
	if rows[0].Comm != "keep" || rows[1].Syscall != "openat" {
		t.Fatalf("unexpected recorded rows: %+v %+v", rows[0], rows[1])
	}
	if rows[0].Family != "FS" || rows[1].Family != "FS" {
		t.Fatalf("recorded family tags = %q,%q, want FS,FS", rows[0].Family, rows[1].Family)
	}
}

func TestTuiTraceStarterFromRunTracePersistsRecorderAcrossRestarts(t *testing.T) {
	recorder := parquet.NewRecorder(parquet.RecorderConfig{
		BatchSize:     1,
		FlushInterval: time.Hour,
	})
	if err := recorder.Start(filepath.Join(t.TempDir(), "trace"), parquet.StartOptions{
		Metadata: parquet.FileMetadata{Mode: "tui"},
	}); err != nil {
		t.Fatalf("recorder.Start() error = %v", err)
	}

	bindings := &traceRuntimeBindingsStub{
		streamBuffer: streamrow.NewRingBuffer(),
		streamSeq:    streamrow.NewSequencer(0),
		recorder:     recorder,
	}
	base := flags.NewFlags()
	base.GlobalFilter = globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "keep"}}

	runs := [][]*event.Pair{
		{
			testTracePair(1, "keep"),
			testTracePair(99, "drop"),
		},
		{
			testTracePair(2, "keep"),
		},
	}
	runIndex := 0
	starter := tuiTraceStarterFromRunTrace(
		base,
		func(_ context.Context, _ flags.Config, started chan<- struct{}, configure func(*eventLoop)) error {
			el := &eventLoop{}
			configure(el)
			for _, pair := range runs[runIndex] {
				el.printCb(pair)
			}
			runIndex++
			close(started)
			return nil
		},
	)

	ctx := runtime.ContextWithRuntimeBindings(context.Background(), bindings)
	if err := starter(ctx); err != nil {
		t.Fatalf("first starter() error = %v", err)
	}
	waitForStreamRows(t, bindings.streamBuffer, 1)

	bindings.filterEpoch = 1
	if err := starter(ctx); err != nil {
		t.Fatalf("second starter() error = %v", err)
	}
	waitForStreamRows(t, bindings.streamBuffer, 2)

	if err := recorder.Stop(); err != nil {
		t.Fatalf("recorder.Stop() error = %v", err)
	}

	status := recorder.Status()
	if status.LastError != nil {
		t.Fatalf("recorder status error = %v, want nil", status.LastError)
	}

	got := readRecordedParquet(t, status.Path)
	if len(got) != 2 {
		t.Fatalf("recorded rows = %d, want 2", len(got))
	}
	if got[0].Seq != 1 || got[1].Seq != 2 {
		t.Fatalf("recorded seq = %d,%d, want 1,2", got[0].Seq, got[1].Seq)
	}
	if got[0].FilterEpoch != 0 || got[1].FilterEpoch != 1 {
		t.Fatalf("recorded filter epochs = %d,%d, want 0,1", got[0].FilterEpoch, got[1].FilterEpoch)
	}
	if snapshot := bindings.streamBuffer.Snapshot(); len(snapshot) != 2 {
		t.Fatalf("stream buffer rows = %d, want 2", len(snapshot))
	}
}

// TestTuiTraceStarterAppliesLiveFilterSwapInPlace exercises the in-place
// filter swap path: after the trace is running, calling the registered
// SetLiveFilterSetter callback should change which events the eventloop's
// printCb admits, without any restart of the trace pipeline.
func TestTuiTraceStarterAppliesLiveFilterSwapInPlace(t *testing.T) {
	bindings := &traceRuntimeBindingsStub{
		streamBuffer: streamrow.NewRingBuffer(),
		streamSeq:    streamrow.NewSequencer(0),
	}
	base := flags.NewFlags()
	base.GlobalFilter = globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "keep"}}

	// release lets the test hold the fake starter open while assertions
	// run. In production, startTrace blocks on el.run for the trace's
	// lifetime, so the runtime bindings keep their live filter setter
	// registered the whole time. Returning immediately would race against
	// the trace starter's deferred SetLiveFilterSetter(nil) cleanup.
	release := make(chan struct{})
	captured := make(chan *eventLoop, 1)
	starter := tuiTraceStarterFromRunTrace(
		base,
		func(_ context.Context, _ flags.Config, started chan<- struct{}, configure func(*eventLoop)) error {
			el := &eventLoop{}
			configure(el)
			captured <- el
			close(started)
			<-release
			return nil
		},
	)

	ctx := runtime.ContextWithRuntimeBindings(context.Background(), bindings)
	starterErr := make(chan error, 1)
	go func() { starterErr <- starter(ctx) }()

	el := <-captured

	// Initial filter from base.GlobalFilter accepts only comm=="keep".
	el.printCb(testTracePair(1, "keep"))
	el.printCb(testTracePair(2, "drop"))
	if got := bindings.streamBuffer.Len(); got != 1 {
		t.Fatalf("stream rows after initial filter = %d, want 1", got)
	}

	// Trace starter must have registered an in-place filter setter.
	setter := bindings.currentLiveFilterSetter()
	if setter == nil {
		t.Fatalf("expected SetLiveFilterSetter to receive a non-nil callback")
	}

	// Swap to a filter that accepts only comm=="drop". No restart should
	// happen — the same eventloop now emits the previously-dropped events.
	setter(globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "drop"}})
	el.printCb(testTracePair(3, "keep"))
	el.printCb(testTracePair(4, "drop"))
	if got := bindings.streamBuffer.Len(); got != 2 {
		t.Fatalf("stream rows after live swap = %d, want 2", got)
	}

	close(release)
	if err := <-starterErr; err != nil {
		t.Fatalf("starter() error = %v", err)
	}
}

// traceRuntimeBindingsStub is a test double for runtime.TraceRuntimeBindings
// that records injected stream sources and exposes the live-filter setter for
// assertions.
type traceRuntimeBindingsStub struct {
	streamBuffer *streamrow.RingBuffer
	streamSource runtime.StreamSource
	streamSeq    *streamrow.Sequencer
	recorder     *parquet.Recorder
	filterEpoch  uint64
	// mu guards liveFilterSetter, which is mutated from the trace-starter
	// goroutine (via SetLiveFilterSetter) and read from the test goroutine
	// when invoking the in-place swap.
	mu               sync.Mutex
	liveFilterSetter func(globalfilter.Filter)
}

func (b *traceRuntimeBindingsStub) SetDashboardSnapshotSource(runtime.SnapshotSource) {}

func (b *traceRuntimeBindingsStub) SetEventStreamSource(source runtime.StreamSource) {
	b.streamSource = source
}

func (b *traceRuntimeBindingsStub) SetLiveTrie(runtime.LiveTrieSource) {}

func (b *traceRuntimeBindingsStub) SetProbeManager(runtime.ProbeManager) {}

func (b *traceRuntimeBindingsStub) SetLiveFilterSetter(setter func(globalfilter.Filter)) {
	b.mu.Lock()
	b.liveFilterSetter = setter
	b.mu.Unlock()
}

func (b *traceRuntimeBindingsStub) currentLiveFilterSetter() func(globalfilter.Filter) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.liveFilterSetter
}

func (b *traceRuntimeBindingsStub) StreamBuffer() runtime.StreamSource {
	return b.streamBuffer
}

func (b *traceRuntimeBindingsStub) Recorder() *parquet.Recorder {
	return b.recorder
}

func (b *traceRuntimeBindingsStub) StreamSequencer() *streamrow.Sequencer {
	return b.streamSeq
}

func (b *traceRuntimeBindingsStub) FilterEpoch() uint64 {
	return b.filterEpoch
}

func testTracePair(seq uint64, comm string) *event.Pair {
	enter := &types.OpenEvent{TraceId: types.SYS_ENTER_OPENAT, Time: seq * 10, Pid: 42, Tid: 84}
	exit := &types.RetEvent{TraceId: types.SYS_EXIT_OPENAT, Time: seq*10 + 1, Ret: int64(seq), Pid: 42, Tid: 84}
	pair := event.NewPair(enter)
	pair.ExitEv = exit
	pair.File = file.NewFd(int32(seq), "/tmp/test", 0)
	pair.Comm = comm
	pair.Duration = seq
	pair.DurationToPrev = seq + 1
	pair.Bytes = seq + 2
	return pair
}

// waitForStreamRows asserts that buffer.Len() equals want immediately.
// starter() returns only after the trace goroutine closes the started channel,
// which happens after all printCb calls have completed and pushed their rows
// into the buffer. The channel close forms a happens-before edge that makes all
// prior writes visible to the test goroutine, so no polling or sleeping is
// needed.
func waitForStreamRows(t *testing.T, buffer *streamrow.RingBuffer, want int) {
	t.Helper()
	if got := buffer.Len(); got != want {
		t.Fatalf("stream buffer len = %d, want %d", got, want)
	}
}

func readRecordedParquet(t *testing.T, path string) []parquet.Record {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open parquet %q: %v", path, err)
	}
	defer f.Close()

	reader := parquetgo.NewGenericReader[parquet.Record](f)
	defer reader.Close()

	var rows []parquet.Record
	buf := make([]parquet.Record, 4)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			rows = append(rows, buf[:n]...)
		}
		if err == nil {
			continue
		}
		if err == io.EOF {
			return rows
		}
		t.Fatalf("read parquet rows: %v", err)
	}
}
