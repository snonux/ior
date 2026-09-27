package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	"ior/internal/statsengine"
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
		runTraceWithContext:  noopTraceRun,
		runTUI:               func(flags.Config, runtime.TraceStarter) error { return nil },
		runTUITestFlames:     func(flags.Config, runtime.TraceStarter) error { return nil },
		runTUITestLiveFlames: func(flags.Config, runtime.TraceStarter) error { return nil },
	}
}

// noopTraceRun is the stub trace run: it neither signals start nor fails.
func noopTraceRun(context.Context, flags.Config, chan<- struct{}, func(*eventLoop), traceSetupHooks) error {
	return nil
}

// captureStdoutStderr redirects the process-wide os.Stdout/os.Stderr into
// pipes and returns the read ends. The returned restore func puts the real
// streams back and closes the pipe write ends; it is idempotent and also
// registered via t.Cleanup as a panic safety net, so callers may simply defer
// it before draining the pipes.
func captureStdoutStderr(t *testing.T) (stdout, stderr io.Reader, restore func()) {
	t.Helper()
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = wOut, wErr
	var once sync.Once
	restore = func() {
		once.Do(func() {
			os.Stdout, os.Stderr = oldOut, oldErr
			_ = wOut.Close()
			_ = wErr.Close()
		})
	}
	t.Cleanup(restore)
	return rOut, rErr, restore
}

// TestPrintStartupBannerPlainModeRoutesBannerToStderr is the stdout-purity
// guard for -plain mode: the ASCII banner is human-facing status output, so it
// must never mix with the CSV rows on stdout.
func TestPrintStartupBannerPlainModeRoutesBannerToStderr(t *testing.T) {
	stdout, stderr, restore := captureStdoutStderr(t)
	printStartupBanner(flags.Config{PlainMode: true})
	restore()

	var outBuf, errBuf bytes.Buffer
	_, _ = io.Copy(&outBuf, stdout)
	_, _ = io.Copy(&errBuf, stderr)

	if outBuf.Len() != 0 {
		t.Fatalf("plain mode wrote %d bytes to stdout, want 0: %q", outBuf.Len(), outBuf.String())
	}
	if !strings.Contains(errBuf.String(), "Next-Generation BPF I/O Syscall Tracer") {
		t.Fatalf("banner not found on stderr, got %q", errBuf.String())
	}
}

// TestPrintStartupBannerDefaultModeKeepsStdout verifies that modes with a TUI
// (or file-based output) keep printing the banner to stdout as before.
func TestPrintStartupBannerDefaultModeKeepsStdout(t *testing.T) {
	stdout, stderr, restore := captureStdoutStderr(t)
	printStartupBanner(flags.Config{})
	restore()

	var outBuf, errBuf bytes.Buffer
	_, _ = io.Copy(&outBuf, stdout)
	_, _ = io.Copy(&errBuf, stderr)

	if errBuf.Len() != 0 {
		t.Fatalf("default mode wrote %d bytes to stderr, want 0: %q", errBuf.Len(), errBuf.String())
	}
	if !strings.Contains(outBuf.String(), "Next-Generation BPF I/O Syscall Tracer") {
		t.Fatalf("banner not found on stdout, got %q", outBuf.String())
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
		t.Fatalf("expected -testflames to stay in TUI mode")
	}

	withTestLiveFlames := base
	withTestLiveFlames.TestLiveFlames = true
	if shouldRunTraceMode(withTestLiveFlames) {
		t.Fatalf("expected -testliveflames to stay in TUI mode")
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
	deps.runTraceWithContext = func(_ context.Context, _ flags.Config, started chan<- struct{}, configure func(*eventLoop), _ traceSetupHooks) error {
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
		if err := starter(context.Background(), runtime.TraceRequest{}); err != nil {
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
		return starter(context.Background(), runtime.TraceRequest{})
	}
	deps.runTUITestLiveFlames = func(flags.Config, runtime.TraceStarter) error {
		t.Fatalf("runTUITestLiveFlames should not be called for -testflames")
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
		t.Fatalf("runTUITestFlames should not be called for -testliveflames")
		return nil
	}
	deps.runTUITestLiveFlames = func(_ flags.Config, starter runtime.TraceStarter) error {
		testLiveFlamesCalled = true
		if starter == nil {
			t.Fatalf("expected non-nil starter for test live flames mode")
		}
		return starter(context.Background(), runtime.TraceRequest{})
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
		func(context.Context, flags.Config, chan<- struct{}, func(*eventLoop), traceSetupHooks) error {
			return errors.New("startup failed")
		},
	)

	err := starter(context.Background(), runtime.TraceRequest{})
	if err == nil || err.Error() != "startup failed" {
		t.Fatalf("expected startup error, got %v", err)
	}
}

func TestTuiTraceStarterFromRunTraceUsesRequestFilter(t *testing.T) {
	base := flags.NewFlags()
	base.PidFilter = 11
	base.TidFilter = 12

	var gotCfg flags.Config
	starter := tuiTraceStarterFromRunTrace(
		base,
		func(_ context.Context, cfg flags.Config, started chan<- struct{}, _ func(*eventLoop), _ traceSetupHooks) error {
			gotCfg = cfg
			close(started)
			return nil
		},
	)

	filter := globalfilter.Filter{
		PID:     &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 2222},
		TID:     &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 3333},
		Comm:    &globalfilter.StringFilter{Pattern: "nginx"},
		File:    &globalfilter.StringFilter{Pattern: "/var/log"},
		Syscall: &globalfilter.StringFilter{Pattern: "read"},
		FD:      &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 7},
	}
	if err := starter(context.Background(), runtime.TraceRequest{Filter: &filter}); err != nil {
		t.Fatalf("starter returned error: %v", err)
	}
	// The starter clones the request filter: the caller's later edits must
	// not reach the running session's config.
	filter.Comm.Pattern = "mutated"
	if gotCfg.PidFilter != 2222 {
		t.Fatalf("expected pid filter from request, got %d", gotCfg.PidFilter)
	}
	if gotCfg.TidFilter != 3333 {
		t.Fatalf("expected tid filter from request, got %d", gotCfg.TidFilter)
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

// TestShouldIngestTracePairMatchesOnEitherRenameName pins that the TUI's
// second filtering stage calls the same MatchPair as the event-loop
// checkpoint, whose file dimension is either-name-aware for rename pairs
// (Candidate.OldFileValue). Before the rule was centralized this stage had
// to remember to pick the wide variant; picking the plain one silently
// narrowed the contract, so a `-path <oldname>` filter kept a rename row in
// -plain output but dropped it on the dashboard.
func TestShouldIngestTracePairMatchesOnEitherRenameName(t *testing.T) {
	pair := &event.Pair{
		File:    file.NewOldnameNewname([]byte("/tmp/old.txt"), []byte("/tmp/new.txt")),
		Oldname: "/tmp/old.txt",
	}

	oldnameFilter := globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: "old.txt"}}
	if !shouldIngestTracePair(oldnameFilter, pair) {
		t.Fatal("a rename matched on its oldname must reach the dashboard, as it does in -plain output")
	}

	newnameFilter := globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: "new.txt"}}
	if !shouldIngestTracePair(newnameFilter, pair) {
		t.Fatal("a rename matched on its newname must reach the dashboard")
	}

	// Widening the file dimension must not turn into a bypass: a pattern
	// matching neither name still rejects, and so does a mismatch on any
	// other dimension.
	otherFilter := globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: "unrelated.txt"}}
	if shouldIngestTracePair(otherFilter, pair) {
		t.Fatal("a pattern matching neither name must still reject the pair")
	}
	fdFilter := globalfilter.Filter{FD: &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 99}}
	if shouldIngestTracePair(fdFilter, pair) {
		t.Fatal("an oldname match must not bypass the other filter dimensions")
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
		func(ctx context.Context, _ flags.Config, _ chan<- struct{}, _ func(*eventLoop), _ traceSetupHooks) error {
			<-ctx.Done()
			return ctx.Err()
		},
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := starter(ctx, runtime.TraceRequest{})
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

func TestHeadlessParquetSinkQueueOverflowIsNotFatal(t *testing.T) {
	// Queue overflow sheds the single row and keeps the session alive, so it
	// must not cancel the headless trace run; real recorder errors must.
	if isFatalRecorderError(nil) {
		t.Fatalf("isFatalRecorderError(nil) = true, want false")
	}
	if isFatalRecorderError(parquet.ErrRecorderQueueFull) {
		t.Fatalf("isFatalRecorderError(ErrRecorderQueueFull) = true, want false")
	}
	joined := errors.Join(parquet.ErrRecorderQueueFull, errors.New("overflow detail"))
	if isFatalRecorderError(joined) {
		t.Fatalf("isFatalRecorderError(joined queue-full) = true, want false")
	}
	if !isFatalRecorderError(parquet.ErrRecorderNotActive) {
		t.Fatalf("isFatalRecorderError(ErrRecorderNotActive) = false, want true")
	}
	if !isFatalRecorderError(errors.New("writer boom")) {
		t.Fatalf("isFatalRecorderError(plain error) = false, want true")
	}
}

func TestHeadlessParquetSinkFailsRunOnRecorderError(t *testing.T) {
	// A recorder that never started rejects rows with ErrRecorderNotActive;
	// the sink must treat that as fatal: cancel the context and record the
	// error for the run result.
	recorder := parquet.NewRecorder(parquet.RecorderConfig{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sink := newHeadlessParquetSink(recorder, cancel)
	el := &eventLoop{}
	sink.configure(el)

	el.printCb(testTracePair(1, "keep"))

	if !errors.Is(sink.err(), parquet.ErrRecorderNotActive) {
		t.Fatalf("sink.err() = %v, want %v", sink.err(), parquet.ErrRecorderNotActive)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatalf("expected the trace context to be cancelled after a fatal recorder error")
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
		func(_ context.Context, _ flags.Config, started chan<- struct{}, configure func(*eventLoop), _ traceSetupHooks) error {
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

	ctx := context.Background()
	if err := starter(ctx, runtime.TraceRequest{Bindings: bindings}); err != nil {
		t.Fatalf("first starter() error = %v", err)
	}
	waitForStreamRows(t, bindings.streamBuffer, 1)

	bindings.filterEpoch = 1
	if err := starter(ctx, runtime.TraceRequest{Bindings: bindings}); err != nil {
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
		streamBuffer:               streamrow.NewRingBuffer(),
		streamSeq:                  streamrow.NewSequencer(0),
		liveFilterUnregisteredDone: make(chan struct{}, 1),
	}
	base := flags.NewFlags()
	base.GlobalFilter = globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "keep"}}

	// release lets the test hold the fake starter open while assertions
	// run. In production, startTrace blocks on el.run for the trace's
	// lifetime, so the runtime bindings keep their live filter setter
	// registered the whole time. Returning immediately would race against
	// the trace starter's ownership-aware cleanup.
	release := make(chan struct{})
	captured := make(chan *eventLoop, 1)
	starter := tuiTraceStarterFromRunTrace(
		base,
		func(_ context.Context, _ flags.Config, started chan<- struct{}, configure func(*eventLoop), _ traceSetupHooks) error {
			el := &eventLoop{}
			configure(el)
			captured <- el
			close(started)
			<-release
			return nil
		},
	)

	ctx := context.Background()
	starterErr := make(chan error, 1)
	go func() { starterErr <- starter(ctx, runtime.TraceRequest{Bindings: bindings}) }()

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
	select {
	case <-bindings.liveFilterUnregisteredDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the trace to unregister its live filter setter")
	}
	if setter := bindings.currentLiveFilterSetter(); setter != nil {
		t.Fatal("expected the live filter setter to be unregistered after the trace stopped")
	}
}

// TestTuiTraceStarterSlowTeardownKeepsNextSessionLiveFilterSetter exercises
// the whole registration lifetime across overlapping trace sessions. Session
// one stops only after session two has installed its setter; its late cleanup
// must not disable in-place filter swaps for the newer session.
func TestTuiTraceStarterSlowTeardownKeepsNextSessionLiveFilterSetter(t *testing.T) {
	bindings := &traceRuntimeBindingsStub{
		streamBuffer:               streamrow.NewRingBuffer(),
		streamSeq:                  streamrow.NewSequencer(0),
		liveFilterUnregisteredDone: make(chan struct{}, 2),
	}
	base := flags.NewFlags()
	base.GlobalFilter = globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "initial"}}
	ctx := context.Background()

	startSession := func() (*eventLoop, chan struct{}) {
		t.Helper()
		release := make(chan struct{})
		captured := make(chan *eventLoop, 1)
		starter := tuiTraceStarterFromRunTrace(
			base,
			func(_ context.Context, _ flags.Config, started chan<- struct{}, configure func(*eventLoop), _ traceSetupHooks) error {
				el := &eventLoop{}
				configure(el)
				captured <- el
				close(started)
				<-release
				return nil
			},
		)
		if err := starter(ctx, runtime.TraceRequest{Bindings: bindings}); err != nil {
			t.Fatalf("starter() error = %v", err)
		}
		return <-captured, release
	}
	waitForUnregister := func() {
		t.Helper()
		select {
		case <-bindings.liveFilterUnregisteredDone:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for a trace session to unregister its live filter setter")
		}
	}

	firstEventLoop, finishFirstSession := startSession()
	secondEventLoop, finishSecondSession := startSession()

	close(finishFirstSession)
	waitForUnregister()

	setter := bindings.currentLiveFilterSetter()
	if setter == nil {
		t.Fatal("slow teardown from the first session unregistered the second session's setter")
	}
	setter(globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "second"}})
	if got := secondEventLoop.Filter().Comm; got == nil || got.Pattern != "second" {
		t.Fatalf("second session filter = %+v, want comm pattern second", got)
	}
	if got := firstEventLoop.Filter().Comm; got == nil || got.Pattern != "initial" {
		t.Fatalf("first session filter = %+v, want its unchanged initial filter", got)
	}

	close(finishSecondSession)
	waitForUnregister()
	if setter := bindings.currentLiveFilterSetter(); setter != nil {
		t.Fatal("second session teardown left its live filter setter registered")
	}
}

// TestTuiTraceStarterInPlaceFilterSwapAdvancesRecordedEpoch regresses audit
// finding M9: rows recorded after an in-place filter swap must carry the
// bindings' live filter epoch, not the value frozen at trace wiring time.
func TestTuiTraceStarterInPlaceFilterSwapAdvancesRecordedEpoch(t *testing.T) {
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

	// release keeps the starter alive so the live filter setter stays
	// registered while the test drives pairs through the print callback.
	// Returning immediately would race against the trace starter's
	// ownership-aware cleanup (see
	// TestTuiTraceStarterAppliesLiveFilterSwapInPlace).
	release := make(chan struct{})
	captured := make(chan *eventLoop, 1)
	starter := tuiTraceStarterFromRunTrace(
		base,
		func(_ context.Context, _ flags.Config, started chan<- struct{}, configure func(*eventLoop), _ traceSetupHooks) error {
			el := &eventLoop{}
			configure(el)
			captured <- el
			close(started)
			<-release
			return nil
		},
	)

	ctx := context.Background()
	starterErr := make(chan error, 1)
	go func() { starterErr <- starter(ctx, runtime.TraceRequest{Bindings: bindings}) }()

	el := <-captured

	// Row while the initial filter (epoch 0) is active.
	el.printCb(testTracePair(1, "keep"))
	waitForStreamRows(t, bindings.streamBuffer, 1)

	// In-place filter swap: the TUI advances the epoch and pushes the new
	// filter into the running pipeline via the registered setter, without a
	// trace restart or runtime re-wiring.
	bindings.filterEpoch = 1
	setter := bindings.currentLiveFilterSetter()
	if setter == nil {
		t.Fatalf("expected live filter setter to be registered")
	}
	setter(globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "keep2"}})

	// Row recorded after the swap must carry the advanced epoch.
	el.printCb(testTracePair(2, "keep2"))
	waitForStreamRows(t, bindings.streamBuffer, 2)

	close(release)
	if err := <-starterErr; err != nil {
		t.Fatalf("starter() error = %v", err)
	}

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
		t.Fatalf("recorded filter epochs = %d,%d, want 0,1 (in-place swap must advance the recorded epoch)", got[0].FilterEpoch, got[1].FilterEpoch)
	}
}

func TestTuiTraceStarterSurfacesAggregateOnlySyscallInSnapshot(t *testing.T) {
	bindings := &traceRuntimeBindingsStub{
		streamBuffer: streamrow.NewRingBuffer(),
		streamSeq:    streamrow.NewSequencer(0),
	}
	base := flags.NewFlags()
	base.SyscallSamplingRates["openat"] = 0

	starter := tuiTraceStarterFromRunTrace(
		base,
		func(_ context.Context, _ flags.Config, started chan<- struct{}, configure func(*eventLoop), _ traceSetupHooks) error {
			el := &eventLoop{}
			configure(el)
			if el.aggregateSink == nil {
				return errors.New("aggregate sink not wired")
			}

			// Simulate a sampled ring-buffer path where openat=0 suppresses
			// openat pair rows but aggregate drains still report openat counts.
			el.printCb(testTracePairWithTraceIDs(1, "ioworkload", types.SYS_ENTER_CLOSE, types.SYS_EXIT_CLOSE))
			el.aggregateSink.IngestSyscallAggregates([]statsengine.SyscallAggregate{
				{
					TraceID:        types.SYS_ENTER_OPENAT,
					Count:          7,
					TotalLatencyNs: 70,
					MinLatencyNs:   10,
					MaxLatencyNs:   10,
				},
			})
			close(started)
			return nil
		},
	)

	ctx := context.Background()
	if err := starter(ctx, runtime.TraceRequest{Bindings: bindings}); err != nil {
		t.Fatalf("starter() error = %v", err)
	}

	waitForStreamRows(t, bindings.streamBuffer, 1)
	rows := bindings.streamBuffer.Snapshot()
	if rows[0].Syscall != "close" {
		t.Fatalf("stream syscall = %q, want close", rows[0].Syscall)
	}
	for _, row := range rows {
		if row.Syscall == "openat" {
			t.Fatalf("did not expect openat in stream rows under aggregate-only path")
		}
	}

	if bindings.snapshotSource == nil {
		t.Fatalf("expected dashboard snapshot source to be wired")
	}
	snap, err := bindings.snapshotSource.Snapshot()
	if err != nil {
		t.Fatalf("snapshot() error = %v", err)
	}
	if snap == nil {
		t.Fatalf("expected non-nil snapshot")
	}

	openatCount := uint64(0)
	closeCount := uint64(0)
	for _, row := range snap.Syscalls() {
		switch row.TraceID {
		case types.SYS_ENTER_OPENAT:
			openatCount = row.Count
		case types.SYS_ENTER_CLOSE:
			closeCount = row.Count
		}
	}
	if openatCount != 7 {
		t.Fatalf("snapshot openat count = %d, want 7 from aggregate ingest", openatCount)
	}
	if closeCount != 1 {
		t.Fatalf("snapshot close count = %d, want 1 from stream pair", closeCount)
	}
}

// traceRuntimeBindingsStub is a test double for runtime.TraceRuntimeBindings
// that records injected stream sources and exposes the live-filter setter for
// assertions.
type traceRuntimeBindingsStub struct {
	streamBuffer   *streamrow.RingBuffer
	streamSource   runtime.StreamSource
	snapshotSource runtime.ResettableSnapshotSource
	streamSeq      *streamrow.Sequencer
	recorder       *parquet.Recorder
	filterEpoch    uint64
	// mu guards liveFilterSetter, which is mutated from the trace-starter
	// goroutine (via SetLiveFilterSetter) and read from the test goroutine
	// when invoking the in-place swap.
	mu                         sync.Mutex
	liveFilterSetter           func(globalfilter.Filter)
	liveFilterRegistration     *struct{ marker byte }
	liveFilterUnregisteredDone chan struct{}
}

func (b *traceRuntimeBindingsStub) SetDashboardSnapshotSource(source runtime.ResettableSnapshotSource) {
	b.snapshotSource = source
}

func (b *traceRuntimeBindingsStub) SetEventStreamSource(source runtime.StreamSource) {
	b.streamSource = source
}

func (b *traceRuntimeBindingsStub) SetLiveTrie(runtime.LiveTrieSource) {}

func (b *traceRuntimeBindingsStub) SetProbeManager(runtime.ProbeManager) {}

func (b *traceRuntimeBindingsStub) SetLiveFilterSetter(setter func(globalfilter.Filter)) func() {
	registration := &struct{ marker byte }{}
	b.mu.Lock()
	b.liveFilterSetter = setter
	b.liveFilterRegistration = registration
	b.mu.Unlock()
	return func() {
		b.mu.Lock()
		if b.liveFilterRegistration == registration {
			b.liveFilterSetter = nil
			b.liveFilterRegistration = nil
		}
		unregisteredDone := b.liveFilterUnregisteredDone
		b.mu.Unlock()
		if unregisteredDone != nil {
			unregisteredDone <- struct{}{}
		}
	}
}

func (b *traceRuntimeBindingsStub) currentLiveFilterSetter() func(globalfilter.Filter) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.liveFilterSetter
}

func (b *traceRuntimeBindingsStub) StreamBuffer() runtime.EventSink {
	if b.streamBuffer == nil {
		return nil
	}
	return b.streamBuffer
}

func (b *traceRuntimeBindingsStub) Recorder() runtime.RecordingController {
	// Typed-nil guard, mirroring the real bindings: a nil recorder must come
	// back as a nil interface.
	if b.recorder == nil {
		return nil
	}
	return b.recorder
}

func (b *traceRuntimeBindingsStub) StreamSequencer() runtime.Sequencer {
	if b.streamSeq == nil {
		return nil
	}
	return b.streamSeq
}

func (b *traceRuntimeBindingsStub) FilterEpoch() uint64 {
	return b.filterEpoch
}

func testTracePair(seq uint64, comm string) *event.Pair {
	return testTracePairWithTraceIDs(seq, comm, types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT)
}

func testTracePairWithTraceIDs(seq uint64, comm string, enterID types.TraceId, exitID types.TraceId) *event.Pair {
	enter := &types.OpenEvent{TraceId: enterID, Time: seq * 10, Pid: 42, Tid: 84}
	exit := &types.RetEvent{TraceId: exitID, Time: seq*10 + 1, Ret: int64(seq), Pid: 42, Tid: 84}
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
	defer func() { _ = f.Close() }()

	reader := parquetgo.NewGenericReader[parquet.Record](f)
	defer func() { _ = reader.Close() }()

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
		if errors.Is(err, io.EOF) {
			return rows
		}
		t.Fatalf("read parquet rows: %v", err)
	}
}

// TestTuiTraceStarterSurfacesAFailureArrivingAfterStart covers the second half
// of the same defect: a trace that signals started and only then fails. The
// starter has already reported success to the TUI by that point, so nothing is
// selecting on its error channel any more; the failure has to reach the user
// through the stream buffer instead of being discarded, which is what left the
// dashboard live-looking and empty.
func TestTuiTraceStarterSurfacesAFailureArrivingAfterStart(t *testing.T) {
	bindings := &traceRuntimeBindingsStub{
		streamBuffer: streamrow.NewRingBuffer(),
		streamSeq:    streamrow.NewSequencer(0),
	}
	// The fake must not return until the starter has, or the failure is not
	// the "arrives after start" case this test is about: with both the
	// started and error channels ready at once, the starter's select picks
	// uniformly at random and roughly 1 run in 100 takes the error arm and
	// returns the failure directly.
	released := make(chan struct{})
	starter := tuiTraceStarterFromRunTrace(
		flags.NewFlags(),
		func(_ context.Context, _ flags.Config, started chan<- struct{}, _ func(*eventLoop), _ traceSetupHooks) error {
			close(started)
			<-released
			return errors.New("get syscall_aggregate_map: not found")
		},
	)

	ctx := context.Background()
	err := starter(ctx, runtime.TraceRequest{Bindings: bindings})
	close(released)
	if err != nil {
		t.Fatalf("starter() error = %v, want nil: the trace did signal start", err)
	}

	rows := waitForStreamRowsEventually(t, bindings.streamBuffer, 1)
	if !rows[0].IsError || rows[0].Syscall != "warning" {
		t.Fatalf("late trace failure row = %+v, want a warning row", rows[0])
	}
	if !strings.Contains(rows[0].FileName, "syscall_aggregate_map") {
		t.Fatalf("late trace failure message = %q, want the starter's error", rows[0].FileName)
	}
}

// TestTuiTraceStarterKeepsACancelledStartSilent pins the second silence rule.
// A setup failure that loses the race with a stop is not something to show:
// the user asked for the trace to end, and the stream buffer it would land in
// is the TUI-owned one that gets reset in place and handed to the *next*
// session, so the message would surface under a trace it has nothing to do
// with. Gating on the error's identity rather than the context is what used to
// let that through - a cancelled starter returns context.Canceled, but the
// trace goroutine's own error is whatever really failed.
func TestTuiTraceStarterKeepsACancelledStartSilent(t *testing.T) {
	bindings := &traceRuntimeBindingsStub{
		streamBuffer: streamrow.NewRingBuffer(),
		streamSeq:    streamrow.NewSequencer(0),
	}
	released := make(chan struct{})
	starter := tuiTraceStarterFromRunTrace(
		flags.NewFlags(),
		func(_ context.Context, _ flags.Config, _ chan<- struct{}, _ func(*eventLoop), _ traceSetupHooks) error {
			<-released
			return errors.New("setup BPF module: attach tracepoints: no such file or directory")
		},
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := starter(ctx, runtime.TraceRequest{Bindings: bindings})
	close(released)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("starter() error = %v, want context.Canceled", err)
	}

	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		if rows := bindings.streamBuffer.Snapshot(); len(rows) != 0 {
			t.Fatalf("cancelled start pushed %+v; a trace the user stopped must not warn, least of all into the next session's stream", rows[0])
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestTuiTraceStarterReportsAStopEvenWhenTheFailureIsReady covers the race the
// silence rule has to survive. When a stop lands at the same moment setup
// fails, both the error channel and ctx.Done() are ready and Go picks between
// them uniformly - so gating only the ctx.Done() arm leaves roughly one run in
// a hundred returning the real setup error for a trace the user stopped. The
// TUI turns that into TracingErrorMsg, which clears the *next* session's
// attach spinner and shows it a failure the previous trace produced.
//
// Both arms must therefore report the cancellation, whichever one wins.
func TestTuiTraceStarterReportsAStopEvenWhenTheFailureIsReady(t *testing.T) {
	bindings := &traceRuntimeBindingsStub{
		streamBuffer: streamrow.NewRingBuffer(),
		streamSeq:    streamrow.NewSequencer(0),
	}
	starter := tuiTraceStarterFromRunTrace(
		flags.NewFlags(),
		func(_ context.Context, _ flags.Config, _ chan<- struct{}, _ func(*eventLoop), _ traceSetupHooks) error {
			return errors.New("setup BPF module: attach tracepoints: no such file or directory")
		},
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Repeated because the arms are chosen at random: a single run takes the
	// unguarded one only about half the time, and the regression this pins was
	// measured at well under 1% per run before both arms were gated.
	for i := range 200 {
		if err := starter(ctx, runtime.TraceRequest{Bindings: bindings}); !errors.Is(err, context.Canceled) {
			t.Fatalf("run %d: starter() error = %v, want context.Canceled: the user stopped this trace", i, err)
		}
	}
}

// TestTuiTraceStarterKeepsAnOrdinaryStopSilent guards the other side of
// reportLateTraceError: a trace that ends without an error (the normal stop
// and restart path, e.g. every filter or PID change) must not push a warning
// row, or the stream would fill with noise on every restart.
func TestTuiTraceStarterKeepsAnOrdinaryStopSilent(t *testing.T) {
	bindings := &traceRuntimeBindingsStub{
		streamBuffer: streamrow.NewRingBuffer(),
		streamSeq:    streamrow.NewSequencer(0),
	}
	stopped := make(chan struct{})
	starter := tuiTraceStarterFromRunTrace(
		flags.NewFlags(),
		func(ctx context.Context, _ flags.Config, started chan<- struct{}, _ func(*eventLoop), _ traceSetupHooks) error {
			close(started)
			<-ctx.Done()
			close(stopped)
			return nil
		},
	)

	ctx, cancel := context.WithCancel(context.Background())
	if err := starter(ctx, runtime.TraceRequest{Bindings: bindings}); err != nil {
		t.Fatalf("starter() error = %v, want nil", err)
	}
	cancel()
	<-stopped

	// The push, if any, happens on the trace goroutine right after it
	// returns, so give it a window in which it could have landed.
	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := bindings.streamBuffer.Len(); got != 0 {
			t.Fatalf("stream buffer rows = %d, want 0 for a clean stop", got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestTuiTraceStarterCompletesShutdownOnlyAfterTraceCleanup pins the outer
// lifecycle seam used by the TUI quit path. The started signal is not a trace
// completion: after cancellation the UI must keep waiting until the trace
// function returns from all deferred cleanup.
func TestTuiTraceStarterCompletesShutdownOnlyAfterTraceCleanup(t *testing.T) {
	reporter := runtime.NewTraceShutdownReporter()
	cleanupStarted := make(chan struct{})
	releaseCleanup := make(chan struct{})
	starter := tuiTraceStarterFromRunTrace(
		flags.NewFlags(),
		func(ctx context.Context, _ flags.Config, started chan<- struct{}, _ func(*eventLoop), _ traceSetupHooks) error {
			close(started)
			<-ctx.Done()
			close(cleanupStarted)
			<-releaseCleanup
			return nil
		},
	)

	ctx, cancel := context.WithCancel(context.Background())
	if err := starter(ctx, runtime.TraceRequest{ShutdownReporter: reporter}); err != nil {
		t.Fatalf("starter() error = %v, want nil", err)
	}
	cancel()
	<-cleanupStarted
	select {
	case got := <-reporter.Updates():
		t.Fatalf("shutdown completed before cleanup returned: %+v", got)
	default:
	}

	close(releaseCleanup)
	select {
	case got := <-reporter.Updates():
		if got.Phase != runtime.TraceShutdownComplete {
			t.Fatalf("shutdown update = %+v, want complete", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for shutdown completion after cleanup")
	}
}

// waitForStreamRowsEventually polls the buffer until it holds want rows, for
// pushes that happen on the trace goroutine after the starter returned.
func waitForStreamRowsEventually(t *testing.T, buffer *streamrow.RingBuffer, want int) []streamrow.Row {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if rows := buffer.Snapshot(); len(rows) >= want {
			return rows
		}
		if time.Now().After(deadline) {
			t.Fatalf("stream buffer len = %d after 5s, want %d", buffer.Len(), want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestModeHandlersReportTheirRunnersError pins the last link in the chain that
// carries a TUI failure to the user.
//
// The TUI reports what the model was showing (finalModelError), the exported
// entry points go through that, and cmd/ior prints whatever internal.Run
// returns and exits 2 - but nothing pinned the step between: a mode handler
// that dropped its runner's error left every test green while the binary
// exited 0 saying nothing, which is the silence the whole error-reporting
// change exists to end.
//
// Each round of review on this found the survivor one level further out than
// the last - the key branch, then the seam, then the exported entry points -
// so this covers every mode handler that delegates to an injected runner, not
// only the TUI one that prompted it.
func TestModeHandlersReportTheirRunnersError(t *testing.T) {
	wantErr := errors.New("create event filter: comm filter max size is 15 (got 20)")

	cases := map[string]struct {
		handler modeHandler
		deps    func(runnerDeps) runnerDeps
	}{
		"tui": {
			handler: &tuiModeHandler{},
			deps: func(d runnerDeps) runnerDeps {
				d.runTUI = func(flags.Config, runtime.TraceStarter) error { return wantErr }
				return d
			},
		},
		"plain trace": {
			handler: &plainTraceModeHandler{},
			deps: func(d runnerDeps) runnerDeps {
				d.runTrace = func(flags.Config) error { return wantErr }
				return d
			},
		},
	}

	for name, tc := range cases {
		deps := tc.deps(stubDeps())
		if err := tc.handler.run(flags.NewFlags(), deps); !errors.Is(err, wantErr) {
			t.Errorf("%s handler returned %v, want its runner's error", name, err)
		}
	}
}
