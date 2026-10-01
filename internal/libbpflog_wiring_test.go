package internal

import (
	"context"
	"errors"
	"slices"
	"testing"

	bpf "github.com/aquasecurity/libbpfgo"

	"ior/internal/flags"
	"ior/internal/runtime"
)

// libbpfLogIsTUI reads the logger's mode under its mutex, like log does.
func libbpfLogIsTUI() bool {
	libbpfLog.mu.Lock()
	defer libbpfLog.mu.Unlock()
	return libbpfLog.tui
}

// TestStartTUITraceSwitchesLibbpfLoggingToTUIMode pins the wiring in
// startTUITrace: once a TUI trace starts, libbpf's output must stop going to
// stderr. The unit tests of libbpfLogger cannot notice if this call is
// dropped, because they configure the mode themselves.
func TestStartTUITraceSwitchesLibbpfLoggingToTUIMode(t *testing.T) {
	// Start from the headless production configuration; restore it afterwards
	// so the global logger does not leak TUI mode into other tests.
	setLibbpfLogging(false)
	t.Cleanup(func() { setLibbpfLogging(false) })
	if libbpfLogIsTUI() {
		t.Fatal("precondition: logger must start in headless mode")
	}

	runs := make(chan capturedTraceRun, 1)
	starter := tuiTraceStarterFromRunTrace(flags.NewFlags(), captureTraceRun(runs))
	if err := starter(context.Background(), runtime.TraceRequest{}); err != nil {
		t.Fatalf("starter() error = %v", err)
	}
	<-runs

	if !libbpfLogIsTUI() {
		t.Fatal("startTUITrace left libbpf logging in headless mode; libbpf lines would corrupt the dashboard")
	}
}

// TestSetupTraceInfraBPFRoutesLibbpfWarningsForTheSetupWindowOnly drives the
// real setupTraceInfraBPF through the module-loader seam: a libbpf WARN logged
// while the module loads must reach the setup warning collector (replayed when
// setup succeeds, appended to the error when it fails, see
// TestSetupTraceInfraFailureCarriesLibbpfWarnings), and once setup has returned
// the route must be gone so later lines are not appended to a collector nobody
// drains.
func TestSetupTraceInfraBPFRoutesLibbpfWarningsForTheSetupWindowOnly(t *testing.T) {
	buf := withLibbpfLogger(t, true, false)
	origBuffer := newBPFModuleFromBuffer
	t.Cleanup(func() { newBPFModuleFromBuffer = origBuffer })
	t.Setenv(bpfObjectOverrideEnv, "") // embedded loader path

	loadErr := errors.New("load failed")
	newBPFModuleFromBuffer = func([]byte, string) (*bpf.Module, error) {
		libbpfLog.log(bpf.LibbpfDebugLevel, "libbpf: debug noise\n")
		libbpfLog.log(bpf.LibbpfWarnLevel, "libbpf: prog 'x': failed to load\n")
		return nil, loadErr
	}

	warnings := &setupWarnings{}
	infra, module, err := setupTraceInfraBPF(context.Background(), flags.NewFlags(), traceSetupHooks{}, func(...any) {}, warnings.add)
	if !errors.Is(err, loadErr) || infra != nil || module != nil {
		t.Fatalf("setupTraceInfraBPF = (%v, %v, %v), want the load error and no infra", infra, module, err)
	}

	// After setup returned, a further WARN must reach nobody.
	libbpfLog.log(bpf.LibbpfWarnLevel, "libbpf: late warning\n")

	if got, want := warnings.drain(), []string{"libbpf: prog 'x': failed to load"}; !slices.Equal(got, want) {
		t.Fatalf("setup warnings = %q, want %q", got, want)
	}
	if buf.Len() != 0 {
		t.Fatalf("TUI mode wrote %q to the headless output", buf.String())
	}
	libbpfLog.mu.Lock()
	routed := libbpfLog.route != nil
	libbpfLog.mu.Unlock()
	if routed {
		t.Fatal("setupTraceInfraBPF left its libbpf warning route installed after returning")
	}
}
