package internal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"ior/internal/flags"
)

// teardownRecorder records the order in which closeTraceInfra runs its
// collaborators. It is mutex-guarded because the error logger may be invoked
// from other goroutines (e.g. the signal handler).
type teardownRecorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *teardownRecorder) record(call string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call)
}

func (r *teardownRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

type fakeRingBuffer struct{ rec *teardownRecorder }

func (f fakeRingBuffer) Stop() { f.rec.record("rb.Stop") }

type fakeProbeManager struct {
	rec  *teardownRecorder
	fail error
}

func (f fakeProbeManager) Close() error {
	f.rec.record("mgr.Close")
	return f.fail
}

type fakeBpfModule struct{ rec *teardownRecorder }

func (f fakeBpfModule) Close() { f.rec.record("module.Close") }

// captureLogger collects log lines for assertions.
type captureLogger struct {
	mu    sync.Mutex
	lines []string
}

func (c *captureLogger) log(args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprint(args...))
}

func (c *captureLogger) joined() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.lines, " ")
}

// TestCloseTraceInfraTearsDownInCanonicalOrder locks the teardown order
// (audit domain-10 F5): ring-buffer polling stops first, then probes detach,
// bindings release, the module closes, and signal handling stops last.
func TestCloseTraceInfraTearsDownInCanonicalOrder(t *testing.T) {
	rec := &teardownRecorder{}
	logs := &captureLogger{}

	closeTraceInfra(logs.log,
		fakeRingBuffer{rec: rec},
		fakeProbeManager{rec: rec},
		func() { rec.record("releaseBindings") },
		fakeBpfModule{rec: rec},
		func() { rec.record("stopSignals") },
	)

	want := []string{"rb.Stop", "mgr.Close", "releaseBindings", "module.Close", "stopSignals"}
	got := rec.snapshot()
	if !slices.Equal(got, want) {
		t.Fatalf("teardown order = %v, want %v", got, want)
	}
	if logs.joined() != "" {
		t.Fatalf("expected no teardown errors, got %q", logs.joined())
	}
}

// TestCloseTraceInfraSkipsMissingCollaborators locks that early-abort paths
// can reuse the helper with explicit nils for infrastructure that a failed
// setup step never created.
func TestCloseTraceInfraSkipsMissingCollaborators(t *testing.T) {
	rec := &teardownRecorder{}
	logs := &captureLogger{}

	closeTraceInfra(logs.log, nil, fakeProbeManager{rec: rec}, nil, fakeBpfModule{rec: rec}, nil)

	want := []string{"mgr.Close", "module.Close"}
	got := rec.snapshot()
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("teardown order = %v, want %v", got, want)
	}
}

// TestCloseTraceInfraLogsProbeCloseFailuresToStderrLogger locks audit
// domain-10 F2: a probe-detach failure is routed to the always-on error
// logger instead of being silently discarded, and the teardown still runs
// the remaining steps.
func TestCloseTraceInfraLogsProbeCloseFailuresToStderrLogger(t *testing.T) {
	rec := &teardownRecorder{}
	logs := &captureLogger{}
	probeErr := errors.New("link destroy failed")

	closeTraceInfra(logs.log,
		fakeRingBuffer{rec: rec},
		fakeProbeManager{rec: rec, fail: probeErr},
		nil,
		fakeBpfModule{rec: rec},
		nil,
	)

	if !strings.Contains(logs.joined(), "BPF probe manager close error:") ||
		!strings.Contains(logs.joined(), probeErr.Error()) {
		t.Fatalf("probe close error was not logged: %q", logs.joined())
	}
	got := rec.snapshot()
	if len(got) != 3 || got[0] != "rb.Stop" || got[1] != "mgr.Close" || got[2] != "module.Close" {
		t.Fatalf("teardown must continue after a probe close error, got %v", got)
	}
}

// TestSetupTraceContextCancelsOnSignal locks the signal wiring (audit
// domain-10 F5): SIGINT/SIGTERM cancel the trace context, the shutdown is
// logged, and stopSignals unregisters the handler again.
func TestSetupTraceContextCancelsOnSignal(t *testing.T) {
	cfg := flags.NewFlags() // TUI defaults: no auto-stop, ctx is cancel-based.
	logs := &captureLogger{}

	ctx, cancel, stopSignals := setupTraceContext(context.Background(), cfg, logs.log)
	defer cancel()
	defer stopSignals()

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("failed to send SIGTERM to self: %v", err)
	}

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatalf("trace context was not cancelled by SIGTERM")
	}
	// The signal goroutine logs before cancelling, so once ctx is done the
	// shutdown message must have been recorded.
	if !strings.Contains(logs.joined(), "Received signal, shutting down...") {
		t.Fatalf("expected the shutdown log, got %q", logs.joined())
	}
}

// TestSetupTraceContextAutoStopsByDuration locks the -duration arm: headless
// configurations receive a timeout context that fires after cfg.Duration.
func TestSetupTraceContextAutoStopsByDuration(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.PlainMode = true
	cfg.Duration = 1
	logs := &captureLogger{}

	ctx, cancel, stopSignals := setupTraceContext(context.Background(), cfg, logs.log)
	defer cancel()
	defer stopSignals()

	if !strings.Contains(logs.joined(), "Probing for") {
		t.Fatalf("expected the duration announcement log, got %q", logs.joined())
	}

	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout context did not fire after %d s", cfg.Duration)
	}
}
