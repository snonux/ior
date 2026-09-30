package internal

import (
	"context"
	"os"
	"strings"
	"testing"

	"ior/internal/flags"
)

// TestRunTraceWithContextRejectsUnwritableFlamegraphOutputBeforeSetup is the
// regression for -flamegraph problems that surfaced only after the whole
// trace: an output that cannot be written must fail before BPF setup. The
// test needs no root because setup is never reached - had Prepare been
// skipped, setupTraceInfra would fail differently (or panic on the missing
// BPF privileges), so the flamegraph-specific error proves the ordering.
func TestRunTraceWithContextRejectsUnwritableFlamegraphOutputBeforeSetup(t *testing.T) {
	gone := t.TempDir()
	t.Chdir(gone)
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	cfg := flags.NewFlags()
	cfg.FlamegraphOutput = true
	cfg.OutputName = "trace"

	err := runTraceWithContext(context.Background(), cfg, nil, nil, traceSetupHooks{})
	if err == nil || !strings.Contains(err.Error(), "-flamegraph output would fail at the end of the trace") {
		t.Fatalf("runTraceWithContext error = %v, want the early -flamegraph output error", err)
	}
}

func TestRunTraceWithContextRejectsFlamegraphNameWithSlashBeforeSetup(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg := flags.NewFlags()
	cfg.FlamegraphOutput = true
	cfg.OutputName = "/tmp/elsewhere/trace"

	err := runTraceWithContext(context.Background(), cfg, nil, nil, traceSetupHooks{})
	if err == nil || !strings.Contains(err.Error(), "base name") {
		t.Fatalf("runTraceWithContext error = %v, want the base-name error", err)
	}
}
