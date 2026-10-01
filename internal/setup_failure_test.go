package internal

import (
	"context"
	"errors"
	"strings"
	"testing"

	bpf "github.com/aquasecurity/libbpfgo"

	"ior/internal/flags"
)

// TestExplainFailureWithoutWarningsKeepsTheError pins the negative case: a
// failure with nothing collected is returned as the very same error value, so
// every message and errors.Is/== check on it is unchanged.
func TestExplainFailureWithoutWarningsKeepsTheError(t *testing.T) {
	cause := errors.New("load failed")
	if got := (&setupWarnings{}).explainFailure(cause); got != cause {
		t.Fatalf("explainFailure with no warnings = %v, want the original error unchanged", got)
	}
}

// TestExplainFailureOnSuccessLeavesTheWarningsQueued pins the success path:
// no error means nothing is appended and, more importantly, nothing is
// drained, because the event loop still has to replay the warnings.
func TestExplainFailureOnSuccessLeavesTheWarningsQueued(t *testing.T) {
	w := &setupWarnings{}
	w.add("sched probe skipped")
	if got := w.explainFailure(nil); got != nil {
		t.Fatalf("explainFailure(nil) = %v, want nil", got)
	}
	if got := w.drain(); len(got) != 1 || got[0] != "sched probe skipped" {
		t.Fatalf("warnings after a successful setup = %q, want them still queued", got)
	}
}

func TestExplainFailureAppendsWarningsAndKeepsTheCause(t *testing.T) {
	cause := errors.New("failed to load BPF object: -22")
	w := &setupWarnings{}
	w.add("libbpf: prog 'x': BPF program load failed: -EINVAL")
	w.add("libbpf: failed to load object")

	err := w.explainFailure(cause)
	if !errors.Is(err, cause) {
		t.Fatalf("errors.Is(%v, cause) = false, want the cause to stay reachable", err)
	}
	want := "failed to load BPF object: -22\n" +
		"Warnings logged during setup:\n" +
		"  - libbpf: prog 'x': BPF program load failed: -EINVAL\n" +
		"  - libbpf: failed to load object"
	if err.Error() != want {
		t.Fatalf("error text = %q, want %q", err.Error(), want)
	}
	if got := w.drain(); len(got) != 0 {
		t.Fatalf("collector still holds %q after the failure took the warnings", got)
	}
}

// TestExplainFailureBoundsAndEscapesWarnings feeds a hostile warning flood:
// ANSI sequences, a huge multi-line verifier log and far more warnings than
// the error screen can show.
func TestExplainFailureBoundsAndEscapesWarnings(t *testing.T) {
	w := &setupWarnings{}
	w.add("libbpf: \x1b[2J\x1b]0;pwned\x07evil‮ name")
	w.add("libbpf: verifier " + strings.Repeat("A", 1<<20) + "\nsecond line\nthird line")
	for i := 0; i < 30; i++ {
		w.add("libbpf: filler", i)
	}

	text := w.explainFailure(errors.New("boom")).Error()

	for _, forbidden := range []string{"\x1b", "\x07", "‮"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("error text carries raw %q: %q", forbidden, text)
		}
	}
	if !strings.Contains(text, `\x1b[2J`) {
		t.Fatalf("error text %q does not show the escaped ESC, the operator could not tell what was dropped", text)
	}
	if strings.Contains(text, "second line") || !strings.Contains(text, "(2 more lines)") {
		t.Fatalf("multi-line warning was not cut to its first line plus a marker: %q", text)
	}
	if lines := strings.Split(text, "\n"); len(lines) != 2+maxFailureWarnings+1 {
		t.Fatalf("error text has %d lines, want cause + header + %d warnings + overflow row:\n%s",
			len(lines), maxFailureWarnings, text)
	}
	if !strings.HasSuffix(text, "... and 24 more warning(s)") {
		t.Fatalf("overflow row missing or wrong: %q", text[max(0, len(text)-60):])
	}
	// Each row is bounded (240 bytes of text, plus marker and bullet).
	for _, line := range strings.Split(text, "\n") {
		if len(line) > maxFailureWarningBytes+64 {
			t.Fatalf("row of %d bytes exceeds the bound: %.80q...", len(line), line)
		}
	}
}

// TestSetupTraceInfraFailureCarriesLibbpfWarnings drives the real shared setup
// through the module-loader seam in TUI mode: libbpf logs the WARN that
// explains the failed load, setup fails, and the error that reaches the TUI
// (and so its error screen) must carry that line - it used to be dropped
// together with the never-drained collector (task bs2). INFO/DEBUG noise stays
// out and the cause stays reachable.
func TestSetupTraceInfraFailureCarriesLibbpfWarnings(t *testing.T) {
	buf := withLibbpfLogger(t, true, false)
	origBuffer := newBPFModuleFromBuffer
	t.Cleanup(func() { newBPFModuleFromBuffer = origBuffer })
	t.Setenv(bpfObjectOverrideEnv, "")

	loadErr := errors.New("load failed")
	newBPFModuleFromBuffer = func([]byte, string) (*bpf.Module, error) {
		libbpfLog.log(bpf.LibbpfDebugLevel, "libbpf: debug noise\n")
		libbpfLog.log(bpf.LibbpfWarnLevel, "libbpf: prog 'x': failed to load: -EINVAL\n")
		return nil, loadErr
	}

	infra, err := setupTraceInfraWithEventLoop(context.Background(), flags.NewFlags(), nil,
		traceSetupHooks{}, func(...any) {}, newTraceEventLoop)
	if infra != nil || !errors.Is(err, loadErr) {
		t.Fatalf("setup = (%v, %v), want no infra and the load error", infra, err)
	}
	if !strings.Contains(err.Error(), "libbpf: prog 'x': failed to load: -EINVAL") {
		t.Fatalf("setup error %q lacks the libbpf warning that explains it", err)
	}
	if strings.Contains(err.Error(), "debug noise") || buf.Len() != 0 {
		t.Fatalf("debug noise or stderr output leaked: error %q, headless output %q", err, buf.String())
	}
}

// TestSetupTraceInfraFailureWithoutWarningsIsUnchanged is the negative twin: a
// failed load that logged no libbpf WARN returns the loader's error as is.
func TestSetupTraceInfraFailureWithoutWarningsIsUnchanged(t *testing.T) {
	withLibbpfLogger(t, true, false)
	origBuffer := newBPFModuleFromBuffer
	t.Cleanup(func() { newBPFModuleFromBuffer = origBuffer })
	t.Setenv(bpfObjectOverrideEnv, "")

	loadErr := errors.New("load failed")
	newBPFModuleFromBuffer = func([]byte, string) (*bpf.Module, error) { return nil, loadErr }

	_, err := setupTraceInfraWithEventLoop(context.Background(), flags.NewFlags(), nil,
		traceSetupHooks{}, func(...any) {}, newTraceEventLoop)
	if err == nil || strings.Contains(err.Error(), "Warnings logged") || !errors.Is(err, loadErr) {
		t.Fatalf("setup error = %v, want the loader error without a warnings block", err)
	}
}
