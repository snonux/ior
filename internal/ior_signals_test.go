package internal

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"ior/internal/flags"
)

// headlessFlamegraphConfig is a -flamegraph run: a file-output headless mode.
func headlessFlamegraphConfig() flags.Config {
	cfg := flags.NewFlags()
	cfg.FlamegraphOutput = true
	cfg.Duration = 60
	return cfg
}

// TestShutdownSignalsAddSIGHUPOnlyForHeadlessModes locks which modes treat
// SIGHUP as a graceful stop (task mq2): every headless mode does, the TUI
// keeps SIGHUP's default because its terminal is gone with the hangup.
func TestShutdownSignalsAddSIGHUPOnlyForHeadlessModes(t *testing.T) {
	plain := flags.NewFlags()
	plain.PlainMode = true
	parquet := flags.NewFlags()
	parquet.ParquetPath = "x.parquet"

	for name, cfg := range map[string]flags.Config{
		"flamegraph": headlessFlamegraphConfig(),
		"plain":      plain,
		"parquet":    parquet,
	} {
		got := shutdownSignals(cfg)
		for _, want := range []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP} {
			if !slices.Contains(got, want) {
				t.Errorf("%s: shutdownSignals = %v, missing %v", name, got, want)
			}
		}
	}

	tui := shutdownSignals(flags.NewFlags())
	if slices.Contains(tui, os.Signal(syscall.SIGHUP)) {
		t.Errorf("TUI: shutdownSignals = %v, must not claim SIGHUP", tui)
	}
	if !slices.Contains(tui, os.Interrupt) || !slices.Contains(tui, os.Signal(syscall.SIGTERM)) {
		t.Errorf("TUI: shutdownSignals = %v, want SIGINT and SIGTERM", tui)
	}
}

// TestSetupTraceContextCancelsOnSIGHUPWhenHeadless: SIGHUP finalises a
// headless run like SIGTERM does - the context is cancelled, not the process
// killed (the test binary surviving the Kill below is itself the proof).
func TestSetupTraceContextCancelsOnSIGHUPWhenHeadless(t *testing.T) {
	logs := &captureLogger{}
	ctx, cancel, stopSignals := setupTraceContext(context.Background(), headlessFlamegraphConfig(), logs.log)
	defer cancel()
	defer stopSignals()

	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("failed to send SIGHUP to self: %v", err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatalf("trace context was not cancelled by SIGHUP")
	}
	if !strings.Contains(logs.joined(), "Received signal, shutting down...") {
		t.Fatalf("expected the shutdown log, got %q", logs.joined())
	}
}

const (
	pipeHelperEnv     = "IOR_TEST_PIPE_HELPER"
	pipeHelperSurvive = "SURVIVED-BROKEN-PIPE"
)

// TestBrokenPipeHelperProcess is the child of the broken-pipe tests, not a
// test by itself. It installs the guard for the mode named in the environment,
// writes to its stderr - which the parent closed the reading end of - and
// reports on stdout that it lived through it.
func TestBrokenPipeHelperProcess(t *testing.T) {
	mode := os.Getenv(pipeHelperEnv)
	if mode == "" {
		t.Skip("helper process only")
	}
	cfg := flags.NewFlags()
	switch mode {
	case "flamegraph":
		cfg.FlamegraphOutput = true
	case "parquet":
		cfg.ParquetPath = "x.parquet"
	case "plain":
		cfg.PlainMode = true
	}
	guardBrokenPipe(cfg)

	_, err := os.Stderr.WriteString("status line into a closed pipe\n")
	// Reaching this line means SIGPIPE did not kill the process; stdout is
	// still open for the parent to read.
	_, _ = os.Stdout.WriteString(pipeHelperSurvive + " " + errorName(err) + "\n")
}

func errorName(err error) string {
	if errors.Is(err, syscall.EPIPE) {
		return "EPIPE"
	}
	return "other"
}

// runBrokenPipeHelper re-executes the test binary as the helper with its
// stderr connected to a pipe nobody reads, and returns its stdout and the
// error from waiting for it.
func runBrokenPipeHelper(t *testing.T, mode string) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil { // no reader left: writes hit EPIPE
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestBrokenPipeHelperProcess$")
	cmd.Env = append(os.Environ(), pipeHelperEnv+"="+mode)
	cmd.Stderr = w
	out, runErr := cmd.Output()
	_ = w.Close()
	return string(out), runErr
}

// TestGuardBrokenPipeKeepsFileOutputModesAlive is the regression test for
// the lost recording: without the guard a write to a closed stderr kills the
// process with SIGPIPE; with it the write just fails with EPIPE.
func TestGuardBrokenPipeKeepsFileOutputModesAlive(t *testing.T) {
	for _, mode := range []string{"flamegraph", "parquet"} {
		t.Run(mode, func(t *testing.T) {
			out, err := runBrokenPipeHelper(t, mode)
			if err != nil {
				t.Fatalf("helper died (%v), output %q", err, out)
			}
			if want := pipeHelperSurvive + " EPIPE"; !strings.Contains(out, want) {
				t.Fatalf("helper output = %q, want %q", out, want)
			}
		})
	}
}

// TestGuardBrokenPipeLeavesPlainModeDefault is the negative test: -plain
// streams its product on stdout, so a closed reader must still end it with
// SIGPIPE like any Unix filter.
func TestGuardBrokenPipeLeavesPlainModeDefault(t *testing.T) {
	out, err := runBrokenPipeHelper(t, "plain")
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("plain helper survived a broken pipe (err=%v, output %q); it must die from SIGPIPE", err, out)
	}
	if strings.Contains(out, pipeHelperSurvive) {
		t.Fatalf("plain helper reached the survive line: %q", out)
	}
}
