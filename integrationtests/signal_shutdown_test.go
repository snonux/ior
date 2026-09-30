package integrationtests

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Task mq2: a headless -flamegraph / -parquet run must still publish its
// recording when the controlling terminal goes away (SIGHUP) or when the
// pipe carrying its stdout/stderr is closed (SIGPIPE). Both used to kill the
// process before the recording was written: the flamegraph left no file and
// the Parquet run left a 0-byte .tmp.

const (
	// shutdownRunDuration is long enough that only the signal under test (or,
	// for the closed-pipe test, the end of the run) can stop ior in time.
	shutdownRunDuration = 60
	// pipeRunDuration is the -duration of the closed-pipe runs: short, because
	// the run must reach its natural end (and its stats writes) to hit the pipe.
	pipeRunDuration = 6
	// shutdownDrainDelay lets the workload's events travel through the ring
	// buffer into the recorder before the run is stopped.
	shutdownDrainDelay = time.Second
)

// signalRun is one started ior process whose stdout/stderr the test owns.
type signalRun struct {
	ior    *exec.Cmd
	stdout io.ReadCloser
	stderr io.ReadCloser
	done   chan error // receives ior's Wait result
}

// startSignalRun starts the open-basic workload and a real ior against it in
// the given output mode, waits until ior is attached and releases the
// workload. The returned run keeps ior's pipes open and drained; the caller
// decides what to do to them.
func startSignalRun(t *testing.T, h TestHarness, modeArgs []string, duration int) *signalRun {
	t.Helper()
	startupFile := h.workloadStartupFile("open-basic")
	workloadCmd, pid, _, err := h.startWorkload("open-basic", startupFile)
	if err != nil {
		t.Fatalf("start workload: %v", err)
	}
	args := append([]string{"-pid", strconv.Itoa(pid), "-duration", strconv.Itoa(duration)}, modeArgs...)
	cmd := exec.Command(h.IorBinary, args...)
	cmd.Dir = h.OutputDir
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("ior stdout pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("ior stderr pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		killAndWait(workloadCmd)
		t.Fatalf("start ior: %v", err)
	}
	t.Cleanup(func() { killAndWait(cmd) })

	ready := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, stdout) }()
	go scanUntilReady(stderr, ready)
	select {
	case <-ready:
	case <-time.After(iorReadyTimeout):
		killAndWait(workloadCmd)
		t.Fatalf("ior did not become ready")
	}
	time.Sleep(iorReadySettleDelay)
	if err := os.WriteFile(startupFile, []byte("ready\n"), 0o600); err != nil {
		t.Fatalf("release workload: %v", err)
	}
	// The workload exits by itself once its scenario is done.
	if err := workloadCmd.Wait(); err != nil {
		t.Fatalf("workload: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	return &signalRun{ior: cmd, stdout: stdout, stderr: stderr, done: done}
}

// scanUntilReady closes ready when ior's readiness line shows up, and keeps
// draining stderr until the pipe ends or is closed by the test.
func scanUntilReady(r io.Reader, ready chan<- struct{}) {
	scanner := bufio.NewScanner(r)
	signalled := false
	for scanner.Scan() {
		if !signalled && strings.Contains(scanner.Text(), iorReadyLine) {
			signalled = true
			close(ready)
		}
	}
}

// requireCleanExit waits for ior to exit and fails unless it exited 0 - a
// signal death (SIGHUP/SIGPIPE) shows up as a non-nil ExitError here.
func (r *signalRun) requireCleanExit(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case err := <-r.done:
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				t.Fatalf("ior did not exit cleanly: %v", exitErr)
			}
			t.Fatalf("waiting for ior: %v", err)
		}
	case <-time.After(within):
		t.Fatalf("ior still running %v after the trigger", within)
	}
}

// requireRecording asserts the mode's recording was published with content and
// no partial temp file was left behind.
func requireRecording(t *testing.T, dir, mode string) {
	t.Helper()
	switch mode {
	case "flamegraph":
		file, err := findIorZstFile(dir, "signal-shutdown")
		if err != nil {
			t.Fatalf("flamegraph recording missing: %v", err)
		}
		result, err := LoadTestResult(file)
		if err != nil {
			t.Fatalf("parse flamegraph recording: %v", err)
		}
		AssertEventsPresent(t, result, []ExpectedEvent{{PathContains: "testfile.txt", Tracepoint: "enter_openat", MinCount: 1}})
	case "parquet":
		rows, err := LoadParquetRows(filepath.Join(dir, "signal-shutdown.parquet"))
		if err != nil {
			t.Fatalf("parquet recording missing or unreadable: %v", err)
		}
		if len(rows) == 0 {
			t.Fatalf("parquet recording has no rows")
		}
	}
	tmps, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(tmps) != 0 {
		t.Fatalf("partial temp files left behind: %v", tmps)
	}
}

func modeArgs(mode, dir string) []string {
	if mode == "parquet" {
		return []string{"-parquet", filepath.Join(dir, "signal-shutdown.parquet")}
	}
	return []string{"-flamegraph", "-name", "signal-shutdown"}
}

// TestHeadlessRecordingSurvivesSIGHUP: SIGHUP is treated like SIGINT/SIGTERM,
// i.e. the run is finalised and the recording published.
func TestHeadlessRecordingSurvivesSIGHUP(t *testing.T) {
	for _, mode := range []string{"flamegraph", "parquet"} {
		t.Run(mode, func(t *testing.T) {
			enableParallelIfRequested(t)
			h := newTestHarness(t)
			run := startSignalRun(t, h, modeArgs(mode, h.OutputDir), shutdownRunDuration)
			time.Sleep(shutdownDrainDelay)
			if err := run.ior.Process.Signal(syscall.SIGHUP); err != nil {
				t.Fatalf("send SIGHUP: %v", err)
			}
			run.requireCleanExit(t, iorShutdownGrace)
			requireRecording(t, h.OutputDir, mode)
		})
	}
}

// TestHeadlessRecordingSurvivesClosedPipes: after the readers of ior's stdout
// and stderr are gone (`ior ... | head -1`, a dropped SSH session), the run
// still ends normally and publishes the recording instead of dying from
// SIGPIPE at its first status write.
func TestHeadlessRecordingSurvivesClosedPipes(t *testing.T) {
	for _, mode := range []string{"flamegraph", "parquet"} {
		t.Run(mode, func(t *testing.T) {
			enableParallelIfRequested(t)
			h := newTestHarness(t)
			run := startSignalRun(t, h, modeArgs(mode, h.OutputDir), pipeRunDuration)
			// Closing the parent's read ends is what `| head` exiting does:
			// every later write by ior gets EPIPE / SIGPIPE.
			_ = run.stdout.Close()
			_ = run.stderr.Close()
			run.requireCleanExit(t, pipeRunDuration*time.Second+iorShutdownGrace)
			requireRecording(t, h.OutputDir, mode)
		})
	}
}
