package integrationtests

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestWorkloadCrashReportsError(t *testing.T) {
	h := newTestHarness(t)
	result, pid, err := h.Run("crash", 5)
	if err == nil {
		t.Fatal("expected error from crashed workload, got nil")
	}
	if pid == 0 {
		t.Fatal("expected non-zero PID from started workload")
	}
	if !strings.Contains(err.Error(), "workload") {
		t.Errorf("error should mention workload, got: %v", err)
	}
	if len(result.Records) != 0 {
		t.Errorf("expected no records from crashed workload, got %d", len(result.Records))
	}
}

func TestWaitBothIorExitError(t *testing.T) {
	workloadCmd := exec.Command("true")
	iorCmd := exec.Command("false")
	if err := workloadCmd.Start(); err != nil {
		t.Fatalf("start workload: %v", err)
	}
	if err := iorCmd.Start(); err != nil {
		t.Fatalf("start ior: %v", err)
	}

	workloadErr, iorErr := waitBoth(workloadCmd, iorCmd, nil, 5, iorShutdownGrace)
	if iorErr == nil {
		t.Fatal("expected ior error, got nil")
	}
	if workloadErr != nil {
		t.Errorf("expected nil workload error, got: %v", workloadErr)
	}
}

func TestWaitBothIorTimeout(t *testing.T) {
	workloadCmd := exec.Command("true")
	iorCmd := exec.Command("sleep", "60")
	if err := workloadCmd.Start(); err != nil {
		t.Fatalf("start workload: %v", err)
	}
	if err := iorCmd.Start(); err != nil {
		t.Fatalf("start ior: %v", err)
	}

	// Use duration=0 and a short grace period so timeout fires quickly.
	// Workload ("true") exits instantly; ior ("sleep 60") exceeds the timeout.
	workloadErr, iorErr := waitBoth(workloadCmd, iorCmd, nil, 0, 500*time.Millisecond)
	if workloadErr != nil {
		t.Errorf("expected nil workload error, got: %v", workloadErr)
	}
	if iorErr == nil {
		t.Fatal("expected ior error from timeout, got nil")
	}
	if !strings.Contains(iorErr.Error(), "timed out") {
		t.Errorf("expected timeout error, got: %v", iorErr)
	}
}

func TestWaitBothBothTimeout(t *testing.T) {
	workloadCmd := exec.Command("sleep", "60")
	iorCmd := exec.Command("sleep", "60")
	if err := workloadCmd.Start(); err != nil {
		t.Fatalf("start workload: %v", err)
	}
	if err := iorCmd.Start(); err != nil {
		t.Fatalf("start ior: %v", err)
	}

	workloadErr, iorErr := waitBoth(workloadCmd, iorCmd, nil, 0, 500*time.Millisecond)
	if workloadErr == nil {
		t.Fatal("expected workload timeout error, got nil")
	}
	if !strings.Contains(workloadErr.Error(), "timed out") {
		t.Errorf("expected workload timeout error, got: %v", workloadErr)
	}
	if iorErr == nil {
		t.Fatal("expected ior timeout error, got nil")
	}
	if !strings.Contains(iorErr.Error(), "timed out") {
		t.Errorf("expected ior timeout error, got: %v", iorErr)
	}
}

func TestWaitBothBothSucceed(t *testing.T) {
	workloadCmd := exec.Command("true")
	iorCmd := exec.Command("true")
	if err := workloadCmd.Start(); err != nil {
		t.Fatalf("start workload: %v", err)
	}
	if err := iorCmd.Start(); err != nil {
		t.Fatalf("start ior: %v", err)
	}

	workloadErr, iorErr := waitBoth(workloadCmd, iorCmd, nil, 5, iorShutdownGrace)
	if workloadErr != nil {
		t.Errorf("expected nil workload error, got: %v", workloadErr)
	}
	if iorErr != nil {
		t.Errorf("expected nil ior error, got: %v", iorErr)
	}
}

func TestIorCrashReportsError(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := t.TempDir()

	// Create a fake workload that prints its PID and exits cleanly.
	workloadBin := writeScript(t, tmpDir, "workload", `echo $$`)

	// Create a fake ior that exits with error immediately.
	iorBin := writeScript(t, tmpDir, "ior", `exit 1`)

	h := TestHarness{
		IorBinary:      iorBin,
		WorkloadBinary: workloadBin,
		BpfObject:      filepath.Join(tmpDir, "fake.bpf.o"),
		OutputDir:      outputDir,
	}

	result, pid, err := h.Run("test", 5)
	if err == nil {
		t.Fatal("expected error when ior crashes, got nil")
	}
	if !strings.Contains(err.Error(), "ior") {
		t.Errorf("error should mention ior, got: %v", err)
	}
	if pid == 0 {
		t.Fatal("expected non-zero workload PID")
	}
	if len(result.Records) != 0 {
		t.Errorf("expected no records from crashed ior, got %d", len(result.Records))
	}
}

func TestIorStartFailureCleansUpWorkload(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := t.TempDir()

	// Create a fake workload that prints PID and sleeps.
	// Use exec to replace the shell so killing the process kills the sleep too.
	workloadBin := writeScript(t, tmpDir, "workload", `echo $$; exec sleep 30`)

	h := TestHarness{
		IorBinary:      "/nonexistent/ior",
		WorkloadBinary: workloadBin,
		BpfObject:      filepath.Join(tmpDir, "fake.bpf.o"),
		OutputDir:      outputDir,
	}

	_, pid, err := h.Run("test", 5)
	if err == nil {
		t.Fatal("expected error when ior binary doesn't exist, got nil")
	}
	if pid == 0 {
		t.Fatal("expected non-zero workload PID even when ior fails to start")
	}
	// Verify the workload process was cleaned up (killed).
	// After Run returns, the workload should no longer be running.
	// On Linux, FindProcess always succeeds, so we check with signal 0.
	proc, procErr := os.FindProcess(pid)
	if procErr == nil {
		if signalErr := proc.Signal(syscall.Signal(0)); signalErr == nil {
			t.Error("workload process is still running after ior start failure")
		}
	}
}

// TestIorArgsForPIDErrorCleansUpWorkload pins task 3q2: when the IorArgsForPID
// callback fails (e.g. an unreadable tid file) after the workload started,
// the run returns the error and the harness kills and reaps the workload
// instead of leaving it to block on its startup file as a zombie. Both the
// flamegraph and the Parquet entry points are covered.
func TestIorArgsForPIDErrorCleansUpWorkload(t *testing.T) {
	runs := map[string]func(h *TestHarness) (int, error){
		"RunWithIorArgs": func(h *TestHarness) (int, error) {
			_, pid, err := h.RunWithIorArgs("test", 5, nil)
			return pid, err
		},
		"RunParquetWithIorArgs": func(h *TestHarness) (int, error) {
			_, pid, err := h.RunParquetWithIorArgs("test", 5, nil)
			return pid, err
		},
	}
	for name, run := range runs {
		t.Run(name, func(t *testing.T) {
			tmpDir := t.TempDir()
			// exec keeps the shell's pid, so killing it kills the sleep too.
			workloadBin := writeScript(t, tmpDir, "workload", `echo $$; exec sleep 30`)
			wantErr := errors.New("tid file unreadable")
			h := TestHarness{
				IorBinary:      "/nonexistent/ior", // must never be reached
				WorkloadBinary: workloadBin,
				OutputDir:      t.TempDir(),
				IorArgsForPID:  func(int) ([]string, error) { return nil, wantErr },
			}
			pid, err := run(&h)
			if !errors.Is(err, wantErr) {
				t.Fatalf("error = %v, want it to wrap %v", err, wantErr)
			}
			if pid == 0 {
				t.Fatal("expected non-zero workload PID")
			}
			// Signal 0 also succeeds for an unreaped zombie, so this checks
			// both that the workload was killed and that it was waited for.
			if err := syscall.Kill(pid, 0); err == nil {
				t.Error("workload still exists (running or unreaped) after the callback failed")
			}
		})
	}
}

func TestStartIorPassesBPFObjectOverrideEnv(t *testing.T) {
	tmpDir := t.TempDir()
	outputDir := t.TempDir()
	overridePath := filepath.Join(tmpDir, "fake.bpf.o")
	iorBin := writeScript(t, tmpDir, "ior", `printf '%s' "$IOR_BPF_OBJECT" > "$PWD/override.txt"`)

	h := TestHarness{
		IorBinary: iorBin,
		BpfObject: overridePath,
		OutputDir: outputDir,
	}

	cmd, err := h.startIor(1234, "test", 5, nil)
	if err != nil {
		t.Fatalf("startIor returned error: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait for fake ior: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(outputDir, "override.txt"))
	if err != nil {
		t.Fatalf("read override marker: %v", err)
	}
	if got, want := string(data), overridePath; got != want {
		t.Fatalf("IOR_BPF_OBJECT = %q, want %q", got, want)
	}
}

// runFakeIor starts the fake ior script through the real startIorArgsWithReady
// and waitBoth (exactly as RunWithIorArgs does, minus the workload release) and
// returns what the harness captured plus waitBoth's ior error. passDone=false
// reproduces the pre-2q2 behaviour of reaping ior without waiting for the
// scanners.
func runFakeIor(t *testing.T, iorBin string, passDone bool, grace time.Duration) (string, error) {
	t.Helper()
	capture := &OutputCapture{}
	h := TestHarness{IorBinary: iorBin, OutputDir: t.TempDir(), IorOutput: capture}
	ior, err := h.startIorArgsWithReady(nil)
	if err != nil {
		t.Fatalf("start fake ior: %v", err)
	}
	workloadCmd := exec.Command("true")
	if err := workloadCmd.Start(); err != nil {
		t.Fatalf("start workload: %v", err)
	}
	done := ior.outputDone
	if !passDone {
		done = nil
	}
	_, iorErr := waitBoth(workloadCmd, ior.cmd, done, 0, grace)
	return capture.String(), iorErr
}

// TestWaitBothKeepsIorFinalOutput pins task 2q2: a fake ior that writes its
// statistics to both streams and exits at once must never lose a line. With
// the old waitBoth, cmd.Wait closed the pipe read ends while the scanners
// still had unread bytes and the tail was silently dropped (16-22 of 400
// runs under load), which made the thread-exit tests flake on a missing
// "ring buffer drops: 0 (" line. Many parallel runs widen the scheduling
// window so a regression shows up reliably.
func TestWaitBothKeepsIorFinalOutput(t *testing.T) {
	iorBin := writeScript(t, t.TempDir(), "ior", `echo "Probing for tracepoints"
echo "stdout filler"
echo "Statistics: ring buffer drops: 0 (" >&2
echo "final stdout line"`)
	const runs, parallel = 200, 32

	var wg sync.WaitGroup
	sem := make(chan struct{}, parallel)
	var mu sync.Mutex
	lost := 0
	for range runs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			out, err := runFakeIor(t, iorBin, true, 10*time.Second)
			ok := err == nil &&
				strings.Contains(out, "ring buffer drops: 0 (") &&
				strings.Contains(out, "final stdout line")
			if !ok {
				mu.Lock()
				lost++
				mu.Unlock()
				t.Errorf("ior output incomplete (err=%v):\n%s", err, out)
			}
		}()
	}
	wg.Wait()
	if lost > 0 {
		t.Fatalf("%d of %d runs lost part of ior's final output", lost, runs)
	}
}

// TestWaitBothNoHangWhenOutputPipeStaysOpen covers the escape hatch of the 2q2
// fix: if a child of ior keeps the output pipe open after ior exited, the
// scanners never see EOF. waitBoth must still return once the timeout fires
// (with a timed-out error), not block forever holding back ior's Wait.
func TestWaitBothNoHangWhenOutputPipeStaysOpen(t *testing.T) {
	// The background sleep inherits stdout/stderr and dies by itself after
	// 3s; ior proper exits immediately.
	iorBin := writeScript(t, t.TempDir(), "ior", `echo "Probing for tracepoints"
sleep 3 &
exit 0`)
	start := time.Now()
	out, err := runFakeIor(t, iorBin, true, 500*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("ior error = %v, want a timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 2500*time.Millisecond {
		t.Fatalf("waitBoth took %v, want to return shortly after the 500ms grace", elapsed)
	}
	if !strings.Contains(out, "Probing for tracepoints") {
		t.Errorf("lines written before the timeout were lost: %q", out)
	}
}

// TestWaitBothAbandonReapsIorAndReleasesGoroutines pins the abandon release in
// waitBoth: when a holder child keeps the output pipe open, ior's Wait is held
// back waiting for the scanners' EOF. After the timeout waitBoth returns and
// must release that Wait (via abandon), otherwise ior stays a zombie and the
// waiter, scanner and outputDone goroutines leak until the holder dies.
func TestWaitBothAbandonReapsIorAndReleasesGoroutines(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "holder.pid")
	// ior exits 0 at once but leaves a backgrounded sleep holding stdout and
	// stderr. The sleep's PID is recorded so the test can kill exactly it.
	iorBin := writeScript(t, dir, "ior", `sleep 30 &
echo $! > `+pidFile)
	t.Cleanup(func() {
		if b, err := os.ReadFile(pidFile); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})

	before := settledGoroutines()
	h := TestHarness{IorBinary: iorBin, OutputDir: t.TempDir()}
	ior, err := h.startIorArgsWithReady(nil)
	if err != nil {
		t.Fatalf("start fake ior: %v", err)
	}
	iorPID := ior.cmd.Process.Pid
	workloadCmd := exec.Command("true")
	if err := workloadCmd.Start(); err != nil {
		t.Fatalf("start workload: %v", err)
	}

	_, iorErr := waitBoth(workloadCmd, ior.cmd, ior.outputDone, 0, 500*time.Millisecond)
	if iorErr == nil || !strings.Contains(iorErr.Error(), "timed out") {
		t.Fatalf("ior error = %v, want a timeout", iorErr)
	}

	// A zombie still answers signal 0; a reaped process yields ESRCH.
	if !waitUntil(2*time.Second, func() bool { return syscall.Kill(iorPID, 0) == syscall.ESRCH }) {
		t.Errorf("ior (pid %d) was not reaped after waitBoth returned", iorPID)
	}
	if !waitUntil(3*time.Second, func() bool { return runtime.NumGoroutine() <= before }) {
		buf := make([]byte, 1<<16)
		t.Errorf("goroutines leaked: %d before, %d after\n%s",
			before, runtime.NumGoroutine(), buf[:runtime.Stack(buf, true)])
	}
}

// settledGoroutines returns the goroutine count once it stopped changing, so
// goroutines still winding down from earlier tests are not counted as leaks.
func settledGoroutines() int {
	n := runtime.NumGoroutine()
	for stable := 0; stable < 5; {
		time.Sleep(20 * time.Millisecond)
		if m := runtime.NumGoroutine(); m == n {
			stable++
		} else {
			n, stable = m, 0
		}
	}
	return n
}

// waitUntil polls cond every 10ms until it holds or the deadline passes.
func waitUntil(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true
}
