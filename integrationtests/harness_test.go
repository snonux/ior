package integrationtests

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	workloadErr, iorErr := waitBoth(workloadCmd, iorCmd, 5, iorShutdownGrace)
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
	workloadErr, iorErr := waitBoth(workloadCmd, iorCmd, 0, 500*time.Millisecond)
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

	workloadErr, iorErr := waitBoth(workloadCmd, iorCmd, 0, 500*time.Millisecond)
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

	workloadErr, iorErr := waitBoth(workloadCmd, iorCmd, 5, iorShutdownGrace)
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
