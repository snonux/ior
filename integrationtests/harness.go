package integrationtests

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	workloadStartupTimeout = 5 * time.Second
	iorShutdownGrace       = 30 * time.Second
)

// TestHarness orchestrates integration tests by starting an ior trace
// against a known ioworkload process and collecting the .ior.zst output.
type TestHarness struct {
	IorBinary      string // path to built ior binary
	WorkloadBinary string // path to built ioworkload binary
	BpfObject      string // path to ior.bpf.o
	OutputDir      string // temp dir for .ior.zst output
}

// Run executes a single integration test scenario. It starts the ioworkload
// binary, reads its PID from stdout, launches ior with a PID filter, waits
// for both to finish, and parses the resulting .ior.zst file.
func (h *TestHarness) Run(scenario string, duration int) (TestResult, int, error) {
	return h.RunWithIorArgs(scenario, duration, nil)
}

// RunWithIorArgs behaves like Run but forwards additional args to ior.
func (h *TestHarness) RunWithIorArgs(scenario string, duration int, extraIorArgs []string) (TestResult, int, error) {
	workloadCmd, workloadPID, err := h.startWorkload(scenario)
	if err != nil {
		return TestResult{}, 0, err
	}

	iorCmd, err := h.startIor(workloadPID, scenario, duration, extraIorArgs)
	if err != nil {
		workloadCmd.Process.Kill()
		workloadCmd.Wait()
		return TestResult{}, workloadPID, err
	}

	workloadErr, iorErr := waitBoth(workloadCmd, iorCmd, duration, iorShutdownGrace)

	if iorErr != nil {
		return TestResult{}, workloadPID, fmt.Errorf("ior: %w", iorErr)
	}
	if workloadErr != nil {
		return TestResult{}, workloadPID, fmt.Errorf("workload: %w", workloadErr)
	}

	iorFile, err := findIorZstFile(h.OutputDir, scenario)
	if err != nil {
		return TestResult{}, workloadPID, fmt.Errorf("find .ior.zst: %w", err)
	}

	result, err := LoadTestResult(iorFile)
	if err != nil {
		return TestResult{}, workloadPID, fmt.Errorf("parse result: %w", err)
	}

	return result, workloadPID, nil
}

func (h *TestHarness) startWorkload(scenario string) (*exec.Cmd, int, error) {
	cmd := exec.Command(h.WorkloadBinary, "--scenario="+scenario)
	cmd.Stderr = os.Stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, 0, fmt.Errorf("workload stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, 0, fmt.Errorf("start workload: %w", err)
	}

	pidCh := make(chan int, 1)
	errCh := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			pid, err := strconv.Atoi(strings.TrimSpace(scanner.Text()))
			if err != nil {
				errCh <- fmt.Errorf("parse workload PID: %w", err)
				return
			}
			pidCh <- pid
		} else if err := scanner.Err(); err != nil {
			errCh <- fmt.Errorf("reading workload stdout: %w", err)
		} else {
			errCh <- fmt.Errorf("workload produced no output")
		}
		// Drain remaining pipe data so cmd.Wait() does not block.
		io.Copy(io.Discard, stdout) //nolint:errcheck
	}()

	select {
	case pid := <-pidCh:
		return cmd, pid, nil
	case err := <-errCh:
		cmd.Process.Kill()
		cmd.Wait()
		return nil, 0, err
	case <-time.After(workloadStartupTimeout):
		cmd.Process.Kill()
		cmd.Wait()
		return nil, 0, fmt.Errorf("timeout waiting for workload PID")
	}
}

func (h *TestHarness) startIor(pid int, scenario string, duration int, extraArgs []string) (*exec.Cmd, error) {
	bpfLink := filepath.Join(h.OutputDir, "ior.bpf.o")
	if err := os.Symlink(h.BpfObject, bpfLink); err != nil {
		return nil, fmt.Errorf("symlink bpf object: %w", err)
	}

	args := []string{
		"-pid", strconv.Itoa(pid),
		"-flamegraph",
		"-name", scenario,
		"-duration", strconv.Itoa(duration),
	}
	args = append(args, extraArgs...)
	cmd := exec.Command(h.IorBinary, args...)
	cmd.Dir = h.OutputDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start ior: %w", err)
	}
	return cmd, nil
}

// waitBoth waits for both the workload and ior commands concurrently.
// If ior does not finish within duration + grace period, it is killed.
func waitBoth(workloadCmd, iorCmd *exec.Cmd, duration int, grace time.Duration) (workloadErr, iorErr error) {
	workloadDone := make(chan error, 1)
	iorDone := make(chan error, 1)

	go func() { workloadDone <- workloadCmd.Wait() }()
	go func() { iorDone <- iorCmd.Wait() }()

	timeout := time.After(time.Duration(duration)*time.Second + grace)

	for workloadDone != nil || iorDone != nil {
		select {
		case err := <-workloadDone:
			workloadErr = err
			workloadDone = nil
		case err := <-iorDone:
			iorErr = err
			iorDone = nil
		case <-timeout:
			if iorDone != nil {
				iorCmd.Process.Kill()
				iorErr = fmt.Errorf("ior timed out")
				iorDone = nil
			}
			if workloadDone != nil {
				workloadCmd.Process.Kill()
				workloadErr = fmt.Errorf("workload timed out")
				workloadDone = nil
			}
			return
		}
	}
	return
}

// findIorZstFile locates the .ior.zst file matching the scenario name in the output directory.
func findIorZstFile(dir, scenario string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read output dir: %w", err)
	}

	for _, e := range entries {
		name := e.Name()
		if strings.Contains(name, scenario) && strings.HasSuffix(name, ".ior.zst") {
			return filepath.Join(dir, name), nil
		}
	}

	return "", fmt.Errorf("no .ior.zst file found for scenario %q in %s", scenario, dir)
}
