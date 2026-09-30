package integrationtests

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	workloadStartupTimeout = 5 * time.Second
	iorReadyTimeout        = 30 * time.Second
	iorReadySettleDelay    = time.Second
	iorShutdownGrace       = 30 * time.Second
	bpfObjectOverrideEnv   = "IOR_BPF_OBJECT"
	workloadStartupFileEnv = "IOR_WORKLOAD_STARTUP_FILE"
	iorReadyLine           = "Probing for "
)

// TestHarness orchestrates integration tests by starting an ior trace
// against a known ioworkload process and collecting the .ior.zst output.
type TestHarness struct {
	IorBinary      string // path to built ior binary
	WorkloadBinary string // path to built ioworkload binary
	BpfObject      string // optional path to external BPF object override
	OutputDir      string // temp dir for .ior.zst output
	WorkloadEnv    []string
	// IorOutput, when set, additionally receives every stdout/stderr line
	// of ior runs that wait for readiness (RunWithIorArgs), so a test can
	// assert on warnings and the end-of-run statistics.
	IorOutput *OutputCapture
	// IorArgsForPID, when set, returns extra ior args that depend on the
	// workload PID (known only once it started), e.g. "-tid <pid>". They are
	// appended after the harness's own args, so they override its -pid.
	// Honoured by RunWithIorArgs and RunParquetWithIorArgs.
	IorArgsForPID func(pid int) []string
}

// OutputCapture is a goroutine-safe line sink: ior's stdout and stderr are
// scanned by two goroutines at once.
type OutputCapture struct {
	mu  sync.Mutex
	buf strings.Builder
}

// Write appends p; it never fails.
func (c *OutputCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

// String returns everything captured so far.
func (c *OutputCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// Run executes a single integration test scenario. It starts the ioworkload
// binary, reads its PID from stdout, launches ior with a PID filter, waits
// for both to finish, and parses the resulting .ior.zst file.
func (h *TestHarness) Run(scenario string, duration int) (TestResult, int, error) {
	return h.RunWithIorArgs(scenario, duration, nil)
}

// RunWithIorArgs behaves like Run but forwards additional args to ior.
func (h *TestHarness) RunWithIorArgs(scenario string, duration int, extraIorArgs []string) (TestResult, int, error) {
	startupFile := h.workloadStartupFile(scenario)
	workloadCmd, workloadPID, workloadStderr, err := h.startWorkload(scenario, startupFile)
	if err != nil {
		return TestResult{}, 0, err
	}

	extraIorArgs = h.withPIDScopedArgs(extraIorArgs, workloadPID)
	iorCmd, readyCh, err := h.startIorForRun(workloadPID, scenario, duration, extraIorArgs)
	if err != nil {
		_ = workloadCmd.Process.Kill()
		_ = workloadCmd.Wait()
		return TestResult{}, workloadPID, err
	}
	if err := releaseWorkloadWhenIorReady(startupFile, workloadCmd, iorCmd, readyCh); err != nil {
		return TestResult{}, workloadPID, err
	}

	workloadErr, iorErr := waitBoth(workloadCmd, iorCmd, duration, iorShutdownGrace)

	if iorErr != nil {
		return TestResult{}, workloadPID, fmt.Errorf("ior: %w", iorErr)
	}
	if workloadErr != nil {
		return TestResult{}, workloadPID, workloadCommandError(workloadErr, workloadStderr.String())
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

// RunParquet executes a scenario in headless Parquet mode and returns the
// recorded Parquet path.
func (h *TestHarness) RunParquet(scenario string, duration int) (string, int, error) {
	return h.RunParquetWithIorArgs(scenario, duration, nil)
}

// RunParquetWithIorArgs behaves like RunParquet but forwards additional args
// to ior.
func (h *TestHarness) RunParquetWithIorArgs(scenario string, duration int, extraIorArgs []string) (string, int, error) {
	parquetPath := filepath.Join(h.OutputDir, scenario+".parquet")
	startupFile := h.workloadStartupFile(scenario)
	workloadCmd, workloadPID, workloadStderr, err := h.startWorkload(scenario, startupFile)
	if err != nil {
		return "", 0, err
	}

	extraIorArgs = h.withPIDScopedArgs(extraIorArgs, workloadPID)
	iorCmd, readyCh, err := h.startIorParquetForRun(workloadPID, parquetPath, duration, extraIorArgs)
	if err != nil {
		_ = workloadCmd.Process.Kill()
		_ = workloadCmd.Wait()
		return "", workloadPID, err
	}
	if err := releaseWorkloadWhenIorReady(startupFile, workloadCmd, iorCmd, readyCh); err != nil {
		return "", workloadPID, err
	}

	workloadErr, iorErr := waitBoth(workloadCmd, iorCmd, duration, iorShutdownGrace)
	if iorErr != nil {
		return "", workloadPID, fmt.Errorf("ior: %w", iorErr)
	}
	if workloadErr != nil {
		return "", workloadPID, workloadCommandError(workloadErr, workloadStderr.String())
	}
	return parquetPath, workloadPID, nil
}

// withPIDScopedArgs appends the IorArgsForPID args for pid to extra, leaving
// the caller's slice untouched.
func (h *TestHarness) withPIDScopedArgs(extra []string, pid int) []string {
	if h.IorArgsForPID == nil {
		return extra
	}
	return append(slices.Clone(extra), h.IorArgsForPID(pid)...)
}

func (h *TestHarness) workloadStartupFile(scenario string) string {
	if filepath.Base(h.WorkloadBinary) != "ioworkload" {
		return ""
	}
	return filepath.Join(h.OutputDir, scenario+".startup")
}

// startWorkload launches the workload for scenario and waits (bounded by
// workloadStartupTimeout) for it to print its PID as the first stdout line.
// The returned buffer captures the workload's stderr for error reporting.
func (h *TestHarness) startWorkload(scenario, startupFile string) (*exec.Cmd, int, *bytes.Buffer, error) {
	cmd, stderr := h.workloadCommand(scenario, startupFile)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, 0, nil, fmt.Errorf("workload stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, 0, nil, fmt.Errorf("start workload: %w", err)
	}

	pidCh, errCh := readWorkloadPID(stdout)
	startupTimer := time.NewTimer(workloadStartupTimeout)
	defer stopAndDrainTimer(startupTimer)

	select {
	case pid := <-pidCh:
		return cmd, pid, stderr, nil
	case err := <-errCh:
		killAndReap(cmd)
		return nil, 0, nil, err
	case <-startupTimer.C:
		killAndReap(cmd)
		return nil, 0, nil, fmt.Errorf("timeout waiting for workload PID")
	}
}

// workloadCommand builds the (unstarted) workload command. Its stderr is teed
// to the test's stderr and to the returned buffer. The environment is only
// overridden when extra env or a startup file is requested; a stale startup
// file is removed first so the workload's fresh write is what callers see.
func (h *TestHarness) workloadCommand(scenario, startupFile string) (*exec.Cmd, *bytes.Buffer) {
	cmd := exec.Command(h.WorkloadBinary, "--scenario="+scenario)
	stderr := &bytes.Buffer{}
	cmd.Stderr = io.MultiWriter(os.Stderr, stderr)
	if len(h.WorkloadEnv) > 0 || startupFile != "" {
		cmd.Env = append(os.Environ(), h.WorkloadEnv...)
		if startupFile != "" {
			_ = os.Remove(startupFile)
			cmd.Env = append(cmd.Env, workloadStartupFileEnv+"="+startupFile)
		}
	}
	return cmd, stderr
}

// readWorkloadPID parses the first stdout line as the workload PID in a
// goroutine, delivering either the PID or an error. After a PID (or a read
// error / EOF) it drains the rest of the pipe so cmd.Wait() does not block on
// a full pipe. On a PID parse error it returns without draining: startWorkload
// then kills the workload, which closes the pipe, so Wait cannot block.
func readWorkloadPID(stdout io.Reader) (<-chan int, <-chan error) {
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
		_, _ = io.Copy(io.Discard, stdout)
	}()
	return pidCh, errCh
}

// killAndReap kills a started workload that failed to report its PID and
// waits for it so no zombie is left behind.
func killAndReap(cmd *exec.Cmd) {
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

func workloadCommandError(err error, stderr string) error {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return fmt.Errorf("workload: %w", err)
	}
	return fmt.Errorf("workload: %w: %s", err, stderr)
}

func (h *TestHarness) startIor(pid int, scenario string, duration int, extraArgs []string) (*exec.Cmd, error) {
	args := []string{
		"-pid", strconv.Itoa(pid),
		"-flamegraph",
		"-name", scenario,
		"-duration", strconv.Itoa(duration),
	}
	args = append(args, extraArgs...)
	return h.startIorArgs(args)
}

func (h *TestHarness) startIorForRun(pid int, scenario string, duration int, extraArgs []string) (*exec.Cmd, <-chan error, error) {
	args := []string{
		"-pid", strconv.Itoa(pid),
		"-flamegraph",
		"-name", scenario,
		"-duration", strconv.Itoa(duration),
	}
	args = append(args, extraArgs...)
	return h.startIorArgsWithReady(args)
}

func (h *TestHarness) startIorParquet(pid int, parquetPath string, duration int, extraArgs []string) (*exec.Cmd, error) {
	args := []string{
		"-pid", strconv.Itoa(pid),
		"-parquet", parquetPath,
		"-duration", strconv.Itoa(duration),
	}
	args = append(args, extraArgs...)
	return h.startIorArgs(args)
}

func (h *TestHarness) startIorParquetForRun(pid int, parquetPath string, duration int, extraArgs []string) (*exec.Cmd, <-chan error, error) {
	args := []string{
		"-pid", strconv.Itoa(pid),
		"-parquet", parquetPath,
		"-duration", strconv.Itoa(duration),
	}
	args = append(args, extraArgs...)
	return h.startIorArgsWithReady(args)
}

func (h *TestHarness) startIorArgs(args []string) (*exec.Cmd, error) {
	cmd := exec.Command(h.IorBinary, args...)
	cmd.Dir = h.OutputDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if h.BpfObject != "" {
		cmd.Env = append(os.Environ(), bpfObjectOverrideEnv+"="+h.BpfObject)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start ior: %w", err)
	}
	return cmd, nil
}

func (h *TestHarness) startIorArgsWithReady(args []string) (*exec.Cmd, <-chan error, error) {
	cmd := exec.Command(h.IorBinary, args...)
	cmd.Dir = h.OutputDir
	if h.BpfObject != "" {
		cmd.Env = append(os.Environ(), bpfObjectOverrideEnv+"="+h.BpfObject)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("ior stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("ior stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start ior: %w", err)
	}

	readyCh := make(chan error, 1)
	var once sync.Once
	signalReady := func(err error) {
		once.Do(func() {
			readyCh <- err
			close(readyCh)
		})
	}

	var outW, errW io.Writer = os.Stdout, os.Stderr
	if h.IorOutput != nil {
		outW = io.MultiWriter(os.Stdout, h.IorOutput)
		errW = io.MultiWriter(os.Stderr, h.IorOutput)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go scanIorOutput(stdout, outW, signalReady, &wg)
	go scanIorOutput(stderr, errW, signalReady, &wg)
	go func() {
		wg.Wait()
		signalReady(fmt.Errorf("ior exited before readiness line"))
	}()

	return cmd, readyCh, nil
}

func scanIorOutput(r io.Reader, w io.Writer, signalReady func(error), wg *sync.WaitGroup) {
	defer wg.Done()
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		_, _ = fmt.Fprintln(w, line)
		if strings.Contains(line, iorReadyLine) {
			signalReady(nil)
		}
	}
	if err := scanner.Err(); err != nil {
		signalReady(fmt.Errorf("read ior output: %w", err))
	}
}

func releaseWorkloadWhenIorReady(startupFile string, workloadCmd, iorCmd *exec.Cmd, readyCh <-chan error) error {
	if startupFile == "" {
		return nil
	}

	timer := time.NewTimer(iorReadyTimeout)
	defer stopAndDrainTimer(timer)

	select {
	case err := <-readyCh:
		if err != nil {
			killAndWait(workloadCmd)
			killAndWait(iorCmd)
			return fmt.Errorf("wait for ior readiness: %w", err)
		}
		time.Sleep(iorReadySettleDelay)
		if err := os.WriteFile(startupFile, []byte("ready\n"), 0o600); err != nil {
			killAndWait(workloadCmd)
			killAndWait(iorCmd)
			return fmt.Errorf("release workload: %w", err)
		}
		return nil
	case <-timer.C:
		killAndWait(workloadCmd)
		killAndWait(iorCmd)
		return fmt.Errorf("timeout waiting for ior readiness")
	}
}

func killAndWait(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

// waitBoth waits for both the workload and ior commands concurrently.
// If ior does not finish within duration + grace period, it is killed.
func waitBoth(workloadCmd, iorCmd *exec.Cmd, duration int, grace time.Duration) (workloadErr, iorErr error) {
	workloadDone := make(chan error, 1)
	iorDone := make(chan error, 1)

	// Pass channels as parameters so subsequent nil assignments in this
	// function do not affect the goroutines' send targets.
	go func(ch chan error) { ch <- workloadCmd.Wait() }(workloadDone)
	go func(ch chan error) { ch <- iorCmd.Wait() }(iorDone)

	timeout := time.NewTimer(time.Duration(duration)*time.Second + grace)
	defer stopAndDrainTimer(timeout)

	for workloadDone != nil || iorDone != nil {
		select {
		case err := <-workloadDone:
			workloadErr = err
			workloadDone = nil
		case err := <-iorDone:
			iorErr = err
			iorDone = nil
		case <-timeout.C:
			if iorDone != nil {
				_ = iorCmd.Process.Kill()
				iorErr = fmt.Errorf("ior timed out")
				iorDone = nil
			}
			if workloadDone != nil {
				_ = workloadCmd.Process.Kill()
				workloadErr = fmt.Errorf("workload timed out")
				workloadDone = nil
			}
			return
		}
	}
	return
}

func stopAndDrainTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
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
