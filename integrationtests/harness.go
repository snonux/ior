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
	// IorEnv holds extra KEY=VALUE entries for ior's environment (on top of
	// the test process's own), typically ior's IOR_TEST_* hooks. Honoured by
	// every run that builds ior through iorCommand.
	IorEnv []string
	// IorWrapper, when set, is a command prefix ior is started through, e.g.
	// "unshare -T --boottime 1000 --". The wrapper must exec ior rather than
	// fork it: the harness signals and reaps the process it started.
	IorWrapper []string
	// IorOutput, when set, additionally receives every stdout/stderr line
	// of ior runs that wait for readiness (RunWithIorArgs). waitBoth reads
	// both pipes to EOF before it reaps ior, so once a run that ended on its
	// own returns, the capture is complete and a test can assert on warnings
	// and the end-of-run statistics without polling. (A run that hit the
	// timeout is killed and may have lost its tail.)
	IorOutput *OutputCapture
	// IorArgsForPID, when set, returns extra ior args that depend on the
	// workload PID (known only once it started), e.g. "-tid <pid>". They are
	// appended after the harness's own args, so they override its -pid.
	// Honoured by RunWithIorArgs and RunParquetWithIorArgs. It runs after the
	// workload started, so it must report failure through its error result
	// and never t.Fatal/runtime.Goexit: the harness kills and reaps the
	// workload when an error is returned, whereas an unwound goroutine would
	// skip that cleanup and leave the workload to time out as a zombie.
	IorArgsForPID func(pid int) ([]string, error)
	// ReleaseDelay is waited on top of iorReadySettleDelay before the
	// workload is released. The harness's timing is otherwise the same in
	// every run, to the millisecond, and so is its phase against ior's
	// periodic work (the 500 ms liveness check of a -pid target); a test
	// whose case depends on where the workload's exit falls in that period
	// varies the delay from run to run (task f23).
	ReleaseDelay time.Duration
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
	return h.runFlamegraph(scenario, duration, extraIorArgs, true)
}

// RunSystemWideWithIorArgs is RunWithIorArgs without the -pid scope: ior traces
// every process (narrowed only by extraIorArgs, typically -comm), so a process
// the workload creates is traced too. A -pid run skips it by design, which is
// the wrong shape for anything about fork children. Without -pid ior does not
// end when the workload does, so the run lasts the full duration seconds: pass a
// short one, long enough for the scenario.
func (h *TestHarness) RunSystemWideWithIorArgs(scenario string, duration int, extraIorArgs []string) (TestResult, int, error) {
	return h.runFlamegraph(scenario, duration, extraIorArgs, false)
}

// runFlamegraph is the shared body of RunWithIorArgs (pidScoped) and
// RunSystemWideWithIorArgs.
func (h *TestHarness) runFlamegraph(scenario string, duration int, extraIorArgs []string, pidScoped bool) (TestResult, int, error) {
	startupFile := h.workloadStartupFile(scenario)
	workloadCmd, workloadPID, workloadStderr, err := h.startWorkload(scenario, startupFile)
	if err != nil {
		return TestResult{}, 0, err
	}

	iorPID := workloadPID
	if pidScoped {
		extraIorArgs, err = h.withPIDScopedArgs(extraIorArgs, workloadPID, workloadCmd)
		if err != nil {
			return TestResult{}, workloadPID, err
		}
	} else {
		iorPID = 0 // startIorForRun: no -pid
	}
	ior, err := h.startIorForRun(iorPID, scenario, duration, extraIorArgs)
	if err != nil {
		_ = workloadCmd.Process.Kill()
		_ = workloadCmd.Wait()
		return TestResult{}, workloadPID, err
	}
	if err := releaseWorkloadWhenIorReady(startupFile, workloadCmd, ior.cmd, ior.ready, h.ReleaseDelay); err != nil {
		return TestResult{}, workloadPID, err
	}

	workloadErr, iorErr := waitBoth(workloadCmd, ior.cmd, ior.outputDone, duration, iorShutdownGrace)

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

	extraIorArgs, err = h.withPIDScopedArgs(extraIorArgs, workloadPID, workloadCmd)
	if err != nil {
		return "", workloadPID, err
	}
	ior, err := h.startIorParquetForRun(workloadPID, parquetPath, duration, extraIorArgs)
	if err != nil {
		_ = workloadCmd.Process.Kill()
		_ = workloadCmd.Wait()
		return "", workloadPID, err
	}
	if err := releaseWorkloadWhenIorReady(startupFile, workloadCmd, ior.cmd, ior.ready, h.ReleaseDelay); err != nil {
		return "", workloadPID, err
	}

	workloadErr, iorErr := waitBoth(workloadCmd, ior.cmd, ior.outputDone, duration, iorShutdownGrace)
	if iorErr != nil {
		return "", workloadPID, fmt.Errorf("ior: %w", iorErr)
	}
	if workloadErr != nil {
		return "", workloadPID, workloadCommandError(workloadErr, workloadStderr.String())
	}
	return parquetPath, workloadPID, nil
}

// withPIDScopedArgs appends the IorArgsForPID args for pid to extra, leaving
// the caller's slice untouched. If IorArgsForPID fails, the already started
// workload is killed and reaped here (it would otherwise block for its
// startup file and linger as a zombie) and the error is returned.
func (h *TestHarness) withPIDScopedArgs(extra []string, pid int, workloadCmd *exec.Cmd) ([]string, error) {
	if h.IorArgsForPID == nil {
		return extra, nil
	}
	scoped, err := h.IorArgsForPID(pid)
	if err != nil {
		killAndReap(workloadCmd)
		return nil, fmt.Errorf("ior args for workload pid %d: %w", pid, err)
	}
	return append(slices.Clone(extra), scoped...), nil
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
// overridden when extra env or a startup file is requested. A stale startup
// file is removed first: the harness writes the file to release the workload
// (releaseWorkloadWhenIorReady) and the workload polls for it, so a leftover
// one would let the workload start before ior has attached.
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

func (h *TestHarness) startIorForRun(pid int, scenario string, duration int, extraArgs []string) (*iorProcess, error) {
	var args []string
	if pid > 0 {
		args = append(args, "-pid", strconv.Itoa(pid))
	}
	args = append(args,
		"-flamegraph",
		"-name", scenario,
		"-duration", strconv.Itoa(duration),
	)
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

func (h *TestHarness) startIorParquetForRun(pid int, parquetPath string, duration int, extraArgs []string) (*iorProcess, error) {
	args := []string{
		"-pid", strconv.Itoa(pid),
		"-parquet", parquetPath,
		"-duration", strconv.Itoa(duration),
	}
	args = append(args, extraArgs...)
	return h.startIorArgsWithReady(args)
}

func (h *TestHarness) startIorArgs(args []string) (*exec.Cmd, error) {
	cmd := h.iorCommand(args)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start ior: %w", err)
	}
	return cmd, nil
}

// iorCommand builds the (unstarted) ior command: run in the output directory
// and, when configured, through IorWrapper and with the BPF object override
// and IorEnv in its environment. A nil Env (neither configured) inherits the
// test process's.
func (h *TestHarness) iorCommand(args []string) *exec.Cmd {
	argv := slices.Concat(h.IorWrapper, []string{h.IorBinary}, args)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = h.OutputDir
	if h.BpfObject != "" || len(h.IorEnv) > 0 {
		cmd.Env = append(os.Environ(), h.IorEnv...)
		if h.BpfObject != "" {
			cmd.Env = append(cmd.Env, bpfObjectOverrideEnv+"="+h.BpfObject)
		}
	}
	return cmd
}

// iorProcess is a started ior whose stdout/stderr are scanned line by line.
type iorProcess struct {
	cmd *exec.Cmd
	// ready delivers nil once ior printed iorReadyLine, or an error if its
	// output ended (or failed) before that.
	ready <-chan error
	// outputDone is closed once both output scanners hit EOF, i.e. every line
	// ior wrote has been forwarded. exec.Cmd.Wait closes the read ends of
	// StdoutPipe/StderrPipe, discarding unread bytes, so Wait must not run
	// before this channel is closed (see waitBoth).
	outputDone <-chan struct{}
}

func (h *TestHarness) startIorArgsWithReady(args []string) (*iorProcess, error) {
	cmd := h.iorCommand(args)
	stdout, stderr, err := iorOutputPipes(cmd)
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start ior: %w", err)
	}

	ready, outputDone := h.scanIorStreams(stdout, stderr)
	return &iorProcess{cmd: cmd, ready: ready, outputDone: outputDone}, nil
}

// iorOutputPipes attaches pipes to ior's stdout and stderr; they must be
// created before cmd.Start.
func iorOutputPipes(cmd *exec.Cmd) (stdout, stderr io.ReadCloser, err error) {
	stdout, err = cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("ior stdout pipe: %w", err)
	}
	stderr, err = cmd.StderrPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("ior stderr pipe: %w", err)
	}
	return stdout, stderr, nil
}

// scanIorStreams forwards every line of ior's stdout/stderr to the test
// process's own streams (and h.IorOutput when set) in one goroutine per
// stream. ready receives nil once iorReadyLine was seen, or an error if the
// output ended first; outputDone closes once both streams hit EOF.
func (h *TestHarness) scanIorStreams(stdout, stderr io.Reader) (ready <-chan error, outputDone <-chan struct{}) {
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
	done := make(chan struct{})
	go func() {
		wg.Wait()
		signalReady(fmt.Errorf("ior exited before readiness line"))
		close(done)
	}()
	return readyCh, done
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
		// Keep draining after a scan error (e.g. an over-long line): stopping
		// would leave the pipe full and block ior on its next write.
		_, _ = io.Copy(io.Discard, r)
	}
}

// releaseWorkloadWhenIorReady writes the startup file the workload waits for
// once ior reported readiness and iorReadySettleDelay plus extraDelay
// (TestHarness.ReleaseDelay) have passed.
func releaseWorkloadWhenIorReady(startupFile string, workloadCmd, iorCmd *exec.Cmd, readyCh <-chan error, extraDelay time.Duration) error {
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
		time.Sleep(iorReadySettleDelay + extraDelay)
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
//
// iorOutputDone, when non-nil, is the outputDone channel of an ior started
// with startIorArgsWithReady. ior's Wait is held back until it closes: Wait
// closes the pipe read ends once the process exited, so calling it while the
// scanners still read discards ior's last buffered lines (typically the final
// statistics block). The channel closes on EOF, i.e. when ior and every
// process inheriting its stdout/stderr have closed them. If that never
// happens (ior hung, or left a child holding the pipe), the timeout below
// kills ior, releases the held-back Wait and reports "ior timed out"; the
// lines lost that way are irrelevant for a failed run.
//
// Trade-off: a child of ior that keeps the output pipe open after ior itself
// exited (even with status 0) therefore yields "ior timed out" after
// duration + grace instead of ior's real exit status, because the scanners
// never reach EOF while the pipe is held. Accepting that was deliberate:
// reporting a hang is preferable to silently truncating ior's output.
//
// Pass nil when ior's output is not scanned (plain exec.Cmd with
// Stdout/Stderr set).
func waitBoth(workloadCmd, iorCmd *exec.Cmd, iorOutputDone <-chan struct{}, duration int, grace time.Duration) (workloadErr, iorErr error) {
	// abandon is closed on return so a Wait held back for the scanners is
	// released even when the output pipe never reaches EOF; it also reaps
	// ior after the timeout kill.
	abandon := make(chan struct{})
	defer close(abandon)
	workloadDone, iorDone := startWaiters(workloadCmd, iorCmd, iorOutputDone, abandon)

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
				iorErr = killTimedOut(iorCmd, "ior")
			}
			if workloadDone != nil {
				workloadErr = killTimedOut(workloadCmd, "workload")
			}
			return
		}
	}
	return
}

// startWaiters reaps both commands in their own goroutines and returns the
// channels (buffered, so a goroutine never blocks after waitBoth returned)
// delivering each Wait result. See waitBoth for iorOutputDone and abandon.
func startWaiters(workloadCmd, iorCmd *exec.Cmd, iorOutputDone <-chan struct{}, abandon <-chan struct{}) (workloadDone, iorDone <-chan error) {
	wch := make(chan error, 1)
	ich := make(chan error, 1)
	go func() { wch <- workloadCmd.Wait() }()
	go func() {
		if iorOutputDone != nil {
			select {
			case <-iorOutputDone:
			case <-abandon:
			}
		}
		ich <- iorCmd.Wait()
	}()
	return wch, ich
}

// killTimedOut kills a command that outlived the waitBoth deadline and returns
// the error to report for it. The command's own Wait goroutine reaps it.
func killTimedOut(cmd *exec.Cmd, name string) error {
	_ = cmd.Process.Kill()
	return fmt.Errorf("%s timed out", name)
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
