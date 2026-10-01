package integrationtests

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
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
	// for the closed-pipe test, the end of the run) can stop ior in time. It
	// must stay well below ioworkload's hold timeout (120s, holdFileTimeout in
	// cmd/ioworkload): a workload that gave up its hold first would end the
	// run by exiting.
	shutdownRunDuration = 60
	// pipeRunDuration is the -duration of the closed-pipe runs: short, because
	// the run must reach its natural end (and its stats writes) to hit the pipe.
	pipeRunDuration = 6
	// shutdownDrainDelay lets the workload's events travel through the ring
	// buffer into the recorder before the run is stopped.
	shutdownDrainDelay = time.Second
)

// Task vr2: a headless -pid run ends when its target exits, so these runs keep
// the workload alive after its I/O (IOR_WORKLOAD_HOLD_FILE) until the test
// releases it; otherwise ior would stop by itself before the signal or pipe
// under test ever happened.

// holdFileEnv is ioworkload's "stay alive until this file exists" variable.
const holdFileEnv = "IOR_WORKLOAD_HOLD_FILE"

// signalRun is one started ior process whose stdout/stderr the test owns.
type signalRun struct {
	ior      *exec.Cmd
	stdout   io.ReadCloser
	stderr   io.ReadCloser
	done     chan error // receives ior's Wait result
	workload *exec.Cmd  // the traced -pid target, alive until releaseTarget
	holdFile string     // creating it lets the workload exit

	mu        sync.Mutex
	stdoutBuf strings.Builder // everything ior wrote to stdout
	stderrBuf strings.Builder // everything ior wrote to stderr
}

// releaseTarget lets the traced workload exit and waits for it, the trigger
// for an ior that should end because its -pid target died.
func (r *signalRun) releaseTarget(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(r.holdFile, []byte("release\n"), 0o600); err != nil {
		t.Fatalf("release target: %v", err)
	}
	if err := r.workload.Wait(); err != nil {
		t.Fatalf("workload: %v", err)
	}
}

// text returns what ior wrote to stdout and to stderr so far.
func (r *signalRun) text() (stdout, stderr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stdoutBuf.String(), r.stderrBuf.String()
}

// lockedWriter appends to a signalRun buffer under its mutex.
type lockedWriter struct {
	mu *sync.Mutex
	b  *strings.Builder
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

// startSignalRun starts the open-basic workload and a real ior against it in
// the given output mode, waits until ior is attached and lets the workload run
// its I/O. The workload then stays alive (see holdFileEnv) until the caller
// calls releaseTarget. The returned run keeps ior's pipes open and drained;
// the caller decides what to do to them.
func startSignalRun(t *testing.T, h TestHarness, modeArgs []string, duration int) *signalRun {
	t.Helper()
	return startSignalRunWith(t, h, modeArgs, duration, func(iorArgs []string) *exec.Cmd {
		return exec.Command(h.IorBinary, iorArgs...)
	})
}

// signalTarget is the workload a signalRun traces and how ior is pointed at
// it: scenario is the ioworkload scenario and scope returns the filter
// arguments ior gets for the workload's pid. The zero value is the open-basic
// workload traced with -pid.
type signalTarget struct {
	scenario string
	scope    func(pid int) ([]string, error)
}

// scenarioName is the scenario to start, open-basic by default.
func (st signalTarget) scenarioName() string {
	if st.scenario == "" {
		return "open-basic"
	}
	return st.scenario
}

// scopeArgs is "-pid <pid>" unless the target brings its own scope.
func (st signalTarget) scopeArgs(pid int) ([]string, error) {
	if st.scope == nil {
		return []string{"-pid", strconv.Itoa(pid)}, nil
	}
	return st.scope(pid)
}

// startSignalRunWith is startSignalRun with the command construction left to
// the caller, so a test can start ior through a wrapper (for instance a shell
// that ignores SIGHUP first). newCmd receives ior's full argument list; the
// command it returns must exec or run ior itself so signals sent to it reach
// ior.
func startSignalRunWith(t *testing.T, h TestHarness, modeArgs []string, duration int, newCmd func(iorArgs []string) *exec.Cmd) *signalRun {
	t.Helper()
	return startTargetRun(t, h, signalTarget{}, modeArgs, duration, newCmd)
}

// startTargetRun is startSignalRunWith for any signalTarget: the workload
// runs the target's scenario and ior traces it with the target's scope. It is
// split into the three phases of a run's start: the held workload
// (startTargetWorkload), ior with drained pipes (startIor) and the readiness
// handshake that lets the workload begin its I/O (awaitIorReady).
func startTargetRun(t *testing.T, h TestHarness, target signalTarget, modeArgs []string, duration int, newCmd func(iorArgs []string) *exec.Cmd) *signalRun {
	t.Helper()
	run, startupFile, pid := startTargetWorkload(t, h, target)
	scope, err := target.scopeArgs(pid)
	if err != nil {
		t.Fatalf("scope ior to the workload: %v", err)
	}
	args := append(append(scope, "-duration", strconv.Itoa(duration)), modeArgs...)
	ready, readers := startIor(t, h, run, newCmd(args))
	awaitIorReady(t, run, ready, readers, startupFile)
	return run
}

// startTargetWorkload starts the target's scenario, parked on its startup file
// and held alive after its scenario by the hold file (see holdFileEnv). It
// returns the run holding just the workload, the startup file whose creation
// lets the scenario begin, and the pid the workload announced. The workload is
// killed at cleanup.
func startTargetWorkload(t *testing.T, h TestHarness, target signalTarget) (run *signalRun, startupFile string, pid int) {
	t.Helper()
	scenario := target.scenarioName()
	startupFile = h.workloadStartupFile(scenario)
	holdFile := filepath.Join(h.OutputDir, scenario+".hold")
	h.WorkloadEnv = append(slices.Clone(h.WorkloadEnv), holdFileEnv+"="+holdFile)
	workloadCmd, pid, _, err := h.startWorkload(scenario, startupFile)
	if err != nil {
		t.Fatalf("start workload: %v", err)
	}
	t.Cleanup(func() { killAndWait(workloadCmd) })
	return &signalRun{workload: workloadCmd, holdFile: holdFile}, startupFile, pid
}

// startIor starts cmd (ior, or a wrapper that runs it) in the output
// directory and drains both of its pipes into run's buffers. ready closes
// when ior's readiness line appears on stderr; readers is done once both
// pipes hit EOF (or the test closed them). ior is killed at cleanup.
func startIor(t *testing.T, h TestHarness, run *signalRun, cmd *exec.Cmd) (ready chan struct{}, readers *sync.WaitGroup) {
	t.Helper()
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
		killAndWait(run.workload)
		t.Fatalf("start ior: %v", err)
	}
	t.Cleanup(func() { killAndWait(cmd) })
	run.ior, run.stdout, run.stderr = cmd, stdout, stderr

	ready = make(chan struct{})
	readers = new(sync.WaitGroup)
	readers.Add(2)
	go func() {
		defer readers.Done()
		_, _ = io.Copy(lockedWriter{&run.mu, &run.stdoutBuf}, stdout)
	}()
	go func() {
		defer readers.Done()
		scanUntilReady(io.TeeReader(stderr, lockedWriter{&run.mu, &run.stderrBuf}), ready)
	}()
	return ready, readers
}

// awaitIorReady waits for ior's readiness line, lets the probes settle,
// releases the workload's scenario through its startup file and arms
// run.done with ior's Wait result.
func awaitIorReady(t *testing.T, run *signalRun, ready <-chan struct{}, readers *sync.WaitGroup, startupFile string) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(iorReadyTimeout):
		killAndWait(run.workload)
		t.Fatalf("ior did not become ready")
	}
	time.Sleep(iorReadySettleDelay)
	if err := os.WriteFile(startupFile, []byte("ready\n"), 0o600); err != nil {
		t.Fatalf("release workload: %v", err)
	}
	run.done = make(chan error, 1)
	go func() {
		// Wait closes the pipes' read ends, discarding unread bytes, so it
		// runs only after both readers hit EOF (or the test closed the pipes).
		readers.Wait()
		run.done <- run.ior.Wait()
	}()
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
	switch mode {
	case "parquet":
		return []string{"-parquet", filepath.Join(dir, "signal-shutdown.parquet")}
	case "plain":
		return []string{"-plain"}
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
// (ended here by its target exiting) still ends normally and publishes the recording instead of dying from
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
			// The target's exit ends the run; its status line, the
			// statistics and the final messages are the writes that hit the
			// closed pipes.
			run.releaseTarget(t)
			run.requireCleanExit(t, pipeRunDuration*time.Second+iorShutdownGrace)
			requireRecording(t, h.OutputDir, mode)
		})
	}
}

// hupIgnoringCmd starts ior the way `nohup ior ... &` does: through a shell
// that sets SIGHUP to ignored and then execs ior, so ior inherits SIG_IGN. exec
// keeps the pid, so signals to the returned command reach ior. (nohup itself
// is avoided: it also redirects output when stdout is a terminal.)
func hupIgnoringCmd(iorBinary string) func(iorArgs []string) *exec.Cmd {
	return func(iorArgs []string) *exec.Cmd {
		script := `trap "" HUP; exec "$@"`
		return exec.Command("sh", append([]string{"-c", script, "sh", iorBinary}, iorArgs...)...)
	}
}

// TestHeadlessRecordingKeepsInheritedSIGHUPIgnore is the nohup regression (task
// mq2 review): a run started with SIGHUP ignored must keep ignoring it. The
// first SIGHUP handling installed a handler over the inherited SIG_IGN, so a
// hangup ended `nohup ior -flamegraph -duration 3600 &` early. Here the run
// gets a SIGHUP right after start and must still be running well after it,
// then end at its own -duration (its target is held alive, so the target's
// exit does not end it first) with the full recording.
func TestHeadlessRecordingKeepsInheritedSIGHUPIgnore(t *testing.T) {
	for _, mode := range []string{"flamegraph", "parquet"} {
		t.Run(mode, func(t *testing.T) {
			enableParallelIfRequested(t)
			h := newTestHarness(t)
			run := startSignalRunWith(t, h, modeArgs(mode, h.OutputDir), pipeRunDuration, hupIgnoringCmd(h.IorBinary))
			time.Sleep(shutdownDrainDelay)
			if err := run.ior.Process.Signal(syscall.SIGHUP); err != nil {
				t.Fatalf("send SIGHUP: %v", err)
			}
			select {
			case err := <-run.done:
				t.Fatalf("ior ended right after a SIGHUP it should have ignored (wait: %v)", err)
			case <-time.After(2 * time.Second):
			}
			run.requireCleanExit(t, pipeRunDuration*time.Second+iorShutdownGrace)
			requireRecording(t, h.OutputDir, mode)
		})
	}
}

// TestHeadlessPidRunEndsWhenTargetExits is the vr2 regression: with the
// default-sized -duration (60s here, 900s in real life) a headless -pid run
// used to keep probing after its target died, and traced whatever process was
// handed the recycled pid. It must now end by itself shortly after the target
// exits (nothing signals ior), say so on stderr, and still publish everything
// the target did. The liveness watcher is off (testDisableTargetWatchEnv), so
// the group-dead exit record alone has to end the run; the watcher has its
// own test below.
func TestHeadlessPidRunEndsWhenTargetExits(t *testing.T) {
	for _, mode := range []string{"flamegraph", "parquet", "plain"} {
		t.Run(mode, func(t *testing.T) {
			enableParallelIfRequested(t)
			h := newTestHarness(t)
			run := startSignalRunWith(t, h, modeArgs(mode, h.OutputDir), shutdownRunDuration,
				iorCmdWithEnv(h, testDisableTargetWatchEnv+"=1"))
			time.Sleep(shutdownDrainDelay)
			select {
			case err := <-run.done:
				t.Fatalf("ior ended while its target was still alive (wait: %v)", err)
			default:
			}

			run.releaseTarget(t)
			// Far below -duration: only the target's exit can have ended it.
			run.requireCleanExit(t, iorShutdownGrace)
			stdout, stderr := run.text()
			if !strings.Contains(stderr, "exited, stopping the trace") {
				t.Fatalf("stderr does not announce the target's exit:\n%s", stderr)
			}
			if !strings.Contains(stderr, "group-dead exits: 1") {
				t.Fatalf("stderr statistics do not show the target's exit:\n%s", stderr)
			}
			if mode == "plain" {
				if !strings.Contains(stdout, "testfile.txt") {
					t.Fatalf("plain output lost the target's rows:\n%s", stdout)
				}
				return
			}
			requireRecording(t, h.OutputDir, mode)
		})
	}
}

// testDisableTargetExitRecordEnv is ior's test hook that turns the
// group-dead-record trigger off (internal.disableTargetExitRecordEnv; it reads
// exactly "1", other values leave the trigger on), leaving
// the liveness watcher as the only thing that can end a run with its target.
const testDisableTargetExitRecordEnv = "IOR_TEST_DISABLE_TARGET_EXIT_RECORD"

// testDisableTargetWatchEnv is the opposite hook (internal.disableTargetWatchEnv,
// also exactly "1"): the liveness watcher does not start, leaving the exit
// records as the only thing that can end a run with its target. Both triggers
// print the same status line, so a test of the record path needs it: with the
// 500 ms watcher running, a broken record trigger would still pass.
const testDisableTargetWatchEnv = "IOR_TEST_DISABLE_TARGET_WATCH"

// iorCmdWithEnv returns a newCmd for startSignalRunWith / startTargetRun that
// runs ior with env added to the test's environment.
func iorCmdWithEnv(h TestHarness, env ...string) func(iorArgs []string) *exec.Cmd {
	return func(iorArgs []string) *exec.Cmd {
		cmd := exec.Command(h.IorBinary, iorArgs...)
		cmd.Env = append(os.Environ(), env...)
		return cmd
	}
}

// TestHeadlessPidRunEndsViaLivenessWatcherWithoutExitRecord covers the
// fallback of the vr2 fix: when the target's group-dead record is lost (ring
// buffer drop) or never produced (death during the probe attach) the run must
// still end. A lost record cannot be forced, so the record trigger is disabled
// through the test hook (the record is still processed and counted, it just no
// longer stops the trace); the run must then end on the watcher alone.
func TestHeadlessPidRunEndsViaLivenessWatcherWithoutExitRecord(t *testing.T) {
	for _, mode := range []string{"flamegraph", "parquet", "plain"} {
		t.Run(mode, func(t *testing.T) {
			enableParallelIfRequested(t)
			h := newTestHarness(t)
			newCmd := func(iorArgs []string) *exec.Cmd {
				cmd := exec.Command(h.IorBinary, iorArgs...)
				cmd.Env = append(os.Environ(), testDisableTargetExitRecordEnv+"=1")
				return cmd
			}
			run := startSignalRunWith(t, h, modeArgs(mode, h.OutputDir), shutdownRunDuration, newCmd)
			time.Sleep(shutdownDrainDelay)
			select {
			case err := <-run.done:
				t.Fatalf("ior ended while its target was still alive (wait: %v)", err)
			default:
			}

			run.releaseTarget(t)
			// The watcher polls every 500ms; -duration is 60s.
			run.requireCleanExit(t, iorShutdownGrace)
			stdout, stderr := run.text()
			if !strings.Contains(stderr, "exited, stopping the trace") {
				t.Fatalf("stderr does not announce the target's exit:\n%s", stderr)
			}
			if mode == "plain" {
				if !strings.Contains(stdout, "testfile.txt") {
					t.Fatalf("plain output lost the target's rows:\n%s", stdout)
				}
				return
			}
			requireRecording(t, h.OutputDir, mode)
		})
	}
}
