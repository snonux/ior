package tui

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ior/internal/parquet"
	"ior/internal/streamrow"
	common "ior/internal/tui/common"

	tea "charm.land/bubbletea/v2"
)

// execDoneMsg is what execTestModel's ExecProcess callback delivers.
type execDoneMsg struct{ err error }

// execTestModel is a model whose Init runs a child through common.ExecProcess,
// the way the stream tab's "open in editor" does. Bubble Tea then blocks its
// event loop in the child, the situation the exec-aware signal handling exists
// for. It records whether the quit request ever reached Update and, unless
// noAutoQuit, quits itself when the child is done (the user closed the editor).
type execTestModel struct {
	child      *exec.Cmd
	noAutoQuit bool
	quitSeen   atomic.Bool
	execDone   atomic.Bool
}

func (m *execTestModel) Init() tea.Cmd {
	return common.ExecProcess(m.child, func(err error) tea.Msg { return execDoneMsg{err: err} })
}
func (m *execTestModel) View() tea.View { return tea.NewView("") }
func (m *execTestModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg.(type) {
	case signalQuitMsg:
		m.quitSeen.Store(true)
		return m, tea.Quit
	case execDoneMsg:
		m.execDone.Store(true)
		if !m.noAutoQuit {
			return m, tea.Quit
		}
	}
	return m, nil
}

// fakeEditor returns a child that writes its pid to a file once it is set up
// and then sleeps. With ignoreTerm it ignores SIGTERM (an editor that does not
// die politely), so only SIGKILL ends it.
func fakeEditor(t *testing.T, ignoreTerm bool, sleep string) (*exec.Cmd, string) {
	t.Helper()
	pidFile := filepath.Join(t.TempDir(), "pid")
	script := `echo $$ > "$1.tmp" && mv "$1.tmp" "$1" && exec sleep ` + sleep
	if ignoreTerm {
		script = `trap '' TERM; ` + script
	}
	cmd := exec.Command("sh", "-c", script, "sh", pidFile)
	// The test program's input is a pipe, which exec would copy to the child
	// on a goroutine that Wait then never sees end; a real terminal is a file
	// and needs none. /dev/null is a file too, so the child owns its stdin.
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = devNull.Close() })
	cmd.Stdin = devNull
	return cmd, pidFile
}

// waitForEditor blocks until the fake editor has started and the exec is
// marked active, and returns its pid.
func waitForEditor(t *testing.T, pidFile string) int {
	t.Helper()
	var pid int
	waitFor(t, func() bool {
		b, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(b)))
		return err == nil && common.ExecActive()
	})
	return pid
}

func processAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }

// recorderRecordingTo starts a real Parquet recorder with one row on a path in
// a temp dir and returns it with the watcher hook that stops it.
func recorderRecordingTo(t *testing.T) (*parquet.Recorder, string, watcherHooks) {
	t.Helper()
	rec := parquet.NewRecorder(parquet.RecorderConfig{})
	path := filepath.Join(t.TempDir(), "rec.parquet")
	if err := rec.Start(path, parquet.StartOptions{}); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	if err := rec.Record(streamrow.Row{}, 0); err != nil {
		t.Fatalf("Record() = %v", err)
	}
	t.Cleanup(func() { _ = rec.Stop() })
	return rec, path, watcherHooks{publishRecording: rec.Stop}
}

// startWatchedProgramWith is startWatchedProgram with explicit hooks.
func startWatchedProgramWith(t *testing.T, model tea.Model, hooks watcherHooks) <-chan error {
	t.Helper()
	holdSignals(t)
	input, inputW := io.Pipe()
	t.Cleanup(func() { _ = inputW.Close() })
	program := newProgram(model, tea.WithInput(input), tea.WithOutput(io.Discard), tea.WithWindowSize(100, 30))
	watcher := watchTerminationSignals(program, hooks)
	t.Cleanup(watcher.stop)
	done := make(chan error, 1)
	go func() {
		_, err := runWithWatcher(program, watcher)
		watcher.stop()
		done <- err
	}()
	return done
}

// TestTwoSignalsDuringAnEditorPublishTheRecordingAndEndTheProgram is the
// reported failure: with an editor owning the terminal the event loop is stuck
// in the child, so Update never ran the quit path, the recording stayed a .tmp,
// hardExit had to end the process and the editor was orphaned. The editor here
// ignores SIGTERM, the worst case.
func TestTwoSignalsDuringAnEditorPublishTheRecordingAndEndTheProgram(t *testing.T) {
	exits := shortSignalTiming(t)
	forceExitGrace = 5 * time.Second // Run must return by itself, hardExit is not the path under test
	_, path, hooks := recorderRecordingTo(t)
	child, pidFile := fakeEditor(t, true, "30")
	model := &execTestModel{child: child}
	done := startWatchedProgramWith(t, model, hooks)
	pid := waitForEditor(t, pidFile)

	sendSignal(t, syscall.SIGTERM)
	// The first SIGTERM publishes the recording right away, while the editor
	// (which ignores the polite SIGTERM) is still running and the loop blocked.
	waitFor(t, func() bool { _, err := os.Stat(path); return err == nil })
	requireFinalisedRecording(t, path)
	select {
	case err := <-done:
		t.Fatalf("Run returned (%v) although the editor ignores SIGTERM", err)
	case <-time.After(3 * repeatSignalWindow):
	}
	if !processAlive(pid) {
		t.Fatal("the editor died from the first SIGTERM although it ignores it")
	}

	sendSignal(t, syscall.SIGTERM)
	if err := waitForRun(t, done, "second SIGTERM during the editor"); !errors.Is(err, errShutdownForced) {
		t.Fatalf("Run() = %v, want errShutdownForced", err)
	}
	if processAlive(pid) {
		t.Fatal("the editor was left running after the forced exit")
	}
	time.Sleep(200 * time.Millisecond)
	if n := exits.Load(); n != 0 {
		t.Fatalf("hardExit called %d times, the forced exit should have unwound Run", n)
	}
	requireFinalisedRecording(t, path)
}

// A single SIGTERM (an external kill) while a well-behaved editor is open ends
// the editor, publishes the recording and lets the normal quit path run: a
// clean exit, no forced exit.
func TestSingleSIGTERMDuringAnEditorShutsDownCleanly(t *testing.T) {
	exits := shortSignalTiming(t)
	_, path, hooks := recorderRecordingTo(t)
	child, pidFile := fakeEditor(t, false, "30")
	model := &execTestModel{child: child, noAutoQuit: true}
	done := startWatchedProgramWith(t, model, hooks)
	pid := waitForEditor(t, pidFile)

	sendSignal(t, syscall.SIGTERM)
	if err := waitForRun(t, done, "single SIGTERM during the editor"); err != nil {
		t.Fatalf("Run() = %v, want a clean exit", err)
	}
	if !model.quitSeen.Load() {
		t.Fatal("the queued quit request never reached Update")
	}
	if processAlive(pid) {
		t.Fatal("the editor was left running")
	}
	requireFinalisedRecording(t, path)
	if exits.Load() != 0 {
		t.Fatal("hardExit was called")
	}
}

// Ctrl+C in a cooked-mode editor SIGINTs ior as well as the editor. It is the
// editor's key: it must neither start the quit path, nor publish the
// recording, nor count towards a forced exit, however often it is pressed.
func TestSIGINTDuringAnEditorIsIgnored(t *testing.T) {
	exits := shortSignalTiming(t)
	rec, _, hooks := recorderRecordingTo(t)
	child, pidFile := fakeEditor(t, false, "2")
	model := &execTestModel{child: child}
	done := startWatchedProgramWith(t, model, hooks)
	pid := waitForEditor(t, pidFile)

	sendSignal(t, syscall.SIGINT)
	time.Sleep(3 * repeatSignalWindow)
	sendSignal(t, syscall.SIGINT) // later than the window: still no "second signal"
	time.Sleep(3 * repeatSignalWindow)
	select {
	case err := <-done:
		t.Fatalf("Run returned (%v) after SIGINT during the editor", err)
	default:
	}
	if !processAlive(pid) {
		t.Fatal("SIGINT ended the editor")
	}
	if !rec.Status().Active {
		t.Fatal("SIGINT during the editor stopped the recording")
	}

	// The editor closes on its own (killed like a user quitting it), the model
	// quits by itself, and no signal request was ever seen.
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	// The killed child makes the exec callback carry an error; the model
	// ignores it, so a clean exit is what is expected.
	if err := waitForRun(t, done, "editor closed"); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if model.quitSeen.Load() {
		t.Fatal("SIGINT during the editor was turned into a quit request")
	}
	if !rec.Status().Active {
		t.Fatal("the recording was stopped without a quit request")
	}
	if exits.Load() != 0 {
		t.Fatal("hardExit was called")
	}
}

// After the editor is closed a SIGINT is an ordinary quit request again.
func TestSIGINTAfterTheEditorClosedQuitsAgain(t *testing.T) {
	child, _ := fakeEditor(t, false, "0")
	model := &execTestModel{child: child, noAutoQuit: true}
	done := startWatchedProgramWith(t, model, watcherHooks{})
	waitFor(t, func() bool { return model.execDone.Load() && !common.ExecActive() })

	sendSignal(t, syscall.SIGINT)
	if err := waitForRun(t, done, "SIGINT after the editor"); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if !model.quitSeen.Load() {
		t.Fatal("SIGINT after the editor closed did not reach the quit path")
	}
}

func TestRelayDropsIgnoredSignalsBeforeCountingThem(t *testing.T) {
	window := repeatSignalWindow
	repeatSignalWindow = 20 * time.Millisecond
	t.Cleanup(func() { repeatSignalWindow = window })

	ch := make(chan os.Signal, 8)
	var quits, forces atomic.Int32
	ignoring := atomic.Bool{}
	ignoring.Store(true)
	stop := relayTerminationSignals(ch,
		func(sig os.Signal) bool { return sig == syscall.SIGINT && ignoring.Load() },
		func() { quits.Add(1) }, func() { forces.Add(1) }, func() {})
	defer stop()

	ch <- syscall.SIGINT
	time.Sleep(60 * time.Millisecond)
	ch <- syscall.SIGINT
	time.Sleep(60 * time.Millisecond)
	if quits.Load() != 0 || forces.Load() != 0 {
		t.Fatalf("ignored SIGINTs acted: quits=%d forces=%d", quits.Load(), forces.Load())
	}
	ch <- syscall.SIGTERM // not ignorable: the first real request
	waitFor(t, func() bool { return quits.Load() == 1 })
	ignoring.Store(false)
	time.Sleep(60 * time.Millisecond)
	ch <- syscall.SIGINT
	waitFor(t, func() bool { return forces.Load() == 1 })
}

// fakeProgram records the calls the watcher makes on the program.
type fakeProgram struct {
	sent     chan tea.Msg
	sendGate chan struct{} // when non-nil, Send blocks until it is closed
	killed   atomic.Int32
}

func newFakeProgram() *fakeProgram { return &fakeProgram{sent: make(chan tea.Msg, 4)} }

// awaitSent waits, bounded, for the watcher to have called Send.
func awaitSent(t *testing.T, f *fakeProgram) {
	t.Helper()
	select {
	case <-f.sent:
	case <-time.After(20 * time.Second):
		t.Fatal("the watcher never sent the quit request")
	}
}

// awaitSignal waits, bounded, for a notification from a test hook, so a lost
// notification fails the test instead of hanging the whole package.
func awaitSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(20 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func (f *fakeProgram) Send(msg tea.Msg) {
	f.sent <- msg
	if f.sendGate != nil {
		<-f.sendGate
	}
}
func (f *fakeProgram) Kill() { f.killed.Add(1) }

// TestForcedExitWaitsForTheLoopToTakeTheQuitRequestBeforeKill pins the
// ordering in force(): Program.Kill reads state the event loop set up, so it
// must not run before the loop has taken the quit request (Send returned),
// unless the loop never does (then after killSyncWait).
func TestForcedExitWaitsForTheLoopToTakeTheQuitRequestBeforeKill(t *testing.T) {
	shortSignalTiming(t)
	repeatSignalWindow = 50 * time.Millisecond
	forceExitGrace = time.Minute
	killSyncWait = 3 * time.Second // far above the 200ms "not yet" check below, even on a loaded machine
	holdSignals(t)

	fake := newFakeProgram()
	fake.sendGate = make(chan struct{})
	w := watchTerminationSignalsFor(fake, false, watcherHooks{execActive: func() bool { return false }})
	t.Cleanup(w.stop)

	sendSignal(t, syscall.SIGTERM)
	awaitSent(t, fake) // the quit request is being sent, but the loop has not taken it
	time.Sleep(2 * repeatSignalWindow)
	sendSignal(t, syscall.SIGTERM)

	time.Sleep(200 * time.Millisecond)
	if fake.killed.Load() != 0 {
		t.Fatal("Kill ran before the loop took the quit request")
	}
	close(fake.sendGate) // the loop takes the request now
	waitFor(t, func() bool { return fake.killed.Load() == 1 })
}

// A loop that never takes the quit request (wedged Update) must not hold the
// forced exit back for longer than killSyncWait.
func TestForcedExitKillsAfterTheSyncWaitWhenTheLoopNeverTakesTheRequest(t *testing.T) {
	shortSignalTiming(t)
	repeatSignalWindow = 50 * time.Millisecond
	forceExitGrace = time.Minute
	killSyncWait = 150 * time.Millisecond
	holdSignals(t)

	fake := newFakeProgram()
	fake.sendGate = make(chan struct{}) // never closed before the test ends
	t.Cleanup(func() { close(fake.sendGate) })
	w := watchTerminationSignalsFor(fake, false, watcherHooks{execActive: func() bool { return false }})
	t.Cleanup(w.stop)

	sendSignal(t, syscall.SIGTERM)
	awaitSent(t, fake)
	time.Sleep(2 * repeatSignalWindow)
	start := time.Now()
	sendSignal(t, syscall.SIGTERM)
	waitFor(t, func() bool { return fake.killed.Load() == 1 })
	if elapsed := time.Since(start); elapsed < killSyncWait {
		t.Fatalf("Kill ran after %v, before the %v sync wait", elapsed, killSyncWait)
	}
}

// A second signal that is only processed after Run returned cleanly must not
// turn the clean shutdown into a forced exit: exit status 0, no Kill, no
// hardExit timer.
func TestLateSecondSignalAfterACleanRunChangesNothing(t *testing.T) {
	exits := shortSignalTiming(t)
	holdSignals(t)
	fake := newFakeProgram()
	w := watchTerminationSignalsFor(fake, false, watcherHooks{execActive: func() bool { return false }})
	t.Cleanup(w.stop)

	sendSignal(t, syscall.SIGTERM)
	awaitSent(t, fake)
	time.Sleep(2 * repeatSignalWindow)
	if w.finish() { // Run returned (cleanly), before the second signal is looked at
		t.Fatal("finish() reported a forced exit although none happened")
	}
	sendSignal(t, syscall.SIGTERM)
	time.Sleep(100 * time.Millisecond)
	w.stop()
	time.Sleep(2 * forceExitGrace)
	if fake.killed.Load() != 0 || exits.Load() != 0 || w.forced {
		t.Fatalf("late signal acted: kills=%d hardExits=%d forced=%v", fake.killed.Load(), exits.Load(), w.forced)
	}
}

// stop must wait for a forced exit that is in progress, and disarm the hardExit
// timer it armed, so nothing acts on the program or the process after Run's
// caller moved on.
func TestStopWaitsForAForcedExitInProgressAndDisarmsHardExit(t *testing.T) {
	exits := shortSignalTiming(t)
	repeatSignalWindow = 50 * time.Millisecond
	forceExitGrace = time.Second // well above the slow publish below, also on a loaded machine
	holdSignals(t)
	fake := newFakeProgram()
	// Buffered: the relay goroutine can reach the hook before the test goroutine
	// waits on the channel, and an unbuffered non-blocking send would then be
	// dropped and leave the test waiting forever. The buffer keeps the
	// notification until the test looks for it; the send never blocks because a
	// forced exit runs the hook at most once (a second one would just be dropped).
	publishing := make(chan struct{}, 1)
	hooks := watcherHooks{
		execActive: func() bool { return false },
		publishRecording: func() error {
			select {
			case publishing <- struct{}{}:
			default:
			}
			time.Sleep(300 * time.Millisecond) // a slow publish keeps the forced exit in progress
			return nil
		},
	}
	w := watchTerminationSignalsFor(fake, false, hooks)
	t.Cleanup(w.stop)

	sendSignal(t, syscall.SIGTERM)
	awaitSent(t, fake)
	time.Sleep(2 * repeatSignalWindow)
	sendSignal(t, syscall.SIGTERM)
	awaitSignal(t, publishing, "the forced exit to start publishing")
	w.stop()
	if fake.killed.Load() != 1 {
		t.Fatal("stop returned before the forced exit in progress finished")
	}
	time.Sleep(2 * forceExitGrace)
	if exits.Load() != 0 {
		t.Fatal("hardExit fired after stop disarmed it")
	}
}

// The watcher took the recorder's Stop failure away from the model's later
// Stop, so it has to surface it itself.
func TestWatcherReportsItsOwnRecorderStopFailure(t *testing.T) {
	w := &terminationWatcher{hooks: watcherHooks{publishRecording: func() error { return errors.New("disk full") }}}
	w.publishRecording()
	if err := w.recordingError(); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("recordingError() = %v, want the stop failure", err)
	}
}

// A recorder stuck on a dead disk cannot hold the watcher longer than
// recordingStopWait.
func TestWatcherPublishIsBounded(t *testing.T) {
	old := recordingStopWait
	recordingStopWait = 50 * time.Millisecond
	t.Cleanup(func() { recordingStopWait = old })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	w := &terminationWatcher{hooks: watcherHooks{publishRecording: func() error { <-release; return nil }}}
	start := time.Now()
	w.publishRecording()
	if time.Since(start) > 5*time.Second {
		t.Fatal("publishRecording waited for a stuck recorder")
	}
}
