package tui

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	tea "charm.land/bubbletea/v2"
)

// signalQuitMsg asks the model to leave through the same path as the quit key:
// stop the Parquet recording (publishing the file), cancel the trace and wait
// for the BPF teardown. It is what the first SIGTERM, SIGINT or SIGHUP becomes
// in the TUI, see watchTerminationSignals.
type signalQuitMsg struct{}

// errShutdownForced is what a forced exit reports: the user (or a supervisor)
// asked twice, or pressed Ctrl+C during the shutdown, so the program left
// before the trace teardown finished. It makes the exit status non-zero.
var errShutdownForced = errors.New("shutdown aborted before the trace teardown finished")

// repeatSignalWindow is how long after the first termination signal further
// signals still count as the same request. Supervisors send such bursts on
// purpose (systemd follows SIGTERM with SIGHUP, a closing terminal hangs up the
// whole process group), and treating one as the "second signal" would cut a
// perfectly healthy teardown short. A variable so tests need not sleep.
var repeatSignalWindow = time.Second

// forceExitGrace is how long the process waits for Run to return after a
// forced exit before it gives up and exits itself: Run cannot return while
// Update is blocked (a recorder Stop stuck on a dead disk), and nothing else
// could end the program then. A variable so tests can shorten it.
var forceExitGrace = 5 * time.Second

// hardExit ends the process when a forced exit could not unwind Run. Reached
// only when Update itself is wedged, so no cleanup is possible or attempted;
// the terminal has already been restored by Program.Kill by then. A variable
// so a test can observe it without dying.
var hardExit = func() {
	fmt.Fprintln(os.Stderr, "ior: "+errShutdownForced.Error()+" (forced exit)")
	os.Exit(1)
}

// signalQuitFilter is the tea.WithFilter hook that keeps a stray QuitMsg or
// InterruptMsg on the model's quit path.
//
// Termination signals no longer reach it: newProgram disables Bubble Tea's own
// signal handler (tea.WithoutSignalHandler) because that handler is one-shot -
// after the first SIGTERM/SIGINT it queues a QuitMsg/InterruptMsg, returns and
// unregisters, so nothing watched for a second signal and a hung shutdown could
// not be interrupted. Worse, it returned from Run without ever calling Update,
// so an active 'R' recording was left as a 0-byte ior-recording-*.parquet.tmp.
// The filter stays as a guard for any other source of these messages (for
// example an input reader that reports ^C without a raw terminal). It runs on
// the event-loop goroutine, the same one that runs Update, so reading the model
// here is race-free.
//
// Only a QuitMsg/InterruptMsg that arrives while the model is NOT shutting
// down is converted. Every legitimate QuitMsg comes from tea.Quit after
// beginShutdown has set quitting (the shutdown-complete message, or straight
// away when no trace ever started), so it passes through unchanged. A model of
// another type, or any other message, passes through untouched.
func signalQuitFilter(model tea.Model, msg tea.Msg) tea.Msg {
	switch msg.(type) {
	case tea.QuitMsg, tea.InterruptMsg:
		if m, ok := model.(*Model); ok && !m.quitting {
			return signalQuitMsg{}
		}
	}
	return msg
}

// handleSignalQuit is Update's side of the first termination signal. It runs
// the same cleanup as the 'q' key, but a recorder Stop failure is not dropped:
// the process is being told to stop, so it must not stay alive over a failing
// recorder (unlike the dashboard 'q', which stays on an error screen), yet the
// recording the user asked for is lost, so the error is kept in lastErr and
// runProgram reports it and exits non-zero. Once Stop has failed the recorder
// is no longer active, so the post-run safety net would see nothing to report.
func (m *Model) handleSignalQuit() (tea.Model, tea.Cmd, bool) {
	if m.quitting {
		return m, nil, true
	}
	if err := m.stopRecording(); err != nil {
		m.lastErr = errors.Join(m.lastErr, fmt.Errorf("finalising Parquet recording: %w", err))
	}
	return m.beginShutdown()
}

// handleKeyWhileShuttingDown is the interactive escape hatch of a hung
// shutdown: every key is ignored while the trace winds down except Ctrl+C, the
// terminal user's "get me out of here", which ends the program at once. The
// tea.Quit passes signalQuitFilter because the model is quitting, Run returns,
// and the error makes the exit status non-zero. The recording was already
// stopped by the quit path that started the shutdown.
func (m *Model) handleKeyWhileShuttingDown(msg tea.KeyPressMsg) (tea.Model, tea.Cmd, bool) {
	if msg.String() == "ctrl+c" {
		m.lastErr = errors.Join(m.lastErr, errShutdownForced)
		return m, tea.Quit, true
	}
	return m, nil, true
}

// terminationWatcher owns the process's termination-signal handling for one
// Bubble Tea program.
type terminationWatcher struct {
	forced atomic.Bool
	stopFn func()
}

// wasForced reports whether a repeated signal ended the program.
func (w *terminationWatcher) wasForced() bool { return w.forced.Load() }

// stop unregisters the handlers and waits for the relay goroutine, so nothing
// acts on the program after Run returned.
func (w *terminationWatcher) stop() { w.stopFn() }

// watchTerminationSignals routes SIGINT, SIGTERM and (unless it was inherited
// as ignored) SIGHUP to the program with these semantics:
//
//   - the first signal is a quit request: signalQuitMsg goes through Update, so
//     the recording is finalised and the trace shut down like after 'q';
//   - a second signal (later than repeatSignalWindow after the first) while the
//     shutdown is still running is an abort: Program.Kill restores the
//     terminal, Run returns, and runProgram publishes the recording (safety
//     net) and reports errShutdownForced, so the exit status is non-zero. If
//     Run does not return within forceExitGrace, hardExit ends the process;
//   - anything after that is ignored.
//
// Bubble Tea's own handler cannot do this (it is one-shot, see
// signalQuitFilter), so the watcher keeps its own signal.Notify registration
// for the whole run. That registration also stops the default action (die on
// the spot) from applying between the first and second signal.
//
// SIGHUP honours the nohup rule of internal.shutdownSignals: when the process
// was started with SIGHUP ignored (`nohup ior ...`, `trap ” HUP`), Notify
// would override that inherited SIG_IGN, so SIGHUP is left alone. SIGINT and
// SIGTERM were always claimed by Bubble Tea, so nothing changes for them.
func watchTerminationSignals(program *tea.Program) *terminationWatcher {
	return watchTerminationSignalsFor(program, signal.Ignored(syscall.SIGHUP))
}

// watchTerminationSignalsFor is watchTerminationSignals with the inherited
// SIGHUP disposition passed in, so the decision is testable without touching
// process state.
func watchTerminationSignalsFor(program *tea.Program, sighupIgnored bool) *terminationWatcher {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, terminationSignals(sighupIgnored)...)

	w := &terminationWatcher{}
	var grace atomic.Pointer[time.Timer]
	quitDelivered := make(chan struct{})
	quit := func() {
		program.Send(signalQuitMsg{})
		close(quitDelivered)
	}
	force := func() {
		w.forced.Store(true)
		grace.Store(time.AfterFunc(forceExitGrace, hardExit))
		// Kill reads state Run set up on the event-loop goroutine. Waiting for
		// the loop to have taken the quit request orders that read after
		// those writes; a loop that never takes it is the wedged case, where
		// Kill goes ahead after a short wait and hardExit is the backstop.
		select {
		case <-quitDelivered:
		case <-time.After(killSyncWait):
		}
		program.Kill()
	}
	stopRelay := relayTerminationSignals(ch, quit, force, func() { signal.Stop(ch) })
	var once sync.Once
	w.stopFn = func() {
		once.Do(func() {
			stopRelay()
			if t := grace.Load(); t != nil {
				t.Stop()
			}
		})
	}
	return w
}

// killSyncWait bounds how long a forced exit waits for the event loop to have
// taken the quit request before it calls Program.Kill anyway.
const killSyncWait = 500 * time.Millisecond

// terminationSignals lists the signals the watcher claims; SIGHUP is left out
// when it was inherited as ignored (the nohup rule above).
func terminationSignals(sighupIgnored bool) []os.Signal {
	sigs := []os.Signal{syscall.SIGINT, syscall.SIGTERM}
	if !sighupIgnored {
		sigs = append(sigs, syscall.SIGHUP)
	}
	return sigs
}

// runWatchedProgram runs program under watchTerminationSignals. It is the body
// of the production runTeaProgram.
func runWatchedProgram(program *tea.Program) (tea.Model, error) {
	watcher := watchTerminationSignals(program)
	defer watcher.stop()
	return runWithWatcher(program, watcher)
}

// runWithWatcher runs program and maps a run ended by the forced exit to
// errShutdownForced instead of Bubble Tea's generic "program was killed". The
// watcher is created by the caller so tests can register it (and know signals
// are handled) before the run starts, driving the identical wiring on a program
// with their own input and output.
func runWithWatcher(program *tea.Program, watcher *terminationWatcher) (tea.Model, error) {
	final, err := program.Run()
	if watcher.wasForced() {
		err = errShutdownForced
	}
	return final, err
}

// relayTerminationSignals calls quit for the first value received on ch and
// force for the first one arriving more than repeatSignalWindow later; further
// values are dropped. Both run on their own goroutine so a blocked Send (the
// loop is busy) or Kill can never stop the relay from watching. stop first
// runs unregister (so no further values arrive), then ends and awaits the
// relay goroutine.
func relayTerminationSignals(ch <-chan os.Signal, quit, force func(), unregister func()) (stop func()) {
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		var first time.Time
		forced := false
		for {
			select {
			case <-ch:
				switch {
				case first.IsZero():
					first = time.Now()
					go quit()
				case !forced && time.Since(first) >= repeatSignalWindow:
					forced = true
					go force()
				}
			case <-done:
				return
			}
		}
	}()
	return func() {
		unregister()
		close(done)
		<-finished
	}
}

// finaliseRecording is the safety net behind the quit path: once the program
// has returned, a recording still active is stopped so its .tmp file is
// published instead of left as an orphan. Normally the model already did this
// and the call is a no-op. It matters for the exits that bypass the model -
// a panic recovered by Bubble Tea, a forced exit that cut a shutdown short. A
// Stop failure is returned joined to the run error, since it means the
// recording the user asked for was lost.
func finaliseRecording(model *Model, runErr error) error {
	if model == nil || model.runtime == nil {
		return runErr
	}
	if err := model.stopRecording(); err != nil {
		return errors.Join(runErr, fmt.Errorf("finalising Parquet recording: %w", err))
	}
	return runErr
}
