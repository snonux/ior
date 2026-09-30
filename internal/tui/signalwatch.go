package tui

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	tea "charm.land/bubbletea/v2"

	common "ior/internal/tui/common"
)

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

// killSyncWait bounds how long a forced exit waits for the event loop to have
// taken the quit request before it calls Program.Kill anyway. A variable so a
// test can pin the ordering without waiting half a second.
var killSyncWait = 500 * time.Millisecond

// recordingStopWait bounds how long the watcher waits for its own recorder
// stop (the publish of the Parquet file) before it goes on. Publishing is a
// flush plus a rename, so this only matters on a dead disk; hardExit is the
// backstop then. A variable so a test can use a recorder that hangs.
var recordingStopWait = 2 * time.Second

// hardExit ends the process when a forced exit could not unwind Run. Reached
// only when Update itself is wedged, so no cleanup is possible or attempted;
// the terminal has already been restored by Program.Kill by then. A variable
// so a test can observe it without dying.
var hardExit = func() {
	fmt.Fprintln(os.Stderr, "ior: "+errShutdownForced.Error()+" (forced exit)")
	os.Exit(1)
}

// programControl is the part of *tea.Program the watcher drives; an interface
// so tests can pin the call order with a fake.
type programControl interface {
	Send(tea.Msg)
	Kill()
}

// watcherHooks are the process-facing dependencies of the watcher, injectable
// for tests. The zero value plus withDefaults is what production uses.
type watcherHooks struct {
	// publishRecording stops the active Parquet recording, publishing its file.
	// It must be safe to call from any goroutine and idempotent (the recorder's
	// Stop is); nil means there is no recorder.
	publishRecording func() error
	// execActive reports whether an editor (or other child) owns the terminal.
	execActive func() bool
	// signalExec signals that child.
	signalExec func(syscall.Signal)
}

// withDefaults fills the exec hooks with the real tracker of common.ExecProcess.
func (h watcherHooks) withDefaults() watcherHooks {
	if h.execActive == nil {
		h.execActive = common.ExecActive
	}
	if h.signalExec == nil {
		h.signalExec = common.SignalExec
	}
	return h
}

// modelRecordingPublisher returns the publishRecording hook for model: it
// stops the model's recorder straight through the runtime bindings, WITHOUT
// the model's own stopRecordingAtQuit, which also syncs dashboard state and so may
// only run on the event-loop goroutine. The recorder is safe for concurrent
// use (Stop waits for a stop already in flight and returns nil then).
func modelRecordingPublisher(model *Model) func() error {
	return func() error {
		if model == nil || model.runtime == nil {
			return nil
		}
		// recorderFinalise also claims the failure of a recording that
		// already died, so a signal quit cannot exit 0 over a lost recording.
		return recorderFinalise(model.runtime.Recorder())
	}
}

// terminationWatcher owns the process's termination-signal handling for one
// Bubble Tea program.
type terminationWatcher struct {
	hooks   watcherHooks
	stopFn  func()
	stopped sync.Once

	mu       sync.Mutex
	finished bool        // Run has returned; a late forced exit is a no-op
	forced   bool        // a forced exit took effect while Run was still going
	grace    *time.Timer // the hardExit backstop, armed by the forced exit
	stopErr  error       // a failure of the watcher's own recorder stop
}

// finish is called once Run has returned. It closes the door on a forced exit
// that is only now being processed (a second signal that arrived as the clean
// shutdown completed must not turn exit 0 into exit 1) and reports whether a
// forced exit did take effect before that.
func (w *terminationWatcher) finish() (forced bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.finished = true
	return w.forced
}

// beginForce records the forced exit and arms the hardExit backstop, unless
// Run already returned. Both happen under one lock, so once finish has run no
// timer can be armed afterwards and stop's disarm cannot miss one.
func (w *terminationWatcher) beginForce() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.finished {
		return false
	}
	w.forced = true
	w.grace = time.AfterFunc(forceExitGrace, hardExit)
	return true
}

// recordingError returns a failure of the watcher's own recorder stop: it took
// the failure away from the model's later Stop (which then finds nothing to
// stop), so runWithWatcher adds it to the run error.
func (w *terminationWatcher) recordingError() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stopErr
}

// publishRecording stops the recording from the watcher goroutine, without
// the event loop, waiting at most recordingStopWait.
func (w *terminationWatcher) publishRecording() {
	if w.hooks.publishRecording == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := w.hooks.publishRecording(); err != nil {
			w.mu.Lock()
			w.stopErr = errors.Join(w.stopErr, fmt.Errorf("finalising Parquet recording: %w", err))
			w.mu.Unlock()
		}
	}()
	select {
	case <-done:
	case <-time.After(recordingStopWait):
	}
}

// stop unregisters the handlers, waits for the relay goroutine (which includes
// a forced exit in progress) and disarms the hardExit timer, so nothing acts
// on the program or the process after this returns. Idempotent.
func (w *terminationWatcher) stop() {
	w.stopped.Do(func() {
		w.stopFn()
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.grace != nil {
			w.grace.Stop()
		}
	})
}

// watchTerminationSignals routes SIGINT, SIGTERM and (unless it was inherited
// as ignored) SIGHUP to the program with these semantics:
//
//   - the first signal is a quit request: signalQuitMsg goes through Update, so
//     the recording is finalised and the trace shut down like after 'q';
//   - a second signal (later than repeatSignalWindow after the first) while the
//     shutdown is still running is an abort: the recording is published (by the
//     watcher itself, see below), Program.Kill restores the terminal, Run
//     returns, and runWithWatcher reports errShutdownForced, so the exit status
//     is non-zero. If Run does not return within forceExitGrace, hardExit ends
//     the process;
//   - anything after that is ignored.
//
// While an editor owns the terminal (common.ExecProcess: the stream tab's
// "open in editor") Bubble Tea's event loop is blocked inside the child, so
// Update cannot run and nothing queued through Send is handled until it exits.
// The watcher therefore does not depend on the loop there:
//
//   - SIGINT is ignored altogether, as Bubble Tea's own handler did around an
//     exec: Ctrl+C in the cooked-mode editor reaches the whole foreground
//     process group, ior included, but it is the editor's key. It does not
//     count as the first signal either;
//   - SIGTERM/SIGHUP (an external kill, a closing terminal) are real
//     shutdown requests. The first one publishes the recording right away
//     (finished before the editor is even gone) and terminates the editor with
//     SIGTERM; the queued signalQuitMsg then runs the normal shutdown as soon
//     as the loop is free again. A second one publishes again (a no-op unless
//     the first attempt was still stuck), kills the editor with SIGKILL and
//     aborts as above, so the recording is safe and the process ends even if
//     the editor ignores SIGTERM.
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
func watchTerminationSignals(program programControl, hooks watcherHooks) *terminationWatcher {
	return watchTerminationSignalsFor(program, signal.Ignored(syscall.SIGHUP), hooks)
}

// watchTerminationSignalsFor is watchTerminationSignals with the inherited
// SIGHUP disposition passed in, so the decision is testable without touching
// process state.
func watchTerminationSignalsFor(program programControl, sighupIgnored bool, hooks watcherHooks) *terminationWatcher {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, terminationSignals(sighupIgnored)...)

	w := &terminationWatcher{hooks: hooks.withDefaults()}
	quitDelivered := make(chan struct{})
	quit := func() {
		if w.hooks.execActive() {
			w.publishRecording()
			w.hooks.signalExec(syscall.SIGTERM)
		}
		program.Send(signalQuitMsg{})
		close(quitDelivered)
	}
	force := func() {
		if !w.beginForce() {
			return
		}
		w.publishRecording()
		if w.hooks.execActive() {
			w.hooks.signalExec(syscall.SIGKILL)
		}
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
	ignore := func(sig os.Signal) bool {
		return sig == syscall.SIGINT && w.hooks.execActive()
	}
	w.stopFn = relayTerminationSignals(ch, ignore, quit, force, func() { signal.Stop(ch) })
	return w
}

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
func runWatchedProgram(program *tea.Program, model *Model) (tea.Model, error) {
	watcher := watchTerminationSignals(program, watcherHooks{publishRecording: modelRecordingPublisher(model)})
	defer watcher.stop()
	return runWithWatcher(program, watcher)
}

// runWithWatcher runs program and maps a run ended by the forced exit to
// errShutdownForced instead of Bubble Tea's generic "program was killed", and
// adds a failure of the watcher's own recorder stop to the result. The watcher
// is created by the caller so tests can register it (and know signals are
// handled) before the run starts, driving the identical wiring on a program
// with their own input and output.
func runWithWatcher(program *tea.Program, watcher *terminationWatcher) (tea.Model, error) {
	final, err := program.Run()
	if watcher.finish() {
		err = errShutdownForced
	}
	return final, errors.Join(err, watcher.recordingError())
}

// relayTerminationSignals calls quit for the first value received on ch (that
// ignore does not drop) and force for the first one arriving more than
// repeatSignalWindow later; further values are dropped. quit runs on its own
// goroutine, since it can block for as long as the event loop is busy (Send)
// and must never stop the relay from watching. force runs on the relay
// goroutine itself: nothing is left to watch for once it starts, and stop
// waiting for it is exactly what keeps a forced exit from outliving Run's
// clean return. stop first runs unregister (so no further values arrive), then
// ends and awaits the relay goroutine.
func relayTerminationSignals(ch <-chan os.Signal, ignore func(os.Signal) bool, quit, force func(), unregister func()) (stop func()) {
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		var first time.Time
		forced := false
		for {
			select {
			case sig := <-ch:
				switch {
				case ignore != nil && ignore(sig):
				case first.IsZero():
					first = time.Now()
					go quit()
				case !forced && time.Since(first) >= repeatSignalWindow:
					forced = true
					force()
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
