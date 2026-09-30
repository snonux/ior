package tui

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	tea "charm.land/bubbletea/v2"
)

// signalQuitMsg asks the model to leave through the same path as the quit key:
// stop the Parquet recording (publishing the file), cancel the trace and wait
// for the BPF teardown. It is what SIGTERM, SIGINT and SIGHUP become in the
// TUI, see signalQuitFilter.
type signalQuitMsg struct{}

// signalQuitFilter is the tea.WithFilter hook that keeps termination signals
// on the model's quit path.
//
// Bubble Tea turns SIGTERM into QuitMsg and SIGINT into InterruptMsg inside
// its own event loop and returns from Run without ever calling Update, so the
// model's cleanup (quitWithBestEffortCleanup, which stops the recorder) never
// ran: an active 'R' recording was left as a 0-byte ior-recording-*.parquet.tmp
// and SIGINT even made Run fail with "program was interrupted". The filter runs
// on the event-loop goroutine, the same one that runs Update, so reading the
// model here is race-free.
//
// Only a QuitMsg/InterruptMsg that arrives while the model is NOT shutting
// down is converted. Every legitimate QuitMsg comes from tea.Quit after
// beginShutdown has set quitting (the shutdown-complete message, or straight
// away when no trace ever started), so it passes through unchanged. That is
// also the escape hatch: a second SIGTERM/SIGINT during a shutdown that hangs
// (a stuck BPF teardown) is not converted again and ends the program at once.
// A model of another type, or anything else, passes through untouched.
func signalQuitFilter(model tea.Model, msg tea.Msg) tea.Msg {
	switch msg.(type) {
	case tea.QuitMsg, tea.InterruptMsg:
		if m, ok := model.(*Model); ok && !m.quitting {
			return signalQuitMsg{}
		}
	}
	return msg
}

// handleSignalQuit is Update's side of signalQuitFilter. Cleanup is best effort
// for the same reason as on the error screen: the process is being told to
// stop, so a failing recorder must not keep it alive. A recorder failure is
// still reported, by runProgram's post-run safety net when the recorder is
// left active.
func (m *Model) handleSignalQuit() (tea.Model, tea.Cmd, bool) {
	if m.quitting {
		return m, nil, true
	}
	return m.quitWithBestEffortCleanup()
}

// forwardHangup routes SIGHUP to the program as a quit request, so closing the
// terminal window or dropping an ssh session also finalises an active
// recording; Bubble Tea handles only SIGINT and SIGTERM, and the default
// SIGHUP action kills the process on the spot. The message is a plain
// tea.QuitMsg, which signalQuitFilter converts, so a hangup during an already
// running shutdown is ignored rather than cutting it short.
//
// It honours the nohup rule of internal.shutdownSignals: when the process was
// started with SIGHUP ignored (`nohup ior ...`, a `trap '' HUP` wrapper),
// signal.Notify would override that inherited SIG_IGN, so nothing is
// installed. The returned function unregisters the handler and waits for its
// goroutine, so nothing sends to the program after Run returned.
func forwardHangup(send func(tea.Msg)) (stop func()) {
	return forwardHangupFor(send, signal.Ignored(syscall.SIGHUP))
}

// forwardHangupFor is forwardHangup with the inherited SIGHUP disposition
// passed in, so the decision is testable without touching process state.
func forwardHangupFor(send func(tea.Msg), sighupIgnored bool) (stop func()) {
	if sighupIgnored {
		return func() {}
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	return relayQuitRequests(ch, send, func() { signal.Stop(ch) })
}

// relayQuitRequests sends tea.QuitMsg to send for every value received on ch
// until the returned stop function is called. stop first runs unregister (so
// no further values arrive), then ends and awaits the relay goroutine.
func relayQuitRequests(ch <-chan os.Signal, send func(tea.Msg), unregister func()) (stop func()) {
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for {
			select {
			case <-ch:
				send(tea.QuitMsg{})
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
// a panic recovered by Bubble Tea, a second signal that cut a shutdown short,
// a killed context. A Stop failure is returned joined to the run error, since
// it means the recording the user asked for was lost.
func finaliseRecording(model *Model, runErr error) error {
	if model == nil || model.runtime == nil {
		return runErr
	}
	if err := model.stopRecording(); err != nil {
		return errors.Join(runErr, fmt.Errorf("finalising Parquet recording: %w", err))
	}
	return runErr
}
