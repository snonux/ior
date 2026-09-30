package tui

import (
	"errors"
	"fmt"

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
