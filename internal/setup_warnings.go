package internal

import (
	"fmt"
	"strings"
	"sync"

	"ior/internal/textsafe"
)

const (
	// maxFailureWarnings caps how many collected warnings one setup failure
	// appends to its error. The libbpf route already limits a TUI setup to 16
	// rows plus a summary; the error screen is much smaller than the stream
	// tab, so fewer lines are kept and the rest only counted.
	maxFailureWarnings = 8
	// maxFailureWarningBytes cuts each appended line (before escaping) so a
	// long verifier-log line cannot fill the error screen on its own.
	maxFailureWarningBytes = 240
)

// setupWarnings collects non-fatal degradations found while a trace is being
// set up - a sched probe that could not attach, a BPF object without the
// ring-buffer drop counter - so they reach the user through one policy in
// every mode.
//
// They are found before the event loop, and therefore before any warning sink,
// exists. Printing them on the spot either wrote over the Bubble Tea screen on
// every TUI trace start (the drop counter went to stderr) or, through the
// mode-dependent logln, dropped them in TUI mode altogether (the sched
// probes). Instead they are handed to the event loop, which replays them as
// warnings once its output is wired: warning rows in the TUI, stderr in the
// headless modes (see notifyWarningOrLog).
//
// The collector is locked because setup is not strictly single-threaded: a TUI
// restart cancels the old session without waiting for it, so its libbpf
// warnings (routed here by libbpfLogger from whichever goroutine is inside
// libbpf) can arrive while the new session's own setup code adds to the same
// collector. The event loop takes ownership of the messages before run starts.
type setupWarnings struct {
	mu       sync.Mutex
	messages []string
}

// add records one warning; its arguments are joined like fmt.Sprintln, which
// keeps it signature-compatible with the func(...any) loggers it replaces.
func (w *setupWarnings) add(args ...any) {
	message := strings.TrimSuffix(fmt.Sprintln(args...), "\n")
	if message == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.messages = append(w.messages, message)
}

// drain hands over the collected warnings and empties the collector, so a
// warning is replayed at most once.
func (w *setupWarnings) drain() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	messages := w.messages
	w.messages = nil
	return messages
}

// wireEventLoopLogging connects a freshly built event loop to the trace's
// console policy: lifecycle lines follow the mode-dependent logln (silent in
// TUI mode, where "Stopping event loop" would otherwise fire over the
// dashboard on every trace restart), and the setup warnings collected so far
// are queued for replay when the loop starts running.
func wireEventLoopLogging(el *eventLoop, logln func(...any), warnings *setupWarnings) {
	el.SetStatusCallback(logln)
	el.deferWarnings(warnings.drain())
}

// setupFailure is a setup error together with the warnings that were collected
// but not yet delivered when it happened. Unwrap keeps errors.Is/As working on
// the original cause.
type setupFailure struct {
	err   error
	lines []string
}

func (e *setupFailure) Error() string {
	var b strings.Builder
	b.WriteString(e.err.Error())
	b.WriteString("\nWarnings logged during setup:")
	for _, line := range e.lines {
		b.WriteString("\n  - ")
		b.WriteString(line)
	}
	return b.String()
}

func (e *setupFailure) Unwrap() error { return e.err }

// explainFailure returns err with the collected, still undelivered warnings
// appended. Without warnings it returns err itself, so a failure that has
// nothing to add is unchanged.
//
// This is how the libbpf WARN lines of a failed load or attach reach the user
// in the TUI: the collector is replayed as warning rows only when the event
// loop starts, which a failed setup never gets to, and the dashboard is not
// there yet - the error screen is the only thing shown. The text is also what
// a headless run prints, which is why it is made safe here and not only by
// the TUI's own SanitizeLines: each warning is cut to its first line and
// maxFailureWarningBytes (the libbpf route already shortens its rows, but
// other collector users make no such promise), escaped with textsafe.Escape
// so kernel or traced text cannot carry terminal escapes, and at most
// maxFailureWarnings are listed with the rest counted.
func (w *setupWarnings) explainFailure(err error) error {
	if err == nil {
		return nil // success: the warnings stay queued for the event loop
	}
	messages := w.drain()
	if len(messages) == 0 {
		return err
	}
	lines := make([]string, 0, min(len(messages), maxFailureWarnings)+1)
	for _, message := range messages[:min(len(messages), maxFailureWarnings)] {
		lines = append(lines, textsafe.Escape(shortenWarning(message, maxFailureWarningBytes)))
	}
	if extra := len(messages) - maxFailureWarnings; extra > 0 {
		lines = append(lines, fmt.Sprintf("... and %d more warning(s)", extra))
	}
	return &setupFailure{err: err, lines: lines}
}
