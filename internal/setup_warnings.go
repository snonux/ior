package internal

import (
	"fmt"
	"strings"
	"sync"
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
