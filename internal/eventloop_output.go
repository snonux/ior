package internal

import (
	"fmt"
	"io"
	"os"

	"ior/internal/event"
	"ior/internal/textsafe"
)

// outputFormatter bundles the pair-emission and warning-notification callbacks
// used by the event loop. Extracting these two concerns into a dedicated type
// separates "what to do with a completed event pair" and "how to report
// non-fatal problems" from the core event-matching and FD-tracking logic.
//
// The struct is embedded (not pointed-to) inside eventLoop. Production
// wiring goes through the Set*Callback setters below so the loop's mutation
// surface is explicit; the fields themselves stay writable for same-package
// tests that construct loops directly.
type outputFormatter struct {
	// printCb is called for each completed, filter-passing event pair.
	// The callback owns the pair after the call: it must either recycle it
	// (ep.Recycle) or hand it off to another owner.
	printCb func(ep *event.Pair)

	// warningCb is an optional callback for non-fatal event-processing
	// warnings (e.g. malformed events, unresolved comms). nil means silent.
	warningCb func(message string)

	// statusCb receives human-facing lifecycle lines ("Stopping event loop",
	// the -pprof hint, the stats wait note). Trace setup wires it to the
	// mode-dependent logln, which is a no-op in TUI mode: those lines used to
	// go straight to the terminal on every trace restart while Bubble Tea
	// owned it. nil falls back to logStatus (stderr) so loops built outside
	// trace setup - tests, benchmarks - keep the historical behaviour.
	statusCb func(args ...any)

	// pendingWarnings are warnings raised before the loop's output was wired
	// (see setupWarnings). run replays them through notifyWarningOrLog before
	// the first event, by which time every mode has installed its sinks.
	pendingWarnings []string
}

// plainStdoutCallback is the eventLoop's default printCb: plainPrintCallback
// bound to os.Stdout with the -escape mode. The binding (and with it the
// terminal check) happens on the first pair rather than when the loop is
// built, so the callback writes to whatever os.Stdout is once events flow,
// as the fmt.Println it replaced did (tests swap os.Stdout after
// constructing the loop). printCb is only ever called from the event loop
// goroutine, so the lazy init needs no lock.
func plainStdoutCallback(mode textsafe.EscapeMode) func(ep *event.Pair) {
	var write func(ep *event.Pair)
	return func(ep *event.Pair) {
		if write == nil {
			write = plainPrintCallback(os.Stdout, mode)
		}
		write(ep)
	}
}

// plainPrintCallback returns the default pair sink, which -plain mode keeps:
// each pair is written to w as one CSV row (event.Pair.CSVRow) and then
// recycled. The escaper is chosen once, here, by mode.Escaper: with the
// default auto mode a terminal gets the attacker-controlled
// comm/name/file columns escaped with textsafe.Escape, so a traced file name
// cannot inject escape sequences into the operator's terminal, while piped
// or redirected rows keep the exact traced bytes for machine consumers.
// -escape=always covers pipes that still end in a terminal (| less -R,
// | tee); -escape=never forces raw output.
func plainPrintCallback(w io.Writer, mode textsafe.EscapeMode) func(ep *event.Pair) {
	escape := mode.Escaper(w)
	return func(ep *event.Pair) {
		_, _ = fmt.Fprintln(w, ep.CSVRow(escape))
		ep.Recycle()
	}
}

// SetPrintCallback replaces the pair-emission callback. The callback owns
// each pair after the call: it must either recycle it (ep.Recycle) or hand it
// off to another owner. This is the production wiring seam for the mode
// packages (plain output, TUI ingest, parquet/flamegraph recorders).
func (e *eventLoop) SetPrintCallback(cb func(ep *event.Pair)) {
	e.printCb = cb
}

// SetWarningCallback replaces the warning-notification sink. nil silences
// warnings; the callback receives one human-readable message per problem.
func (e *eventLoop) SetWarningCallback(cb func(message string)) {
	e.warningCb = cb
}

// SetStatusCallback replaces the human-facing status-line sink. The callback
// receives fmt.Sprintln-style arguments; nil restores the stderr default.
func (e *eventLoop) SetStatusCallback(cb func(args ...any)) {
	e.statusCb = cb
}

// notifyStatus delivers one lifecycle status line to statusCb, or to stderr
// when none is wired. Unlike warnings, status lines are purely informational,
// so a silent sink (TUI mode) is allowed to drop them.
func (f *outputFormatter) notifyStatus(args ...any) {
	if f.statusCb == nil {
		logStatus(args...)
		return
	}
	f.statusCb(args...)
}

// deferWarnings queues warnings for replay when the loop starts running. It
// must be called before run.
func (f *outputFormatter) deferWarnings(messages []string) {
	f.pendingWarnings = append(f.pendingWarnings, messages...)
}

// flushPendingWarnings replays the queued warnings, once, on the event-loop
// goroutine - the same goroutine every other warning is raised on.
// notifyWarningOrLog is used because these report degraded observability the
// user must see in every mode: a TUI warning row, or stderr where no warning
// sink is wired.
func (f *outputFormatter) flushPendingWarnings() {
	pending := f.pendingWarnings
	f.pendingWarnings = nil
	for _, message := range pending {
		f.notifyWarningOrLog(message)
	}
}

// emit invokes printCb for the given pair, falling back to a safe recycle-only
// callback when printCb has not been set. This prevents a nil-pointer dereference
// during early initialisation or in tests that do not configure printCb.
func (f *outputFormatter) emit(ep *event.Pair) {
	if f.printCb != nil {
		f.printCb(ep)
		return
	}
	// Fallback: recycle the pair so it is not leaked even when no callback is wired.
	ep.Recycle()
}

// notifyWarning delivers message to warningCb if one is registered and the
// message is non-empty. Silently drops the message otherwise so callers do not
// need to guard every warning site.
func (f *outputFormatter) notifyWarning(message string) {
	if f.warningCb == nil || message == "" {
		return
	}
	f.warningCb(message)
}

// notifyWarningOrLog delivers message to warningCb when one is registered and
// falls back to stderr when none is. Modes without a warning sink (-plain,
// -flamegraph, headless -parquet) never wire warningCb - only
// makeTUIEventLoopConfigurer does - so plain notifyWarning silently discards
// everything they report. That is acceptable for a per-event nuisance warning,
// but not for a signal about lost data: use this for warnings the user must
// see in every mode. stdout stays machine-readable because logStatus writes to
// stderr.
func (f *outputFormatter) notifyWarningOrLog(message string) {
	if message == "" {
		return
	}
	if f.warningCb != nil {
		f.warningCb(message)
		return
	}
	logStatus("Warning:", message)
}
