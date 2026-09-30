package internal

import (
	"ior/internal/event"
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

	// flusher is the buffered sink behind printCb, when there is one (the
	// default -plain sink). The event loop flushes it when the loop stops and
	// within plainFlushInterval of a row being buffered, so buffering never
	// hides output for long. nil for every callback installed through
	// SetPrintCallback (TUI, parquet, flamegraph, pprof), which write
	// synchronously or hand the pair off; WrapPrintCallback keeps it,
	// because its wrapper still feeds the same sink.
	flusher pairFlusher

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

// SetPrintCallback replaces the pair-emission callback. The callback owns
// each pair after the call: it must either recycle it (ep.Recycle) or hand it
// off to another owner. This is the production wiring seam for the mode
// packages (plain output, TUI ingest, parquet/flamegraph recorders).
//
// It also drops the default -plain sink's flusher, because it replaces the
// callback outright: that sink is no longer fed, so there is nothing left for
// the loop to flush. Use it for a callback that wraps but does NOT feed the
// previous callback/sink (TUI ingest, recorders). A wrapper that still feeds
// the previous callback must use WrapPrintCallback instead, which keeps the
// flusher; using SetPrintCallback there would leave the sink fed but never
// flushed on the timer or at shutdown.
func (e *eventLoop) SetPrintCallback(cb func(ep *event.Pair)) {
	e.printCb = cb
	e.flusher = nil
}

// WrapPrintCallback replaces the pair-emission callback with wrap(current).
// The wrapper must hand every pair it does not consume itself on to next (or
// recycle it), so the buffered sink behind the current callback keeps being
// fed and its flusher stays valid: unlike SetPrintCallback this does NOT drop
// the flusher. That is what keeps the -plain buffer flushed (timer and
// shutdown) when trace setup puts the active-probe filter in front of it.
// A nil current callback is passed to wrap as nil.
func (e *eventLoop) WrapPrintCallback(wrap func(next func(ep *event.Pair)) func(ep *event.Pair)) {
	e.printCb = wrap(e.printCb)
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
