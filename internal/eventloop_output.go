package internal

import "ior/internal/event"

// outputFormatter bundles the pair-emission and warning-notification callbacks
// used by the event loop. Extracting these two concerns into a dedicated type
// separates "what to do with a completed event pair" and "how to report
// non-fatal problems" from the core event-matching and FD-tracking logic.
//
// The struct is embedded (not pointed-to) inside eventLoop so that existing
// call sites — including tests — can still write e.printCb = ... and
// e.warningCb = ... without any changes.
type outputFormatter struct {
	// printCb is called for each completed, filter-passing event pair.
	// The callback owns the pair after the call: it must either recycle it
	// (ep.Recycle) or hand it off to another owner.
	printCb func(ep *event.Pair)

	// warningCb is an optional callback for non-fatal event-processing
	// warnings (e.g. malformed events, unresolved comms). nil means silent.
	warningCb func(message string)
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
