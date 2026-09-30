package probes

import (
	"context"
	"errors"

	tea "charm.land/bubbletea/v2"
)

// SetAllRequestMsg asks the TUI to attach (Active) or detach every probe: the
// modal's a / n keys. Like a family batch (FamilyBatchRequestMsg) the modal
// only requests it and the TUI owns the run, because the walk over every probe
// takes seconds and must belong to a trace session: the TUI records the
// intended probe set when the key is pressed, runs the walk through SetAllCmd
// on the session's context and ignores the outcome of a session that has
// ended. A modal that ran it itself would keep attaching to a manager that is
// about to close after a restart, and the restart would start without the
// user's intent.
type SetAllRequestMsg struct {
	Active bool
}

// requestSetAll returns the command that delivers a SetAllRequestMsg.
func requestSetAll(active bool) tea.Cmd {
	request := SetAllRequestMsg{Active: active}
	return func() tea.Msg { return request }
}

// SetAllCmd attaches (active) or detaches every probe of manager and yields a
// ProbeToggledMsg tagged with session, the trace session that owns manager.
//
// It works from a fresh States() read and uses Attach/Detach rather than
// Toggle, so it only touches probes not yet in the requested state and is
// idempotent: pressing a twice, or after the list shown in the modal went
// stale, never flips a probe back. ctx is the trace session's: once it is
// cancelled (restart, stop, quit) the walk stops before the next probe instead
// of attaching more to a manager that is about to close, and the result
// carries the context's error. The result has no Intent: the TUI records it
// when it starts the walk (see ProbeToggledMsg).
func SetAllCmd(ctx context.Context, manager Manager, active bool, session uint64) tea.Cmd {
	return func() tea.Msg {
		if manager == nil {
			return ProbeToggledMsg{Session: session, Err: errors.New("probe manager unavailable")}
		}
		change := manager.Detach
		if active {
			change = manager.Attach
		}
		var firstErr error
		for _, p := range manager.States() {
			if err := ctx.Err(); err != nil {
				return ProbeToggledMsg{Session: session, Err: err}
			}
			if p.Active == active {
				continue
			}
			if err := change(p.Syscall); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return ProbeToggledMsg{Session: session, Err: firstErr}
	}
}
