package tui

import (
	"ior/internal/tui/pidpicker"

	tea "charm.land/bubbletea/v2"
)

// screenRouter owns screen-transition state for the TUI. It tracks the picker
// return bookmark used when the user navigates from the dashboard to the PID or
// TID picker and may want to cancel back to the original dashboard view.
type screenRouter struct {
	// pickerReturn is non-nil while the user has navigated from the dashboard
	// back to the PID/TID picker. The stored values are used to restart the
	// trace if the user presses Esc to cancel the picker navigation.
	pickerReturn *pickerReturnState
}

// newScreenRouter creates an empty screenRouter with no pending return state.
func newScreenRouter() screenRouter {
	return screenRouter{}
}

// savePendingReturn records the current pid/tid so Esc can restore the
// dashboard if the user decides not to select a new process.
func (r *screenRouter) savePendingReturn(pid, tid int) {
	r.pickerReturn = &pickerReturnState{
		pidFilter: pid,
		tidFilter: tid,
	}
}

// takePendingReturn consumes and returns the stored picker return state,
// clearing it in the process. Returns (zero, false) when no pending state exists.
func (r *screenRouter) takePendingReturn() (pickerReturnState, bool) {
	if r.pickerReturn == nil {
		return pickerReturnState{}, false
	}
	state := *r.pickerReturn
	r.pickerReturn = nil
	return state, true
}

// hasPendingReturn reports whether the user navigated from the dashboard to
// the picker (meaning Esc should return to the dashboard instead of quitting).
func (r *screenRouter) hasPendingReturn() bool {
	return r.pickerReturn != nil
}

// applyWindowSizeToPicker sends the current window size to the pid picker when
// valid dimensions are available. Returns the updated picker and an optional
// size command.
func applyWindowSizeToPicker(picker pidpicker.Model, width, height int) (pidpicker.Model, tea.Cmd) {
	if width <= 0 || height <= 0 {
		return picker, nil
	}
	msg := tea.WindowSizeMsg{Width: width, Height: height}
	next, cmd := picker.Update(msg)
	return next.(pidpicker.Model), cmd
}
