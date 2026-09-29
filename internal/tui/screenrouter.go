package tui

import (
	"ior/internal/tui/pidpicker"

	tea "charm.land/bubbletea/v2"
)

// screenRouter owns screen-transition state for the TUI: which screen is
// active, and the picker return bookmark used when the user navigates from the
// dashboard to the PID or TID picker and may want to cancel back to the
// original dashboard view.
//
// Model reads this state through current/pendingReturn and changes it only
// through the transition methods, so the invariant "a return bookmark exists
// only while the re-selection picker is showing" is kept in one place instead
// of in every Model path that switches screens.
type screenRouter struct {
	// active is the screen currently shown.
	active Screen
	// pickerReturn is non-nil while the user has navigated from the dashboard
	// back to the PID/TID picker. The stored values are used to restart the
	// trace if the user presses Esc to cancel the picker navigation.
	pickerReturn *pickerReturnState
}

// pickerReturnState is the pid/tid filter pair a cancelled re-selection
// restores.
type pickerReturnState struct {
	pidFilter int
	tidFilter int
}

// newScreenRouter creates a router showing initial with no pending return
// state.
func newScreenRouter(initial Screen) screenRouter {
	return screenRouter{active: initial}
}

// current reports the active screen.
func (r *screenRouter) current() Screen {
	return r.active
}

// showDashboard switches to the dashboard. Any return bookmark is dropped:
// once the dashboard is showing there is no picker navigation left to cancel.
func (r *screenRouter) showDashboard() {
	r.active = ScreenDashboard
	r.pickerReturn = nil
}

// showPickerWithReturn switches to the picker and records the current pid/tid
// so Esc can restore the dashboard if the user decides not to select a new
// process.
func (r *screenRouter) showPickerWithReturn(pid, tid int) {
	r.active = ScreenPIDPicker
	r.pickerReturn = &pickerReturnState{
		pidFilter: pid,
		tidFilter: tid,
	}
}

// pendingReturn returns the stored picker return state without consuming it.
// Returns (zero, false) when no pending state exists - that is, when the
// picker was not reached from the dashboard, so Esc should quit rather than
// return. The bookmark is only dropped once the transition back to the
// dashboard actually happens (showDashboard), so a caller that fails halfway
// keeps it intact.
func (r *screenRouter) pendingReturn() (pickerReturnState, bool) {
	if r.pickerReturn == nil {
		return pickerReturnState{}, false
	}
	return *r.pickerReturn, true
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
