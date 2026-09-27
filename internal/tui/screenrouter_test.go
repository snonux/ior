package tui

import "testing"

func TestScreenRouterStartsOnTheInitialScreenWithNoReturn(t *testing.T) {
	for _, initial := range []Screen{ScreenPIDPicker, ScreenDashboard} {
		r := newScreenRouter(initial)
		if got := r.current(); got != initial {
			t.Fatalf("newScreenRouter(%v).current() = %v", initial, got)
		}
		if r.hasPendingReturn() {
			t.Fatalf("newScreenRouter(%v) has a pending return", initial)
		}
		if _, ok := r.pendingReturn(); ok {
			t.Fatalf("newScreenRouter(%v).pendingReturn() reported a bookmark", initial)
		}
	}
}

func TestScreenRouterPickerWithReturnBookmarksPidAndTid(t *testing.T) {
	r := newScreenRouter(ScreenDashboard)
	r.showPickerWithReturn(1234, 5678)

	if got := r.current(); got != ScreenPIDPicker {
		t.Fatalf("current() = %v, want picker", got)
	}
	state, ok := r.pendingReturn()
	if !ok {
		t.Fatal("pendingReturn() reported no bookmark after showPickerWithReturn")
	}
	if state.pidFilter != 1234 || state.tidFilter != 5678 {
		t.Fatalf("pendingReturn() = %+v, want pid=1234 tid=5678", state)
	}
	// pendingReturn peeks: a caller that fails halfway through the return
	// transition must still find the bookmark on its next attempt.
	if _, ok := r.pendingReturn(); !ok || !r.hasPendingReturn() {
		t.Fatal("pendingReturn() consumed the bookmark")
	}
}

func TestScreenRouterShowDashboardDropsTheReturn(t *testing.T) {
	r := newScreenRouter(ScreenDashboard)
	r.showPickerWithReturn(1, 2)
	r.showDashboard()

	if got := r.current(); got != ScreenDashboard {
		t.Fatalf("current() = %v, want dashboard", got)
	}
	if r.hasPendingReturn() {
		t.Fatal("showDashboard left the picker return pending")
	}
}

func TestScreenRouterClearPendingReturnKeepsTheScreen(t *testing.T) {
	r := newScreenRouter(ScreenDashboard)
	r.showPickerWithReturn(1, 2)
	r.clearPendingReturn()

	if got := r.current(); got != ScreenPIDPicker {
		t.Fatalf("current() = %v, want picker kept", got)
	}
	if r.hasPendingReturn() {
		t.Fatal("clearPendingReturn left the bookmark in place")
	}
	// Clearing twice, or with nothing pending, is a harmless no-op.
	r.clearPendingReturn()
	if _, ok := r.pendingReturn(); ok {
		t.Fatal("pendingReturn() reported a bookmark after a double clear")
	}
}
