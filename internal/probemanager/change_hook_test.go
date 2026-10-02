package probemanager

import (
	"context"
	"errors"
	"testing"

	"ior/internal/parkwait"
	"ior/internal/types"
)

// Tests for the change hook (SetChangeHook, task o03). The event loop hangs
// the restart fold's guard on it, and the guard is sound only if the hook runs
// while the changing syscall's enter tracepoint is not attached: before an
// attach touches a tracepoint, after a detach destroyed its links, and before
// the opposite change of the same syscall can begin. The tests below observe
// the fake programs and links from inside the hook, which is the only place
// that order can be seen.

// hookedRead is a manager with one registered syscall, read, whose two
// programs hand out one link each, and a hook that counts its calls and
// records what the fakes had seen at each call.
type hookedRead struct {
	mgr          *Manager
	enter, exit  *fakeProgram
	calls        int
	attachesSeen [][2]int // enter and exit AttachTracepoint calls so far
	destroysSeen [][2]int // enter and exit link Destroy calls so far
}

// newHookedRead registers read without attaching it (attached false) or
// attaches it at startup, as AttachAll does, and only then installs the hook.
func newHookedRead(t *testing.T, attached bool) *hookedRead {
	t.Helper()
	h := &hookedRead{
		enter: &fakeProgram{link: &fakeLink{}},
		exit:  &fakeProgram{link: &fakeLink{}},
	}
	h.mgr = NewManager(&fakeAttacher{programs: map[string]*fakeProgram{
		"handle_sys_enter_read": h.enter,
		"handle_sys_exit_read":  h.exit,
	}, errs: map[string]error{}})
	selectAll := func(string) bool { return attached }
	if err := h.mgr.AttachAll(selectAll, []string{"sys_enter_read", "sys_exit_read"}, nil); err != nil {
		t.Fatalf("AttachAll: %v", err)
	}
	h.mgr.SetChangeHook(h.observe)
	return h
}

func (h *hookedRead) observe() {
	h.calls++
	h.attachesSeen = append(h.attachesSeen, [2]int{h.enter.attachCalls(), h.exit.attachCalls()})
	h.destroysSeen = append(h.destroysSeen, [2]int{h.enter.link.destroyCalls(), h.exit.link.destroyCalls()})
}

// TestChangeHookRunsBeforeAnAttachTouchesATracepoint: a runtime attach is
// reported once, and at that moment neither tracepoint of the syscall has been
// attached yet. Reported afterwards, the enter probe would already have seen a
// syscall that the listener's note claims to be older than.
func TestChangeHookRunsBeforeAnAttachTouchesATracepoint(t *testing.T) {
	h := newHookedRead(t, false)
	if err := h.mgr.Attach("read"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if h.calls != 1 {
		t.Fatalf("hook ran %d times for one attach, want once", h.calls)
	}
	if h.attachesSeen[0] != [2]int{0, 0} {
		t.Fatalf("hook saw %v tracepoint attaches (enter, exit), want none yet", h.attachesSeen[0])
	}
	if !h.mgr.IsActive("read") {
		t.Fatal("read is not active after Attach")
	}
}

// TestChangeHookRunsAfterADetachDestroyedBothLinks: a runtime detach is
// reported once, when both links are gone. Reported before, a call the old
// attachment still saw - an interrupted exit - would be younger than the note.
func TestChangeHookRunsAfterADetachDestroyedBothLinks(t *testing.T) {
	h := newHookedRead(t, true)
	if err := h.mgr.Detach("read"); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if h.calls != 1 {
		t.Fatalf("hook ran %d times for one detach, want once", h.calls)
	}
	if h.destroysSeen[0] != [2]int{1, 1} {
		t.Fatalf("hook saw %v link destroys (enter, exit), want both done", h.destroysSeen[0])
	}
	if h.mgr.IsActive("read") {
		t.Fatal("read is still active after Detach")
	}
}

// TestChangeHookFollowsEveryToggle: the modal's toggle is a detach or an
// attach, and each one is reported in its own order.
func TestChangeHookFollowsEveryToggle(t *testing.T) {
	h := newHookedRead(t, true)
	for range 2 {
		if err := h.mgr.Toggle("read"); err != nil {
			t.Fatalf("Toggle: %v", err)
		}
	}
	if h.calls != 2 {
		t.Fatalf("hook ran %d times for a detach and an attach, want 2", h.calls)
	}
	if h.destroysSeen[0] != [2]int{1, 1} {
		t.Fatalf("the detach was reported with %v link destroys, want both done", h.destroysSeen[0])
	}
	// One attach each from AttachAll; the re-attach has not begun.
	if h.attachesSeen[1] != [2]int{1, 1} {
		t.Fatalf("the re-attach was reported with %v attaches, want only the startup ones", h.attachesSeen[1])
	}
}

// TestChangeHookIsSilentWhenNothingChanges: the startup attach ran before
// anybody listened, attaching an attached probe and detaching a detached one
// change nothing, and Close ends the session. None of them is a runtime
// change, and a report would clear the kernel's restart state and refuse folds
// for nothing.
func TestChangeHookIsSilentWhenNothingChanges(t *testing.T) {
	h := newHookedRead(t, true)
	if err := h.mgr.Attach("read"); err != nil {
		t.Fatalf("Attach of an attached probe: %v", err)
	}
	if h.calls != 0 {
		t.Fatalf("hook ran %d times for the startup attach and a no-op attach, want 0", h.calls)
	}
	if err := h.mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if h.calls != 0 {
		t.Fatalf("hook ran %d times for Close, want 0", h.calls)
	}

	h = newHookedRead(t, false)
	if err := h.mgr.Detach("read"); err != nil {
		t.Fatalf("Detach of a detached probe: %v", err)
	}
	if h.calls != 0 {
		t.Fatalf("hook ran %d times for a no-op detach, want 0", h.calls)
	}
}

// TestChangeHookReportsFailedChanges: an attach that fails had its enter
// tracepoint attached for a moment, and a detach that fails may have destroyed
// one link of two. Both moved what the kernel sees, so both are reported.
func TestChangeHookReportsFailedChanges(t *testing.T) {
	h := newHookedRead(t, false)
	h.exit.err = errors.New("no such tracepoint")
	if err := h.mgr.Attach("read"); err == nil {
		t.Fatal("Attach with a failing exit tracepoint returned nil")
	}
	if h.calls != 1 || h.attachesSeen[0] != [2]int{0, 0} {
		t.Fatalf("failed attach: hook ran %d times, saw %v; want once, before any attach", h.calls, h.attachesSeen)
	}

	h = newHookedRead(t, true)
	h.exit.link.err = errors.New("busy")
	if err := h.mgr.Detach("read"); err == nil {
		t.Fatal("Detach with a failing exit link returned nil")
	}
	if h.calls != 1 || h.destroysSeen[0] != [2]int{1, 1} {
		t.Fatalf("failed detach: hook ran %d times, saw %v; want once, after both destroy attempts", h.calls, h.destroysSeen)
	}
}

// TestChangeHookCanBeRemovedAndMayReadTheManager: a nil hook stops the
// reports, and a hook runs without the manager lock, so it can ask the manager
// what is attached (the detach's own state is committed only afterwards).
func TestChangeHookCanBeRemovedAndMayReadTheManager(t *testing.T) {
	h := newHookedRead(t, true)
	var activeInHook bool
	h.mgr.SetChangeHook(func() { activeInHook = h.mgr.IsActive("read") })
	if err := h.mgr.Detach("read"); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if !activeInHook {
		t.Fatal("the hook read read as inactive before the detach was committed")
	}

	h.mgr.SetChangeHook(nil)
	if err := h.mgr.Attach("read"); err != nil {
		t.Fatalf("Attach without a hook: %v", err)
	}
	var none *Manager
	none.SetChangeHook(func() {}) // a nil manager has nothing to report
}

// TestChangeHookHoldsBackTheOppositeChange: the detach's report must be over
// before the same syscall can be attached again. The listener notes the time
// of the change in the hook; an attach that slipped in before that note would
// let the kernel announce a stale restart the note does not cover.
func TestChangeHookHoldsBackTheOppositeChange(t *testing.T) {
	h := newHookedRead(t, true)
	inHook, leaveHook := make(chan struct{}), make(chan struct{})
	h.mgr.SetChangeHook(func() {
		close(inHook)
		<-leaveHook
	})
	detached := make(chan error, 1)
	go func() { detached <- h.mgr.Detach("read") }()
	<-inHook

	const frame = "(*Manager).Attach"
	baseline := parkwait.Count(frame, parkwait.MutexLock, parkwait.Semacquire)
	h.mgr.SetChangeHook(nil) // the attach below reports nothing; it must still wait
	attached := make(chan error, 1)
	go func() { attached <- h.mgr.Attach("read") }()
	parkwait.Await{Frame: frame, Reasons: []string{parkwait.MutexLock, parkwait.Semacquire}, Baseline: baseline,
		TimeoutMsg: "Attach did not wait for the detach's change hook"}.Run(t)
	if got := h.enter.attachCalls(); got != 1 {
		t.Fatalf("enter tracepoint attached %d times while the detach's hook ran, want only the startup attach", got)
	}

	close(leaveHook)
	if err := <-detached; err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if err := <-attached; err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if got := h.enter.attachCalls(); got != 2 {
		t.Fatalf("enter tracepoint attached %d times after the hook returned, want 2", got)
	}
}

// TestFamilyBatchReportsEachProbeItChanges: a family toggle is a batch of
// single changes, and each probe that changes is reported - not the ones
// already in the requested state.
func TestFamilyBatchReportsEachProbeItChanges(t *testing.T) {
	mgr := newFamilyTestManager(t) // read attached; write, socket, connect, nanosleep not
	calls := 0
	mgr.SetChangeHook(func() { calls++ })

	result, err := mgr.AttachFamily(context.Background(), types.FamilyFS, nil)
	if err != nil || result.Changed != 1 {
		t.Fatalf("AttachFamily(FS) = %+v, %v; want write attached", result, err)
	}
	if calls != 1 {
		t.Fatalf("hook ran %d times attaching one probe (read was attached), want 1", calls)
	}

	result, err = mgr.DetachFamily(context.Background(), types.FamilyFS, nil)
	if err != nil || result.Changed != 2 {
		t.Fatalf("DetachFamily(FS) = %+v, %v; want read and write detached", result, err)
	}
	if calls != 3 {
		t.Fatalf("hook ran %d times in all, want 3 (one attach, two detaches)", calls)
	}
}
