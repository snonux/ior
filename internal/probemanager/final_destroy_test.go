package probemanager

import (
	"errors"
	"testing"
)

// Tests for the rule that a link's Destroy is final (Link): it is called at
// most once, and the link is gone afterwards also when Destroy returned an
// error. With the real link the tracepoint is detached and the link freed in
// either case, so a second Destroy is a use after free. The manager used to
// keep a link whose destroy had failed - after a detach, and (task z13) after
// an attach that had to take its enter link back - and destroyed it again at
// the next Detach or at Close.
//
// Every fake link of the package records a Destroy beyond the first, and
// TestMain fails the run over it; the tests below also count the calls.

var (
	errExitAttach   = errors.New("no such exit tracepoint")
	errEnterDestroy = errors.New("enter link busy")
	errExitDestroy  = errors.New("exit link busy")
)

// newReadAfterFailedCleanup returns read after an attach that failed and
// whose cleanup reported an error too: the exit program refused to attach,
// and the destroy of the enter link attached just before returned an error.
// Both keep failing until the test repairs them.
func newReadAfterFailedCleanup(t *testing.T) *hookedRead {
	t.Helper()
	h := newHookedRead(t, false)
	h.exit.err = errExitAttach
	h.enter.link.err = errEnterDestroy
	err := h.mgr.Attach("read")
	if !errors.Is(err, errExitAttach) || !errors.Is(err, errEnterDestroy) {
		t.Fatalf("Attach = %v, want the exit attach error and the enter cleanup error", err)
	}
	h.assertDestroyCalls(t, 1, 0)
	return h
}

// newReadAfterFailedDetach returns read, attached at startup and detached
// with the given destroy errors (nil: that destroy succeeds), and the error
// Detach returned.
func newReadAfterFailedDetach(t *testing.T, enterErr, exitErr error) (*hookedRead, error) {
	t.Helper()
	h := newHookedRead(t, true)
	h.enter.link.err = enterErr
	h.exit.link.err = exitErr
	err := h.mgr.Detach("read")
	h.assertDestroyCalls(t, 1, 1)
	return h, err
}

// assertDestroyCalls checks how often Destroy was called on the enter and on
// the exit link so far.
func (h *hookedRead) assertDestroyCalls(t *testing.T, enter, exit int) {
	t.Helper()
	gotEnter, gotExit := h.enter.link.destroyCalls(), h.exit.link.destroyCalls()
	if gotEnter != enter || gotExit != exit {
		t.Fatalf("Destroy called %d (enter) and %d (exit) times, want %d and %d", gotEnter, gotExit, enter, exit)
	}
}

// assertOff checks that the manager calls read inactive in every view of it,
// with an error recorded (wantErr) or without one.
func (h *hookedRead) assertOff(t *testing.T, wantErr bool) {
	t.Helper()
	if h.mgr.IsActive("read") {
		t.Fatal("read is active although both its tracepoints are detached")
	}
	if active, total := h.mgr.ActiveCount(); active != 0 || total != 1 {
		t.Fatalf("ActiveCount = %d/%d, want 0/1", active, total)
	}
	states := h.mgr.States()
	if len(states) != 1 || states[0].Active || (states[0].Error != "") != wantErr {
		t.Fatalf("States = %+v, want read inactive, an error recorded: %t", states, wantErr)
	}
}

// assertAttachesAfresh attaches read again once both programs attach, and
// checks that it is a full attach: each tracepoint attached once more
// (attaches in all), exactly one live link each, no further destroy, the
// probe active and its error gone.
func (h *hookedRead) assertAttachesAfresh(t *testing.T, attaches int) {
	t.Helper()
	h.exit.err = nil
	enterDestroys, exitDestroys := h.enter.link.destroyCalls(), h.exit.link.destroyCalls()
	if err := h.mgr.Attach("read"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if enter, exit := h.enter.attachCalls(), h.exit.attachCalls(); enter != attaches || exit != attaches {
		t.Fatalf("tracepoints attached %d (enter) and %d (exit) times, want %d each", enter, exit, attaches)
	}
	if enter, exit := h.enter.link.live(), h.exit.link.live(); enter != 1 || exit != 1 {
		t.Fatalf("%d live enter links and %d live exit links, want exactly one each", enter, exit)
	}
	h.assertDestroyCalls(t, enterDestroys, exitDestroys)
	if states := h.mgr.States(); !states[0].Active || states[0].Error != "" {
		t.Fatalf("States = %+v, want read active without an error", states)
	}
}

// closeAndRecordProgress closes the manager and returns the progress it
// reported.
func (h *hookedRead) closeAndRecordProgress(t *testing.T) [][2]int {
	t.Helper()
	var progress [][2]int
	err := h.mgr.CloseWithProgress(func(completed, total int) {
		progress = append(progress, [2]int{completed, total})
	})
	if err != nil {
		t.Fatalf("CloseWithProgress: %v", err)
	}
	return progress
}

// TestFailedAttachCleanupLeavesTheProbeOff: the enter link whose destroy
// reported an error is gone like any destroyed link, so the probe is inactive
// with the error recorded and no link left. The attach was reported twice
// like any attach, the second time after the one destroy.
func TestFailedAttachCleanupLeavesTheProbeOff(t *testing.T) {
	h := newReadAfterFailedCleanup(t)
	h.assertOff(t, true)
	if live := h.enter.link.live(); live != 0 {
		t.Fatalf("%d live enter links after the failed attach, want none", live)
	}
	if h.calls != 2 || h.attachesSeen[1] != [2]int{1, 1} || h.destroysSeen[1] != [2]int{1, 0} {
		t.Fatalf("hook ran %d times, saw attaches %v and destroys %v; want twice, the second after the destroy",
			h.calls, h.attachesSeen, h.destroysSeen)
	}
}

// TestAttachAfterAFailedCleanupAttachesBothTracepointsAfresh: nothing of the
// failed attempt is left, so the next Attach is an ordinary one - both
// tracepoints, reported twice - and leaves exactly one live enter link.
func TestAttachAfterAFailedCleanupAttachesBothTracepointsAfresh(t *testing.T) {
	h := newReadAfterFailedCleanup(t)
	h.assertAttachesAfresh(t, 2)
	if h.calls != 4 || h.attachesSeen[2] != [2]int{1, 1} || h.attachesSeen[3] != [2]int{2, 2} {
		t.Fatalf("hook ran %d times, saw attaches %v; want 4, the last two around the second attach",
			h.calls, h.attachesSeen)
	}
}

// TestDetachAndCloseAfterAFailedCleanupDestroyNothing: there is no link left
// for a Detach or for Close, and the one that was destroyed with an error
// must not be destroyed again. Detach is a silent no-op and Close has no pair
// to detach.
func TestDetachAndCloseAfterAFailedCleanupDestroyNothing(t *testing.T) {
	h := newReadAfterFailedCleanup(t)
	if err := h.mgr.Detach("read"); err != nil {
		t.Fatalf("Detach of an inactive probe: %v", err)
	}
	if h.calls != 2 {
		t.Fatalf("hook ran %d times, want only the two reports of the failed attach", h.calls)
	}
	progress := h.closeAndRecordProgress(t)
	if len(progress) != 1 || progress[0] != [2]int{0, 0} {
		t.Fatalf("progress = %v, want 0/0 only: no pair to detach", progress)
	}
	h.assertDestroyCalls(t, 1, 0)
}

// TestCloseDuringAFailedAttachDestroysEachLinkOnce: an attach that finds the
// manager closed when it comes to commit destroys the links it brought, each
// once, and stores none; a cleanup error is returned with the attach error.
func TestCloseDuringAFailedAttachDestroysEachLinkOnce(t *testing.T) {
	h := newHookedRead(t, false)
	enter, exit := &fakeLink{err: errEnterDestroy}, &fakeLink{}
	if err := h.mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err := h.mgr.commitAttach("read", enter, exit, errExitAttach)
	if !errors.Is(err, errEnterDestroy) || !errors.Is(err, errExitAttach) {
		t.Fatalf("commitAttach on a closed manager = %v, want the cleanup error and the attach error", err)
	}
	if enter.destroyCalls() != 1 || exit.destroyCalls() != 1 {
		t.Fatalf("links destroyed %d (enter) and %d (exit) times, want once each",
			enter.destroyCalls(), exit.destroyCalls())
	}
	if h.mgr.IsActive("read") {
		t.Fatal("a closed manager took the link of an attach that finished after Close")
	}
}

// TestFailedAttachThatCleansUpLeavesNothingBehind is the ordinary failure:
// the enter link is destroyed again without an error, the probe is inactive
// with the attach error and without a link, a Detach has nothing to do, and
// the next Attach starts from scratch.
func TestFailedAttachThatCleansUpLeavesNothingBehind(t *testing.T) {
	h := newHookedRead(t, false)
	h.exit.err = errExitAttach
	if err := h.mgr.Attach("read"); !errors.Is(err, errExitAttach) {
		t.Fatalf("Attach = %v, want the exit attach error", err)
	}
	h.assertOff(t, true)
	if err := h.mgr.Detach("read"); err != nil || h.calls != 2 {
		t.Fatalf("Detach = %v, hook ran %d times; want a silent no-op", err, h.calls)
	}
	h.assertDestroyCalls(t, 1, 0)
	h.assertAttachesAfresh(t, 2)
}

// TestDetachWithAFailedDestroyLeavesTheProbeOff: whichever destroy reports an
// error, both links were destroyed exactly once and are gone, so the probe is
// inactive - there is no half-detached state - with the error returned and
// recorded, and the detach reported once, after both destroys.
func TestDetachWithAFailedDestroyLeavesTheProbeOff(t *testing.T) {
	for _, tc := range []struct {
		name              string
		enterErr, exitErr error
	}{
		{"enter destroy fails", errEnterDestroy, nil},
		{"exit destroy fails", nil, errExitDestroy},
		{"both destroys fail", errEnterDestroy, errExitDestroy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := newReadAfterFailedDetach(t, tc.enterErr, tc.exitErr)
			if err == nil || errors.Is(err, errEnterDestroy) != (tc.enterErr != nil) ||
				errors.Is(err, errExitDestroy) != (tc.exitErr != nil) {
				t.Fatalf("Detach = %v, want exactly the destroy errors %v and %v", err, tc.enterErr, tc.exitErr)
			}
			h.assertOff(t, true)
			if got := h.mgr.States()[0].Error; got != err.Error() {
				t.Fatalf("recorded error %q, want the one Detach returned: %q", got, err)
			}
			if h.calls != 1 || h.destroysSeen[0] != [2]int{1, 1} {
				t.Fatalf("hook ran %d times, saw destroys %v; want once, after both", h.calls, h.destroysSeen)
			}
		})
	}
}

// TestDetachAfterAFailedDetachDestroysNothing: nothing is left to retry. A
// second Detach is the no-op it is for every inactive probe: no Destroy, no
// report.
func TestDetachAfterAFailedDetachDestroysNothing(t *testing.T) {
	h, _ := newReadAfterFailedDetach(t, errEnterDestroy, errExitDestroy)
	if err := h.mgr.Detach("read"); err != nil {
		t.Fatalf("second Detach = %v, want a no-op", err)
	}
	h.assertDestroyCalls(t, 1, 1)
	if h.calls != 1 {
		t.Fatalf("hook ran %d times, want only the report of the first detach", h.calls)
	}
}

// TestToggleAfterAFailedDetachAttachesAfresh: the probe is off, so the
// modal's toggle attaches it - both tracepoints anew, one live link each -
// and the recorded error goes.
func TestToggleAfterAFailedDetachAttachesAfresh(t *testing.T) {
	h, _ := newReadAfterFailedDetach(t, errEnterDestroy, nil)
	if err := h.mgr.Toggle("read"); err != nil {
		t.Fatalf("Toggle: %v", err)
	}
	if enter, exit := h.enter.attachCalls(), h.exit.attachCalls(); enter != 2 || exit != 2 {
		t.Fatalf("tracepoints attached %d (enter) and %d (exit) times, want 2 each", enter, exit)
	}
	if enter, exit := h.enter.link.live(), h.exit.link.live(); enter != 1 || exit != 1 {
		t.Fatalf("%d live enter links and %d live exit links, want exactly one each", enter, exit)
	}
	h.assertDestroyCalls(t, 1, 1)
	if states := h.mgr.States(); !states[0].Active || states[0].Error != "" {
		t.Fatalf("States = %+v, want read active without an error", states)
	}
}

// TestCloseAfterAFailedDetachCallsNoSecondDestroy: Close has no pair to
// detach and leaves the two destroyed links alone.
func TestCloseAfterAFailedDetachCallsNoSecondDestroy(t *testing.T) {
	h, _ := newReadAfterFailedDetach(t, errEnterDestroy, errExitDestroy)
	progress := h.closeAndRecordProgress(t)
	if len(progress) != 1 || progress[0] != [2]int{0, 0} {
		t.Fatalf("progress = %v, want 0/0 only: no pair to detach", progress)
	}
	h.assertDestroyCalls(t, 1, 1)
	if h.calls != 1 {
		t.Fatalf("hook ran %d times, want Close silent", h.calls)
	}
}

// TestDetachThatSucceedsLeavesNoError is the ordinary detach: the probe is
// inactive without an error, each link destroyed once, and Close afterwards
// destroys nothing.
func TestDetachThatSucceedsLeavesNoError(t *testing.T) {
	h, err := newReadAfterFailedDetach(t, nil, nil)
	if err != nil {
		t.Fatalf("Detach: %v", err)
	}
	h.assertOff(t, false)
	if progress := h.closeAndRecordProgress(t); len(progress) != 1 || progress[0] != [2]int{0, 0} {
		t.Fatalf("progress = %v, want 0/0 only: no pair to detach", progress)
	}
	h.assertDestroyCalls(t, 1, 1)
}

// TestCloseDestroysAnAttachedPairOnceDespiteErrors: Close takes the links of
// an attached pair and destroys each once, also when both destroys report an
// error, which it returns (the enter link's first).
func TestCloseDestroysAnAttachedPairOnceDespiteErrors(t *testing.T) {
	h := newHookedRead(t, true)
	h.enter.link.err = errEnterDestroy
	h.exit.link.err = errExitDestroy
	if err := h.mgr.Close(); !errors.Is(err, errEnterDestroy) {
		t.Fatalf("Close = %v, want the enter destroy error", err)
	}
	h.assertDestroyCalls(t, 1, 1)
	if err := h.mgr.Close(); err != nil {
		t.Fatalf("second Close = %v, want a no-op", err)
	}
	h.assertDestroyCalls(t, 1, 1)
}

// TestDetachWhoseHookPanicsLeavesNoLinkToDestroyAgain pins the order that
// makes a second Destroy impossible rather than merely avoided: the links
// leave the entry before they are destroyed, not when the detach is
// committed. A listener that panics after the destroys cuts the Detach short
// of its commit, and Close must still find no link to destroy again.
func TestDetachWhoseHookPanicsLeavesNoLinkToDestroyAgain(t *testing.T) {
	h := newHookedRead(t, true)
	h.mgr.SetChangeHook(func(Change) { panic("listener failed") })
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("Detach did not pass the hook's panic on")
			}
		}()
		_ = h.mgr.Detach("read")
	}()
	h.assertDestroyCalls(t, 1, 1)
	if err := h.mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	h.assertDestroyCalls(t, 1, 1)
}
