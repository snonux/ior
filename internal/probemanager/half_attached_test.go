package probemanager

import (
	"errors"
	"testing"
)

// Tests for the attach that fails half-way and cannot be undone (task z13):
// the exit tracepoint does not attach, and the enter link attached just before
// cannot be destroyed again. The enter tracepoint is then still attached in the
// kernel, so the manager has to keep its link: forgotten, the next Attach
// attached a second enter program beside it and every enter record of the
// syscall arrived twice, with nothing left that could destroy the first.

var (
	errExitAttach   = errors.New("no such exit tracepoint")
	errEnterDestroy = errors.New("enter link busy")
)

// newHalfAttachedRead returns read after such an attach: the exit program
// refuses to attach and the enter link refuses to be destroyed. Both keep
// failing until the test repairs them.
func newHalfAttachedRead(t *testing.T) *hookedRead {
	t.Helper()
	h := newHookedRead(t, false)
	h.exit.err = errExitAttach
	h.enter.link.err = errEnterDestroy
	err := h.mgr.Attach("read")
	if !errors.Is(err, errExitAttach) || !errors.Is(err, errEnterDestroy) {
		t.Fatalf("Attach = %v, want the exit attach error and the enter cleanup error", err)
	}
	if got := h.enter.link.destroyCalls(); got != 1 {
		t.Fatalf("enter link destroyed %d times by the failed attach, want one attempt", got)
	}
	return h
}

// TestHalfAttachedProbeIsShownActiveWithItsError: the probe has a tracepoint
// attached, and that is what IsActive, States and ActiveCount say - the same
// answer as for a detach that left a link - with the attach error beside it,
// which is what the probes modal renders. The attach itself was reported twice
// like any attach.
func TestHalfAttachedProbeIsShownActiveWithItsError(t *testing.T) {
	h := newHalfAttachedRead(t)
	if !h.mgr.IsActive("read") {
		t.Fatal("read is inactive although its enter tracepoint is still attached")
	}
	if active, total := h.mgr.ActiveCount(); active != 1 || total != 1 {
		t.Fatalf("ActiveCount = %d/%d, want 1/1", active, total)
	}
	states := h.mgr.States()
	if len(states) != 1 || !states[0].Active || states[0].Error == "" {
		t.Fatalf("States = %+v, want read active with the attach error", states)
	}
	if h.calls != 2 || h.attachesSeen[1] != [2]int{1, 1} || h.destroysSeen[1] != [2]int{1, 0} {
		t.Fatalf("hook ran %d times, saw attaches %v and destroys %v; want twice, the second after the destroy attempt",
			h.calls, h.attachesSeen, h.destroysSeen)
	}
}

// TestAttachOfAHalfAttachedProbeAttachesNoSecondEnterProgram is the defect:
// the retained link makes the next Attach the no-op it is for every probe
// that still has a link, also once the exit tracepoint would attach. It
// changes nothing, so it reports nothing.
func TestAttachOfAHalfAttachedProbeAttachesNoSecondEnterProgram(t *testing.T) {
	h := newHalfAttachedRead(t)
	h.exit.err = nil
	if err := h.mgr.Attach("read"); err != nil {
		t.Fatalf("Attach of a half-attached probe: %v", err)
	}
	if enter, exit := h.enter.attachCalls(), h.exit.attachCalls(); enter != 1 || exit != 1 {
		t.Fatalf("tracepoints attached %d (enter) and %d (exit) times, want the one attempt each of the failed attach",
			enter, exit)
	}
	if h.calls != 2 {
		t.Fatalf("hook ran %d times, want only the two reports of the failed attach", h.calls)
	}
	if !h.mgr.IsActive("read") {
		t.Fatal("read is inactive although its enter tracepoint is still attached")
	}
}

// TestDetachOfAHalfAttachedProbeRetriesTheDestroy: Detach - what the modal's
// toggle does for an active probe - destroys the retained link and reports,
// and only then can the pair be attached anew, both tracepoints once. A
// destroy that fails again keeps the link, and the probe active, once more.
func TestDetachOfAHalfAttachedProbeRetriesTheDestroy(t *testing.T) {
	h := newHalfAttachedRead(t)
	if err := h.mgr.Detach("read"); err == nil {
		t.Fatal("Detach returned nil although the enter link still cannot be destroyed")
	}
	if !h.mgr.IsActive("read") || h.enter.link.destroyCalls() != 2 {
		t.Fatalf("after a failed retry: active %t, enter link destroyed %d times; want active and 2",
			h.mgr.IsActive("read"), h.enter.link.destroyCalls())
	}

	h.enter.link.err = nil
	if err := h.mgr.Detach("read"); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if h.mgr.IsActive("read") || h.mgr.States()[0].Error != "" {
		t.Fatalf("States = %+v after the retained link was destroyed, want read inactive without an error", h.mgr.States())
	}
	if h.calls != 4 || h.destroysSeen[3] != [2]int{3, 0} {
		t.Fatalf("hook ran %d times, saw destroys %v; want 4, the last after the third destroy", h.calls, h.destroysSeen)
	}
	assertReadAttachesAnew(t, h)
}

// assertReadAttachesAnew attaches read after its retained link is gone: one
// more attach of each tracepoint, and no further destroy.
func assertReadAttachesAnew(t *testing.T, h *hookedRead) {
	t.Helper()
	h.exit.err = nil
	destroyed := h.enter.link.destroyCalls()
	if err := h.mgr.Attach("read"); err != nil {
		t.Fatalf("Attach after the detach: %v", err)
	}
	if enter, exit := h.enter.attachCalls(), h.exit.attachCalls(); enter != 2 || exit != 2 {
		t.Fatalf("tracepoints attached %d (enter) and %d (exit) times, want 2 each", enter, exit)
	}
	if got := h.enter.link.destroyCalls(); got != destroyed || !h.mgr.IsActive("read") {
		t.Fatalf("enter link destroyed %d times (was %d), active %t; want no destroy and an active probe",
			got, destroyed, h.mgr.IsActive("read"))
	}
}

// TestCloseDestroysTheLinkOfAHalfAttachedProbe: Close counts the probe among
// the pairs it has to detach and destroys the retained link, silently like
// every Close.
func TestCloseDestroysTheLinkOfAHalfAttachedProbe(t *testing.T) {
	h := newHalfAttachedRead(t)
	h.enter.link.err = nil
	var progress [][2]int
	err := h.mgr.CloseWithProgress(func(completed, total int) {
		progress = append(progress, [2]int{completed, total})
	})
	if err != nil {
		t.Fatalf("CloseWithProgress: %v", err)
	}
	if got := h.enter.link.destroyCalls(); got != 2 {
		t.Fatalf("enter link destroyed %d times, want 2: the failed cleanup and Close", got)
	}
	if len(progress) != 2 || progress[0] != [2]int{0, 1} || progress[1] != [2]int{1, 1} {
		t.Fatalf("progress = %v, want 0/1 then 1/1: one pair to detach", progress)
	}
	if h.calls != 2 || h.exit.link.destroyCalls() != 0 {
		t.Fatalf("hook ran %d times, exit link destroyed %d times; want Close silent and the exit link untouched",
			h.calls, h.exit.link.destroyCalls())
	}
}

// TestCloseDuringAHalfFailedAttachRetriesTheDestroy: an attach that finds the
// manager closed when it comes to commit has nowhere to keep the link - Close
// has taken its snapshot - so it tries the destroy once more itself.
func TestCloseDuringAHalfFailedAttachRetriesTheDestroy(t *testing.T) {
	h := newHookedRead(t, false)
	link := &fakeLink{}
	if err := h.mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err := h.mgr.commitAttach("read", link, nil, errExitAttach)
	if err == nil || link.destroyCalls() != 1 {
		t.Fatalf("commitAttach on a closed manager = %v, link destroyed %d times; want an error and one destroy",
			err, link.destroyCalls())
	}
	if h.mgr.IsActive("read") {
		t.Fatal("a closed manager took the link of an attach that finished after Close")
	}
}

// TestFailedAttachThatCleansUpLeavesNothingBehind is the ordinary failure,
// unchanged: the enter link is destroyed again, the probe is inactive with
// the error and without a link, Close has nothing to detach, and the next
// Attach starts from scratch.
func TestFailedAttachThatCleansUpLeavesNothingBehind(t *testing.T) {
	h := newHookedRead(t, false)
	h.exit.err = errExitAttach
	if err := h.mgr.Attach("read"); !errors.Is(err, errExitAttach) {
		t.Fatalf("Attach = %v, want the exit attach error", err)
	}
	states := h.mgr.States()
	if h.mgr.IsActive("read") || states[0].Active || states[0].Error == "" {
		t.Fatalf("States = %+v, want read inactive with the attach error", states)
	}
	if err := h.mgr.Detach("read"); err != nil || h.calls != 2 || h.enter.link.destroyCalls() != 1 {
		t.Fatalf("Detach = %v, hook ran %d times, enter link destroyed %d times; want a silent no-op",
			err, h.calls, h.enter.link.destroyCalls())
	}

	h.exit.err = nil
	if err := h.mgr.Attach("read"); err != nil {
		t.Fatalf("second Attach: %v", err)
	}
	if enter, exit := h.enter.attachCalls(), h.exit.attachCalls(); enter != 2 || exit != 2 {
		t.Fatalf("tracepoints attached %d (enter) and %d (exit) times, want 2 each", enter, exit)
	}
	if !h.mgr.IsActive("read") || h.mgr.States()[0].Error != "" {
		t.Fatalf("States = %+v after the second attach, want read active without an error", h.mgr.States())
	}
}
