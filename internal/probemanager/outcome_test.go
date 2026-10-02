package probemanager

import (
	"errors"
	"strings"
	"testing"
)

// Tests for what a change leaves on the probe when it did not go the ordinary
// way (task 223): the links of an attach whose listener panics, the recorded
// error across a call that changes nothing, the text of an error made of
// several, and the destroys of an attach that finds the manager closed.

// expectPanic runs call and fails the test with notPanicked unless it panics.
func expectPanic(t *testing.T, notPanicked string, call func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal(notPanicked)
		}
	}()
	call()
}

// recordedError returns the error States shows for read, the one probe of a
// hookedRead.
func (h *hookedRead) recordedError(t *testing.T) string {
	t.Helper()
	states := h.mgr.States()
	if len(states) != 1 {
		t.Fatalf("States = %+v, want read alone", states)
	}
	return states[0].Error
}

// TestAttachWhoseEndReportPanicsKeepsItsLinks: both tracepoints are attached
// when the end of an attach is reported. A listener that panics there cuts
// the Attach short, and the two links must be on the entry all the same.
// Dropped, they stayed attached while the manager called the probe inactive:
// the next Attach attached a second pair, and every record came twice.
func TestAttachWhoseEndReportPanicsKeepsItsLinks(t *testing.T) {
	h := newHookedRead(t, false)
	h.mgr.SetChangeHook(func(change Change) {
		if change.Phase == ChangeEnds {
			panic("listener failed")
		}
	})
	expectPanic(t, "Attach did not pass the hook's panic on", func() { _ = h.mgr.Attach("read") })
	h.mgr.SetChangeHook(nil)

	if !h.mgr.IsActive("read") {
		t.Fatal("read is inactive although both its tracepoints are attached: the links were dropped")
	}
	if err := h.mgr.Attach("read"); err != nil {
		t.Fatalf("Attach of the attached probe: %v", err)
	}
	if enter, exit := h.enter.link.live(), h.exit.link.live(); enter != 1 || exit != 1 {
		t.Fatalf("%d live enter links and %d live exit links, want exactly one each", enter, exit)
	}
	if err := h.mgr.Detach("read"); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	h.assertDestroyCalls(t, 1, 1)
	h.assertOff(t, false)
}

// TestAttachIsCommittedAfterItsEndReport pins the order of the two things an
// Attach does on its way out, both deferred: the end is reported while the
// manager still calls the probe inactive, and only then is it committed
// (SetChangeHook: a report is over before the new state shows).
func TestAttachIsCommittedAfterItsEndReport(t *testing.T) {
	h := newHookedRead(t, false)
	var activeAt []bool
	h.mgr.SetChangeHook(func(Change) { activeAt = append(activeAt, h.mgr.IsActive("read")) })
	if err := h.mgr.Attach("read"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if len(activeAt) != 2 || activeAt[0] || activeAt[1] {
		t.Fatalf("read active at the reports of its attach: %v, want two reports, inactive at both", activeAt)
	}
	if !h.mgr.IsActive("read") {
		t.Fatal("read is inactive after its attach")
	}
}

// TestAttachWhoseAttacherPanicsCommitsNothing: an attach that never returned
// has no outcome. The probe keeps what the last change left on it - here the
// error of an earlier failed attach - instead of looking like one that was
// attached and detached without an error.
func TestAttachWhoseAttacherPanicsCommitsNothing(t *testing.T) {
	h := newReadAfterFailedCleanup(t)
	recorded := h.recordedError(t)
	h.enter.onAttach = func() { panic("attach failed hard") }
	expectPanic(t, "Attach did not pass the attacher's panic on", func() { _ = h.mgr.Attach("read") })
	if got := h.recordedError(t); got != recorded || got == "" {
		t.Fatalf("recorded error after the panic = %q, want it kept: %q", got, recorded)
	}
	h.assertOff(t, true)
}

// TestDetachOfAProbeWithoutALinkKeepsItsRecordedError: the recorded error
// says why a probe is off, and the probes modal shows it beside the probe. A
// Detach that finds no link changes nothing, so it must not wipe it, whether
// the error came from a failed attach or from a destroy.
func TestDetachOfAProbeWithoutALinkKeepsItsRecordedError(t *testing.T) {
	afterFailedDetach := func(t *testing.T) *hookedRead {
		h, _ := newReadAfterFailedDetach(t, errEnterDestroy, nil)
		return h
	}
	for name, setup := range map[string]func(*testing.T) *hookedRead{
		"after a failed attach": newReadAfterFailedCleanup,
		"after a failed detach": afterFailedDetach,
	} {
		t.Run(name, func(t *testing.T) {
			h := setup(t)
			recorded := h.recordedError(t)
			if recorded == "" {
				t.Fatal("the failed change recorded no error")
			}
			if err := h.mgr.Detach("read"); err != nil {
				t.Fatalf("Detach of a probe without a link = %v, want nil", err)
			}
			if got := h.recordedError(t); got != recorded {
				t.Fatalf("recorded error after the Detach = %q, want it kept: %q", got, recorded)
			}
		})
	}
}

// TestCloseKeepsTheRecordedErrorOfAProbeItDoesNotDestroy: Close records the
// outcome of its own destroys only. A probe it finds without a link keeps its
// error, which whoever still holds the manager can read from States.
func TestCloseKeepsTheRecordedErrorOfAProbeItDoesNotDestroy(t *testing.T) {
	h := newReadAfterFailedCleanup(t)
	recorded := h.recordedError(t)
	if err := h.mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := h.recordedError(t); got != recorded || got == "" {
		t.Fatalf("recorded error after Close = %q, want it kept: %q", got, recorded)
	}
}

// TestCloseRecordsTheOutcomeOfItsOwnDestroys is the other half: for a pair
// Close destroys, the recorded error is that of the destroys - the one Close
// returns, or none when both went through.
func TestCloseRecordsTheOutcomeOfItsOwnDestroys(t *testing.T) {
	failing := newHookedRead(t, true)
	failing.enter.link.err = errEnterDestroy
	if err := failing.mgr.Close(); !errors.Is(err, errEnterDestroy) {
		t.Fatalf("Close = %v, want the enter destroy error", err)
	}
	if got := failing.recordedError(t); got != errEnterDestroy.Error() {
		t.Fatalf("recorded error after Close = %q, want %q", got, errEnterDestroy)
	}

	clean := newHookedRead(t, true)
	if err := clean.mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := clean.recordedError(t); got != "" {
		t.Fatalf("recorded error after a clean Close = %q, want none", got)
	}
}

// TestAttachErrorWithAFailedCleanupIsOneLine: the error of an attach whose
// cleanup failed too is two errors. It is shown in the modal's probe row and
// error line and in the skip warning, so its text is one line; errors.Is
// still finds both (newReadAfterFailedCleanup checks that).
func TestAttachErrorWithAFailedCleanupIsOneLine(t *testing.T) {
	h := newReadAfterFailedCleanup(t)
	want := "attach sys_exit_read: " + errExitAttach.Error() +
		"; cleanup enter link after exit attach failure: " + errEnterDestroy.Error()
	if got := h.recordedError(t); got != want {
		t.Fatalf("recorded error = %q, want %q", got, want)
	}
}

// codedError is an error type of this test's own, for errors.As.
type codedError struct{ code int }

func (e *codedError) Error() string { return "coded error" }

// TestJoinOnOneLine pins the helper: nil for no error, the error itself for
// one, and for several a text without a line feed that errors.Is and
// errors.As look into as they do for errors.Join.
func TestJoinOnOneLine(t *testing.T) {
	if err := joinOnOneLine(nil, nil); err != nil {
		t.Fatalf("joinOnOneLine(nil, nil) = %v, want nil", err)
	}
	if err := joinOnOneLine(nil, errExitAttach, nil); err != errExitAttach {
		t.Fatalf("joinOnOneLine of one error = %v, want that very error", err)
	}
	err := joinOnOneLine(errExitAttach, nil, &codedError{code: 7}, errEnterDestroy)
	if want := "no such exit tracepoint; coded error; enter link busy"; err.Error() != want {
		t.Fatalf("joined text = %q, want %q", err, want)
	}
	if !errors.Is(err, errExitAttach) || !errors.Is(err, errEnterDestroy) || errors.Is(err, errExitDestroy) {
		t.Fatalf("errors.Is on %v does not find exactly its parts", err)
	}
	var coded *codedError
	if !errors.As(err, &coded) || coded.code != 7 {
		t.Fatalf("errors.As on %v found %+v, want the coded part", err, coded)
	}
}

// TestCommitAttachOnAClosedManagerDestroysOutsideTheManagerLock: an attach
// that finds the manager closed destroys the links it brought. Each destroy
// waits for a grace period, so they must not run under the manager lock,
// which every reader of the manager takes, and they run at once like the
// pair of a Detach. Here each destroy reads the manager, which under the
// lock never returns, and waits for the other to be in flight.
func TestCommitAttachOnAClosedManagerDestroysOutsideTheManagerLock(t *testing.T) {
	h := newHookedRead(t, false)
	if err := h.mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	gate := newDestroyGate(2)
	onDestroy := func() {
		_ = h.mgr.IsActive("read")
		gate.hook()
	}
	enter, exit := &fakeLink{onDestroy: onDestroy, err: errEnterDestroy}, &fakeLink{onDestroy: onDestroy}

	committed := goErr(func() error { return h.mgr.commitAttach("read", enter, exit, errExitAttach) })
	err := awaitWithin(t, committed, "commitAttach on a closed manager did not return: it destroys under the manager lock")

	want := "probe manager is closed; " + errExitAttach.Error() + "; cleanup enter read: " + errEnterDestroy.Error()
	if err == nil || err.Error() != want || strings.Contains(err.Error(), "\n") {
		t.Fatalf("commitAttach on a closed manager = %q, want %q", err, want)
	}
	if maxSeen, timedOut := gate.result(); timedOut || maxSeen != 2 {
		t.Fatalf("the two destroys were serial: max in flight = %d, timedOut = %v", maxSeen, timedOut)
	}
	if enter.destroyCalls() != 1 || exit.destroyCalls() != 1 {
		t.Fatalf("links destroyed %d (enter) and %d (exit) times, want once each",
			enter.destroyCalls(), exit.destroyCalls())
	}
}
