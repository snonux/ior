package probemanager

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"ior/internal/parkwait"
	"ior/internal/types"
)

// Tests for the change hook (SetChangeHook, tasks o03 and x13). The event loop
// hangs the restart fold's guard on it, and the guard is sound only if the
// hook runs at the right moments and with the right phase: ChangeBegins before
// an attach touches a tracepoint and ChangeEnds when the attach is over, in
// pairs, Changed after a detach destroyed its links, and each time before the
// opposite change of the same syscall can begin. The tests below observe the
// fake programs and links from inside the hook, which is the only place that
// order can be seen.

// changeWait bounds every wait of these tests for something that must happen.
// The manager's locks decide whether it does: with a wrong order a call never
// returns, and the test then says which one instead of running into the test
// binary's timeout ten minutes later. It is not a synchronisation guess - a
// passing run takes what it waits for as soon as it is there.
const changeWait = 10 * time.Second

// awaitWithin receives from ch (a closed channel counts) and fails the test,
// naming what did not happen, when nothing arrives within changeWait. Call it
// on the test goroutine.
func awaitWithin[T any](t *testing.T, ch <-chan T, notDone string) T {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(changeWait):
		t.Fatalf("%s within %v", notDone, changeWait)
		panic("unreachable")
	}
}

// removeHookDuringAChange removes the manager's hook while a change of read
// is under way and holds the probe's attach mutex. Removing a hook waits for
// no change (SetChangeHook). One that waited as setting a hook does would
// wait for that change, which in these tests waits for the caller: so the
// removal runs on a goroutine of its own and must return while the change is
// held.
func (h *hookedRead) removeHookDuringAChange(t *testing.T) {
	t.Helper()
	removed := make(chan struct{})
	go func() {
		defer close(removed)
		h.mgr.SetChangeHook(nil)
	}()
	awaitWithin(t, removed, "removing the hook did not return while a change was under way")
}

// hookedRead is a manager with one registered syscall, read, whose two
// programs hand out one link each, and a hook that counts its calls and
// records the phase of each and what the fakes had seen at it.
type hookedRead struct {
	mgr          *Manager
	enter, exit  *fakeProgram
	calls        int
	phases       []ChangePhase
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

func (h *hookedRead) observe(phase ChangePhase) {
	h.calls++
	h.phases = append(h.phases, phase)
	h.attachesSeen = append(h.attachesSeen, [2]int{h.enter.attachCalls(), h.exit.attachCalls()})
	h.destroysSeen = append(h.destroysSeen, [2]int{h.enter.link.destroyCalls(), h.exit.link.destroyCalls()})
}

// TestChangeHookRunsBeforeAndAfterAnAttach: a runtime attach is reported
// twice, as its begin and its end. At the first report neither tracepoint of
// the syscall has been attached yet: reported only afterwards, the enter probe
// would already have seen a syscall that the listener's note claims to be
// older than. At the second both are attached: the two are attached one after
// the other, and a syscall that ran in between - seen at its enter and not at
// its exit, or not at all - is younger than the first note. Without the second
// report the event loop folded a later call into a row interrupted during the
// attach; without the phases it could not know that an attach is in flight
// between the two, and folded on the records the fresh pair produced meanwhile.
func TestChangeHookRunsBeforeAndAfterAnAttach(t *testing.T) {
	h := newHookedRead(t, false)
	if err := h.mgr.Attach("read"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if !slices.Equal(h.phases, []ChangePhase{ChangeBegins, ChangeEnds}) {
		t.Fatalf("one attach was reported as %v, want its begin and then its end", h.phases)
	}
	if h.attachesSeen[0] != [2]int{0, 0} {
		t.Fatalf("first report saw %v tracepoint attaches (enter, exit), want none yet", h.attachesSeen[0])
	}
	if h.attachesSeen[1] != [2]int{1, 1} {
		t.Fatalf("second report saw %v tracepoint attaches (enter, exit), want both done", h.attachesSeen[1])
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
	if !slices.Equal(h.phases, []ChangePhase{Changed}) {
		t.Fatalf("one detach was reported as %v, want once, as a change that is over", h.phases)
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
	if !slices.Equal(h.phases, []ChangePhase{Changed, ChangeBegins, ChangeEnds}) {
		t.Fatalf("a detach and an attach were reported as %v, want the detach once, then the attach's begin and end",
			h.phases)
	}
	if h.destroysSeen[0] != [2]int{1, 1} {
		t.Fatalf("the detach was reported with %v link destroys, want both done", h.destroysSeen[0])
	}
	// One attach each from AttachAll; the re-attach has not begun.
	if h.attachesSeen[1] != [2]int{1, 1} {
		t.Fatalf("the re-attach was first reported with %v attaches, want only the startup ones", h.attachesSeen[1])
	}
	if h.attachesSeen[2] != [2]int{2, 2} {
		t.Fatalf("the re-attach was last reported with %v attaches, want both tracepoints attached again", h.attachesSeen[2])
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
// tracepoint attached for a moment, and a detach whose destroy reports an
// error has destroyed both links all the same (Link). Both moved what the
// kernel sees, so both are reported - the failed attach twice like any attach,
// the second time when the enter link it had attached is destroyed again:
// that is a detach, and a detach is reported when it is over.
func TestChangeHookReportsFailedChanges(t *testing.T) {
	h := newHookedRead(t, false)
	h.exit.err = errors.New("no such tracepoint")
	if err := h.mgr.Attach("read"); err == nil {
		t.Fatal("Attach with a failing exit tracepoint returned nil")
	}
	if !slices.Equal(h.phases, []ChangePhase{ChangeBegins, ChangeEnds}) ||
		h.attachesSeen[0] != [2]int{0, 0} || h.attachesSeen[1] != [2]int{1, 1} {
		t.Fatalf("failed attach: reported as %v, saw %v; want its begin before any attach and its end after both attempts",
			h.phases, h.attachesSeen)
	}
	if h.destroysSeen[1] != [2]int{1, 0} {
		t.Fatalf("failed attach: second report saw %v link destroys (enter, exit), want the enter link already destroyed",
			h.destroysSeen[1])
	}

	h = newHookedRead(t, true)
	h.exit.link.err = errors.New("busy")
	if err := h.mgr.Detach("read"); err == nil {
		t.Fatal("Detach with a failing exit link returned nil")
	}
	if !slices.Equal(h.phases, []ChangePhase{Changed}) || h.destroysSeen[0] != [2]int{1, 1} {
		t.Fatalf("failed detach: reported as %v, saw %v; want once, after both destroys", h.phases, h.destroysSeen)
	}
	if h.mgr.IsActive("read") {
		t.Fatal("read is still active after a detach that destroyed both links")
	}
}

// TestChangeHookCanBeRemovedAndMayReadTheManager: a nil hook stops the
// reports, and a hook runs without the manager lock, so it can ask the manager
// what is attached (the detach's own state is committed only afterwards).
func TestChangeHookCanBeRemovedAndMayReadTheManager(t *testing.T) {
	h := newHookedRead(t, true)
	var activeInHook bool
	h.mgr.SetChangeHook(func(ChangePhase) { activeInHook = h.mgr.IsActive("read") })
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
	none.SetChangeHook(func(ChangePhase) {}) // a nil manager has nothing to report
}

// TestChangeHookHoldsBackTheOppositeChange: the detach's report must be over
// before the same syscall can be attached again. The listener notes the time
// of the change in the hook; an attach that slipped in before that note would
// let the kernel announce a stale restart the note does not cover.
func TestChangeHookHoldsBackTheOppositeChange(t *testing.T) {
	h := newHookedRead(t, true)
	inHook, leaveHook := make(chan struct{}), make(chan struct{})
	h.mgr.SetChangeHook(func(ChangePhase) {
		close(inHook)
		<-leaveHook
	})
	detached := make(chan error, 1)
	go func() { detached <- h.mgr.Detach("read") }()
	awaitWithin(t, inHook, "Detach did not report to the hook")

	const frame = "(*Manager).Attach"
	baseline := parkwait.Count(frame, parkwait.MutexLock, parkwait.Semacquire)
	h.removeHookDuringAChange(t) // the attach below reports nothing; it must still wait
	attached := make(chan error, 1)
	go func() { attached <- h.mgr.Attach("read") }()
	parkwait.Await{Frame: frame, Reasons: []string{parkwait.MutexLock, parkwait.Semacquire}, Baseline: baseline,
		TimeoutMsg: "Attach did not wait for the detach's change hook"}.Run(t)
	if got := h.enter.attachCalls(); got != 1 {
		t.Fatalf("enter tracepoint attached %d times while the detach's hook ran, want only the startup attach", got)
	}

	close(leaveHook)
	if err := awaitWithin(t, detached, "Detach did not return after its hook did"); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if err := awaitWithin(t, attached, "Attach did not return after the detach"); err != nil {
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
	var phases []ChangePhase
	mgr.SetChangeHook(func(phase ChangePhase) { phases = append(phases, phase) })

	result, err := mgr.AttachFamily(context.Background(), types.FamilyFS, nil)
	if err != nil || result.Changed != 1 {
		t.Fatalf("AttachFamily(FS) = %+v, %v; want write attached", result, err)
	}
	if !slices.Equal(phases, []ChangePhase{ChangeBegins, ChangeEnds}) {
		t.Fatalf("attaching one probe (read was attached) was reported as %v, want its begin and its end", phases)
	}

	result, err = mgr.DetachFamily(context.Background(), types.FamilyFS, nil)
	if err != nil || result.Changed != 2 {
		t.Fatalf("DetachFamily(FS) = %+v, %v; want read and write detached", result, err)
	}
	if !slices.Equal(phases[2:], []ChangePhase{Changed, Changed}) {
		t.Fatalf("detaching two probes was reported as %v, want each once, as a change that is over", phases[2:])
	}
}

// TestChangeEndsFollowsAnAttachThatPanics: a listener counts the attaches
// under way from the begins and the ends. An attacher that panics must not
// leave it counting: the end is reported on the way out, and the panic goes on
// to the caller.
func TestChangeEndsFollowsAnAttachThatPanics(t *testing.T) {
	h := newHookedRead(t, false)
	h.enter.onAttach = func() { panic("attach failed hard") }
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("Attach did not pass the attacher's panic on")
			}
		}()
		_ = h.mgr.Attach("read")
	}()
	if !slices.Equal(h.phases, []ChangePhase{ChangeBegins, ChangeEnds}) {
		t.Fatalf("an attach that panicked was reported as %v, want its begin and its end", h.phases)
	}
	if h.attachesSeen[1] != [2]int{1, 0} {
		t.Fatalf("the end saw %v tracepoint attaches (enter, exit), want it reported after the attempt", h.attachesSeen[1])
	}
}

// TestChangeEndsReachesTheHookThatWasToldOfTheBegin: the two reports of an
// attach go to one listener. A hook removed while the attach runs still gets
// the end - it counted the begin - and nobody else does.
// The hook is removed from inside the attach (removeHookDuringAChange).
func TestChangeEndsReachesTheHookThatWasToldOfTheBegin(t *testing.T) {
	h := newHookedRead(t, false)
	h.enter.onAttach = func() { h.removeHookDuringAChange(t) }
	if err := h.mgr.Attach("read"); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if !slices.Equal(h.phases, []ChangePhase{ChangeBegins, ChangeEnds}) {
		t.Fatalf("the hook removed during the attach was told %v, want the begin and the end of that attach", h.phases)
	}
	if err := h.mgr.Detach("read"); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if h.calls != 2 {
		t.Fatalf("the removed hook ran %d times, want no report of a change that began after it was removed", h.calls)
	}
}

// underWay starts change, an Attach or a Detach of read, on a goroutine of
// the caller's and returns once the change is held inside the fake whose hook
// gate points to (a program's onAttach, a link's onDestroy), which the change
// must call once. finish lets it go on and returns what it returned.
func underWay(t *testing.T, gate *func(), change func() error) (finish func() error) {
	t.Helper()
	inside, leave := make(chan struct{}), make(chan struct{})
	*gate = func() {
		close(inside)
		<-leave
	}
	result := make(chan error, 1)
	go func() { result <- change() }()
	awaitWithin(t, inside, "the change did not reach the fake it was to be held in")
	return func() error {
		t.Helper()
		close(leave)
		return awaitWithin(t, result, "the change did not return after its fake let it go")
	}
}

// setHookDuring sets a hook while a change of read is under way and requires
// SetChangeHook to wait for it: parked on the probe's attach mutex until
// finish has let the change end, and returned after that. It returns what the
// new hook is told, then and later.
func (h *hookedRead) setHookDuring(t *testing.T, finish func() error) *[]ChangePhase {
	t.Helper()
	const frame = "(*probeEntry).awaitChange"
	baseline := parkwait.Count(frame, parkwait.MutexLock, parkwait.Semacquire)
	told := new([]ChangePhase)
	installed := make(chan struct{})
	go func() {
		defer close(installed)
		h.mgr.SetChangeHook(func(phase ChangePhase) { *told = append(*told, phase) })
	}()
	parkwait.Await{Frame: frame, Reasons: []string{parkwait.MutexLock, parkwait.Semacquire}, Baseline: baseline,
		Done: installed, DoneMsg: "SetChangeHook returned while a change was under way",
		TimeoutMsg: "SetChangeHook did not wait for the change under way"}.Run(t)

	if err := finish(); err != nil {
		t.Fatalf("the change under way: %v", err)
	}
	awaitWithin(t, installed, "SetChangeHook did not return after the change under way was over")
	return told
}

// TestSetChangeHookWaitsForAnAttachUnderWay: an attach that began before a
// hook was set reports to the earlier hook, and the new one would learn
// neither that it is in flight nor when it ends. So setting a hook returns
// only once that attach is over: whoever installed it then takes note of
// everything before, and every later change reports to it from its begin.
func TestSetChangeHookWaitsForAnAttachUnderWay(t *testing.T) {
	h := newHookedRead(t, false)
	finish := underWay(t, &h.enter.onAttach, func() error { return h.mgr.Attach("read") })
	later := h.setHookDuring(t, finish)

	if !slices.Equal(h.phases, []ChangePhase{ChangeBegins, ChangeEnds}) {
		t.Fatalf("the earlier hook was told %v of the attach it saw begin, want its begin and its end", h.phases)
	}
	if len(*later) != 0 {
		t.Fatalf("the hook set during the attach was told %v, want nothing of an attach whose begin it missed", *later)
	}
	if err := h.mgr.Detach("read"); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if !slices.Equal(*later, []ChangePhase{Changed}) || h.calls != 2 {
		t.Fatalf("the detach was reported as %v to the new hook and the earlier one ran %d times, want Changed and 2",
			*later, h.calls)
	}
}

// TestSetChangeHookWaitsForADetachUnderWay: a detach reports once, when its
// links are gone, to the hook that is set at that moment. One that is still
// destroying its links when a hook is set therefore reports to the new hook -
// but a detach that had just made its report to the earlier hook, or to
// nobody, looks the same to the caller, who is about to take note of
// everything before the install. So setting a hook waits for a detach under
// way as it does for an attach, and returns when the detach is over.
func TestSetChangeHookWaitsForADetachUnderWay(t *testing.T) {
	h := newHookedRead(t, true)
	finish := underWay(t, &h.enter.link.onDestroy, func() error { return h.mgr.Detach("read") })
	later := h.setHookDuring(t, finish)

	if !slices.Equal(*later, []ChangePhase{Changed}) {
		t.Fatalf("the hook set during the detach was told %v, want the one report the detach made after that", *later)
	}
	if h.calls != 0 {
		t.Fatalf("the earlier hook ran %d times, want 0: it was replaced before the detach reported", h.calls)
	}
	if h.mgr.IsActive("read") {
		t.Fatal("read is still active after the detach SetChangeHook waited for")
	}
}
