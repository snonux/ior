package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"

	"golang.org/x/sys/unix"
)

// move_mount (KindTwoFdNames) captures two paths, from_pathname and
// to_pathname, with the same nofault bpf_probe_read_user_str() as rename/link,
// so either can arrive empty when its string sits on a never-touched page. Its
// exit handler now re-reads both through the two fixup slots (task vs2):
// FIRST carries from_pathname, SECOND to_pathname. Userspace decodes the
// two_fd_names_event into a types.TwoFdEvent (decodeTwoFdNamesEvent), whose
// Oldname/Newname fields hold the two paths; these tests drive that decoder
// through the real raw-event path, enter -> fixup(s) -> exit.

// moveMountEnterWithStatus is the raw enter of a move_mount with both
// descriptors at AT_FDCWD, so absolute names are reported as they are.
func moveMountEnterWithStatus(t *testing.T, from string, fromStatus uint32, to string, toStatus uint32) []byte {
	t.Helper()
	ev := types.TwoFdNamesEvent{
		EventType:     types.ENTER_TWO_FD_NAMES_EVENT,
		TraceId:       types.SYS_ENTER_MOVE_MOUNT,
		Time:          defaulTime,
		Pid:           execCommPid,
		Tid:           execCommTid,
		FdA:           unix.AT_FDCWD,
		FdB:           unix.AT_FDCWD,
		OldnameStatus: fromStatus,
		NewnameStatus: toStatus,
		SchemaVersion: types.TWO_FD_EVENT_SCHEMA_VERSION,
	}
	copy(ev.Oldname[:], from)
	copy(ev.Newname[:], to)
	raw, err := ev.Bytes()
	if err != nil {
		t.Fatalf("TwoFdNamesEvent.Bytes() error = %v", err)
	}
	return raw
}

// runMoveMount feeds a move_mount enter, its fixups and a failing exit (a
// failed call is the realistic case for an unprivileged or bogus move, and it
// keeps resolveCapturedDirfdPath from consulting the empty-path flags).
func runMoveMount(t *testing.T, el *eventLoop, enter []byte, fixups ...[]byte) *event.Pair {
	t.Helper()
	return runPairWithFixups(t, el, enter, types.SYS_EXIT_MOVE_MOUNT, -int64(unix.EINVAL), fixups...)
}

const (
	mmFromCaptured = "/srv/vs2-from-captured"
	mmToCaptured   = "/srv/vs2-to-captured"
	mmFromRecover  = "/srv/vs2-from-recovered"
	mmToRecover    = "/srv/vs2-to-recovered"
)

// slotFixup describes one fixup record a case feeds between enter and exit as
// a (trace, slot, name) triple, so a case can also forge a record stamped for
// another syscall or an out-of-range slot.
type slotFixup struct {
	trace types.TraceId
	slot  uint32
	name  string
}

// buildSlotFixups encodes a case's fixups into raw ring-buffer records, in
// order; no fixups yields no records.
func buildSlotFixups(t *testing.T, fixups []slotFixup) [][]byte {
	t.Helper()
	raw := make([][]byte, 0, len(fixups))
	for _, f := range fixups {
		raw = append(raw, makeSlotFixup(t, f.trace, f.slot, f.name))
	}
	return raw
}

var (
	mmFirst  = slotFixup{types.SYS_ENTER_MOVE_MOUNT, types.OPEN_NAME_FIXUP_SLOT_FIRST, mmFromRecover}
	mmSecond = slotFixup{types.SYS_ENTER_MOVE_MOUNT, types.OPEN_NAME_FIXUP_SLOT_SECOND, mmToRecover}
	mmBoth   = []slotFixup{mmFirst, mmSecond}
)

// moveMountSlotCases is the table of TestMoveMountFixupRecoversEachPathThroughItsOwnSlot:
// the captured paths and statuses of the enter, the fixups that follow it and
// the from/to names the row must end up with.
var moveMountSlotCases = []struct {
	name             string
	from, to         string
	fromStat, toStat uint32
	fixups           []slotFixup
	wantFrom, wantTo string
}{
	{name: "both faulted, both recovered", fromStat: types.PATH_READ_FAILED, toStat: types.PATH_READ_FAILED,
		fixups: mmBoth, wantFrom: mmFromRecover, wantTo: mmToRecover},
	{name: "only from_pathname faulted", to: mmToCaptured, fromStat: types.PATH_READ_FAILED, toStat: types.PATH_READ_OK,
		fixups: []slotFixup{mmFirst}, wantFrom: mmFromRecover, wantTo: mmToCaptured},
	{
		// Without the slot a recovered to_pathname would land on the
		// still-empty from_pathname.
		name: "only to_pathname faulted", from: mmFromCaptured, fromStat: types.PATH_READ_OK, toStat: types.PATH_READ_FAILED,
		fixups: []slotFixup{mmSecond}, wantFrom: mmFromCaptured, wantTo: mmToRecover,
	},
	{name: "both faulted, only to_pathname recovered", fromStat: types.PATH_READ_FAILED, toStat: types.PATH_READ_FAILED,
		fixups: []slotFixup{mmSecond}, wantTo: mmToRecover},
	{name: "both faulted, nothing recovered", fromStat: types.PATH_READ_FAILED, toStat: types.PATH_READ_FAILED},
	{name: "captured paths are never overwritten", from: mmFromCaptured, to: mmToCaptured,
		fromStat: types.PATH_READ_OK, toStat: types.PATH_READ_OK, fixups: mmBoth, wantFrom: mmFromCaptured, wantTo: mmToCaptured},
	{name: "a NULL pointer is never promoted to a path", fromStat: types.PATH_READ_NULL, toStat: types.PATH_READ_NULL, fixups: mmBoth},
	{name: "a fixup recorded for another syscall is ignored", fromStat: types.PATH_READ_FAILED, toStat: types.PATH_READ_FAILED,
		fixups: []slotFixup{{types.SYS_ENTER_RENAME, types.OPEN_NAME_FIXUP_SLOT_FIRST, mmFromRecover},
			{types.SYS_ENTER_RENAME, types.OPEN_NAME_FIXUP_SLOT_SECOND, mmToRecover}}},
	{name: "an out-of-range slot is ignored", fromStat: types.PATH_READ_FAILED, toStat: types.PATH_READ_FAILED,
		fixups: []slotFixup{{types.SYS_ENTER_MOVE_MOUNT, 2, mmToRecover}}},
}

func TestMoveMountFixupRecoversEachPathThroughItsOwnSlot(t *testing.T) {
	for _, tc := range moveMountSlotCases {
		t.Run(tc.name, func(t *testing.T) {
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			enter := moveMountEnterWithStatus(t, tc.from, tc.fromStat, tc.to, tc.toStat)
			ep := runMoveMount(t, el, enter, buildSlotFixups(t, tc.fixups)...)
			if ep == nil {
				t.Fatal("the move_mount pair was dropped")
			}
			defer ep.Recycle()
			if ep.Oldname != tc.wantFrom || ep.File.Name() != tc.wantTo {
				t.Fatalf("move_mount row from=%q to=%q, want from=%q to=%q", ep.Oldname, ep.File.Name(), tc.wantFrom, tc.wantTo)
			}
		})
	}
}

// move_mount has no enter gate (its raw handler's filter is nil), so a -path
// filter is judged only at the exit checkpoint, after the fixups landed: a
// recovered to_pathname must match it, and an unrecovered one must not.
func TestMoveMountPathFilterSeesTheRecoveredName(t *testing.T) {
	const target = "/srv/vs2-filter-target"
	filter := globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: "vs2-filter-target"}}
	failed := uint32(types.PATH_READ_FAILED)

	t.Run("recovered", func(t *testing.T) {
		el := newFilteredEventLoop(t, filter)
		ep := runMoveMount(t, el, moveMountEnterWithStatus(t, "", failed, "", failed),
			makeSlotFixup(t, types.SYS_ENTER_MOVE_MOUNT, types.OPEN_NAME_FIXUP_SLOT_SECOND, target))
		if ep == nil {
			t.Fatal("-path dropped the move_mount whose to_pathname was recovered")
		}
		defer ep.Recycle()
		if got := ep.File.Name(); got != target {
			t.Fatalf("move_mount row file = %q, want %q", got, target)
		}
	})

	t.Run("unrecovered", func(t *testing.T) {
		el := newFilteredEventLoop(t, filter)
		if ep := runMoveMount(t, el, moveMountEnterWithStatus(t, "", failed, "", failed)); ep != nil {
			defer ep.Recycle()
			t.Fatalf("-path kept a move_mount with no recovered name: file=%q", ep.File.Name())
		}
	})
}

// applyRecoveredFilename is the per-kind dispatch; these cases pin its
// move_mount branch directly, including the lean two_fd_event of close_range
// and kcmp, which NewTwoFdEventFast decodes into the same Go type with zeroed
// names and both statuses set to PATH_READ_NULL, and which must never be named
// by a stray record.
func TestApplyRecoveredFilenameTwoFdEvent(t *testing.T) {
	const recovered = "/srv/vs2-direct"
	fixup := func(traceID types.TraceId, slot uint32) *types.OpenNameFixupEvent {
		ev := &types.OpenNameFixupEvent{EventType: types.OPEN_NAME_FIXUP_EVENT, TraceId: traceID, Tid: execCommTid, Slot: slot}
		copy(ev.Filename[:], recovered)
		return ev
	}

	t.Run("each slot fills only its own path", func(t *testing.T) {
		ev := &types.TwoFdEvent{TraceId: types.SYS_ENTER_MOVE_MOUNT,
			OldnameStatus: types.PATH_READ_FAILED, NewnameStatus: types.PATH_READ_FAILED}
		applyRecoveredFilename(ev, fixup(types.SYS_ENTER_MOVE_MOUNT, types.OPEN_NAME_FIXUP_SLOT_SECOND))
		if got := types.StringValue(ev.Oldname[:]); got != "" || ev.OldnameStatus != types.PATH_READ_FAILED {
			t.Fatalf("a SECOND-slot record touched from_pathname: %q status %d", got, ev.OldnameStatus)
		}
		if got := types.StringValue(ev.Newname[:]); got != recovered || ev.NewnameStatus != types.PATH_READ_OK {
			t.Fatalf("to_pathname = %q status %d, want %q PATH_READ_OK", got, ev.NewnameStatus, recovered)
		}
		applyRecoveredFilename(ev, fixup(types.SYS_ENTER_MOVE_MOUNT, types.OPEN_NAME_FIXUP_SLOT_FIRST))
		if got := types.StringValue(ev.Oldname[:]); got != recovered || ev.OldnameStatus != types.PATH_READ_OK {
			t.Fatalf("from_pathname = %q status %d, want %q PATH_READ_OK", got, ev.OldnameStatus, recovered)
		}
	})

	t.Run("the lean close_range/kcmp payload is never named", func(t *testing.T) {
		for _, traceID := range []types.TraceId{types.SYS_ENTER_CLOSE_RANGE, types.SYS_ENTER_KCMP} {
			for _, size := range []int{leanTwoFdKernelSize, leanTwoFdCompactSize} {
				ev := decodeLeanTwoFdEnter(t, traceID, size)
				for _, slot := range []uint32{types.OPEN_NAME_FIXUP_SLOT_FIRST, types.OPEN_NAME_FIXUP_SLOT_SECOND} {
					applyRecoveredFilename(ev, fixup(traceID, slot))
				}
				if types.StringValue(ev.Oldname[:]) != "" || types.StringValue(ev.Newname[:]) != "" {
					t.Fatalf("trace %d, %d-byte payload: lean two-fd payload got names %q/%q", traceID, size,
						types.StringValue(ev.Oldname[:]), types.StringValue(ev.Newname[:]))
				}
				ev.Recycle()
			}
		}
	})
}

// The lean two_fd_event reaches userspace as sizeof(struct two_fd_event), 48
// bytes with tail padding, or as its 44-byte compact form; NewTwoFdEventFast
// accepts both.
const (
	leanTwoFdKernelSize  = 48
	leanTwoFdCompactSize = 44
)

// decodeLeanTwoFdEnter runs a lean close_range/kcmp enter payload of the given
// size through the real decoder, NewTwoFdEventFast, and pins the shape it
// yields: no names and both statuses PATH_READ_NULL. A stray fixup for such an
// event must then be refused by spliceRecoveredPath's PATH_READ_FAILED guard,
// since its trace ID matches.
func decodeLeanTwoFdEnter(t *testing.T, traceID types.TraceId, size int) *types.TwoFdEvent {
	t.Helper()
	_, raw := makeEnterTwoFdEvent(t, defaulTime, execCommPid, execCommTid, 3, 9, 0, traceID)
	if len(raw) != leanTwoFdKernelSize {
		t.Fatalf("lean two_fd_event encoded to %d bytes, want %d", len(raw), leanTwoFdKernelSize)
	}
	ev := types.NewTwoFdEventFast(raw[:size])
	if ev == nil {
		t.Fatalf("NewTwoFdEventFast rejected a %d-byte lean payload", size)
	}
	if ev.OldnameStatus != types.PATH_READ_NULL || ev.NewnameStatus != types.PATH_READ_NULL ||
		types.StringValue(ev.Oldname[:]) != "" || types.StringValue(ev.Newname[:]) != "" {
		t.Fatalf("lean two-fd decode: names %q/%q statuses %d/%d, want empty and PATH_READ_NULL",
			types.StringValue(ev.Oldname[:]), types.StringValue(ev.Newname[:]), ev.OldnameStatus, ev.NewnameStatus)
	}
	return ev
}

// A move_mount fixup whose tid has no pending enter (filtered, never seen, or
// already paired) must be dropped without a row and without naming the
// pending move_mount of a different tid.
func TestMoveMountFixupWithoutAPendingEnterIsDropped(t *testing.T) {
	const otherTid = execCommTid + 1000
	failed := uint32(types.PATH_READ_FAILED)

	el := newFilteredEventLoop(t, globalfilter.Filter{})
	out := make(chan *event.Pair, 1)
	for _, slot := range []uint32{types.OPEN_NAME_FIXUP_SLOT_FIRST, types.OPEN_NAME_FIXUP_SLOT_SECOND} {
		el.processRawEvent(makeSlotFixupForTid(t, otherTid, types.SYS_ENTER_MOVE_MOUNT, slot, "/srv/vs2-orphan"), out)
	}
	select {
	case ep := <-out:
		ep.Recycle()
		t.Fatal("a fixup with no pending enter produced a row")
	default:
	}

	ep := runMoveMount(t, el, moveMountEnterWithStatus(t, "", failed, "", failed),
		makeSlotFixupForTid(t, otherTid, types.SYS_ENTER_MOVE_MOUNT, types.OPEN_NAME_FIXUP_SLOT_FIRST, "/srv/vs2-orphan"),
		makeSlotFixupForTid(t, otherTid, types.SYS_ENTER_MOVE_MOUNT, types.OPEN_NAME_FIXUP_SLOT_SECOND, "/srv/vs2-orphan"))
	if ep == nil {
		t.Fatal("the move_mount pair was dropped")
	}
	defer ep.Recycle()
	if ep.Oldname != "" || ep.File.Name() != "" {
		t.Fatalf("a fixup for tid %d named the move_mount of tid %d: from=%q to=%q", otherTid, execCommTid, ep.Oldname, ep.File.Name())
	}
}
