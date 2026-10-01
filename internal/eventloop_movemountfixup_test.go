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

func TestMoveMountFixupRecoversEachPathThroughItsOwnSlot(t *testing.T) {
	const (
		fromCaptured = "/srv/vs2-from-captured"
		toCaptured   = "/srv/vs2-to-captured"
		fromRecover  = "/srv/vs2-from-recovered"
		toRecover    = "/srv/vs2-to-recovered"
	)
	ok, failed, null := uint32(types.PATH_READ_OK), uint32(types.PATH_READ_FAILED), uint32(types.PATH_READ_NULL)
	first, second := uint32(types.OPEN_NAME_FIXUP_SLOT_FIRST), uint32(types.OPEN_NAME_FIXUP_SLOT_SECOND)
	mm := types.SYS_ENTER_MOVE_MOUNT
	both := func(t *testing.T) [][]byte {
		return [][]byte{makeSlotFixup(t, mm, first, fromRecover), makeSlotFixup(t, mm, second, toRecover)}
	}

	for _, tc := range []struct {
		name             string
		from, to         string
		fromStat, toStat uint32
		fixups           func(t *testing.T) [][]byte
		wantFrom, wantTo string
	}{
		{name: "both faulted, both recovered", fromStat: failed, toStat: failed, fixups: both,
			wantFrom: fromRecover, wantTo: toRecover},
		{name: "only from_pathname faulted", to: toCaptured, fromStat: failed, toStat: ok,
			fixups:   func(t *testing.T) [][]byte { return [][]byte{makeSlotFixup(t, mm, first, fromRecover)} },
			wantFrom: fromRecover, wantTo: toCaptured},
		{
			// Without the slot a recovered to_pathname would land on the
			// still-empty from_pathname.
			name: "only to_pathname faulted", from: fromCaptured, fromStat: ok, toStat: failed,
			fixups:   func(t *testing.T) [][]byte { return [][]byte{makeSlotFixup(t, mm, second, toRecover)} },
			wantFrom: fromCaptured, wantTo: toRecover,
		},
		{name: "both faulted, only to_pathname recovered", fromStat: failed, toStat: failed,
			fixups: func(t *testing.T) [][]byte { return [][]byte{makeSlotFixup(t, mm, second, toRecover)} },
			wantTo: toRecover},
		{name: "both faulted, nothing recovered", fromStat: failed, toStat: failed,
			fixups: func(t *testing.T) [][]byte { return nil }},
		{name: "captured paths are never overwritten", from: fromCaptured, to: toCaptured, fromStat: ok, toStat: ok,
			fixups: both, wantFrom: fromCaptured, wantTo: toCaptured},
		{name: "a NULL pointer is never promoted to a path", fromStat: null, toStat: null, fixups: both},
		{name: "a fixup recorded for another syscall is ignored", fromStat: failed, toStat: failed,
			fixups: func(t *testing.T) [][]byte {
				return [][]byte{makeSlotFixup(t, types.SYS_ENTER_RENAME, first, fromRecover),
					makeSlotFixup(t, types.SYS_ENTER_RENAME, second, toRecover)}
			}},
		{name: "an out-of-range slot is ignored", fromStat: failed, toStat: failed,
			fixups: func(t *testing.T) [][]byte { return [][]byte{makeSlotFixup(t, mm, 2, toRecover)} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			ep := runMoveMount(t, el, moveMountEnterWithStatus(t, tc.from, tc.fromStat, tc.to, tc.toStat), tc.fixups(t)...)
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
// and kcmp, which decodes into the same Go type with zeroed names and
// PATH_READ_OK statuses and must never be named by a stray record.
func TestApplyRecoveredFilenameTwoFdEvent(t *testing.T) {
	const recovered = "/srv/vs2-direct"
	fixup := func(traceID types.TraceId, slot uint32) *types.OpenNameFixupEvent {
		ev := &types.OpenNameFixupEvent{EventType: types.OPEN_NAME_FIXUP_EVENT, TraceId: traceID, Tid: execCommTid, Slot: slot}
		copy(ev.Filename[:], recovered)
		return ev
	}
	enter := func(traceID types.TraceId, fromStatus, toStatus uint32) *types.TwoFdEvent {
		return &types.TwoFdEvent{TraceId: traceID, OldnameStatus: fromStatus, NewnameStatus: toStatus}
	}

	t.Run("each slot fills only its own path", func(t *testing.T) {
		ev := enter(types.SYS_ENTER_MOVE_MOUNT, types.PATH_READ_FAILED, types.PATH_READ_FAILED)
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
			ev := enter(traceID, types.PATH_READ_OK, types.PATH_READ_OK)
			for _, slot := range []uint32{types.OPEN_NAME_FIXUP_SLOT_FIRST, types.OPEN_NAME_FIXUP_SLOT_SECOND} {
				applyRecoveredFilename(ev, fixup(traceID, slot))
			}
			if types.StringValue(ev.Oldname[:]) != "" || types.StringValue(ev.Newname[:]) != "" {
				t.Fatalf("trace %d: lean two-fd payload got names %q/%q", traceID,
					types.StringValue(ev.Oldname[:]), types.StringValue(ev.Newname[:]))
			}
		}
	})
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
