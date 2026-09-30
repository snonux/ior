package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"

	"golang.org/x/sys/unix"
)

// The faulted-path recovery first covered only the open kinds. A stat, access,
// unlink, inotify_add_watch or rename whose path string sat in a never-touched
// page lost its name the same way - bpf_probe_read_user_str() is a nofault
// read - and stayed empty: -path could not match the row and the Files tab
// attributed it to ''. The same OPEN_NAME_FIXUP_EVENT control record now
// repairs those enter events, and because rename/link carry two names the
// record says which one it is for (OpenNameFixupEvent.Slot). The tests below
// drive the record through the real raw-event path, in the order the ring
// buffer delivers enter -> fixup(s) -> exit.

// makeSlotFixup builds the control record the generated exit handler emits
// (ior_emit_name_fixup, internal/c/filter.c) for one path slot.
func makeSlotFixup(t *testing.T, traceID types.TraceId, slot uint32, filename string) []byte {
	t.Helper()
	ev := types.OpenNameFixupEvent{
		EventType: types.OPEN_NAME_FIXUP_EVENT,
		TraceId:   traceID,
		Tid:       execCommTid,
		Slot:      slot,
	}
	copy(ev.Filename[:], filename)
	raw, err := ev.Bytes()
	if err != nil {
		t.Fatalf("OpenNameFixupEvent.Bytes() error = %v", err)
	}
	return raw
}

// pathEnterWithStatus is an enter of a pathname-kind syscall whose name read
// ended in status; a non-empty name is only meaningful with PATH_READ_OK.
func pathEnterWithStatus(t *testing.T, traceID types.TraceId, dirfd int32, name string, status uint32) []byte {
	t.Helper()
	ev := types.PathEvent{
		EventType:      types.ENTER_PATH_EVENT,
		TraceId:        traceID,
		Time:           defaulTime,
		Pid:            execCommPid,
		Tid:            execCommTid,
		Dirfd:          dirfd,
		PathnameStatus: status,
		TargetStatus:   types.PATH_TARGET_REQUIRED,
		SchemaVersion:  types.PATH_EVENT_SCHEMA_VERSION,
	}
	copy(ev.Pathname[:], name)
	raw, err := ev.Bytes()
	if err != nil {
		t.Fatalf("PathEvent.Bytes() error = %v", err)
	}
	return raw
}

// nameEnterWithStatus is the rename/link counterpart with one status per name.
func nameEnterWithStatus(t *testing.T, traceID types.TraceId, oldname string, oldStatus uint32, newname string, newStatus uint32) []byte {
	t.Helper()
	ev := types.NameEvent{
		EventType:     types.ENTER_NAME_EVENT,
		TraceId:       traceID,
		Time:          defaulTime,
		Pid:           execCommPid,
		Tid:           execCommTid,
		Olddirfd:      unix.AT_FDCWD,
		Newdirfd:      unix.AT_FDCWD,
		OldnameStatus: oldStatus,
		NewnameStatus: newStatus,
		SchemaVersion: types.NAME_EVENT_SCHEMA_VERSION,
	}
	copy(ev.Oldname[:], oldname)
	copy(ev.Newname[:], newname)
	raw, err := ev.Bytes()
	if err != nil {
		t.Fatalf("NameEvent.Bytes() error = %v", err)
	}
	return raw
}

// runPairWithFixups feeds enter, then the fixup records, then the exit, and
// returns the emitted pair (nil when the filter dropped it).
func runPairWithFixups(t *testing.T, el *eventLoop, enter []byte, exitID types.TraceId, ret int64, fixups ...[]byte) *event.Pair {
	t.Helper()
	out := make(chan *event.Pair, 1)
	el.processRawEvent(enter, out)
	for _, fixup := range fixups {
		el.processRawEvent(fixup, out)
	}
	_, exitRaw := makeExitRetEvent(t, defaulTime+openPairLatency, execCommPid, execCommTid, exitID, ret)
	el.processRawEvent(exitRaw, out)
	select {
	case ep := <-out:
		return ep
	default:
		return nil
	}
}

func TestPathFixupRecoversAFaultedPathname(t *testing.T) {
	const target = "/tmp/fq2-no-such-target"

	t.Run("the recovered name reaches the row", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{})
		ep := runPairWithFixups(t, el,
			pathEnterWithStatus(t, types.SYS_ENTER_ACCESS, unix.AT_FDCWD, "", types.PATH_READ_FAILED),
			types.SYS_EXIT_ACCESS, -int64(unix.ENOENT),
			makeSlotFixup(t, types.SYS_ENTER_ACCESS, types.OPEN_NAME_FIXUP_SLOT_FIRST, target))
		if ep == nil {
			t.Fatal("the access pair was dropped")
		}
		defer ep.Recycle()
		if got := ep.File.Name(); got != target {
			t.Fatalf("access row file = %q, want %q", got, target)
		}
	})

	t.Run("without the fixup the row keeps the empty name", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{})
		ep := runPairWithFixups(t, el,
			pathEnterWithStatus(t, types.SYS_ENTER_ACCESS, unix.AT_FDCWD, "", types.PATH_READ_FAILED),
			types.SYS_EXIT_ACCESS, -int64(unix.ENOENT))
		if ep == nil {
			t.Fatal("the access pair was dropped")
		}
		defer ep.Recycle()
		if got := ep.File.Name(); got != "" {
			t.Fatalf("access row file = %q, want the empty name of an unrecovered read", got)
		}
	})

	t.Run("a relative name is resolved against its dirfd once recovered", func(t *testing.T) {
		const dirfd = int32(31)
		dir := t.TempDir()
		el := newFilteredEventLoop(t, globalfilter.Filter{})
		el.fdState().set(dirfd, execCommPid, file.NewFd(dirfd, dir, unix.O_RDONLY|unix.O_DIRECTORY))
		ep := runPairWithFixups(t, el,
			pathEnterWithStatus(t, types.SYS_ENTER_UNLINKAT, dirfd, "", types.PATH_READ_FAILED),
			types.SYS_EXIT_UNLINKAT, -int64(unix.ENOENT),
			makeSlotFixup(t, types.SYS_ENTER_UNLINKAT, types.OPEN_NAME_FIXUP_SLOT_FIRST, "victim"))
		if ep == nil {
			t.Fatal("the unlinkat pair was dropped")
		}
		defer ep.Recycle()
		if got, want := ep.File.Name(), dir+"/victim"; got != want {
			t.Fatalf("unlinkat row file = %q, want %q", got, want)
		}
	})
}

// A fixup may only ever repair what it was recorded for. Each negative case
// below would graft a wrong or unproven path onto a row if a guard regressed.
func TestPathFixupNeverGraftsTheWrongName(t *testing.T) {
	const captured = "/etc/hostname"
	const recovered = "/tmp/fq2-recovered"
	first, second := uint32(types.OPEN_NAME_FIXUP_SLOT_FIRST), uint32(types.OPEN_NAME_FIXUP_SLOT_SECOND)

	for _, tc := range []struct {
		name     string
		enter    func(t *testing.T) []byte
		fixup    func(t *testing.T) []byte
		exit     types.TraceId
		wantName string
	}{
		{
			name: "a name the enter side captured is authoritative",
			enter: func(t *testing.T) []byte {
				return pathEnterWithStatus(t, types.SYS_ENTER_ACCESS, unix.AT_FDCWD, captured, types.PATH_READ_OK)
			},
			fixup:    func(t *testing.T) []byte { return makeSlotFixup(t, types.SYS_ENTER_ACCESS, first, recovered) },
			exit:     types.SYS_EXIT_ACCESS,
			wantName: captured,
		},
		{
			name: "a NULL pointer is never promoted to a path",
			enter: func(t *testing.T) []byte {
				return pathEnterWithStatus(t, types.SYS_ENTER_ACCESS, unix.AT_FDCWD, "", types.PATH_READ_NULL)
			},
			fixup:    func(t *testing.T) []byte { return makeSlotFixup(t, types.SYS_ENTER_ACCESS, first, recovered) },
			exit:     types.SYS_EXIT_ACCESS,
			wantName: "",
		},
		{
			name: "a fixup recorded for another syscall is ignored",
			enter: func(t *testing.T) []byte {
				return pathEnterWithStatus(t, types.SYS_ENTER_UNLINK, unix.AT_FDCWD, "", types.PATH_READ_FAILED)
			},
			fixup:    func(t *testing.T) []byte { return makeSlotFixup(t, types.SYS_ENTER_ACCESS, first, recovered) },
			exit:     types.SYS_EXIT_UNLINK,
			wantName: "",
		},
		{
			name: "the newname slot means nothing to a single-path syscall",
			enter: func(t *testing.T) []byte {
				return pathEnterWithStatus(t, types.SYS_ENTER_ACCESS, unix.AT_FDCWD, "", types.PATH_READ_FAILED)
			},
			fixup:    func(t *testing.T) []byte { return makeSlotFixup(t, types.SYS_ENTER_ACCESS, second, recovered) },
			exit:     types.SYS_EXIT_ACCESS,
			wantName: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			ep := runPairWithFixups(t, el, tc.enter(t), tc.exit, 0, tc.fixup(t))
			if ep == nil {
				t.Fatal("the pair was dropped")
			}
			defer ep.Recycle()
			if got := ep.File.Name(); got != tc.wantName {
				t.Fatalf("row file = %q, want %q", got, tc.wantName)
			}
		})
	}
}

// rename(old, new) can fault either name, both or neither, and each recovery
// is independent: a record for one slot must only ever touch its own name.
func TestNameFixupRecoversEachNameThroughItsOwnSlot(t *testing.T) {
	const (
		oldCaptured = "/srv/old-captured"
		newCaptured = "/srv/new-captured"
		oldRecover  = "/srv/old-recovered"
		newRecover  = "/srv/new-recovered"
	)
	ok, failed := uint32(types.PATH_READ_OK), uint32(types.PATH_READ_FAILED)
	first, second := uint32(types.OPEN_NAME_FIXUP_SLOT_FIRST), uint32(types.OPEN_NAME_FIXUP_SLOT_SECOND)
	rename := types.SYS_ENTER_RENAME

	for _, tc := range []struct {
		name               string
		oldName, newName   string
		oldStatus, newStat uint32
		fixups             func(t *testing.T) [][]byte
		wantOld, wantNew   string
	}{
		{
			name: "both faulted, both recovered", oldStatus: failed, newStat: failed,
			fixups: func(t *testing.T) [][]byte {
				return [][]byte{makeSlotFixup(t, rename, first, oldRecover), makeSlotFixup(t, rename, second, newRecover)}
			},
			wantOld: oldRecover, wantNew: newRecover,
		},
		{
			name: "only the old name faulted", oldName: "", newName: newCaptured, oldStatus: failed, newStat: ok,
			fixups:  func(t *testing.T) [][]byte { return [][]byte{makeSlotFixup(t, rename, first, oldRecover)} },
			wantOld: oldRecover, wantNew: newCaptured,
		},
		{
			// The regression this slot exists for: with a single unlabelled
			// record the recovered newname would land on the still-empty old name.
			name: "only the new name faulted", oldName: oldCaptured, newName: "", oldStatus: ok, newStat: failed,
			fixups:  func(t *testing.T) [][]byte { return [][]byte{makeSlotFixup(t, rename, second, newRecover)} },
			wantOld: oldCaptured, wantNew: newRecover,
		},
		{
			name: "both faulted, only the new name recovered", oldStatus: failed, newStat: failed,
			fixups:  func(t *testing.T) [][]byte { return [][]byte{makeSlotFixup(t, rename, second, newRecover)} },
			wantOld: "", wantNew: newRecover,
		},
		{
			name: "both faulted, only the old name recovered", oldStatus: failed, newStat: failed,
			fixups:  func(t *testing.T) [][]byte { return [][]byte{makeSlotFixup(t, rename, first, oldRecover)} },
			wantOld: oldRecover, wantNew: "",
		},
		{
			name: "both faulted, nothing recovered", oldStatus: failed, newStat: failed,
			fixups:  func(t *testing.T) [][]byte { return nil },
			wantOld: "", wantNew: "",
		},
		{
			name: "a captured name is never overwritten", oldName: oldCaptured, newName: newCaptured, oldStatus: ok, newStat: ok,
			fixups: func(t *testing.T) [][]byte {
				return [][]byte{makeSlotFixup(t, rename, first, oldRecover), makeSlotFixup(t, rename, second, newRecover)}
			},
			wantOld: oldCaptured, wantNew: newCaptured,
		},
		{
			name: "a fixup of another syscall is ignored", oldStatus: failed, newStat: failed,
			fixups: func(t *testing.T) [][]byte {
				return [][]byte{makeSlotFixup(t, types.SYS_ENTER_LINK, first, oldRecover), makeSlotFixup(t, types.SYS_ENTER_LINK, second, newRecover)}
			},
			wantOld: "", wantNew: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			enter := nameEnterWithStatus(t, rename, tc.oldName, tc.oldStatus, tc.newName, tc.newStat)
			ep := runPairWithFixups(t, el, enter, types.SYS_EXIT_RENAME, 0, tc.fixups(t)...)
			if ep == nil {
				t.Fatal("the rename pair was dropped")
			}
			defer ep.Recycle()
			if ep.Oldname != tc.wantOld || ep.File.Name() != tc.wantNew {
				t.Fatalf("rename row old=%q new=%q, want old=%q new=%q", ep.Oldname, ep.File.Name(), tc.wantOld, tc.wantNew)
			}
		})
	}
}

func TestFdPathFixupRecoversAFaultedWatchTarget(t *testing.T) {
	const (
		groupFd = int32(5)
		target  = "/tmp/fq2-watched"
	)
	for _, tc := range []struct {
		name     string
		fixup    bool
		wantName string
	}{
		{name: "recovered", fixup: true, wantName: target},
		{name: "unrecovered keeps the empty name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			ev := types.FdPathEvent{
				EventType:      types.ENTER_FD_PATH_EVENT,
				TraceId:        types.SYS_ENTER_INOTIFY_ADD_WATCH,
				Time:           defaulTime,
				Pid:            execCommPid,
				Tid:            execCommTid,
				Fd:             groupFd,
				Dirfd:          unix.AT_FDCWD,
				PathnameStatus: types.PATH_READ_FAILED,
				SchemaVersion:  types.FD_PATH_EVENT_SCHEMA_VERSION,
			}
			enter, err := ev.Bytes()
			if err != nil {
				t.Fatalf("FdPathEvent.Bytes() error = %v", err)
			}
			var fixups [][]byte
			if tc.fixup {
				fixups = append(fixups, makeSlotFixup(t, types.SYS_ENTER_INOTIFY_ADD_WATCH, types.OPEN_NAME_FIXUP_SLOT_FIRST, target))
			}
			ep := runPairWithFixups(t, el, enter, types.SYS_EXIT_INOTIFY_ADD_WATCH, 1, fixups...)
			if ep == nil {
				t.Fatal("the inotify_add_watch pair was dropped")
			}
			defer ep.Recycle()
			if got := ep.File.Name(); got != tc.wantName {
				t.Fatalf("inotify_add_watch row file = %q, want %q", got, tc.wantName)
			}
		})
	}
}

// matchRawPathEvent and matchRawNameEvent used to judge the path dimension on
// the empty payload name, so `-path X` dropped a faulted stat/unlink/rename at
// enter - before the fixup that would have named it could arrive. The path
// dimension is now deferred (not waived) for PATH_READ_FAILED, to the exit
// checkpoint where the recovered name exists.
func TestPathFilterDefersAFaultedNameToTheExitCheckpoint(t *testing.T) {
	filter := globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: "wanted"}}

	t.Run("pathname: a recovered match survives -path", func(t *testing.T) {
		el := newFilteredEventLoop(t, filter)
		ep := runPairWithFixups(t, el,
			pathEnterWithStatus(t, types.SYS_ENTER_UNLINK, unix.AT_FDCWD, "", types.PATH_READ_FAILED),
			types.SYS_EXIT_UNLINK, 0,
			makeSlotFixup(t, types.SYS_ENTER_UNLINK, types.OPEN_NAME_FIXUP_SLOT_FIRST, "/srv/wanted"))
		if ep == nil {
			t.Fatal("-path dropped the unlink whose name the exit recovered")
		}
		ep.Recycle()
	})

	t.Run("pathname: an unrecovered name cannot leak past -path", func(t *testing.T) {
		el := newFilteredEventLoop(t, filter)
		if ep := runPairWithFixups(t, el,
			pathEnterWithStatus(t, types.SYS_ENTER_UNLINK, unix.AT_FDCWD, "", types.PATH_READ_FAILED),
			types.SYS_EXIT_UNLINK, 0); ep != nil {
			defer ep.Recycle()
			t.Fatalf("an unlink with no name survived -path wanted: %v", ep.File)
		}
	})

	t.Run("pathname: a recovered non-match is dropped", func(t *testing.T) {
		el := newFilteredEventLoop(t, filter)
		if ep := runPairWithFixups(t, el,
			pathEnterWithStatus(t, types.SYS_ENTER_UNLINK, unix.AT_FDCWD, "", types.PATH_READ_FAILED),
			types.SYS_EXIT_UNLINK, 0,
			makeSlotFixup(t, types.SYS_ENTER_UNLINK, types.OPEN_NAME_FIXUP_SLOT_FIRST, "/srv/other")); ep != nil {
			defer ep.Recycle()
			t.Fatalf("an unlink recovered as /srv/other survived -path wanted: %v", ep.File)
		}
	})

	t.Run("pathname: a captured non-match is still dropped at enter", func(t *testing.T) {
		// Deferral is for PATH_READ_FAILED only; a successfully read name is
		// judged at enter exactly as before.
		ev := &types.PathEvent{TraceId: types.SYS_ENTER_UNLINK, Dirfd: unix.AT_FDCWD, PathnameStatus: types.PATH_READ_OK}
		copy(ev.Pathname[:], "/srv/other")
		if matchRawPathEvent(filter, ev) {
			t.Error("a captured /srv/other passed the -path wanted enter gate")
		}
		ev.PathnameStatus = types.PATH_READ_FAILED
		ev.Pathname[0] = 0
		if !matchRawPathEvent(filter, ev) {
			t.Error("a faulted pathname was dropped at enter instead of deferred")
		}
	})

	t.Run("name: either faulted name defers, each recovered independently", func(t *testing.T) {
		el := newFilteredEventLoop(t, filter)
		// Only the NEW name faulted; the old one was captured and does not
		// match, so only the recovered newname can make the row pass.
		ep := runPairWithFixups(t, el,
			nameEnterWithStatus(t, types.SYS_ENTER_RENAME, "/srv/other", types.PATH_READ_OK, "", types.PATH_READ_FAILED),
			types.SYS_EXIT_RENAME, 0,
			makeSlotFixup(t, types.SYS_ENTER_RENAME, types.OPEN_NAME_FIXUP_SLOT_SECOND, "/srv/wanted"))
		if ep == nil {
			t.Fatal("-path dropped the rename whose newname the exit recovered")
		}
		ep.Recycle()

		el = newFilteredEventLoop(t, filter)
		if ep := runPairWithFixups(t, el,
			nameEnterWithStatus(t, types.SYS_ENTER_RENAME, "", types.PATH_READ_FAILED, "/srv/other", types.PATH_READ_OK),
			types.SYS_EXIT_RENAME, 0); ep != nil {
			defer ep.Recycle()
			t.Fatalf("a rename with an unrecovered oldname and a non-matching newname survived -path: %v", ep.File)
		}
	})

	t.Run("name: captured non-matching names are still dropped at enter", func(t *testing.T) {
		ev := &types.NameEvent{TraceId: types.SYS_ENTER_RENAME, Olddirfd: unix.AT_FDCWD, Newdirfd: unix.AT_FDCWD}
		copy(ev.Oldname[:], "/srv/a")
		copy(ev.Newname[:], "/srv/b")
		if matchRawNameEvent(filter, ev) {
			t.Error("captured /srv/a -> /srv/b passed the -path wanted enter gate")
		}
	})
}
