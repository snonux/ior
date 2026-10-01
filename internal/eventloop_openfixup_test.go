package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"

	"golang.org/x/sys/unix"
)

// About 2% of system-wide openat events - and ~15% of the openats of a
// fork/exec workload - used to arrive with an empty filename payload, because
// bpf_probe_read_user_str() at sys_enter is a nofault read and returns -EFAULT
// when the path string's page is not resident yet. Those rows printed "E:name",
// registered their descriptor under the empty string so every later
// read/write/close on it lost its path too, and could never match a -path
// pattern.
//
// The kernel now stashes the user pointer on that failure and re-reads it at
// sys_exit, where its own getname() has already faulted the page in, and
// publishes the result as an OPEN_NAME_FIXUP_EVENT control record. The tests
// below drive that record through the real raw-event path.

// recoveredName is the path an empty-name open recovers at sys_exit.
const recoveredName = "/usr/lib/locale/locale-archive"

func TestOpenNameFixupUsesTheNarrowControlRecordContract(t *testing.T) {
	var decoded runtimeDecodedEvent = &types.OpenNameFixupEvent{}
	if _, ok := decoded.(event.Event); ok {
		t.Fatal("OpenNameFixupEvent must not claim syscall PID/time semantics")
	}
}

// makeOpenNameFixupEvent builds the compact control record the generated exit
// handler emits (ior_emit_open_name_fixup, internal/c/filter.c). It carries the
// pending enter's tid and trace ID plus the filename read a second time.
func makeOpenNameFixupEvent(t *testing.T, tid uint32, traceID types.TraceId, filename string) []byte {
	t.Helper()
	ev := types.OpenNameFixupEvent{
		EventType: types.OPEN_NAME_FIXUP_EVENT,
		TraceId:   traceID,
		Tid:       tid,
	}
	copy(ev.Filename[:], filename)
	raw, err := ev.Bytes()
	if err != nil {
		t.Fatalf("OpenNameFixupEvent.Bytes() error = %v", err)
	}
	return raw
}

func makeOpenEnterEvent(t *testing.T, filename, comm string) []byte {
	t.Helper()
	ev := types.OpenEvent{
		EventType:     types.ENTER_OPEN_EVENT,
		TraceId:       types.SYS_ENTER_OPENAT,
		Time:          defaulTime,
		Pid:           execCommPid,
		Tid:           execCommTid,
		Flags:         syscall.O_RDONLY,
		SchemaVersion: types.OPEN_EVENT_SCHEMA_VERSION,
	}
	if filename == "" {
		// This helper models the only empty open payload that can later receive
		// a fixup: a failed non-NULL nofault read. A genuine NULL or successfully
		// captured empty string is terminal and must not defer the raw path gate.
		ev.FilenameStatus = types.PATH_READ_FAILED
	}
	copy(ev.Filename[:], filename)
	copy(ev.Comm[:], comm)
	raw, err := ev.Bytes()
	if err != nil {
		t.Fatalf("OpenEvent.Bytes() error = %v", err)
	}
	return raw
}

// feedOpenPairWithFixup drives enter -> [fixup] -> exit through the raw event
// path in the order the ring buffer delivers them, and returns the emitted
// pair or nil when the filter dropped it. A nil fixup feeds no control record;
// a non-nil pointer to "" feeds the real all-zero record produced when the
// exit-side probe successfully reads a valid empty C string.
func feedOpenPairWithFixup(t *testing.T, el *eventLoop, payloadName string, fixupName *string, comm string, ret int64) *event.Pair {
	t.Helper()
	out := make(chan *event.Pair, 1)
	el.processRawEvent(makeOpenEnterEvent(t, payloadName, comm), out)
	if fixupName != nil {
		el.processRawEvent(makeOpenNameFixupEvent(t, execCommTid, types.SYS_ENTER_OPENAT, *fixupName), out)
	}
	_, exitRaw := makeExitRetEvent(t, defaulTime+openPairLatency, execCommPid, execCommTid,
		types.SYS_EXIT_OPENAT, ret)
	el.processRawEvent(exitRaw, out)
	select {
	case ep := <-out:
		return ep
	default:
		return nil
	}
}

func openFixup(filename string) *string {
	return &filename
}

func TestOpenNameFixupRecoversAnEmptyFilename(t *testing.T) {
	const openedFd = 7

	t.Run("the recovered name reaches the row", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{})
		ep := feedOpenPairWithFixup(t, el, "", openFixup(recoveredName), "ioworkload", openedFd)
		if ep == nil {
			t.Fatal("the open pair was dropped")
		}
		defer ep.Recycle()
		if got := ep.File.Name(); got != recoveredName {
			t.Fatalf("row file = %q, want %q", got, recoveredName)
		}
	})

	t.Run("without the fixup the row keeps printing E:name", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{})
		ep := feedOpenPairWithFixup(t, el, "", nil, "ioworkload", openedFd)
		if ep == nil {
			t.Fatal("the open pair was dropped")
		}
		defer ep.Recycle()
		if got := ep.File.Name(); got != "" {
			t.Fatalf("row file = %q, want the empty name that models an unrecovered open", got)
		}
		if got := ep.File.String(); got == "" || got[:6] != "E:name" {
			t.Fatalf("row file repr = %q, want it to start with E:name", got)
		}
	})

	t.Run("the recovered name also registers the descriptor", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{})
		ep := feedOpenPairWithFixup(t, el, "", openFixup(recoveredName), "ioworkload", openedFd)
		if ep == nil {
			t.Fatal("the open pair was dropped")
		}
		ep.Recycle()
		// The whole point of recovering the name is that it also un-poisons
		// the fd table: before, every later read/write/close on the descriptor
		// inherited the empty string the open registered.
		fdFile, ok := el.fdState().get(openedFd, execCommPid)
		if !ok {
			t.Fatalf("fd %d was not registered", openedFd)
		}
		if got := fdFile.Name(); got != recoveredName {
			t.Fatalf("fd %d registered as %q, want %q", openedFd, got, recoveredName)
		}
	})
}

func TestOpenNameFixupEmptyControlRecordProvesAValidEmptyPath(t *testing.T) {
	const (
		dirfd    = int32(31)
		openedFD = int32(32)
	)
	target := t.TempDir()

	for _, tc := range []struct {
		name       string
		status     uint32
		fixup      *string
		wantTarget bool
	}{
		{name: "successful empty reread", status: types.PATH_READ_FAILED, fixup: openFixup(""), wantTarget: true},
		{name: "no control record", status: types.PATH_READ_FAILED},
		{name: "NULL cannot be promoted", status: types.PATH_READ_NULL, fixup: openFixup("")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			el.fdState().set(dirfd, execCommPid, file.NewFd(dirfd, target, unix.O_PATH))
			out := make(chan *event.Pair, 1)
			enter := &types.OpenEvent{
				EventType:      types.ENTER_OPEN_EVENT,
				TraceId:        types.SYS_ENTER_OPEN_TREE,
				Time:           defaulTime,
				Pid:            execCommPid,
				Tid:            execCommTid,
				Flags:          unix.AT_EMPTY_PATH,
				Dirfd:          dirfd,
				SchemaVersion:  types.OPEN_EVENT_SCHEMA_VERSION,
				FilenameStatus: tc.status,
			}
			copy(enter.Comm[:], "ioworkload")
			enterRaw, err := enter.Bytes()
			if err != nil {
				t.Fatalf("OpenEvent.Bytes() error = %v", err)
			}
			el.processRawEvent(enterRaw, out)
			if tc.fixup != nil {
				el.processRawEvent(makeOpenNameFixupEvent(t, execCommTid, types.SYS_ENTER_OPEN_TREE, *tc.fixup), out)
			}
			_, exitRaw := makeExitRetEvent(t, defaulTime+openPairLatency, execCommPid, execCommTid,
				types.SYS_EXIT_OPEN_TREE, int64(openedFD))
			el.processRawEvent(exitRaw, out)

			select {
			case ep := <-out:
				defer ep.Recycle()
				wantName := ""
				if tc.wantTarget {
					wantName = target
				}
				if ep.File.Name() != wantName || ep.File.FD() != openedFD {
					t.Fatalf("file = %q fd %d, want %q fd %d", ep.File.Name(), ep.File.FD(), wantName, openedFD)
				}
				tracked, ok := el.fdState().get(openedFD, execCommPid)
				if !ok || tracked.Name() != wantName {
					t.Fatalf("tracked fd = %#v, want name %q", tracked, wantName)
				}
			default:
				t.Fatal("open_tree pair was dropped")
			}
		})
	}
}

func TestOpenNameFixupNeverOverwritesACapturedName(t *testing.T) {
	const capturedName = "/etc/hostname"
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	// The enter-side read is the authoritative one: it saw the caller's buffer
	// at the moment of the call. A fixup must never replace it, whatever the
	// kernel re-read at exit.
	ep := feedOpenPairWithFixup(t, el, capturedName, openFixup(recoveredName), "ioworkload", 3)
	if ep == nil {
		t.Fatal("the open pair was dropped")
	}
	defer ep.Recycle()
	if got := ep.File.Name(); got != capturedName {
		t.Fatalf("row file = %q, want the enter-captured %q", got, capturedName)
	}
}

func TestOpenNameFixupIgnoresAForeignPendingEnter(t *testing.T) {
	t.Run("a pending enter of a different kind is left alone", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{})
		out := make(chan *event.Pair, 1)
		_, enterRaw := makeEnterPathEvent(t, defaulTime, execCommPid, execCommTid,
			"/etc/ld.so.preload", types.SYS_ENTER_ACCESS)
		el.processRawEvent(enterRaw, out)
		el.processRawEvent(makeOpenNameFixupEvent(t, execCommTid, types.SYS_ENTER_OPENAT, recoveredName), out)
		_, exitRaw := makeExitRetEvent(t, defaulTime+openPairLatency, execCommPid, execCommTid,
			types.SYS_EXIT_ACCESS, -2)
		el.processRawEvent(exitRaw, out)

		select {
		case ep := <-out:
			defer ep.Recycle()
			if got := ep.File.Name(); got != "/etc/ld.so.preload" {
				t.Fatalf("access row file = %q, want /etc/ld.so.preload", got)
			}
		default:
			t.Fatal("the access pair was dropped")
		}
	})

	// The kernel already refuses to recover a name whose per-tid enter state
	// belongs to a different syscall (the enter_trace_id check in
	// ior_on_syscall_exit_impl, which the exit handlers reach through
	// ior_on_syscall_exit_take_filename and only copies the stashed pointer
	// out past that check). This is the userspace half of the same guard:
	// open(2) and openat(2) are both open_event kinds on the same tid, so the
	// type assertion alone cannot tell them apart - only the trace ID can.
	t.Run("a pending open of a different syscall is left alone", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{})
		out := make(chan *event.Pair, 1)
		enterEv := types.OpenEvent{
			EventType:     types.ENTER_OPEN_EVENT,
			TraceId:       types.SYS_ENTER_OPEN,
			Time:          defaulTime,
			Pid:           execCommPid,
			Tid:           execCommTid,
			SchemaVersion: types.OPEN_EVENT_SCHEMA_VERSION,
		}
		copy(enterEv.Comm[:], "ioworkload")
		enterRaw, err := enterEv.Bytes()
		if err != nil {
			t.Fatalf("OpenEvent.Bytes() error = %v", err)
		}
		el.processRawEvent(enterRaw, out)
		el.processRawEvent(makeOpenNameFixupEvent(t, execCommTid, types.SYS_ENTER_OPENAT, recoveredName), out)
		_, exitRaw := makeExitRetEvent(t, defaulTime+openPairLatency, execCommPid, execCommTid,
			types.SYS_EXIT_OPEN, 9)
		el.processRawEvent(exitRaw, out)

		select {
		case ep := <-out:
			defer ep.Recycle()
			if got := ep.File.Name(); got != "" {
				t.Fatalf("an openat fixup was grafted onto a pending open: file = %q", got)
			}
		default:
			t.Fatal("the open pair was dropped")
		}
	})
}

// TestEmptyNameOpenDefersOnlyThePathGateAtEnter pins the enter-gate decision.
//
// matchRawOpenEvent used to judge the path dimension on the payload filename,
// so an empty-name open was dropped before its exit fixup could arrive - which
// is why `-path X` silently missed exactly these events even though the row
// itself would have been repaired. The path dimension is now deferred (not
// waived) for an empty payload name: the comm dimension still applies at enter,
// and the full pair filter applies at exit, where the recovered name is
// available.
func TestEmptyNameOpenDefersOnlyThePathGateAtEnter(t *testing.T) {
	pathFilter := func() globalfilter.Filter {
		return globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: "locale-archive"}}
	}

	t.Run("a recovered name matches a -path filter it could not match at enter", func(t *testing.T) {
		el := newFilteredEventLoop(t, pathFilter())
		ep := feedOpenPairWithFixup(t, el, "", openFixup(recoveredName), "ioworkload", 7)
		if ep == nil {
			t.Fatal("a -path run dropped the open whose name the exit recovered")
		}
		defer ep.Recycle()
		if got := ep.File.Name(); got != recoveredName {
			t.Fatalf("row file = %q, want %q", got, recoveredName)
		}
	})

	t.Run("an unrecovered name cannot leak past the -path filter", func(t *testing.T) {
		el := newFilteredEventLoop(t, pathFilter())
		if ep := feedOpenPairWithFixup(t, el, "", nil, "ioworkload", 7); ep != nil {
			defer ep.Recycle()
			t.Fatalf("an open with no name survived -path locale-archive: %v", ep.File)
		}
	})

	t.Run("a recovered name that does not match is still dropped", func(t *testing.T) {
		el := newFilteredEventLoop(t, pathFilter())
		if ep := feedOpenPairWithFixup(t, el, "", openFixup("/etc/hostname"), "ioworkload", 7); ep != nil {
			defer ep.Recycle()
			t.Fatalf("an open recovered as /etc/hostname survived -path locale-archive: %v", ep.File)
		}
	})

	// Deferring the *file* dimension must not turn into waiving the gate. The
	// comm dimension is answerable from the payload whatever the filename read
	// did, so it still applies here - the exit checkpoint would catch a
	// non-matching comm too, but only after the event had been paired, its
	// descriptor registered and its comm cached. Asserted on the gate itself
	// because that difference is invisible end to end.
	t.Run("the comm dimension is still applied at enter", func(t *testing.T) {
		filter := globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "ioworkload"}}
		emptyName := &types.OpenEvent{TraceId: types.SYS_ENTER_OPENAT, FilenameStatus: types.PATH_READ_FAILED}
		copy(emptyName.Comm[:], "someoneelse")
		if matchRawOpenEvent(filter, emptyName) {
			t.Error("an empty-name open from comm=someoneelse passed the -comm ioworkload gate")
		}
		copy(emptyName.Comm[:], "ioworkload\x00")
		if !matchRawOpenEvent(filter, emptyName) {
			t.Error("an empty-name open from comm=ioworkload was dropped by the -comm ioworkload gate")
		}
	})

	t.Run("NULL and valid empty names do not defer as recoverable failures", func(t *testing.T) {
		filter := pathFilter()
		for _, status := range []uint32{types.PATH_READ_NULL, types.PATH_READ_OK} {
			ev := &types.OpenEvent{TraceId: types.SYS_ENTER_OPENAT, Dirfd: 9, FilenameStatus: status}
			if matchRawOpenEvent(filter, ev) {
				t.Fatalf("status %d empty openat name incorrectly deferred the path gate", status)
			}
		}
	})
}

// TestMatchRawOpenEventHandlesTypedNil pins that the open gate survives a
// typed-nil *types.OpenEvent. The type assertion succeeds for one of those, so
// the gate must nil-check before reading Filename[0] to decide which dimension
// set applies — the sibling gates get this for free by delegating straight to
// a Match* helper that opens with its own nil check.
//
// Not reachable through the live decoder today, but this gate runs on every
// open event and the enter-side deferral made it dereference where it used to
// delegate. It also keeps MatchOpenEventComm's own nil contract exercisable
// from its only production caller.
func TestMatchRawOpenEventHandlesTypedNil(t *testing.T) {
	var nilEvent *types.OpenEvent
	filter := globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: "anything"}}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("matchRawOpenEvent panicked on a typed-nil event: %v", r)
		}
	}()
	if matchRawOpenEvent(filter, nilEvent) {
		t.Fatal("a typed-nil open event must not match a -path filter")
	}
}
