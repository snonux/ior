package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
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

// makeOpenNameFixupEvent builds the control record the generated exit handler
// emits (ior_emit_open_name_fixup, internal/c/filter.c). It reuses struct
// open_event - the record carries exactly one thing, the enter payload's
// filename read a second time - and is stamped with the *enter* trace ID.
func makeOpenNameFixupEvent(t *testing.T, time uint64, pid, tid uint32, traceID types.TraceId, filename string) []byte {
	t.Helper()
	ev := types.OpenEvent{
		EventType: types.OPEN_NAME_FIXUP_EVENT,
		TraceId:   traceID,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
		Flags:     -1,
	}
	copy(ev.Filename[:], filename)
	raw, err := ev.Bytes()
	if err != nil {
		t.Fatalf("OpenEvent.Bytes() error = %v", err)
	}
	return raw
}

func makeOpenEnterEvent(t *testing.T, filename, comm string) []byte {
	t.Helper()
	ev := types.OpenEvent{
		EventType: types.ENTER_OPEN_EVENT,
		TraceId:   types.SYS_ENTER_OPENAT,
		Time:      defaulTime,
		Pid:       execCommPid,
		Tid:       execCommTid,
		Flags:     syscall.O_RDONLY,
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
// pair or nil when the filter dropped it. An empty fixupName feeds no control
// record at all, modelling a name the kernel could not recover either.
func feedOpenPairWithFixup(t *testing.T, el *eventLoop, payloadName, fixupName, comm string, ret int64) *event.Pair {
	t.Helper()
	out := make(chan *event.Pair, 1)
	el.processRawEvent(makeOpenEnterEvent(t, payloadName, comm), out)
	if fixupName != "" {
		el.processRawEvent(makeOpenNameFixupEvent(t, defaulTime+50, execCommPid, execCommTid,
			types.SYS_ENTER_OPENAT, fixupName), out)
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

func TestOpenNameFixupRecoversAnEmptyFilename(t *testing.T) {
	const openedFd = 7

	t.Run("the recovered name reaches the row", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{})
		ep := feedOpenPairWithFixup(t, el, "", recoveredName, "ioworkload", openedFd)
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
		ep := feedOpenPairWithFixup(t, el, "", "", "ioworkload", openedFd)
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
		ep := feedOpenPairWithFixup(t, el, "", recoveredName, "ioworkload", openedFd)
		if ep == nil {
			t.Fatal("the open pair was dropped")
		}
		ep.Recycle()
		// The whole point of recovering the name is that it also un-poisons
		// the fd table: before, every later read/write/close on the descriptor
		// inherited the empty string the open registered.
		fdFile, ok := el.fdState().get(openedFd)
		if !ok {
			t.Fatalf("fd %d was not registered", openedFd)
		}
		if got := fdFile.Name(); got != recoveredName {
			t.Fatalf("fd %d registered as %q, want %q", openedFd, got, recoveredName)
		}
	})
}

func TestOpenNameFixupNeverOverwritesACapturedName(t *testing.T) {
	const capturedName = "/etc/hostname"
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	// The enter-side read is the authoritative one: it saw the caller's buffer
	// at the moment of the call. A fixup must never replace it, whatever the
	// kernel re-read at exit.
	ep := feedOpenPairWithFixup(t, el, capturedName, recoveredName, "ioworkload", 3)
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
		el.processRawEvent(makeOpenNameFixupEvent(t, defaulTime+50, execCommPid, execCommTid,
			types.SYS_ENTER_OPENAT, recoveredName), out)
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
	// ior_take_pending_filename). This is the userspace half of the same guard:
	// open(2) and openat(2) are both open_event kinds on the same tid, so the
	// type assertion alone cannot tell them apart - only the trace ID can.
	t.Run("a pending open of a different syscall is left alone", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{})
		out := make(chan *event.Pair, 1)
		enterEv := types.OpenEvent{
			EventType: types.ENTER_OPEN_EVENT,
			TraceId:   types.SYS_ENTER_OPEN,
			Time:      defaulTime,
			Pid:       execCommPid,
			Tid:       execCommTid,
		}
		copy(enterEv.Comm[:], "ioworkload")
		enterRaw, err := enterEv.Bytes()
		if err != nil {
			t.Fatalf("OpenEvent.Bytes() error = %v", err)
		}
		el.processRawEvent(enterRaw, out)
		el.processRawEvent(makeOpenNameFixupEvent(t, defaulTime+50, execCommPid, execCommTid,
			types.SYS_ENTER_OPENAT, recoveredName), out)
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
		ep := feedOpenPairWithFixup(t, el, "", recoveredName, "ioworkload", 7)
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
		if ep := feedOpenPairWithFixup(t, el, "", "", "ioworkload", 7); ep != nil {
			defer ep.Recycle()
			t.Fatalf("an open with no name survived -path locale-archive: %v", ep.File)
		}
	})

	t.Run("a recovered name that does not match is still dropped", func(t *testing.T) {
		el := newFilteredEventLoop(t, pathFilter())
		if ep := feedOpenPairWithFixup(t, el, "", "/etc/hostname", "ioworkload", 7); ep != nil {
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
		emptyName := &types.OpenEvent{TraceId: types.SYS_ENTER_OPENAT}
		copy(emptyName.Comm[:], "someoneelse")
		if matchRawOpenEvent(filter, emptyName) {
			t.Error("an empty-name open from comm=someoneelse passed the -comm ioworkload gate")
		}
		copy(emptyName.Comm[:], "ioworkload\x00")
		if !matchRawOpenEvent(filter, emptyName) {
			t.Error("an empty-name open from comm=ioworkload was dropped by the -comm ioworkload gate")
		}
	})
}
