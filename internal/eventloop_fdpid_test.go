package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// This file pins the (pid, fd) keying of fdTracker.files. The flat per-fd map
// it replaced made whichever process registered an fd number last own it, so
// two traced processes holding the same descriptor number - fd 3 and fd 6 are
// near-universal - labelled each other's rows with the wrong filename, and one
// process's close evicted the other's still-open mapping. Every test here
// feeds events for two different pids through the real handler paths.

const (
	crossPidA = 5150
	crossPidB = 5151
	crossTidA = 5150
	crossTidB = 5151
	crossFd   = int32(7)
)

// feedOpenPairForPid drives one openat enter/exit pair for an explicit pid
// through the raw event path, so handleOpenExit registers the descriptor in
// the fd table exactly as it would during a real run.
func feedOpenPairForPid(t *testing.T, el *eventLoop, filename string, pid, tid uint32, ret int64) *event.Pair {
	t.Helper()
	return feedOpenPairWithFlags(t, el, filename, pid, tid, ret, syscall.O_RDONLY)
}

// feedOpenPairWithFlags is feedOpenPairForPid with explicit openat flags, for
// tests that depend on the registered descriptor's flags (e.g. O_CLOEXEC).
func feedOpenPairWithFlags(t *testing.T, el *eventLoop, filename string, pid, tid uint32, ret int64, flags int32) *event.Pair {
	t.Helper()

	enterEv := types.OpenEvent{
		EventType:     types.ENTER_OPEN_EVENT,
		TraceId:       types.SYS_ENTER_OPENAT,
		Time:          defaulTime,
		Pid:           pid,
		Tid:           tid,
		Flags:         flags,
		SchemaVersion: types.OPEN_EVENT_SCHEMA_VERSION,
	}
	copy(enterEv.Filename[:], filename)
	copy(enterEv.Comm[:], "crosspid")
	enterRaw, err := enterEv.Bytes()
	if err != nil {
		t.Fatalf("encode open enter event: %v", err)
	}
	exitEv := types.RetEvent{
		EventType: types.EXIT_OPEN_EVENT,
		TraceId:   types.SYS_EXIT_OPENAT,
		Time:      defaulTime + openPairLatency,
		Ret:       ret,
		Pid:       pid,
		Tid:       tid,
	}
	exitRaw, err := exitEv.Bytes()
	if err != nil {
		t.Fatalf("encode open exit event: %v", err)
	}
	return feedRawPair(t, el, enterRaw, exitRaw)
}

// feedReadPairForPid drives one read enter/exit pair, whose row must resolve
// the descriptor through the owning pid's slice of the fd table.
func feedReadPairForPid(t *testing.T, el *eventLoop, pid, tid uint32, fd int32) *event.Pair {
	t.Helper()
	_, enterRaw := makeEnterFdEvent(t, defaulTime, pid, tid, fd, types.SYS_ENTER_READ)
	_, exitRaw := makeExitRetEvent(t, defaulTime+openPairLatency, pid, tid, types.SYS_EXIT_READ, 128)
	return feedRawPair(t, el, enterRaw, exitRaw)
}

// TestTwoPidsSameFdNumberKeepTheirOwnFiles is the core regression test for the
// (pid, fd) keying: two processes open different files on the same descriptor
// number, and every later row of each process must report its own file. Under
// the flat per-fd map the second open overwrote the first entry, so process A's
// reads were labelled with process B's filename.
func TestTwoPidsSameFdNumberKeepTheirOwnFiles(t *testing.T) {
	const fileA = "/tmp/cross-pid-A.txt"
	const fileB = "/tmp/cross-pid-B.txt"

	el := newFilteredEventLoop(t, globalfilter.Filter{})

	if ep := feedOpenPairForPid(t, el, fileA, crossPidA, crossTidA, int64(crossFd)); ep != nil {
		defer ep.Recycle()
	}
	if ep := feedOpenPairForPid(t, el, fileB, crossPidB, crossTidB, int64(crossFd)); ep != nil {
		defer ep.Recycle()
	}

	// Both entries must coexist in the table: same fd number, different pids.
	resolvedA, okA := el.fdState().get(crossFd, crossPidA)
	resolvedB, okB := el.fdState().get(crossFd, crossPidB)
	if !okA || resolvedA == nil || resolvedA.Name() != fileA {
		t.Fatalf("pid %d fd %d resolved to %v, want %q", crossPidA, crossFd, resolvedA, fileA)
	}
	if !okB || resolvedB == nil || resolvedB.Name() != fileB {
		t.Fatalf("pid %d fd %d resolved to %v, want %q", crossPidB, crossFd, resolvedB, fileB)
	}

	// And the rows each process emits must carry its own file, not whatever
	// the other process registered last.
	epA := feedReadPairForPid(t, el, crossPidA, crossTidA, crossFd)
	if epA == nil {
		t.Fatal("read row of pid A was dropped by an empty filter")
	}
	defer epA.Recycle()
	if epA.File == nil || epA.File.Name() != fileA {
		t.Fatalf("pid %d read fd %d and reported %v, want its own %q",
			crossPidA, crossFd, epA.File, fileA)
	}

	epB := feedReadPairForPid(t, el, crossPidB, crossTidB, crossFd)
	if epB == nil {
		t.Fatal("read row of pid B was dropped by an empty filter")
	}
	defer epB.Recycle()
	if epB.File == nil || epB.File.Name() != fileB {
		t.Fatalf("pid %d read fd %d and reported %v, want its own %q",
			crossPidB, crossFd, epB.File, fileB)
	}
}

// TestOnePidsCloseDoesNotEvictTheOthersFd pins the eviction half of the same
// keying: close (and close_range) by one process must not drop another
// process's entry for the same descriptor number, because close cannot touch
// another process's descriptor table.
func TestOnePidsCloseDoesNotEvictTheOthersFd(t *testing.T) {
	const fileA = "/tmp/close-A.txt"
	const fileB = "/tmp/close-B.txt"

	setup := func(t *testing.T) *eventLoop {
		el := newFilteredEventLoop(t, globalfilter.Filter{})
		if ep := feedOpenPairForPid(t, el, fileA, crossPidA, crossTidA, int64(crossFd)); ep != nil {
			defer ep.Recycle()
		}
		if ep := feedOpenPairForPid(t, el, fileB, crossPidB, crossTidB, int64(crossFd)); ep != nil {
			defer ep.Recycle()
		}
		return el
	}

	t.Run("close", func(t *testing.T) {
		el := setup(t)
		_, enterRaw := makeEnterFdEvent(t, defaulTime, crossPidA, crossTidA, crossFd, types.SYS_ENTER_CLOSE)
		_, exitRaw := makeExitRetEvent(t, defaulTime+openPairLatency, crossPidA, crossTidA, types.SYS_EXIT_CLOSE, 0)
		if ep := feedRawPair(t, el, enterRaw, exitRaw); ep != nil {
			defer ep.Recycle()
		}

		if _, ok := el.fdState().get(crossFd, crossPidA); ok {
			t.Fatalf("pid %d fd %d still tracked after its own close", crossPidA, crossFd)
		}
		verifyFileDescriptor(t, el, crossPidB, crossFd, fileB)
	})

	t.Run("close_range", func(t *testing.T) {
		el := setup(t)
		_, enterRaw := makeEnterTwoFdEvent(t, defaulTime, crossPidA, crossTidA,
			crossFd, crossFd+8, 0, types.SYS_ENTER_CLOSE_RANGE)
		_, exitRaw := makeExitRetEvent(t, defaulTime+openPairLatency, crossPidA, crossTidA,
			types.SYS_EXIT_CLOSE_RANGE, 0)
		if ep := feedRawPair(t, el, enterRaw, exitRaw); ep != nil {
			defer ep.Recycle()
		}

		if _, ok := el.fdState().get(crossFd, crossPidA); ok {
			t.Fatalf("pid %d fd %d still tracked after its own close_range", crossPidA, crossFd)
		}
		verifyFileDescriptor(t, el, crossPidB, crossFd, fileB)
	})
}

// processExitEventWireSize pins the kernel payload size of struct
// process_exit_event (internal/c/types.h): 4+4+8+4+4+4(group_dead)+
// 4(reserved) with no trailing padding, so kernel and binary.Write payloads
// share one size.
const processExitEventWireSize = 32

// makeProcessExitEvent builds the exit record of a task that was the last
// thread of its process (group_dead set) - the record that also evicts the
// process's fd-table entries.
func makeProcessExitEvent(t *testing.T, time uint64, pid, tid uint32) []byte {
	t.Helper()
	return makeTaskExitEvent(t, time, pid, tid, true)
}

// makeThreadExitEvent builds the exit record of a thread whose siblings still
// live (group_dead clear): only tid-keyed state may be dropped.
func makeThreadExitEvent(t *testing.T, time uint64, pid, tid uint32) []byte {
	t.Helper()
	return makeTaskExitEvent(t, time, pid, tid, false)
}

func makeTaskExitEvent(t *testing.T, time uint64, pid, tid uint32, groupDead bool) []byte {
	t.Helper()
	ev := types.ProcessExitEvent{
		EventType: types.PROCESS_EXIT_EVENT,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
	}
	if groupDead {
		ev.GroupDead = 1
	}
	raw, err := ev.Bytes()
	if err != nil {
		t.Fatalf("ProcessExitEvent.Bytes() error = %v", err)
	}
	if len(raw) != processExitEventWireSize {
		t.Fatalf("ProcessExitEvent wire size = %d, want %d", len(raw), processExitEventWireSize)
	}
	return raw
}

// TestProcessExitEventEvictsOnlyThatPidsFdEntries pins the sched_process_exit
// control record path: a dead process's slice of the (pid, fd) key space is
// garbage, and without the eviction it lingered until LRU trimming. The
// control record must evict that pid's entries from both the fd table and the
// procfs cache while leaving every other pid untouched, and must never become
// a row.
func TestProcessExitEventEvictsOnlyThatPidsFdEntries(t *testing.T) {
	el := newFilteredEventLoop(t, globalfilter.Filter{})

	el.fdState().set(crossFd, crossPidA, file.NewFd(crossFd, "/tmp/exit-A.txt", syscall.O_RDONLY))
	el.fdState().set(crossFd, crossPidB, file.NewFd(crossFd, "/tmp/exit-B.txt", syscall.O_RDONLY))
	el.fdState().setProcFdCache(9, crossPidA, file.NewFdWithPid(9, crossPidA))
	el.fdState().setProcFdCache(9, crossPidB, file.NewFdWithPid(9, crossPidB))

	out := make(chan *event.Pair, 1)
	el.processRawEvent(makeProcessExitEvent(t, defaulTime, crossPidA, crossTidA), out)

	// A control record never becomes a row.
	select {
	case ep := <-out:
		if ep != nil {
			ep.Recycle()
			t.Fatal("process exit control record was emitted as a row")
		}
	default:
	}

	// Process A's entries are gone from both maps...
	if _, ok := el.fdState().get(crossFd, crossPidA); ok {
		t.Fatalf("pid %d fd %d still tracked after the process exited", crossPidA, crossFd)
	}
	if _, ok := el.fdState().cachedProcFdFile(9, crossPidA); ok {
		t.Fatalf("pid %d fd 9 still cached after the process exited", crossPidA)
	}
	// ...and process B's are untouched.
	verifyFileDescriptor(t, el, crossPidB, crossFd, "/tmp/exit-B.txt")
	if _, ok := el.fdState().cachedProcFdFile(9, crossPidB); !ok {
		t.Fatalf("pid %d fd 9 must stay cached: another process exited, not this one", crossPidB)
	}
}

// TestThreadExitKeepsTheProcessFdEntries pins the group_dead gate:
// sched_process_exit fires per thread, and a thread dying while its siblings
// live must not evict the process's descriptors. Evicting used to push every
// later syscall on them through the /proc/<pid>/fd fallback, renaming the
// descriptor (pipe:0:3:4 -> pipe:[N]) or losing it entirely once closed.
func TestThreadExitKeepsTheProcessFdEntries(t *testing.T) {
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	el.fdState().set(crossFd, crossPidA, file.NewFd(crossFd, "/tmp/thread-exit.txt", syscall.O_RDONLY))
	el.fdState().setProcFdCache(9, crossPidA, file.NewFdWithPid(9, crossPidA))

	el.processRawEvent(makeThreadExitEvent(t, defaulTime, crossPidA, crossTidA), make(chan *event.Pair, 1))

	verifyFileDescriptor(t, el, crossPidA, crossFd, "/tmp/thread-exit.txt")
	if _, ok := el.fdState().cachedProcFdFile(9, crossPidA); !ok {
		t.Fatalf("pid %d fd 9 evicted from the procfs cache by a mere thread exit", crossPidA)
	}

	// The group-dead exit of the last thread then does evict.
	el.processRawEvent(makeProcessExitEvent(t, defaulTime+1, crossPidA, crossTidA+1), make(chan *event.Pair, 1))
	if _, ok := el.fdState().get(crossFd, crossPidA); ok {
		t.Fatalf("pid %d fd %d still tracked after the whole process exited", crossPidA, crossFd)
	}
	if _, ok := el.fdState().cachedProcFdFile(9, crossPidA); ok {
		t.Fatalf("pid %d fd 9 still cached after the whole process exited", crossPidA)
	}
}

// TestTruncatedProcessExitRecordIsIgnored pins the negative path: a record
// shorter than the group_dead layout (such as the old 24-byte one) fails to
// decode instead of being read as a thread exit or, worse, a group-dead one,
// so it changes no state and emits no row.
func TestTruncatedProcessExitRecordIsIgnored(t *testing.T) {
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	el.fdState().set(crossFd, crossPidA, file.NewFd(crossFd, "/tmp/truncated.txt", syscall.O_RDONLY))

	raw := makeProcessExitEvent(t, defaulTime, crossPidA, crossTidA)
	out := make(chan *event.Pair, 1)
	el.processRawEvent(raw[:24], out)

	select {
	case ep := <-out:
		if ep != nil {
			ep.Recycle()
			t.Fatal("truncated process exit record was emitted as a row")
		}
	default:
	}
	verifyFileDescriptor(t, el, crossPidA, crossFd, "/tmp/truncated.txt")
}

// TestFdTableRetainsRecentlyUsedEntries pins the LRU cap the per-(pid, fd)
// table needs: its key space grows with every traced process, so unlike the
// flat map it must evict. Like the procfs cache, eviction is least-recently-
// used, and the ages metadata must shrink with the table.
func TestFdTableRetainsRecentlyUsedEntries(t *testing.T) {
	fdt := newFDTracker(nil)
	fdt.maxFiles = 2
	el := &eventLoop{fdTracker: fdt}

	el.fdTracker.set(10, crossPidA, file.NewFd(10, "/tmp/ten", syscall.O_RDONLY))
	el.fdTracker.set(11, crossPidA, file.NewFd(11, "/tmp/eleven", syscall.O_RDONLY))

	// Refresh fd 10 so fd 11 becomes the least recently used entry.
	if _, ok := el.fdTracker.get(10, crossPidA); !ok {
		t.Fatalf("expected first fd entry to exist before refresh")
	}

	el.fdTracker.set(12, crossPidA, file.NewFd(12, "/tmp/twelve", syscall.O_RDONLY))

	if _, ok := el.fdTracker.get(10, crossPidA); !ok {
		t.Fatalf("expected recently used fd entry to be retained")
	}
	if _, ok := el.fdTracker.get(11, crossPidA); ok {
		t.Fatalf("expected least recently used fd entry to be evicted")
	}
	if _, ok := el.fdTracker.get(12, crossPidA); !ok {
		t.Fatalf("expected newest fd entry to be retained")
	}
	if got := len(el.fdTracker.fileAges); got != 2 {
		t.Fatalf("fd table metadata size = %d, want 2", got)
	}
}

// TestDeletePidPresenceSetInvariants pins the per-pid index fast path from
// both sides: an exit for a pid that never registered is a no-op that leaves
// other pids alone, and the index never *misses* (a pid that registered is
// always evicted, and can re-register afterwards - pid numbers are reused by
// the kernel).
func TestDeletePidPresenceSetInvariants(t *testing.T) {
	// A zero-value tracker has no index at all; exit records must not panic
	// on it (a lookup in the nil index map finds nothing).
	(&fdTracker{}).deletePid(crossPidA)

	fdt := newFDTracker(nil)
	// A constructed tracker has an empty (non-nil) index: exit of a pid that
	// never registered takes the absent-pid early return.
	fdt.deletePid(crossPidA)

	fdt.set(crossFd, crossPidA, file.NewFd(crossFd, "/tmp/present.txt", syscall.O_RDONLY))

	// Exit of a pid that never registered: no-op, must not touch A.
	fdt.deletePid(crossPidB)
	if _, ok := fdt.get(crossFd, crossPidA); !ok {
		t.Fatalf("exit of an unregistered pid evicted pid %d's entry", crossPidA)
	}

	// Exit of the registered pid: evicts it.
	fdt.deletePid(crossPidA)
	if _, ok := fdt.get(crossFd, crossPidA); ok {
		t.Fatalf("pid %d fd %d still tracked after deletePid", crossPidA, crossFd)
	}

	// Repeated exit is a no-op, and re-registration works after the exit
	// (kernel pid reuse: the same tgid can come back as a new process).
	fdt.deletePid(crossPidA)
	fdt.set(crossFd, crossPidA, file.NewFd(crossFd, "/tmp/reused.txt", syscall.O_RDONLY))
	if _, ok := fdt.get(crossFd, crossPidA); !ok {
		t.Fatalf("pid %d could not re-register after deletePid", crossPidA)
	}
}

// TestFdTableCapCountsEntriesNotDescriptorNumbers pins what the cap measures
// now that the key is composite: 2 pids x 2 fds is four entries, not two, so a
// cap of three must evict one even though only two distinct fd numbers exist.
func TestFdTableCapCountsEntriesNotDescriptorNumbers(t *testing.T) {
	fdt := newFDTracker(nil)
	fdt.maxFiles = 3

	for _, pid := range []uint32{crossPidA, crossPidB} {
		fdt.set(3, pid, file.NewFd(3, "/tmp/three", syscall.O_RDONLY))
		fdt.set(6, pid, file.NewFd(6, "/tmp/six", syscall.O_RDONLY))
	}

	if got := len(fdt.files); got != 3 {
		t.Fatalf("fd table size = %d, want 3: the cap counts (pid, fd) entries, not descriptor numbers", got)
	}
	if got := len(fdt.fileAges); got != 3 {
		t.Fatalf("fd table metadata size = %d, want 3", got)
	}
}
