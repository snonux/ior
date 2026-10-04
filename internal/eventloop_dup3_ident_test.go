package internal

import (
	"os"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// Task d23: dup3_event carries the identity of its old descriptor, so a dup3
// is checked like a dup or dup2 (handleDup3Exit, resolveIdentifiedOnExit)
// before registerDup copies the fd table entry to the new number. Before, a
// stale entry - the number rebound by something the trace cannot see - was
// copied unchecked and named every row of the new number for its whole life.

const dup3TargetOldName = "/data/dup3-target-before.txt"

// dup3Row is a dup3(fd, newFd, flags) of this process whose record says fd
// named the file ident when it entered at enterNs.
type dup3Row struct {
	fd, newFd int32
	flags     int32
	ident     uint32
	enterNs   uint64
}

// feedIdentDup3 feeds row as a current dup3 record (with the identity word)
// and its exit, which returns newFd, and returns the emitted pair.
func feedIdentDup3(t *testing.T, el *eventLoop, row dup3Row) *event.Pair {
	t.Helper()
	return feedDup3Record(t, el, row, false)
}

// feedDup3Record feeds row; legacy cuts the record to the 32 bytes of an
// object built before the identity word.
func feedDup3Record(t *testing.T, el *eventLoop, row dup3Row, legacy bool) *event.Pair {
	t.Helper()
	pid := uint32(os.Getpid())
	enter := types.Dup3Event{EventType: types.ENTER_DUP3_EVENT, TraceId: types.SYS_ENTER_DUP3, Time: row.enterNs,
		Pid: pid, Tid: execCommTid, Fd: row.fd, Flags: row.flags, FileIdent: row.ident}
	enterRaw, err := enter.Bytes()
	if err != nil {
		t.Fatalf("Dup3Event.Bytes: %v", err)
	}
	if legacy {
		enterRaw = enterRaw[:32]
	}
	_, exitRaw := makeExitRetEvent(t, row.enterNs+openPairLatency, pid, execCommTid, types.SYS_EXIT_DUP3, int64(row.newFd))
	return mustEmit(t, feedRawPair(t, el, enterRaw, exitRaw), "dup3")
}

// trackTarget gives the dup3 target number an fd table entry of an earlier
// file, which a dup3 replaces either way.
func trackTarget(el *eventLoop, target int32) {
	el.fdState().set(target, uint32(os.Getpid()), file.NewFd(target, dup3TargetOldName, syscall.O_RDONLY))
}

// requireCopy fails unless the fd table holds a copy of name with identity
// ident on target, close-on-exec known and set as cloexec says.
func requireCopy(t *testing.T, el *eventLoop, target int32, name string, ident uint32, cloexec bool) {
	t.Helper()
	copied, ok := el.fdState().get(target, uint32(os.Getpid()))
	fdCopy, isFd := copied.(*file.FdFile)
	if !ok || !isFd || fdCopy.Name() != name || fdCopy.Ident() != ident {
		t.Fatalf("dup3 target = %v (ok=%v), want a copy of %q with identity %d", copied, ok, name, ident)
	}
	if set, known := fdCopy.CloseOnExec(); set != cloexec || !known {
		t.Fatalf("copy close-on-exec = (%v, %v), want (%v, true)", set, known, cloexec)
	}
}

// The live shape: an open ior traced registered the number, an invisible
// reopen put another file there, and a dup3 of the number reports that
// file. The stale entry is dropped and counted, the row is named after what
// procfs shows (the file of the record's identity), and the target number
// gets no copy: its earlier entry goes, and it is resolved on first use.
func TestDup3OfAStaleBindingCopiesNothing(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	reopened, ident := placeFileOn(t, n, "reopened.txt")
	feedIdentOpen(t, el, staleOpenName, n, ident+1)
	trackTarget(el, n+1)

	ep := feedIdentDup3(t, el, dup3Row{fd: n, newFd: n + 1, ident: ident, enterNs: bootClockNs()})
	if got := ep.File.Name(); got != reopened {
		t.Fatalf("dup3 row named %q, want %q", got, reopened)
	}
	verifyFdNotTracked(t, el, pid, n)
	verifyFdNotTracked(t, el, pid, n+1)
	verifyProcFdNotCached(t, el, pid, n+1)
	if el.fdState().staleBindings != 1 {
		t.Fatalf("staleBindings = %d, want 1", el.fdState().staleBindings)
	}
}

// An entry of the file the record reports is copied as before, with the
// identity and dup3's O_CLOEXEC.
func TestDup3OfTheTrackedFileCopiesIt(t *testing.T) {
	n := freeFdNumber(t)
	el := identLoop(t)
	feedIdentOpen(t, el, staleOpenName, n, 4711)
	trackTarget(el, n+1)

	ep := feedIdentDup3(t, el, dup3Row{fd: n, newFd: n + 1, flags: syscall.O_CLOEXEC, ident: 4711, enterNs: bootClockNs()})
	if got := ep.File.Name(); got != staleOpenName {
		t.Fatalf("dup3 row named %q, want the traced %q", got, staleOpenName)
	}
	requireCopy(t, el, n+1, staleOpenName, 4711, true)
	requireNothingCounted(t, el)
}

// An entry bound after the dup3 entered (another thread's open returned the
// number first) is of a later file: it stays, the row goes unnamed, and the
// target gets no copy of the later file, which the dup3 did not duplicate.
func TestDup3ThatEnteredBeforeTheBindingCopiesNothing(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identLoop(t)
	openNs := bootClockNs()
	feedIdentOpenAt(t, el, laterOpenName, n, 4712, openNs)
	trackTarget(el, n+1)

	ep := feedIdentDup3(t, el, dup3Row{fd: n, newFd: n + 1, ident: 4711, enterNs: openNs - 1000})
	requireUnnamedOf(t, ep.File, 4711)
	verifyFileDescriptor(t, el, pid, n, laterOpenName)
	verifyFdNotTracked(t, el, pid, n+1)
	requireNothingCounted(t, el)
}

// The controls: without the capture the word is not read, and an older
// object's 32-byte record has none. Both copy the entry unchecked, as dup3
// did before the word existed.
func TestDup3WithoutATrustedIdentityCopiesAsBefore(t *testing.T) {
	cases := []struct {
		name    string
		capture bool
		legacy  bool
	}{
		{name: "capture off", capture: false, legacy: false},
		{name: "record of an older object", capture: true, legacy: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := freeFdNumber(t)
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			el.trustFileIdents(tc.capture)
			el.fdState().readClockUnknown = false
			_, ident := placeFileOn(t, n, "other.txt")
			feedIdentOpen(t, el, staleOpenName, n, ident+1)

			row := dup3Row{fd: n, newFd: n + 1, ident: ident, enterNs: bootClockNs()}
			if got := feedDup3Record(t, el, row, tc.legacy).File.Name(); got != staleOpenName {
				t.Fatalf("dup3 row named %q, want the traced %q", got, staleOpenName)
			}
			copyIdent := uint32(0)
			if tc.capture {
				copyIdent = ident + 1
			}
			requireCopy(t, el, n+1, staleOpenName, copyIdent, false)
		})
	}
}
