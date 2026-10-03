package internal

import (
	"os"
	"strings"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// Task e23: the exit handler tracks descriptors and checks procfs answers
// for every pair, also one a userspace filter then drops (the table is the
// process's, -comm judges the thread; -path judges the name the handler
// finds). The file identity line counts for the reported rows only what
// their own handlers did, and names the dropped rows' part apart.

// identFilteredTid is a second thread of this process, whose comm the -comm
// filter of identCommLoop does not select.
const identFilteredTid = execCommTid + 1

// identCommLoop is identLoop under -comm: execCommTid is selected,
// identFilteredTid is not.
func identCommLoop(t *testing.T) *eventLoop {
	t.Helper()
	el := newPairCommFilterEventLoop(t, false, pairCommFilterPattern)
	el.setCachedComm(identFilteredTid, "other")
	el.trustFileIdents(true)
	el.fdState().readClockUnknown = false
	return el
}

// feedIdentRowOf is feedIdentRow for a row of thread tid that the filter may
// drop: it returns nil then.
func feedIdentRowOf(t *testing.T, el *eventLoop, tid uint32, row identRow) *event.Pair {
	t.Helper()
	pid := uint32(os.Getpid())
	enter := types.FdEvent{EventType: types.ENTER_FD_EVENT, TraceId: row.enter, Time: row.enterNs,
		Pid: pid, Tid: tid, Fd: row.fd, FileIdent: row.ident}
	enterRaw, err := enter.Bytes()
	if err != nil {
		t.Fatalf("FdEvent.Bytes: %v", err)
	}
	_, exitRaw := makeExitRetEvent(t, row.enterNs+openPairLatency, pid, tid, row.exit, row.ret)
	ep := feedRawPair(t, el, enterRaw, exitRaw)
	if ep != nil {
		t.Cleanup(ep.Recycle)
	}
	return ep
}

// requireIdentCounts fails unless the identity line's figures are these: the
// reported rows' stale bindings and refusals, then the dropped rows'.
func requireIdentCounts(t *testing.T, el *eventLoop, stale, refused, droppedStale, droppedRefused uint64) {
	t.Helper()
	tr := el.fdState()
	got := [4]uint64{tr.staleBindings - tr.droppedRowStale, tr.rejectedAnswers - tr.droppedRowRejected,
		tr.droppedRowStale, tr.droppedRowRejected}
	if want := [4]uint64{stale, refused, droppedStale, droppedRefused}; got != want {
		t.Fatalf("identity counts (stale, refused, dropped rows' stale, refused) = %v, want %v", got, want)
	}
}

// writeOfClosedFile is a write row on fd n of a file that has left the
// number since: procfs shows the reuser, and the row is refused its name.
func writeOfClosedFile(t *testing.T, n int32) identRow {
	t.Helper()
	enterNs := bootClockNs()
	placePipeOn(t, n)
	_, reuserIdent := procNameAndIdent(t, n)
	return identRow{enter: types.SYS_ENTER_WRITE, exit: types.SYS_EXIT_WRITE, fd: n,
		ident: reuserIdent + 1, enterNs: enterNs, ret: 1}
}

// The task's live case: under -comm the rows of every other process were
// refused procfs answers too, and the line counted them as the run's.
func TestRefusalOfARowTheCommFilterDropsIsCountedApart(t *testing.T) {
	el := identCommLoop(t)
	row := writeOfClosedFile(t, freeFdNumber(t))

	if ep := feedIdentRowOf(t, el, identFilteredTid, row); ep != nil {
		t.Fatalf("row of the thread -comm does not select was emitted: %v", ep)
	}
	requireIdentCounts(t, el, 0, 0, 0, 1)

	ep := feedIdentRowOf(t, el, execCommTid, row)
	if ep == nil {
		t.Fatal("row of the selected thread must be emitted")
	}
	requireUnnamedOf(t, ep.File, row.ident)
	requireIdentCounts(t, el, 0, 1, 0, 1)

	const want = "\tfile identity: 0 stale fd bindings dropped, 1 rows refused a procfs answer for another file" +
		" (not counting rows a filter dropped: 0 and 1)\n"
	if got := el.fileIdentStatLine(); got != want {
		t.Fatalf("stat line = %q, want %q", got, want)
	}
}

// A refused row has no name, so a -path filter drops it whatever it asks
// for: under -path every refusal is a dropped row's.
func TestRefusalOfARowThePathFilterDropsIsCountedApart(t *testing.T) {
	el := newFilteredEventLoop(t, globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: "pipe"}})
	el.trustFileIdents(true)
	el.fdState().readClockUnknown = false
	row := writeOfClosedFile(t, freeFdNumber(t))

	if ep := feedIdentRowOf(t, el, execCommTid, row); ep != nil {
		t.Fatalf("unnamed row passed the path filter: %v", ep)
	}
	requireIdentCounts(t, el, 0, 0, 0, 1)
}

// bindStale gives fd n of this process an fd table entry of another file
// than ident, bound before every row: the next row of ident drops it.
func bindStale(el *eventLoop, n int32, ident uint32) {
	stale := file.NewFd(n, staleOpenName, syscall.O_RDONLY)
	stale.SetIdent(ident + 1)
	el.fdState().set(n, uint32(os.Getpid()), stale)
}

// The same for the other figure: the binding is dropped for the process
// either way (the selected thread's next row must not be named after it),
// but only a reported row's drop counts as the run's.
func TestStaleBindingOfARowTheCommFilterDropsIsCountedApart(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := identCommLoop(t)
	name, ident := placeFileOn(t, n, "rebound.txt")

	bindStale(el, n, ident)
	if ep := feedIdentRowOf(t, el, identFilteredTid, readRow(n, ident)); ep != nil {
		t.Fatalf("row of the thread -comm does not select was emitted: %v", ep)
	}
	verifyFdNotTracked(t, el, pid, n)
	requireIdentCounts(t, el, 0, 0, 1, 0)

	bindStale(el, n, ident)
	ep := feedIdentRowOf(t, el, execCommTid, readRow(n, ident))
	if ep == nil || ep.File.Name() != name {
		t.Fatalf("row of the selected thread = %v, want one named %q", ep, name)
	}
	requireIdentCounts(t, el, 1, 0, 1, 0)
}

// The line is there for the dropped rows alone, says nothing about them
// when there were none, and keeps the two figures it always had in place.
func TestFileIdentStatLineNamesDroppedRowsApart(t *testing.T) {
	const figures = "\tfile identity: 2 stale fd bindings dropped, 3 rows refused a procfs answer for another file"
	el := identLoop(t)
	tr := el.fdState()

	tr.staleBindings, tr.rejectedAnswers = 2, 3
	if got := el.fileIdentStatLine(); got != figures+"\n" {
		t.Fatalf("stat line without dropped rows = %q, want %q", got, figures+"\n")
	}
	tr.staleBindings, tr.rejectedAnswers = 3, 10
	tr.droppedRowStale, tr.droppedRowRejected = 1, 7
	want := figures + " (not counting rows a filter dropped: 1 and 7)\n"
	if got := el.fileIdentStatLine(); got != want {
		t.Fatalf("stat line = %q, want %q", got, want)
	}
	tr.staleBindings, tr.rejectedAnswers = 1, 7
	if got := el.fileIdentStatLine(); !strings.HasPrefix(got, "\tfile identity: 0 stale fd bindings dropped, 0 rows refused") ||
		!strings.HasSuffix(got, "(not counting rows a filter dropped: 1 and 7)\n") {
		t.Fatalf("stat line of dropped rows only = %q, want zeroes and their note", got)
	}
}
