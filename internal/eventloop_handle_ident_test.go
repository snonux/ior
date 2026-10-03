package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

// Task a23: the exit record of an open_by_handle_at says which file the call
// opened (its identity, task 603). The procfs fallback for a handle ior has no
// name for is checked against it: an answer of another file is a file that
// reused the number before the loop looked, and the row and the fd table
// entry stay unnamed, as for the kinds of task 423's deny list - but this
// covers a reuse by a regular file as well, which the deny list cannot.

// openByHandleWithIdent feeds an open_by_handle_at of handle h by the feed's
// task that returned fd and whose exit record identifies the opened file as
// ident, and returns its row.
func (f *handleFeed) openByHandleWithIdent(h testHandle, fd int32, ident uint32) *event.Pair {
	f.t.Helper()
	_, enter := makeEnterOpenByHandleEvent(f.t, f.time, f.pid, f.tid, syscall.O_RDONLY, h)
	exit := types.RetEvent{EventType: types.EXIT_RET_EVENT, TraceId: types.SYS_EXIT_OPEN_BY_HANDLE_AT,
		Time: f.time + 100, Ret: int64(fd), Pid: f.pid, Tid: f.tid, FileIdent: ident}
	exitRaw, err := exit.Bytes()
	if err != nil {
		f.t.Fatalf("RetEvent.Bytes: %v", err)
	}
	f.time += 1000
	before := len(f.rows)
	f.consume(enter, exitRaw)
	if len(f.rows) != before+1 {
		f.t.Fatalf("open_by_handle_at emitted %d rows, want 1", len(f.rows)-before)
	}
	return f.rows[before]
}

// newIdentHandleFeed is newLiveHandleFeed in a run that captures file
// identities (captured) or not.
func newIdentHandleFeed(t *testing.T, captured bool) *handleFeed {
	t.Helper()
	feed := newLiveHandleFeed(t)
	feed.el.trustFileIdents(captured)
	feed.el.fdState().readClockUnknown = false
	return feed
}

// The number holds a regular file when the loop looks. The exit record says
// whether that is the file the call opened: the same identity, or none, and
// procfs names the row; another identity, and the row and the entry are
// unnamed, keep the call's flags and the identity of the opened file, and
// the refusal is counted. A run without the capture does not read the word.
func TestUnknownHandleProcfsNameIsCheckedAgainstTheOpenedFile(t *testing.T) {
	tests := []struct {
		name        string
		captured    bool
		identDelta  uint32 // added to the identity of the file on the number
		zeroIdent   bool   // the exit record reports no identity
		wantNamed   bool
		wantRefused uint64
	}{
		{name: "same file", captured: true, wantNamed: true},
		{name: "another file", captured: true, identDelta: 1, wantRefused: 1},
		{name: "no identity in the exit record", captured: true, zeroIdent: true, wantNamed: true},
		{name: "another file, run without the capture", identDelta: 1, wantNamed: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := freeFdNumber(t)
			name, ident := placeFileOn(t, n, "reused-by-a-file.txt")
			opened := ident + tc.identDelta
			if tc.zeroIdent {
				opened = 0
			}
			feed := newIdentHandleFeed(t, tc.captured)
			ep := feed.openByHandleWithIdent(testHandleB, n, opened)
			assertHandleIdentRow(t, feed, ep, n, map[bool]string{true: name, false: ""}[tc.wantNamed])
			if got := feed.el.fdState().rejectedAnswers; got != tc.wantRefused {
				t.Fatalf("rejectedAnswers = %d, want %d", got, tc.wantRefused)
			}
			if tc.wantNamed {
				return
			}
			fdFile := ep.File.(*file.FdFile)
			if fdFile.Ident() != opened || fdFile.Flags() != file.Flags(syscall.O_RDONLY) || !fdFile.NameFromProcFS() {
				t.Fatalf("refused row = %v (ident %d), want the opened identity %d, the call's flags and the mark",
					fdFile, fdFile.Ident(), opened)
			}
		})
	}
}

// assertHandleIdentRow is assertHandleRow, and the row shows the identity
// rendering of an unnamed file (E:ino:<n>) when wantName is empty.
func assertHandleIdentRow(t *testing.T, feed *handleFeed, ep *event.Pair, fd int32, wantName string) {
	t.Helper()
	assertHandleRow(t, feed, ep, fd, wantName)
	if wantName == "" && ep.File.(*file.FdFile).Ident() == 0 {
		t.Fatalf("unnamed row %v has no identity", ep.File)
	}
}

// A handle ior has a name for is named by it whatever the number holds by
// now: the identity check is only for the procfs fallback.
func TestNamedHandleIsNotCheckedAgainstProcfs(t *testing.T) {
	n := freeFdNumber(t)
	_, ident := placeFileOn(t, n, "reused-by-a-file.txt")
	feed := newIdentHandleFeed(t, true)
	feed.nameToHandle("/data/b.txt", testHandleB)
	ep := feed.openByHandleWithIdent(testHandleB, n, ident+1)
	assertHandleRow(t, feed, ep, n, "/data/b.txt")
	if got := ep.File.(*file.FdFile).Ident(); got != ident+1 {
		t.Fatalf("row identity = %d, want the exit record's %d", got, ident+1)
	}
	requireNothingCounted(t, feed.el)
}

// An answer that changed under both readings mixes two files and is refused
// in a run with the capture, whether or not the exit record names the opened
// file (task d23: without an identity it used to name the row); one
// consistent reading names the row. Read twice either way (readProcFd). A
// torn answer is not counted as refused for another file, as in
// resolveUntracked.
func TestUnknownHandleProcfsNameThatChangedUnderTheReadIsRefused(t *testing.T) {
	for _, opened := range []uint32{4711, 0} {
		for _, stable := range []bool{false, true} {
			feed := newIdentHandleFeed(t, true)
			proc := &scriptedProc{answers: []procAnswer{{name: "/data/torn.txt", ident: 4711, stable: stable}}}
			feed.el.fdState().readFdIdent = proc.read
			ep := feed.openByHandleWithIdent(testHandleB, 9, opened)
			want := map[bool]string{true: "/data/torn.txt", false: ""}[stable]
			assertHandleRow(t, feed, ep, 9, want)
			if got := identOf(ep.File); got != opened {
				t.Fatalf("opened=%d stable=%v: row identity %d, want %d", opened, stable, got, opened)
			}
			if wantReads := map[bool]int{true: 1, false: 2}[stable]; proc.reads != wantReads {
				t.Fatalf("opened=%d stable=%v: procfs read %d times, want %d", opened, stable, proc.reads, wantReads)
			}
			requireNothingCounted(t, feed.el)
		}
	}
}

// Without the capture there is no second reading, so nothing is torn: the
// fallback names the row from its one reading, as before task a23.
func TestUnknownHandleProcfsNameWithoutTheCaptureIsReadOnce(t *testing.T) {
	feed := newIdentHandleFeed(t, false)
	proc := &scriptedProc{answers: []procAnswer{{name: "/data/torn.txt", ident: 4711, stable: false}}}
	feed.el.fdState().readFdIdent = proc.read
	n := freeFdNumber(t)
	name, _ := placeFileOn(t, n, "read-once.txt")
	ep := feed.openByHandleWithIdent(testHandleB, n, 0)
	assertHandleRow(t, feed, ep, n, name)
	if proc.reads != 0 {
		t.Fatalf("scripted reader asked %d times in a run without the capture", proc.reads)
	}
}
