package internal

import (
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// These tests cover the name_to_handle_at side: which calls file a name under
// a handle, and which name.

// assertNoHandleNames checks that nothing was filed and nothing stays parked.
func assertNoHandleNames(t *testing.T, feed *handleFeed) {
	t.Helper()
	handles := feed.el.handleState()
	if len(handles.names) != 0 {
		t.Fatalf("handle names = %v, want none", handles.names)
	}
	if len(handles.taken) != 0 {
		t.Fatalf("parked handles = %v, want none", handles.taken)
	}
}

// nameToHandleReturning feeds a name_to_handle_at whose exit returned ret,
// with the given records between enter and exit.
func (f *handleFeed) nameToHandleReturning(pathname string, ret int64, between ...[]byte) {
	f.t.Helper()
	_, enter := makeEnterPathEvent(f.t, f.time, f.pid, f.tid, pathname, types.SYS_ENTER_NAME_TO_HANDLE_AT)
	_, exit := makeExitRetEvent(f.t, f.time+100, f.pid, f.tid, types.SYS_EXIT_NAME_TO_HANDLE_AT, ret)
	f.consume(enter)
	f.consume(between...)
	f.consume(exit)
	f.time += 1000
}

// handleRecord builds the control record of the feed's next call (the one
// whose exit is stamped f.time+100).
func (f *handleFeed) handleRecord(h testHandle) types.FileHandleEvent {
	f.t.Helper()
	ev, _ := makeFileHandleEvent(f.t, f.time+100, f.pid, f.tid, h)
	return ev
}

// TestFailedNameToHandleAtFilesNoName: a failed call returned no handle. BPF
// emits no record for it - that includes the EOVERFLOW a caller provokes with
// handle_bytes 0 to learn the size - and even a record that arrived anyway
// must not put the pathname under a handle the call did not return.
func TestFailedNameToHandleAtFilesNoName(t *testing.T) {
	t.Run("size probe without a record", func(t *testing.T) {
		feed := newHandleFeed(t, globalfilter.Filter{})
		feed.nameToHandleReturning("/data/a.txt", -int64(syscall.EOVERFLOW))
		assertNoHandleNames(t, feed)
		assertHandleRow(t, feed, feed.openByHandle(testHandleA, 70), 70, "")
	})
	t.Run("failure with a record", func(t *testing.T) {
		feed := newHandleFeed(t, globalfilter.Filter{})
		record := feed.handleRecord(testHandleA)
		feed.nameToHandleReturning("/data/a.txt", -int64(syscall.ENOENT), eventBytes(t, &record))
		assertNoHandleNames(t, feed)
	})
}

// TestSizeProbeThenRealCallFilesTheName is the usual calling pattern: probe
// with handle_bytes 0 (EOVERFLOW), then call again with a buffer.
func TestSizeProbeThenRealCallFilesTheName(t *testing.T) {
	feed := newHandleFeed(t, globalfilter.Filter{})
	feed.nameToHandleReturning("/data/a.txt", -int64(syscall.EOVERFLOW))
	feed.nameToHandle("/data/a.txt", testHandleA)
	assertHandleRow(t, feed, feed.openByHandle(testHandleA, 70), 70, "/data/a.txt")
}

// TestNameToHandleAtWithoutARecordFilesNoName: a successful call whose handle
// record never arrived (an older BPF object, an unreadable buffer, a record
// lost to backpressure) has no handle to file its pathname under.
func TestNameToHandleAtWithoutARecordFilesNoName(t *testing.T) {
	feed := newHandleFeed(t, globalfilter.Filter{})
	feed.nameToHandleReturning("/data/a.txt", 0)
	assertNoHandleNames(t, feed)
}

// TestHandleRecordIsAcceptedOnlyForItsOwnCall covers the records the loop
// must refuse, each fed between the enter and the exit of a successful
// name_to_handle_at.
func TestHandleRecordIsAcceptedOnlyForItsOwnCall(t *testing.T) {
	tests := map[string]func(ev *types.FileHandleEvent){
		"another tid":          func(ev *types.FileHandleEvent) { ev.Tid++ },
		"another syscall's ID": func(ev *types.FileHandleEvent) { ev.TraceId = types.SYS_ENTER_ACCESS },
		"another call's time":  func(ev *types.FileHandleEvent) { ev.Time-- },
		"an unreadable handle": func(ev *types.FileHandleEvent) { ev.HandleStatus = types.FILE_HANDLE_READ_FAILED },
		"an empty handle":      func(ev *types.FileHandleEvent) { ev.HandleBytes = 0 },
	}
	for name, spoil := range tests {
		t.Run(name, func(t *testing.T) {
			feed := newHandleFeed(t, globalfilter.Filter{})
			record := feed.handleRecord(testHandleA)
			spoil(&record)
			feed.nameToHandleReturning("/data/a.txt", 0, eventBytes(t, &record))
			assertNoHandleNames(t, feed)
		})
	}
}

// TestHandleRecordNeedsAPendingNameToHandleAt: without the call's enter there
// is no exit handler that could name the handle - the enter was shed by the
// raw path filter or lost - and a pending enter of another syscall is not it.
func TestHandleRecordNeedsAPendingNameToHandleAt(t *testing.T) {
	t.Run("no pending enter", func(t *testing.T) {
		feed := newHandleFeed(t, globalfilter.Filter{})
		record := feed.handleRecord(testHandleA)
		feed.consume(eventBytes(t, &record))
		assertNoHandleNames(t, feed)
	})
	t.Run("pending enter of another path syscall", func(t *testing.T) {
		feed := newHandleFeed(t, globalfilter.Filter{})
		_, enter := makeEnterPathEvent(t, feed.time, feed.pid, feed.tid, "/etc/hosts", types.SYS_ENTER_ACCESS)
		record := feed.handleRecord(testHandleA)
		record.TraceId = types.SYS_ENTER_ACCESS
		feed.consume(enter, eventBytes(t, &record))
		assertNoHandleNames(t, feed)
	})
}

// TestLostExitDoesNotMisfileTheNextCall: the handle of a call whose exit
// record was lost stays parked. The thread's next name_to_handle_at - whose
// own record is lost in turn - must not file ITS pathname under that handle:
// the times differ. Positional pairing would name handle A after /data/b.txt.
func TestLostExitDoesNotMisfileTheNextCall(t *testing.T) {
	feed := newHandleFeed(t, globalfilter.Filter{})
	_, enter := makeEnterPathEvent(t, feed.time, feed.pid, feed.tid, "/data/a.txt", types.SYS_ENTER_NAME_TO_HANDLE_AT)
	record := feed.handleRecord(testHandleA)
	feed.consume(enter, eventBytes(t, &record))
	feed.time += 1000

	feed.nameToHandleReturning("/data/b.txt", 0)
	assertNoHandleNames(t, feed)
	assertHandleRow(t, feed, feed.openByHandle(testHandleA, 70), 70, "")
}

// nameToHandleOfFd feeds a successful name_to_handle_at(fd, "", AT_EMPTY_PATH)
// that returned handle h: the handle of the file behind a descriptor.
func (f *handleFeed) nameToHandleOfFd(fd int32, h testHandle) {
	f.t.Helper()
	ev, _ := makeEnterPathEvent(f.t, f.time, f.pid, f.tid, "", types.SYS_ENTER_NAME_TO_HANDLE_AT)
	ev.Dirfd = fd
	ev.Flags = unix.AT_EMPTY_PATH
	ev.PathnameStatus = types.PATH_READ_OK
	ev.TargetStatus = types.PATH_TARGET_REQUIRED
	_, record := makeFileHandleEvent(f.t, f.time+100, f.pid, f.tid, h)
	_, exit := makeExitRetEvent(f.t, f.time+100, f.pid, f.tid, types.SYS_EXIT_NAME_TO_HANDLE_AT, 0)
	f.consume(eventBytes(f.t, &ev), record, exit)
	f.time += 1000
}

// TestHandleTakenThroughADescriptorCarriesItsTrackedName replaces the opaque
// stash rules of tasks l03 and m03. A handle taken with AT_EMPTY_PATH is
// filed under whatever ior calls the descriptor - a traced memfd or pidfd
// name, the directory an O_TMPFILE file is tracked under, a relative path as
// the task spelled it. None of these names can be compared with a /proc link,
// which is why such a stash used to be spent on the thread's NEXT open,
// whichever handle that opened. Keyed by the handle, each names its own open
// and no other, in any order.
func TestHandleTakenThroughADescriptorCarriesItsTrackedName(t *testing.T) {
	names := []string{"memfd:scratch", "pidfd:0", "/data/tmpfile-dir", "relative/file.txt", "fsopen:ext4"}
	for _, tracked := range names {
		t.Run(tracked, func(t *testing.T) {
			feed := newHandleFeed(t, globalfilter.Filter{})
			feed.el.fdState().set(5, feed.pid, file.NewFd(5, tracked, syscall.O_RDWR))
			feed.nameToHandleOfFd(5, testHandleA)
			feed.nameToHandle("/data/b.txt", testHandleB)

			assertHandleRow(t, feed, feed.openByHandle(testHandleB, 70), 70, "/data/b.txt")
			assertHandleRow(t, feed, feed.openByHandle(testHandleA, 71), 71, tracked)
			assertHandleRow(t, feed, feed.openByHandle(defaultTestHandle, 72), 72, "")
		})
	}
}

// TestRelativePathHandleNamesItsOwnOpenOnly: a relative pathname is filed as
// the task spelled it (ior does not know the task's working directory).
func TestRelativePathHandleNamesItsOwnOpenOnly(t *testing.T) {
	feed := newHandleFeed(t, globalfilter.Filter{})
	feed.nameToHandle("rel.txt", testHandleA)

	assertHandleRow(t, feed, feed.openByHandle(testHandleB, 70), 70, "")
	assertHandleRow(t, feed, feed.openByHandle(testHandleA, 71), 71, "rel.txt")
}

// TestAmendingControlRecordsPassAHeldRestart: a handle record, like a name
// fixup, belongs to a call made inside a signal handler and must not end the
// wait of the interrupted row held for that tid; other control records do.
func TestAmendingControlRecordsPassAHeldRestart(t *testing.T) {
	if !amendsPendingEnter(&types.FileHandleEvent{}) || !amendsPendingEnter(&types.OpenNameFixupEvent{}) {
		t.Fatal("a handle record and a name fixup amend the pending enter")
	}
	if amendsPendingEnter(&types.ProcessExitEvent{}) || amendsPendingEnter(&types.TaskRenameEvent{}) {
		t.Fatal("a task record does not amend a pending enter")
	}
}
