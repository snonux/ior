package internal

import (
	"testing"

	"ior/internal/globalfilter"
)

// These tests cover the life of a handle name that is scoped to the process
// that took the handle (task 523): it ends with that process, so that the
// next process handed the pid is not named by it, and with nothing less -
// not a thread's exit, not an execve - and an absolute name is nobody's to
// take along.

// handleLeaderTid is the tid of the feed process's thread group leader. The
// feed's own calls are made by another thread of it (defaultTid).
const handleLeaderTid = defaultPid

// assertScopedNameIsGone checks that the next owner of the feed's pid is not
// named by a predecessor's scoped take of testHandleA, and that the tracker
// kept nothing of it.
func assertScopedNameIsGone(t *testing.T, feed *handleFeed) {
	t.Helper()
	assertHandleRow(t, feed, feed.openByHandle(testHandleA, 70), 70, "")
	assertNoHandleNames(t, feed)
	assertScopedIndex(t, feed.el.handleState())
}

// TestScopedHandleNamesEndWithTheirProcess: the group-dead exit record of
// the taker's process drops its scoped names, whichever thread it comes
// from. A process that is later handed the pid - here the same fixture pid -
// opens the handle unnamed instead of by the dead one's relative pathname or
// descriptor name.
func TestScopedHandleNamesEndWithTheirProcess(t *testing.T) {
	for _, source := range scopedSources() {
		t.Run(source.name, func(t *testing.T) {
			feed := newHandleFeed(t, globalfilter.Filter{})
			source.take(feed)

			feed.consume(makeProcessExitEvent(t, feed.time, feed.pid, feed.tid))
			assertScopedNameIsGone(t, feed)
		})
	}
}

// TestScopedHandleNamesEndOnALegacyExitRecord: the 24-byte exit record of an
// object that predates group_dead does not say whether the process died, and
// is treated as the fd table treats it - every exit evicts, because a name
// kept for a dead process is the worse error.
func TestScopedHandleNamesEndOnALegacyExitRecord(t *testing.T) {
	feed := newHandleFeed(t, globalfilter.Filter{})
	feed.nameToHandle("rel.txt", testHandleA)

	legacy := makeProcessExitEvent(t, feed.time, feed.pid, feed.tid)[:24]
	feed.consume(legacy)
	assertScopedNameIsGone(t, feed)
}

// notTheEndOfAProcess lists records that end a thread or a program but not
// the thread group the scoped name belongs to, and one that only looks like
// the pid being handed on.
func notTheEndOfAProcess(t *testing.T, feed *handleFeed) map[string][]byte {
	t.Helper()
	const sibling = defaultTid + 1
	return map[string][]byte{
		// pthread_exit in main: the leader goes first, its threads run on.
		"the leader's exit":     makeThreadExitEvent(t, feed.time, feed.pid, handleLeaderTid),
		"the taking thread's":   makeThreadExitEvent(t, feed.time, feed.pid, feed.tid),
		"another process's end": makeProcessExitEvent(t, feed.time, feed.pid+100, feed.pid+100),
		"an execve":             makeProcessExecEvent(t, feed.time, feed.pid, handleLeaderTid, "next"),
		"a non-leader execve":   makeProcessExecEventFrom(t, feed.time, feed.pid, handleLeaderTid, feed.tid, "next"),
		"a new thread":          makeForkRecord(t, feed.pid, feed.pid, sibling+1, cloneFlagThread),
		"a forked child":        makeForkRecord(t, feed.pid, feed.pid+200, feed.pid+200, 0),
		// Malformed: a new process whose pid is its live creator's.
		// Treated as a recycled pid it would cost a running process its
		// names.
		"its own child": makeForkRecord(t, feed.pid, feed.pid, sibling+2, 0),
	}
}

// TestScopedHandleNamesOutliveThreadsAndExecs: the name is the process's.
// The exit of one of its threads - the leader's included, which can precede
// the others' - leaves it, and so does an execve: the new program has the
// same pid and working directory, and the handle still opens the same file.
// A task record that claims the process is its own new child leaves it too
// (retireRecycledPid; fdTracker.inherit has the same guard).
// Every surviving thread of the process is still named by it.
func TestScopedHandleNamesOutliveThreadsAndExecs(t *testing.T) {
	const sibling = defaultTid + 1
	feed := newHandleFeed(t, globalfilter.Filter{})
	for name, record := range notTheEndOfAProcess(t, feed) {
		t.Run(name, func(t *testing.T) {
			feed := newHandleFeed(t, globalfilter.Filter{})
			feed.nameToHandle("rel.txt", testHandleA)

			feed.consume(record)
			feed.tid = sibling
			assertHandleRow(t, feed, feed.openByHandle(testHandleA, 70), 70, "rel.txt")
			assertScopedIndex(t, feed.el.handleState())
		})
	}
}

// TestRecycledPidDoesNotInheritScopedHandleNames: the exit record of the
// taker's process was lost, so its scoped names are still there when the
// kernel hands the pid to a new process. The new process's task record
// clears them, as it clears the fd table's leftovers.
func TestRecycledPidDoesNotInheritScopedHandleNames(t *testing.T) {
	const creator = defaultPid + 300
	feed := newHandleFeed(t, globalfilter.Filter{})
	feed.nameToHandle("rel.txt", testHandleA)

	feed.consume(makeForkRecord(t, creator, feed.pid, feed.pid, 0))
	feed.tid = feed.pid
	assertScopedNameIsGone(t, feed)
}

// TestAbsoluteHandleNameOutlivesItsTaker: an absolute pathname is filed for
// every opener and is not the taker's to take along; a handle is routinely
// taken by one process for another to open later.
func TestAbsoluteHandleNameOutlivesItsTaker(t *testing.T) {
	feed := newHandleFeed(t, globalfilter.Filter{})
	feed.nameToHandle("/data/a.txt", testHandleA)
	feed.consume(makeProcessExitEvent(t, feed.time, feed.pid, feed.tid))

	assertHandleRow(t, feed, feed.openByHandle(testHandleA, 70), 70, "/data/a.txt")
	feed.asOtherProcess()
	assertHandleRow(t, feed, feed.openByHandle(testHandleA, 71), 71, "/data/a.txt")
}

// TestScopedTakeLeavesTheAbsoluteNameToTheOthers drives the decision of task
// 523 through the loop: process B takes, by a relative pathname, a handle
// process A filed under an absolute one. B's opens are named by B's take,
// A's and a third process's still by the absolute name - rows that used to
// fall back to procfs, failed calls among them unnamed - and when B is gone
// the next owner of its pid is given the absolute name like everyone else.
func TestScopedTakeLeavesTheAbsoluteNameToTheOthers(t *testing.T) {
	const pidA, pidB, pidC = defaultPid, defaultPid + 100, defaultPid + 200
	feed := newHandleFeed(t, globalfilter.Filter{})
	feed.nameToHandle("/data/a.txt", testHandleA)
	feed.pid, feed.tid = pidB, pidB
	feed.nameToHandle("rel.txt", testHandleA)
	assertHandleRow(t, feed, feed.openByHandle(testHandleA, 70), 70, "rel.txt")

	for _, pid := range []uint32{pidA, pidC} {
		feed.pid, feed.tid = pid, pid
		assertHandleRow(t, feed, feed.openByHandle(testHandleA, 71), 71, "/data/a.txt")
	}

	feed.consume(makeProcessExitEvent(t, feed.time, pidB, pidB))
	feed.pid, feed.tid = pidB, pidB
	assertHandleRow(t, feed, feed.openByHandle(testHandleA, 72), 72, "/data/a.txt")
	assertScopedIndex(t, feed.el.handleState())
}
