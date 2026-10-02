package internal

import (
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// These tests cover where the name of a handle may come from and whom it is
// given to: a name is filed for every later open of the handle, by any
// process, so it must be one a traced call gave ior, and a name that only
// means something in the process that took the handle must stay there.

// unopenedFd is a descriptor number no test process has open, so that an
// open_by_handle_at "returning" it cannot be named by procfs either.
const unopenedFd = 1 << 20

// asOtherProcess makes the feed's next calls those of a task of another
// process (one that does not exist on this host).
func (f *handleFeed) asOtherProcess() {
	f.pid, f.tid = defaultPid+100, defaultPid+100
}

// untrackedSource is one way a name_to_handle_at can name its file through a
// descriptor whose only name is the /proc link the loop would read now, or
// was when the entry it is a copy of was made (a dup, a fork): the copy
// keeps the mark of its source (FdFile.Dup).
type untrackedSource struct {
	name string
	take func(feed *handleFeed, fd int32)
}

func untrackedSources() []untrackedSource {
	return []untrackedSource{
		{"the descriptor itself", func(feed *handleFeed, fd int32) {
			feed.nameToHandleOfFd(fd, testHandleA)
		}},
		{"a path below the descriptor", func(feed *handleFeed, fd int32) {
			feed.nameToHandleUnder(fd, "below.txt", 0, testHandleA)
		}},
		{"a table entry named from procfs", func(feed *handleFeed, fd int32) {
			feed.trackFromProcfs(fd)
			feed.nameToHandleOfFd(fd, testHandleA)
		}},
		{"a duplicate of a table entry named from procfs", func(feed *handleFeed, fd int32) {
			const dupFd = unopenedFd + 1
			feed.el.registerDup(feed.trackFromProcfs(fd), feed.pid, dupFd, 0)
			feed.requireNamedEntry(dupFd)
			feed.nameToHandleOfFd(dupFd, testHandleA)
		}},
		{"a forked child's copy of a table entry named from procfs", func(feed *handleFeed, fd int32) {
			feed.trackFromProcfs(fd)
			parent := feed.pid
			feed.asOtherProcess()
			feed.el.fdState().inherit(parent, feed.pid)
			feed.requireNamedEntry(fd)
			feed.nameToHandleOfFd(fd, testHandleA)
		}},
	}
}

// trackFromProcfs puts descriptor fd of the feed's process into the fd table
// under the name its /proc link has now, as an open_by_handle_at of an
// unknown handle or an io_uring_setup does, and returns the entry.
func (f *handleFeed) trackFromProcfs(fd int32) *file.FdFile {
	f.t.Helper()
	fdFile := file.NewFdWithPid(fd, f.pid)
	f.el.fdState().set(fd, f.pid, fdFile)
	f.requireNamedEntry(fd)
	return fdFile
}

// requireNamedEntry fails the test unless the fd table holds a named entry
// for descriptor fd of the feed's process. The sources that copy an entry
// need it: a copy that was never made, or has no name, would file nothing
// for that reason alone, and the test would pass without the mark.
func (f *handleFeed) requireNamedEntry(fd int32) {
	f.t.Helper()
	if tracked, ok := f.el.fdState().get(fd, f.pid); !ok || tracked.Name() == "" {
		f.t.Fatalf("fd table entry (pid=%d, fd=%d) = %v (ok=%v), want a named one", f.pid, fd, tracked, ok)
	}
}

// TestHandleTakenThroughAnUntrackedDescriptorFilesNoName pins the failure
// mode a procfs-derived source name had. The descriptor the handle is taken
// through is not in ior's fd table, so its only name is the /proc link as it
// is when the loop handles the exit - and here that link is a decoy, standing
// for the newer file a task opened under the number after it closed the one
// the handle belongs to. Filing it would name every later open of the handle,
// by any process, after the decoy. Nothing is filed, and the open falls
// back like one of an unknown handle.
func TestHandleTakenThroughAnUntrackedDescriptorFilesNoName(t *testing.T) {
	for _, source := range untrackedSources() {
		t.Run(source.name, func(t *testing.T) {
			decoy := int32(openTestFd(t, t.TempDir(), syscall.O_RDONLY|syscall.O_DIRECTORY))
			feed := newLiveHandleFeed(t)

			source.take(feed, decoy)
			assertNoHandleNames(t, feed)
			assertHandleRow(t, feed, feed.openByHandle(testHandleA, unopenedFd), unopenedFd, "")
		})
	}
}

// TestUnnamedTakeLeavesTheAbsoluteNameInPlace drives the decision of the
// task 523 review through the loop: the handle already has an absolute name
// when it is taken again through a descriptor ior cannot name. That take
// files nothing - the decoy least of all - and is no evidence against the
// older name, so the taker and every other process are still named by it
// (k03 dropped it, and every opener fell back to procfs).
func TestUnnamedTakeLeavesTheAbsoluteNameInPlace(t *testing.T) {
	const older = "/data/older-name.txt"
	for _, source := range untrackedSources() {
		t.Run(source.name, func(t *testing.T) {
			decoy := int32(openTestFd(t, t.TempDir(), syscall.O_RDONLY|syscall.O_DIRECTORY))
			feed := newLiveHandleFeed(t)
			feed.nameToHandle(older, testHandleA)

			source.take(feed, decoy)
			want := map[handleKey]handleEntry{testHandleA.key(): {absolute: older}}
			if got := feed.el.handleState().names; !reflect.DeepEqual(got, want) {
				t.Fatalf("handle names = %v, want %v", got, want)
			}
			assertHandleRow(t, feed, feed.openByHandle(testHandleA, unopenedFd), unopenedFd, older)
			feed.pid, feed.tid = defaultPid+200, defaultPid+200
			assertHandleRow(t, feed, feed.openByHandle(testHandleA, unopenedFd), unopenedFd, older)
		})
	}
}

// TestHandleTakenBelowATrackedDirectoryIsFiledAbsolute is the other side: a
// dirfd ior saw being opened has a traced name, the joined path is absolute,
// and it names the open of the handle in any process.
func TestHandleTakenBelowATrackedDirectoryIsFiledAbsolute(t *testing.T) {
	feed := newHandleFeed(t, globalfilter.Filter{})
	feed.el.fdState().set(5, feed.pid, file.NewFd(5, "/data/dir", syscall.O_RDONLY|syscall.O_DIRECTORY))
	feed.nameToHandleUnder(5, "sub/a.txt", 0, testHandleA)
	feed.nameToHandleOfFd(5, testHandleB)

	feed.asOtherProcess()
	assertHandleRow(t, feed, feed.openByHandle(testHandleA, 70), 70, "/data/dir/sub/a.txt")
	assertHandleRow(t, feed, feed.openByHandle(testHandleB, 71), 71, "/data/dir")
}

// TestHandleBelowAnUnnamedOrUnaskedDirectoryFilesNoName: a tracked dirfd
// helps only if ior has a name for it and the call really went through it. A
// path below a descriptor ior tracks without a name (its own pathname was
// never read) would be filed as if it were relative to the working
// directory; an empty pathname without AT_EMPTY_PATH is not the descriptor
// (the kernel answers ENOENT, so such a successful record is not BPF's).
func TestHandleBelowAnUnnamedOrUnaskedDirectoryFilesNoName(t *testing.T) {
	t.Run("unnamed directory", func(t *testing.T) {
		feed := newHandleFeed(t, globalfilter.Filter{})
		feed.el.fdState().set(5, feed.pid, file.NewFd(5, "", syscall.O_RDONLY|syscall.O_DIRECTORY))
		feed.nameToHandleUnder(5, "a.txt", 0, testHandleA)
		assertNoHandleNames(t, feed)
	})
	t.Run("empty pathname without AT_EMPTY_PATH", func(t *testing.T) {
		feed := newHandleFeed(t, globalfilter.Filter{})
		feed.el.fdState().set(5, feed.pid, file.NewFd(5, "/data/dir", syscall.O_RDONLY|syscall.O_DIRECTORY))
		feed.nameToHandleUnder(5, "", 0, testHandleA)
		assertNoHandleNames(t, feed)
	})
}

// TestHandleOfTheWorkingDirectoryFilesNoName: an empty pathname at AT_FDCWD
// is the caller's working directory, which ior has no name for.
func TestHandleOfTheWorkingDirectoryFilesNoName(t *testing.T) {
	feed := newHandleFeed(t, globalfilter.Filter{})
	feed.nameToHandleUnder(unix.AT_FDCWD, "", unix.AT_EMPTY_PATH, testHandleA)
	assertNoHandleNames(t, feed)
}

// TestHandleOfAnUnvalidatedPathnameFilesNoName: the name is only filed when
// the record says the pathname was read and the kernel had to resolve it.
// BPF never reports a successful name_to_handle_at otherwise, so these are
// records of a foreign producer; like resolvePathEvent the loop fails closed
// rather than file a string it cannot vouch for.
func TestHandleOfAnUnvalidatedPathnameFilesNoName(t *testing.T) {
	spoils := map[string]func(ev *types.PathEvent){
		"pathname read failed": func(ev *types.PathEvent) { ev.PathnameStatus = types.PATH_READ_FAILED },
		"target not validated": func(ev *types.PathEvent) { ev.TargetStatus = types.PATH_TARGET_UNKNOWN },
	}
	for name, spoil := range spoils {
		t.Run(name, func(t *testing.T) {
			feed := newHandleFeed(t, globalfilter.Filter{})
			enter, _ := makeEnterPathEvent(t, feed.time, feed.pid, feed.tid, "/data/a.txt", types.SYS_ENTER_NAME_TO_HANDLE_AT)
			spoil(&enter)
			record := feed.handleRecord(testHandleA)
			_, exit := makeExitRetEvent(t, feed.time+handleCallDuration, feed.pid, feed.tid, types.SYS_EXIT_NAME_TO_HANDLE_AT, 0)
			feed.consume(eventBytes(t, &enter), eventBytes(t, &record), exit)
			assertNoHandleNames(t, feed)
		})
	}
}

// scopedSource is one way a name_to_handle_at gets a name that is not an
// absolute pathname.
type scopedSource struct {
	name string
	take func(feed *handleFeed)
	want string
}

func scopedSources() []scopedSource {
	const dirfd = 5
	track := func(feed *handleFeed, name string) {
		feed.el.fdState().set(dirfd, feed.pid, file.NewFd(dirfd, name, syscall.O_RDONLY))
	}
	return []scopedSource{
		{"a pathname relative to the working directory", func(feed *handleFeed) {
			feed.nameToHandle("rel.txt", testHandleA)
		}, "rel.txt"},
		{"a descriptor without a path", func(feed *handleFeed) {
			track(feed, "memfd:scratch")
			feed.nameToHandleOfFd(dirfd, testHandleA)
		}, "memfd:scratch"},
		{"a path below a directory opened by a relative name", func(feed *handleFeed) {
			track(feed, "reldir")
			feed.nameToHandleUnder(dirfd, "a.txt", 0, testHandleA)
		}, filepath.Join("reldir", "a.txt")},
	}
}

// TestScopedHandleNameStaysInTheProcessThatTookIt: a name that is not an
// absolute pathname is relative to the taker's working directory, or names
// one of its descriptors, and says nothing in another process. Every thread
// of the taking process is named by it; an opener in another process falls
// back, and the entry is still there for the taker afterwards.
func TestScopedHandleNameStaysInTheProcessThatTookIt(t *testing.T) {
	for _, source := range scopedSources() {
		t.Run(source.name, func(t *testing.T) {
			feed := newHandleFeed(t, globalfilter.Filter{})
			source.take(feed)

			feed.tid = defaultTid + 1
			assertHandleRow(t, feed, feed.openByHandle(testHandleA, 70), 70, source.want)

			feed.asOtherProcess()
			assertHandleRow(t, feed, feed.openByHandle(testHandleA, 71), 71, "")
			failed := feed.openByHandle(testHandleA, -int64(syscall.ESTALE))
			assertFailedHandleRow(t, failed, syscall.ESTALE, "")

			feed.pid, feed.tid = defaultPid, defaultTid
			assertHandleRow(t, feed, feed.openByHandle(testHandleA, 72), 72, source.want)
		})
	}
}

// TestHandleRecordOfACallWhoseEnterNeverArrivedIsRefused: the enter pending
// for the tid can be an EARLIER name_to_handle_at, one whose exit record was
// lost, while the enter of the call the handle record belongs to never got
// here (lost, or shed by -path). Record and exit agree with each other, so
// only the enter time in the record tells that the pending pathname is not
// this call's; without it handle B would be filed as /data/a.txt for good.
func TestHandleRecordOfACallWhoseEnterNeverArrivedIsRefused(t *testing.T) {
	feed := newHandleFeed(t, globalfilter.Filter{})
	_, staleEnter := makeEnterPathEvent(t, feed.time, feed.pid, feed.tid, "/data/a.txt", types.SYS_ENTER_NAME_TO_HANDLE_AT)
	feed.consume(staleEnter)
	feed.time += 1000

	exitTime := feed.time + handleCallDuration
	_, record := makeFileHandleEvent(t, exitTime, feed.pid, feed.tid, testHandleB)
	_, exit := makeExitRetEvent(t, exitTime, feed.pid, feed.tid, types.SYS_EXIT_NAME_TO_HANDLE_AT, 0)
	feed.consume(record, exit)
	feed.time += 1000

	assertNoHandleNames(t, feed)
	assertHandleRow(t, feed, feed.openByHandle(testHandleB, 70), 70, "")
}

// TestMalformedNameToHandleAtExitDropsTheParkedHandle: an exit that is not a
// ret record files nothing, and it still ends the call, so the handle parked
// for it must not wait for the thread's next name_to_handle_at.
func TestMalformedNameToHandleAtExitDropsTheParkedHandle(t *testing.T) {
	feed := newHandleFeed(t, globalfilter.Filter{})
	enter, _ := makeEnterPathEvent(t, feed.time, feed.pid, feed.tid, "/data/a.txt", types.SYS_ENTER_NAME_TO_HANDLE_AT)
	exitTime := feed.time + handleCallDuration
	feed.el.handleState().park(feed.tid, testHandleA.key(), exitTime)

	ep := event.NewPair(&enter)
	ep.ExitEv = &types.FdEvent{EventType: types.ENTER_FD_EVENT, Time: exitTime, Pid: feed.pid, Tid: feed.tid}
	if feed.el.recordNameToHandleAt(ep, &enter) {
		t.Fatal("a name_to_handle_at pair was kept for emission")
	}
	assertNoHandleNames(t, feed)
}
