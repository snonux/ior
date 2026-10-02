package internal

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

// These tests cover the one check the procfs fallback of an unknown handle
// has (task 423, reachableByHandle): what /proc/<pid>/fd/<fd> shows under the
// number an open_by_handle_at returned is not believed when it is a kind of
// file no handle can open, because the number was reused by then.

// TestReachableByHandleLinkTexts pins the deny list on link texts: the three
// handle-less kinds, the exact pidfd exemption, and everything else passing.
func TestReachableByHandleLinkTexts(t *testing.T) {
	denied := []string{
		"socket:[6343197]", "pipe:[6343199]", "anon_inode:[eventfd]",
		"anon_inode:[eventpoll]", "anon_inode:[timerfd]", "anon_inode:inotify",
		"anon_inode:[pidfd] (deleted)", "anon_inode:[pidfd]x", "anon_inode:",
	}
	for _, target := range denied {
		if reachableByHandle(target) {
			t.Errorf("reachableByHandle(%q) = true, want false", target)
		}
	}
	kept := []string{
		"anon_inode:[pidfd]", "pidfd:[77]", "net:[4026531833]",
		"mnt:[4026531832]", "cgroup:[4026531835]", "/data/a.txt",
		"/memfd:x (deleted)", "/data/socket:[1]", "relative", "",
	}
	for _, target := range kept {
		if !reachableByHandle(target) {
			t.Errorf("reachableByHandle(%q) = false, want true", target)
		}
	}
}

// reusedKind is a descriptor of this test process that stands for what a
// number is by the time the loop looks at it.
type reusedKind struct {
	name string
	// linkPrefix is what the descriptor's /proc link must start with for the
	// case to test what it says.
	linkPrefix string
	open       func(t *testing.T) int
}

// closeOnCleanup closes fd when the test ends and returns it.
func closeOnCleanup(t *testing.T, fd int, err error, what string) int {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	return fd
}

// testPipeEnd returns one end of a new pipe (0 reads, 1 writes).
func testPipeEnd(t *testing.T, end int) int {
	t.Helper()
	var p [2]int
	if err := syscall.Pipe(p[:]); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(p[0]); _ = syscall.Close(p[1]) })
	return p[end]
}

// handleLessKinds are descriptors no open_by_handle_at can return.
func handleLessKinds() []reusedKind {
	return []reusedKind{
		{"a socket", "socket:[", func(t *testing.T) int {
			fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
			return closeOnCleanup(t, fd, err, "socket")
		}},
		{"the read end of a pipe", "pipe:[", func(t *testing.T) int { return testPipeEnd(t, 0) }},
		{"the write end of a pipe", "pipe:[", func(t *testing.T) int { return testPipeEnd(t, 1) }},
		{"an eventfd", "anon_inode:", func(t *testing.T) int {
			fd, err := unix.Eventfd(0, 0)
			return closeOnCleanup(t, fd, err, "eventfd")
		}},
		{"an epoll descriptor", "anon_inode:", func(t *testing.T) int {
			fd, err := unix.EpollCreate1(0)
			return closeOnCleanup(t, fd, err, "epoll_create1")
		}},
	}
}

// handleOpenableKinds are the non-path descriptors a handle CAN open.
func handleOpenableKinds() []reusedKind {
	return []reusedKind{
		{"a pidfd", pidfdLinkText, func(t *testing.T) int {
			fd, err := unix.PidfdOpen(os.Getpid(), 0)
			if errors.Is(err, unix.ENOSYS) {
				t.Skip("pidfd_open is not implemented on this kernel (before 5.3)")
			}
			return closeOnCleanup(t, fd, err, "pidfd_open")
		}},
		{"a namespace", "net:[", func(t *testing.T) int {
			fd, err := syscall.Open("/proc/self/ns/net", syscall.O_RDONLY, 0)
			return closeOnCleanup(t, fd, err, "open /proc/self/ns/net")
		}},
	}
}

// requireProcLink returns what procfs calls descriptor fd of this process,
// and fails the test unless that is the kind the case is about: a case whose
// link read otherwise would pass, or fail, for a reason that is not its own.
func requireProcLink(t *testing.T, fd int, prefix string) string {
	t.Helper()
	link := file.NewFdWithPid(int32(fd), uint32(os.Getpid())).Name()
	if !strings.HasPrefix(link, prefix) {
		t.Fatalf("/proc/self/fd/%d reads %q, want a %q link", fd, link, prefix)
	}
	return link
}

// takeHandleOf asks the kernel of this host for the handle of descriptor fd.
func takeHandleOf(fd int) error {
	_, _, err := unix.NameToHandleAt(fd, "", unix.AT_EMPTY_PATH)
	return err
}

// requireNotExportable checks the deny list against the kernel the test runs
// on: err is what name_to_handle_at answered for a descriptor of a denied
// kind. Only a handle (no error) proves the list wrong. EOPNOTSUPP confirms
// it; any other error - EPERM under a seccomp filter, ENOSYS without the
// syscall - means this kernel could not be asked, which says nothing about
// the list, so it is logged and the rest of the test, which does not depend
// on the answer, runs.
func requireNotExportable(t *testing.T, kind string, err error) {
	t.Helper()
	switch {
	case err == nil:
		t.Fatalf("name_to_handle_at of %s returned a handle: the deny list is wrong for this kernel", kind)
	case !errors.Is(err, unix.EOPNOTSUPP):
		t.Logf("name_to_handle_at of %s: %v (this kernel cannot be asked; deny list not checked against it)", kind, err)
	}
}

// TestUnknownHandleIsNotNamedAfterAHandleLessDescriptor: the number the call
// returned is a socket, a pipe or an anonymous inode by the time the loop
// reads its /proc link. The row and the fd table entry stay unnamed, with the
// call's flags (the fdinfo is the newer file's) and the procfs mark; they
// used to be named "socket:[N]", "pipe:[N]" or "anon_inode:[eventfd]".
func TestUnknownHandleIsNotNamedAfterAHandleLessDescriptor(t *testing.T) {
	for _, kind := range handleLessKinds() {
		t.Run(kind.name, func(t *testing.T) {
			fd := kind.open(t)
			requireProcLink(t, fd, kind.linkPrefix)
			requireNotExportable(t, kind.name, takeHandleOf(fd))

			feed := newLiveHandleFeed(t)
			ep := feed.openByHandle(testHandleB, int64(fd))
			assertHandleRow(t, feed, ep, int32(fd), "")
			fdFile := ep.File.(*file.FdFile)
			if got := fdFile.Flags(); got != file.Flags(syscall.O_RDONLY) {
				t.Fatalf("row flags = %v, want the call's O_RDONLY", got)
			}
			if !fdFile.NameFromProcFS() {
				t.Fatal("the unnamed entry is not marked as a look at procfs")
			}
		})
	}
}

// TestUnknownHandleKeepsTheProcfsNameOfAnOpenableDescriptor is the other
// side: a pidfd and a namespace descriptor are what an open_by_handle_at
// returns for a pidfs or nsfs handle, so their link text names the row.
func TestUnknownHandleKeepsTheProcfsNameOfAnOpenableDescriptor(t *testing.T) {
	for _, kind := range handleOpenableKinds() {
		t.Run(kind.name, func(t *testing.T) {
			fd := kind.open(t)
			link := requireProcLink(t, fd, kind.linkPrefix)
			if err := takeHandleOf(fd); err != nil {
				// Older kernels export neither; the name is then believed too
				// readily, which is the accepted side of the deny list.
				t.Logf("name_to_handle_at of %s: %v (not exportable on this kernel)", kind.name, err)
			}

			feed := newLiveHandleFeed(t)
			assertHandleRow(t, feed, feed.openByHandle(testHandleB, int64(fd)), int32(fd), link)
		})
	}
}

// fdRow feeds one successful fd syscall (enter, exit) on descriptor fd by
// the feed's task and returns the row it emitted.
func (f *handleFeed) fdRow(enter, exit types.TraceId, fd int32) *event.Pair {
	f.t.Helper()
	_, enterRaw := makeEnterFdEvent(f.t, f.time, f.pid, f.tid, fd, enter)
	_, exitRaw := makeExitRetEvent(f.t, f.time+100, f.pid, f.tid, exit, 0)
	before := len(f.rows)
	f.consume(enterRaw, exitRaw)
	f.time += 1000
	if len(f.rows) != before+1 {
		f.t.Fatalf("%s emitted %d rows, want 1", enter.Name(), len(f.rows)-before)
	}
	return f.rows[before]
}

// assertUnnamedWithCallFlags checks a row on the kept unnamed entry: no
// name, and the flags of the open_by_handle_at that made the entry.
func assertUnnamedWithCallFlags(t *testing.T, ep *event.Pair) {
	t.Helper()
	fdFile, isFd := ep.File.(*file.FdFile)
	if !isFd || fdFile.Name() != "" || fdFile.Flags() != file.Flags(syscall.O_RDONLY) {
		t.Fatalf("%s row file = %v, want unnamed with the call's O_RDONLY", ep.EnterEv.GetTraceId().Name(), ep.File)
	}
}

// TestRefusedProcfsNameLastsUntilTheClose pins how long the unnamed entry
// of a refused answer lives (procFdFile). It is kept so that the rows on
// the number are not named after the newer file while they are still the
// call's own descriptor's: they stay unnamed, with the call's flags, up to
// and including the close. The close removes the entry, and the next row
// on the number asks procfs afresh and gets the socket that holds it now.
func TestRefusedProcfsNameLastsUntilTheClose(t *testing.T) {
	kind := handleLessKinds()[0]
	fd := int32(kind.open(t))
	link := requireProcLink(t, int(fd), kind.linkPrefix)
	feed := newLiveHandleFeed(t)
	assertHandleRow(t, feed, feed.openByHandle(testHandleB, int64(fd)), fd, "")

	assertUnnamedWithCallFlags(t, feed.fdRow(types.SYS_ENTER_READ, types.SYS_EXIT_READ, fd))
	assertUnnamedWithCallFlags(t, feed.fdRow(types.SYS_ENTER_CLOSE, types.SYS_EXIT_CLOSE, fd))
	if tracked, ok := feed.el.fdState().get(fd, feed.pid); ok {
		t.Fatalf("the close left the unnamed entry %v in the fd table", tracked)
	}

	after := feed.fdRow(types.SYS_ENTER_READ, types.SYS_EXIT_READ, fd)
	if got := after.File.Name(); got != link {
		t.Fatalf("row after the close named %q, want the fresh procfs answer %q", got, link)
	}
}
