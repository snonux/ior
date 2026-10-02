package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

func pairRet(t *testing.T, ep *event.Pair) int64 {
	t.Helper()
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		t.Fatalf("exit event is %T, want *types.RetEvent", ep.ExitEv)
	}
	return retEv.Ret
}

func assertFailedHandleRow(t *testing.T, ep *event.Pair, errno syscall.Errno, wantName string) {
	t.Helper()
	if ep == nil {
		t.Fatal("failed open_by_handle_at emitted no row")
	}
	if !ep.Is(types.SYS_ENTER_OPEN_BY_HANDLE_AT) {
		t.Fatalf("row is %s, want open_by_handle_at", ep.EnterEv.GetTraceId().Name())
	}
	if got := pairRet(t, ep); got != -int64(errno) || !event.IsErrorRet(got) {
		t.Fatalf("row ret = %d, want the error -%d (%v)", got, int64(errno), errno)
	}
	if ep.File == nil {
		t.Fatal("failed row carries no file; want a descriptor-less pathname like a failed open")
	}
	if got := ep.File.Name(); got != wantName {
		t.Fatalf("failed row named %q, want %q", got, wantName)
	}
	if fd, ok := ep.FileDescriptor(); ok {
		t.Fatalf("failed row reports fd %d, want none", fd)
	}
}

// TestFailedOpenByHandleAtEmitsAnErrorRow is the regression for task eq2: a
// failed open_by_handle_at used to be recycled in the exit handler, so EPERM
// (no CAP_DAC_READ_SEARCH), EBADF (bad mount_fd) and ESTALE (file gone) calls
// produced no row, no error and no "syscalls after filter" count. Each must be
// one error row carrying no descriptor, exactly like a failed open.
//
// Since task k03 the row is named after the file the call's own handle
// belongs to. There is no descriptor to look at, so the tid-keyed stash this
// replaced could only assume the thread's last name_to_handle_at - /b below -
// was the handle that failed.
func TestFailedOpenByHandleAtEmitsAnErrorRow(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EPERM, syscall.EBADF, syscall.ESTALE} {
		t.Run(errno.Error(), func(t *testing.T) {
			feed := newHandleFeed(t, globalfilter.Filter{})
			feed.nameToHandle("/data/a.txt", testHandleA)
			feed.nameToHandle("/data/b.txt", testHandleB)

			ep := feed.openByHandle(testHandleA, -int64(errno))
			assertFailedHandleRow(t, ep, errno, "/data/a.txt")
			if got := feed.el.numSyscallsAfterFilter; got != 1 {
				t.Fatalf("syscalls after filter = %d, want 1", got)
			}
		})
	}
}

// TestFailedOpenOfAnUnknownHandleIsUnnamed: without a name for the handle a
// failed row has nothing to be named after - there is no descriptor procfs
// could be asked about - and must not borrow the name of another handle.
func TestFailedOpenOfAnUnknownHandleIsUnnamed(t *testing.T) {
	feed := newHandleFeed(t, globalfilter.Filter{})
	feed.nameToHandle("/data/a.txt", testHandleA)

	ep := feed.openByHandle(testHandleB, -int64(syscall.ESTALE))
	assertFailedHandleRow(t, ep, syscall.ESTALE, "")
}

// TestFailedOpenByHandleAtRegistersNoFd: a failed call returns no descriptor,
// so the fd table must not gain an entry - not even for the number the errno
// would be if it were mistaken for an fd.
func TestFailedOpenByHandleAtRegistersNoFd(t *testing.T) {
	feed := newHandleFeed(t, globalfilter.Filter{})
	feed.nameToHandle("/data/a.txt", testHandleA)
	before := len(feed.el.fdState().files)
	feed.openByHandle(testHandleA, -int64(syscall.EBADF))
	if after := len(feed.el.fdState().files); after != before {
		t.Fatalf("fd table grew from %d to %d entries after a failed open_by_handle_at", before, after)
	}
}

// TestFailedOpenByHandleAtFilterDimensions pins how the pair filter treats a
// failed row, which has a path (the handle's) but no descriptor - the same
// shape as a failed open: -path matches the name, -fd never matches, and an
// errors-only filter keeps it.
func TestFailedOpenByHandleAtFilterDimensions(t *testing.T) {
	tests := []struct {
		name   string
		filter globalfilter.Filter
		kept   bool
	}{
		{"path matches the handle's name", testFilter("", "eq2-filtered"), true},
		{"path does not match", testFilter("", "something-else"), false},
		{"fd filter", globalfilter.Filter{FD: globalfilter.NewEqFilter(3)}, false},
		{"errors only", globalfilter.Filter{ErrorsOnly: true}, true},
		{"ret equals errno", globalfilter.Filter{RetVal: globalfilter.NewEqFilter(-int64(syscall.EBADF))}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			feed := newHandleFeed(t, tc.filter)
			feed.nameToHandle("/tmp/eq2-filtered.txt", testHandleA)
			feed.openByHandle(testHandleA, -int64(syscall.EBADF))
			if got := len(feed.rows); got != map[bool]int{true: 1, false: 0}[tc.kept] {
				t.Fatalf("emitted %d rows, want kept=%v", got, tc.kept)
			}
			if got := int(feed.el.numSyscallsAfterFilter); got != len(feed.rows) {
				t.Fatalf("syscalls after filter = %d, emitted %d", got, len(feed.rows))
			}
		})
	}
}
