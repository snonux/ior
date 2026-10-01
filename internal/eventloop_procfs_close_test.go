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

// Task jr2: a close row of a descriptor the fd table does not know used to be
// labelled by readlink(/proc/<pid>/fd/<fd>) at exit time, i.e. after the close.
// That named nothing, or the file the program had meanwhile put on the same
// number. Closing rows now take the fd table, then a procfs-cache answer read
// before the close entered, and never procfs (eventloop_procfs_close.go).
//
// Like the ir2 tests these use this process's real pid and descriptors, so a
// procfs read would be genuine: a pipe placed on the number stands for "the
// file that reused it", and a row named after it proves procfs was read.

// feedRealPidCloseAt feeds close(fd) attributed to this process, entering at
// enterNs on the boot clock and returning ret. The enter time is what the
// close row compares procfs-cache stamps against, so the tests pass real
// boot-clock readings instead of the fixed defaulTime.
func feedRealPidCloseAt(t *testing.T, el *eventLoop, fd int32, enterNs uint64, ret int64) *event.Pair {
	t.Helper()
	pid := uint32(os.Getpid())
	_, enterRaw := makeEnterFdEvent(t, enterNs, pid, execCommTid, fd, types.SYS_ENTER_CLOSE)
	_, exitRaw := makeExitRetEvent(t, enterNs+openPairLatency, pid, execCommTid, types.SYS_EXIT_CLOSE, ret)
	return feedRawPair(t, el, enterRaw, exitRaw)
}

// feedRealPidCloseRangeAt feeds close_range(first, last, flags) attributed to
// this process, entering at enterNs and returning ret.
func feedRealPidCloseRangeAt(t *testing.T, el *eventLoop, first, last int32, flags, enterNs uint64, ret int64) *event.Pair {
	t.Helper()
	pid := uint32(os.Getpid())
	_, enterRaw := makeEnterTwoFdEvent(t, enterNs, pid, execCommTid, first, last, flags, types.SYS_ENTER_CLOSE_RANGE)
	_, exitRaw := makeExitRetEvent(t, enterNs+openPairLatency, pid, execCommTid, types.SYS_EXIT_CLOSE_RANGE, ret)
	return feedRawPair(t, el, enterRaw, exitRaw)
}

// closingCase feeds one descriptor-releasing syscall on fd entering at enterNs.
type closingCase struct {
	name string
	feed func(t *testing.T, el *eventLoop, fd int32, enterNs uint64) *event.Pair
}

func closingCases() []closingCase {
	return []closingCase{
		{"close", func(t *testing.T, el *eventLoop, fd int32, enterNs uint64) *event.Pair {
			return feedRealPidCloseAt(t, el, fd, enterNs, 0)
		}},
		{"close/EINTR", func(t *testing.T, el *eventLoop, fd int32, enterNs uint64) *event.Pair {
			// The descriptor is released even when close reports EINTR.
			return feedRealPidCloseAt(t, el, fd, enterNs, -int64(syscall.EINTR))
		}},
		{"close_range", func(t *testing.T, el *eventLoop, fd int32, enterNs uint64) *event.Pair {
			return feedRealPidCloseRangeAt(t, el, fd, fd, 0, enterNs, 0)
		}},
	}
}

// mustEmit fails the test when the pair was not emitted and recycles it at the
// end of the test otherwise.
func mustEmit(t *testing.T, ep *event.Pair, what string) *event.Pair {
	t.Helper()
	if ep == nil {
		t.Fatalf("%s row must be emitted", what)
	}
	t.Cleanup(ep.Recycle)
	return ep
}

// requireUnnamedUnknown fails unless f is the "no name, unknown flags" file.
func requireUnnamedUnknown(t *testing.T, f file.File, fd int32) {
	t.Helper()
	if got := f.Name(); got != "" {
		t.Fatalf("close row of untracked fd %d named %q, want no name (procfs read after the close)", fd, got)
	}
	fdf, ok := f.(*file.FdFile)
	if !ok || fdf.Flags() != file.Flags(-1) {
		t.Fatalf("close row of untracked fd %d = %v, want an FdFile with unknown flags", fd, f)
	}
}

// The live symptom: the number was closed and already reused (here by a pipe)
// when the close row is processed. The row must not take the reuser's name,
// nor may the reuser's answer be cached for the number. The read that follows
// is the control that procfs does answer for it: the pipe is genuinely there.
func TestUntrackedCloseIgnoresTheDescriptorThatReusedTheNumber(t *testing.T) {
	pid := uint32(os.Getpid())
	for _, tc := range closingCases() {
		t.Run(tc.name, func(t *testing.T) {
			n := freeFdNumber(t)
			reuser := placePipeOn(t, n)
			el := newFilteredEventLoop(t, globalfilter.Filter{})

			ep := mustEmit(t, tc.feed(t, el, n, bootClockNs()), "close")
			requireUnnamedUnknown(t, ep.File, n)
			verifyProcFdNotCached(t, el, pid, n)
			verifyFdNotTracked(t, el, pid, n)

			read := mustEmit(t, feedRealPidFdPair(t, el, types.SYS_ENTER_READ, types.SYS_EXIT_READ, n, 1), "read")
			if got := read.File.Name(); got != reuser {
				t.Fatalf("control: read on fd %d named %q, want the reusing pipe %q", n, got, reuser)
			}
		})
	}
}

// The number is not open at all when the row is processed (procfs would fail
// with ENOENT): the row stays unnamed and nothing is cached, exactly as before.
func TestUntrackedCloseOfAFreeNumberIsUnnamed(t *testing.T) {
	pid := uint32(os.Getpid())
	for _, tc := range closingCases() {
		t.Run(tc.name, func(t *testing.T) {
			n := freeFdNumber(t)
			el := newFilteredEventLoop(t, globalfilter.Filter{})

			ep := mustEmit(t, tc.feed(t, el, n, bootClockNs()), "close")
			requireUnnamedUnknown(t, ep.File, n)
			verifyProcFdNotCached(t, el, pid, n)
		})
	}
}

// An untracked descriptor that an earlier event resolved through procfs while
// it was still open is labelled by that answer: its stamp says it was read
// before the close entered. The close evicts it, so the descriptor that reuses
// the number is read afresh.
func TestUntrackedCloseUsesTheProcfsAnswerFromBeforeTheClose(t *testing.T) {
	pid := uint32(os.Getpid())
	for _, tc := range closingCases() {
		t.Run(tc.name, func(t *testing.T) {
			n := freeFdNumber(t)
			before := placePipeOn(t, n)
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			mustEmit(t, feedRealPidFdPair(t, el, types.SYS_ENTER_WRITE, types.SYS_EXIT_WRITE, n, 1), "write")
			verifyProcFdCached(t, el, pid, n)

			// The program closes the number and a new pipe takes it before
			// ior processes the close.
			after := placePipeOn(t, n)
			if after == before {
				t.Fatalf("test setup: the new pipe %q reuses the old name", after)
			}
			ep := mustEmit(t, tc.feed(t, el, n, bootClockNs()), "close")
			if got := ep.File.Name(); got != before {
				t.Fatalf("close row named %q, want the pre-close procfs answer %q", got, before)
			}
			verifyProcFdNotCached(t, el, pid, n)

			read := mustEmit(t, feedRealPidFdPair(t, el, types.SYS_ENTER_READ, types.SYS_EXIT_READ, n, 1), "read")
			if got := read.File.Name(); got != after {
				t.Fatalf("read after the close named %q, want the new pipe %q", got, after)
			}
		})
	}
}

// The cache is filled at processing time, which lags the kernel. Live, a write
// just before the close was processed after the close and the reusing pipe(),
// so it read and cached the pipe; the close row then repeated that. A cache
// entry read after the close entered says nothing about the closed descriptor
// and must be ignored, and the close still evicts it.
func TestUntrackedCloseIgnoresAProcfsAnswerReadAfterTheClose(t *testing.T) {
	pid := uint32(os.Getpid())
	for _, tc := range closingCases() {
		t.Run(tc.name, func(t *testing.T) {
			n := freeFdNumber(t)
			reuser := placePipeOn(t, n)
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			write := mustEmit(t, feedRealPidFdPair(t, el, types.SYS_ENTER_WRITE, types.SYS_EXIT_WRITE, n, 1), "write")
			if write.File.Name() != reuser {
				t.Fatalf("test setup: the lagging write read %q, want the reusing pipe %q", write.File.Name(), reuser)
			}
			readNs, ok := el.fdState().cachedProcFdReadAt(n, pid)
			if !ok || readNs == 0 {
				t.Fatalf("test setup: the write's procfs answer is not cached with a read time (%d, %v)", readNs, ok)
			}

			// The close entered just before that read was made.
			ep := mustEmit(t, tc.feed(t, el, n, readNs-1), "close")
			requireUnnamedUnknown(t, ep.File, n)
			verifyProcFdNotCached(t, el, pid, n)
		})
	}
}

// A cache entry without a read time (setProcFdCache, as for entries not read
// by resolve) cannot be shown to predate the close and is not used for the
// close row. Replacing a stamped entry that way also drops the old stamp.
func TestUntrackedCloseIgnoresAnUnstampedCacheEntry(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	el.fdState().setProcFdCacheRead(n, pid, file.NewFd(n, "stamped", syscall.O_RDONLY), 1)
	el.fdState().setProcFdCache(n, pid, file.NewFd(n, "unstamped", syscall.O_RDONLY))

	ep := mustEmit(t, feedRealPidCloseAt(t, el, n, bootClockNs(), 0), "close")
	requireUnnamedUnknown(t, ep.File, n)
	verifyProcFdNotCached(t, el, pid, n)
}

// Negative control: a tracked descriptor's close row keeps the fd-table name,
// even though procfs now names something else, and the close still evicts it.
func TestTrackedCloseKeepsTheFdTableName(t *testing.T) {
	pid := uint32(os.Getpid())
	for _, tc := range closingCases() {
		t.Run(tc.name, func(t *testing.T) {
			n := freeFdNumber(t)
			placePipeOn(t, n)
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			el.fdState().set(n, pid, file.NewFd(n, "traced-open", syscall.O_RDWR))

			ep := mustEmit(t, tc.feed(t, el, n, bootClockNs()), "close")
			if got := ep.File.Name(); got != "traced-open" {
				t.Fatalf("tracked close row named %q, want the fd-table name", got)
			}
			verifyFdNotTracked(t, el, pid, n)
		})
	}
}

// A close answering EBADF keeps the ir2 behaviour: the fd-table name when
// there is one (left in place), otherwise unnamed, and never a procfs read.
func TestEBADFCloseStillSkipsProcfs(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	placePipeOn(t, n)
	el := newFilteredEventLoop(t, globalfilter.Filter{})

	ep := mustEmit(t, feedRealPidCloseAt(t, el, n, bootClockNs(), -int64(syscall.EBADF)), "close")
	requireUnnamedUnknown(t, ep.File, n)
	verifyProcFdNotCached(t, el, pid, n)
}

// close_range with CLOSE_RANGE_CLOEXEC closes nothing, so its descriptor is
// still open and the ordinary procfs resolution stays correct for it.
func TestCloexecCloseRangeStillResolvesThroughProcfs(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	want := placePipeOn(t, n)
	el := newFilteredEventLoop(t, globalfilter.Filter{})

	ep := mustEmit(t, feedRealPidCloseRangeAt(t, el, n, n, closeRangeCloexec, bootClockNs(), 0), "close_range")
	if got := ep.File.Name(); got != want || !strings.HasPrefix(got, "pipe:[") {
		t.Fatalf("CLOEXEC close_range row named %q, want the open pipe %q", got, want)
	}
	verifyProcFdCached(t, el, pid, n)
}

// A close_range that fails (EINVAL: first > last or unknown flags) returns
// before releasing anything, so its descriptor is still open and procfs names
// it correctly; the row must keep that name rather than go blank, and the
// failed call evicts nothing.
func TestFailedCloseRangeStillResolvesThroughProcfs(t *testing.T) {
	pid := uint32(os.Getpid())
	n := freeFdNumber(t)
	want := placePipeOn(t, n)
	el := newFilteredEventLoop(t, globalfilter.Filter{})

	ep := mustEmit(t, feedRealPidCloseRangeAt(t, el, n, n-1, 0, bootClockNs(), -int64(syscall.EINVAL)), "close_range")
	if got := ep.File.Name(); got != want || !strings.HasPrefix(got, "pipe:[") {
		t.Fatalf("failed close_range row named %q, want the still-open pipe %q", got, want)
	}
	verifyProcFdCached(t, el, pid, n)
}

func TestClosesDescriptor(t *testing.T) {
	pair := func(ev event.Event) *event.Pair { return &event.Pair{EnterEv: ev} }
	exited := func(ev event.Event, ret int64) *event.Pair {
		return &event.Pair{EnterEv: ev, ExitEv: &types.RetEvent{Ret: ret}}
	}
	closeRange := func() *types.TwoFdEvent { return &types.TwoFdEvent{TraceId: types.SYS_ENTER_CLOSE_RANGE} }
	for name, tc := range map[string]struct {
		ep   *event.Pair
		want bool
	}{
		"close":               {pair(&types.FdEvent{TraceId: types.SYS_ENTER_CLOSE}), true},
		"close_range":         {pair(&types.TwoFdEvent{TraceId: types.SYS_ENTER_CLOSE_RANGE}), true},
		"close_range unshare": {pair(&types.TwoFdEvent{TraceId: types.SYS_ENTER_CLOSE_RANGE, Extra: closeRangeUnshare}), true},
		"close_range cloexec": {pair(&types.TwoFdEvent{TraceId: types.SYS_ENTER_CLOSE_RANGE, Extra: closeRangeCloexec}), false},
		"close_range ok":      {exited(closeRange(), 0), true},
		"close_range EINVAL":  {exited(closeRange(), -int64(syscall.EINVAL)), false},
		"close EINTR":         {exited(&types.FdEvent{TraceId: types.SYS_ENTER_CLOSE}, -int64(syscall.EINTR)), true},
		"read":                {pair(&types.FdEvent{TraceId: types.SYS_ENTER_READ}), false},
		"dup2":                {pair(&types.FdEvent{TraceId: types.SYS_ENTER_DUP2}), false},
		"no enter record":     {&event.Pair{}, false},
	} {
		if got := closesDescriptor(tc.ep); got != tc.want {
			t.Errorf("%s: closesDescriptor = %v, want %v", name, got, tc.want)
		}
	}
}

// The read time travels with its cache entry: a forked child's copy keeps it
// (the child's descriptor is the parent's, read at that time), a table rekey
// moves it, and every removal drops it, so a later entry on the same key never
// inherits a stale read time.
func TestProcfsReadTimeFollowsTheCacheEntry(t *testing.T) {
	const parent, child, moved uint32 = 4100, 4101, 4102
	const fd int32 = 7
	tr := newFDTracker(nil)
	tr.setProcFdCacheRead(fd, parent, file.NewFd(fd, "read-early", syscall.O_RDONLY), 42)

	tr.inherit(parent, child)
	if got, ok := tr.cachedProcFdReadAt(fd, child); !ok || got != 42 {
		t.Fatalf("inherited entry read time = %d, %v; want 42", got, ok)
	}
	tr.rekeyTable(child, moved)
	if got, ok := tr.cachedProcFdReadAt(fd, moved); !ok || got != 42 {
		t.Fatalf("rekeyed entry read time = %d, %v; want 42", got, ok)
	}
	if _, ok := tr.cachedProcFdReadAt(fd, child); ok {
		t.Fatal("rekey left the read time under the old table")
	}
	tr.deleteProcFdCache(fd, parent)
	if _, ok := tr.cachedProcFdReadAt(fd, parent); ok {
		t.Fatal("a deleted cache entry kept its read time")
	}
	if len(tr.procFdReadAt) != 1 {
		t.Fatalf("read times = %v, want only the rekeyed entry's", tr.procFdReadAt)
	}
}
