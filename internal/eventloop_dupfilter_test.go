package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// The dup family is the fd-state counterpart of TestDroppedOpenStillRegistersTheFd.
//
// handleOpenExit registers the descriptor it opened *before* applying the pair
// filter, because the fd table is global: a row this run does not want must
// still leave that table correct for the rows it does want. handleFdExit
// (dup/dup2/pidfd_getfd), handleDup3Exit and handleFcntlExit
// (F_DUPFD/F_DUPFD_CLOEXEC, F_SETFL) used to do the opposite - filter first,
// mutate afterwards - so a dropped dup row left the duplicated descriptor
// unregistered and every later read/write/close on it lost its filename (or,
// when the target fd number was already tracked, kept reporting the file it
// used to point at). Unlike the numeric dimensions this is reachable from the
// CLI today, through -path and -comm.
//
// pidfd_getfd carried a second, sharper form of the same defect: applyFdTransferOp
// re-pointed ep.File at the transferred file only after the filter had judged
// the pair on the *source* pidfd, so the value filtered on and the value
// printed genuinely differed.

const (
	dupSourceFd  = 21
	dupTargetFd  = 22
	dupFilename  = "/tmp/dupped.txt"
	dupPairStart = defaulTime + 200
	// writePairStart is late enough that the write pair cannot be paired with
	// the dup pair's enter event.
	writePairStart = defaulTime + 400
)

// dropsEveryPairOfLatency is a filter that drops every pair whose latency is
// openPairLatency (the open and dup rows fed below) and keeps the follow-up
// write row, which is fed one nanosecond slower. Filtering on latency keeps the
// discriminator orthogonal to the path: the whole point is that the dup row and
// the later write row report the *same* file.
func dropsEveryPairOfLatency() globalfilter.Filter {
	return globalfilter.Filter{
		LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: openPairLatency + 1},
	}
}

// feedFdPair drives one fd_event enter / ret_event exit pair through the raw
// event path and returns the emitted pair, or nil when the filter dropped it.
func feedFdPair(t *testing.T, el *eventLoop, enterTrace, exitTrace types.TraceId,
	fd int32, ret int64, enterTime, exitTime uint64) *event.Pair {
	t.Helper()
	_, enterRaw := makeEnterFdEvent(t, enterTime, execCommPid, execCommTid, fd, enterTrace)
	_, exitRaw := makeExitRetEvent(t, exitTime, execCommPid, execCommTid, exitTrace, ret)
	return feedRawPair(t, el, enterRaw, exitRaw)
}

// feedRawPair pushes one already-encoded enter/exit pair into the event loop.
func feedRawPair(t *testing.T, el *eventLoop, enterRaw, exitRaw []byte) *event.Pair {
	t.Helper()
	out := make(chan *event.Pair, 1)
	el.processRawEvent(enterRaw, out)
	el.processRawEvent(exitRaw, out)
	select {
	case ep := <-out:
		return ep
	default:
		return nil
	}
}

// feedWriteOnDupTarget feeds a write on the duplicated descriptor, slow enough
// to satisfy dropsEveryPairOfLatency. This is the row the user asked for and
// the one that loses its filename when the dup row's registration is skipped.
func feedWriteOnDupTarget(t *testing.T, el *eventLoop) *event.Pair {
	t.Helper()
	return feedFdPair(t, el, types.SYS_ENTER_WRITE, types.SYS_EXIT_WRITE,
		dupTargetFd, 7, writePairStart, writePairStart+openPairLatency+1)
}

// registerDupSourceViaDroppedOpen opens dupFilename on dupSourceFd through a row
// the filter drops, which is exactly the ordering TestDroppedOpenStillRegistersTheFd
// pins for handleOpenExit.
func registerDupSourceViaDroppedOpen(t *testing.T, el *eventLoop) {
	t.Helper()
	if ep := feedOpenPair(t, el, dupFilename, "ioworkload", dupSourceFd); ep != nil {
		defer ep.Recycle()
		t.Fatalf("open row survived a -latency filter it cannot satisfy: %v", ep)
	}
	if _, ok := el.fdState().get(dupSourceFd, execCommPid); !ok {
		t.Fatalf("fd %d was not registered by the dropped open row", dupSourceFd)
	}
}

func TestDroppedDupStillRegistersTheDuplicatedFd(t *testing.T) {
	cases := []struct {
		name    string
		feedDup func(t *testing.T, el *eventLoop) *event.Pair
	}{
		{
			name: "dup",
			feedDup: func(t *testing.T, el *eventLoop) *event.Pair {
				return feedFdPair(t, el, types.SYS_ENTER_DUP, types.SYS_EXIT_DUP,
					dupSourceFd, dupTargetFd, dupPairStart, dupPairStart+openPairLatency)
			},
		},
		{
			name: "dup2",
			feedDup: func(t *testing.T, el *eventLoop) *event.Pair {
				return feedFdPair(t, el, types.SYS_ENTER_DUP2, types.SYS_EXIT_DUP2,
					dupSourceFd, dupTargetFd, dupPairStart, dupPairStart+openPairLatency)
			},
		},
		{
			name: "dup3",
			feedDup: func(t *testing.T, el *eventLoop) *event.Pair {
				_, enterRaw := makeEnterDup3Event(t, dupPairStart, execCommPid, execCommTid,
					dupSourceFd, syscall.O_CLOEXEC)
				_, exitRaw := makeExitRetEvent(t, dupPairStart+openPairLatency,
					execCommPid, execCommTid, types.SYS_EXIT_DUP3, dupTargetFd)
				return feedRawPair(t, el, enterRaw, exitRaw)
			},
		},
		{
			name: "fcntl F_DUPFD",
			feedDup: func(t *testing.T, el *eventLoop) *event.Pair {
				return feedFcntlPair(t, el, syscall.F_DUPFD, 0, dupTargetFd)
			},
		},
		{
			name: "fcntl F_DUPFD_CLOEXEC",
			feedDup: func(t *testing.T, el *eventLoop) *event.Pair {
				return feedFcntlPair(t, el, syscall.F_DUPFD_CLOEXEC, 0, dupTargetFd)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			el := newFilteredEventLoop(t, dropsEveryPairOfLatency())
			registerDupSourceViaDroppedOpen(t, el)

			if ep := tc.feedDup(t, el); ep != nil {
				defer ep.Recycle()
				t.Fatalf("%s row survived a -latency filter it cannot satisfy: %v", tc.name, ep)
			}

			resolved, ok := el.fdState().get(dupTargetFd, execCommPid)
			if !ok || resolved == nil {
				t.Fatalf("fd %d was not registered because the %s row was filtered out",
					dupTargetFd, tc.name)
			}
			if resolved.Name() != dupFilename {
				t.Fatalf("fd %d resolved to %q, want %q", dupTargetFd, resolved.Name(), dupFilename)
			}

			// The row the run actually asked for: a later write on the
			// duplicated descriptor must still carry the original filename.
			ep := feedWriteOnDupTarget(t, el)
			if ep == nil {
				t.Fatalf("the write on fd %d must survive the latency filter", dupTargetFd)
			}
			defer ep.Recycle()
			if ep.File == nil || ep.File.Name() != dupFilename {
				t.Fatalf("write on fd %d reported file %v, want %q: the dropped %s row cost it its filename",
					dupTargetFd, ep.File, dupFilename, tc.name)
			}
		})
	}
}

// feedFcntlPair drives one fcntl enter/exit pair with the given cmd and arg.
func feedFcntlPair(t *testing.T, el *eventLoop, cmd uint32, arg uint64, ret int64) *event.Pair {
	t.Helper()
	_, enterRaw := makeEnterFcntlEvent(t, dupPairStart, execCommPid, execCommTid,
		dupSourceFd, cmd, arg)
	_, exitRaw := makeExitRetEvent(t, dupPairStart+openPairLatency, execCommPid, execCommTid,
		types.SYS_EXIT_FCNTL, ret)
	return feedRawPair(t, el, enterRaw, exitRaw)
}

// TestDroppedFcntlSetflStillUpdatesTheFdTable covers the fourth mutation that
// used to sit behind handleFcntlExit's filter: F_SETFL promotes a
// procfs-resolved descriptor into the fd table with its new flags. While that
// ran after the checkpoint, a dropped F_SETFL row left the descriptor known
// only to the (evictable) procfs cache and its flag change unrecorded.
func TestDroppedFcntlSetflStillUpdatesTheFdTable(t *testing.T) {
	const cachedName = "/tmp/setfl.txt"
	el := newFilteredEventLoop(t, dropsEveryPairOfLatency())
	// Seed O_RDWR|O_APPEND and pass arg = O_RDWR|O_NONBLOCK, which is the shape
	// a real caller produces (F_GETFL then OR). This is deliberately
	// order-sensitive: with MergeFlags' two int32 arguments swapped the result
	// would be O_APPEND|O_NONBLOCK, so the assertion below pins the call site's
	// argument order as well as the merge itself. It also exercises the clear
	// half — O_APPEND was set and arg omits it, so it must go.
	//
	// The access mode in the seed is what makes the assertion sharp at all:
	// with a zero seed a lossy flag replace and a correct F_SETFL merge are
	// indistinguishable, so the check below could not fail legibly.
	el.fdState().setProcFdCache(dupSourceFd, execCommPid,
		file.NewFd(dupSourceFd, cachedName, syscall.O_RDWR|syscall.O_APPEND))
	if _, ok := el.fdState().get(dupSourceFd, execCommPid); ok {
		t.Fatalf("fd %d must start out known only to the procfs cache", dupSourceFd)
	}

	if ep := feedFcntlPair(t, el, syscall.F_SETFL, syscall.O_RDWR|syscall.O_NONBLOCK, 0); ep != nil {
		defer ep.Recycle()
		t.Fatalf("fcntl row survived a -latency filter it cannot satisfy: %v", ep)
	}

	resolved, ok := el.fdState().get(dupSourceFd, execCommPid)
	if !ok || resolved == nil {
		t.Fatalf("fd %d was not registered because the F_SETFL row was filtered out", dupSourceFd)
	}
	if resolved.Name() != cachedName {
		t.Fatalf("fd %d resolved to %q, want %q", dupSourceFd, resolved.Name(), cachedName)
	}
	fdFile, ok := resolved.(*file.FdFile)
	if !ok {
		t.Fatalf("fd %d resolved to %T, want *file.FdFile", dupSourceFd, resolved)
	}
	// Both halves matter, and the access mode is the sharper one: F_SETFL
	// changes the settable status flags only (fcntl(2)), so the O_RDWR the
	// descriptor was opened with has to survive the call. Replacing the flag
	// word with arg&settable instead of merging into it dropped the access
	// mode, and because the fd table entry is what every later read/write/close
	// on this descriptor resolves through, the whole rest of its life reported
	// O_RDONLY. Under a replace the arg's own O_RDWR is masked away with
	// everything else outside the settable set, so the defect shows up here as
	// exactly that missing O_RDWR.
	want := file.Flags(syscall.O_RDWR | syscall.O_NONBLOCK)
	if fdFile.Flags() != want {
		t.Fatalf("fd %d flags = %v, want %v", dupSourceFd, fdFile.Flags(), want)
	}
}

// TestPidfdGetfdIsFilteredOnTheFileItReports pins that the pair filter judges a
// pidfd_getfd row on the transferred file - the one the row prints - and not on
// the source pidfd it was resolved from. The enter payload carries args[0], the
// pidfd, so ep.File starts out as the pidfd; applyFdTransferOp re-points it at
// the returned descriptor. While that assignment happened after the checkpoint,
// `-path <transferred file>` dropped the very row that reports it and
// `-path pidfd` kept a row that reports something else entirely.
//
// The event's pid is this test process so that file.NewFdWithPid readlinks a
// real /proc/self/fd entry, which is exactly what the runtime path does.
func TestPidfdGetfdIsFilteredOnTheFileItReports(t *testing.T) {
	const pidfd = 19
	const pidfdName = "pidfd:0"

	path := filepath.Join(t.TempDir(), "pidfd-transferred.txt")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create transferred file: %v", err)
	}
	defer func() { _ = f.Close() }()
	transferredFd := int32(f.Fd())
	// The runtime resolves the descriptor by readlinking /proc/self/fd, which
	// returns the fully resolved path. Compare against that, not against the
	// TempDir path: on a host whose TMPDIR traverses a symlink (a common
	// container layout) the two differ and every exact-match assertion below
	// would fail for reasons that have nothing to do with the filter.
	path, err = os.Readlink(fmt.Sprintf("/proc/self/fd/%d", transferredFd))
	if err != nil {
		t.Fatalf("readlink transferred fd: %v", err)
	}
	selfPid := uint32(os.Getpid())

	feedPidfdGetfd := func(t *testing.T, el *eventLoop) *event.Pair {
		t.Helper()
		el.fdState().set(pidfd, selfPid, file.NewFd(pidfd, pidfdName, -1))
		_, enterRaw := makeEnterFdEvent(t, defaulTime, selfPid, selfPid, pidfd,
			types.SYS_ENTER_PIDFD_GETFD)
		_, exitRaw := makeExitRetEvent(t, defaulTime+openPairLatency, selfPid, selfPid,
			types.SYS_EXIT_PIDFD_GETFD, int64(transferredFd))
		return feedRawPair(t, el, enterRaw, exitRaw)
	}

	t.Run("kept by -path on the transferred file", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{
			File: &globalfilter.StringFilter{Pattern: "pidfd-transferred.txt"},
		})
		ep := feedPidfdGetfd(t, el)
		if ep == nil {
			t.Fatalf("pidfd_getfd row was dropped by -path %q, the very file it reports",
				"pidfd-transferred.txt")
		}
		defer ep.Recycle()
		if ep.File == nil || ep.File.Name() != path {
			t.Fatalf("pidfd_getfd row reported file %v, want %q", ep.File, path)
		}
		resolved, ok := el.fdState().get(transferredFd, selfPid)
		if !ok || resolved == nil || resolved.Name() != path {
			t.Fatalf("transferred fd %d was not registered as %q", transferredFd, path)
		}
	})

	t.Run("dropped by -path on the source pidfd", func(t *testing.T) {
		el := newFilteredEventLoop(t, globalfilter.Filter{
			File: &globalfilter.StringFilter{Pattern: pidfdName},
		})
		if ep := feedPidfdGetfd(t, el); ep != nil {
			defer ep.Recycle()
			t.Fatalf("pidfd_getfd row survived -path %q while reporting %v: "+
				"the filtered value and the printed value must be the same",
				pidfdName, ep.File)
		}
		// Dropped or not, the transferred descriptor is global state and must
		// still be registered for the rows the run does want.
		resolved, ok := el.fdState().get(transferredFd, selfPid)
		if !ok || resolved == nil || resolved.Name() != path {
			t.Fatalf("transferred fd %d was not registered as %q", transferredFd, path)
		}
	})
}

// TestDroppedCloseStillEvictsTheFd is the eviction half of the rule the dup
// tests pin from the registration side. applyFdCloseState runs before the
// checkpoint, so a close row dropped by a filter must still remove the entry.
//
// Regressing this is worse than the dup bug it accompanies: a stale entry
// mislabels the NEXT syscall that reuses the descriptor number with the old
// file — a wrong row rather than a missing filename.
func TestDroppedCloseStillEvictsTheFd(t *testing.T) {
	const cachedName = "/tmp/closed.txt"

	el := newFilteredEventLoop(t, dropsEveryPairOfLatency())
	el.fdState().set(dupSourceFd, execCommPid, file.NewFd(dupSourceFd, cachedName, syscall.O_RDONLY))

	_, enterRaw := makeEnterFdEvent(t, defaulTime, execCommPid, execCommTid, dupSourceFd,
		types.SYS_ENTER_CLOSE)
	_, exitRaw := makeExitRetEvent(t, defaulTime+openPairLatency, execCommPid, execCommTid,
		types.SYS_EXIT_CLOSE, 0)
	if ep := feedRawPair(t, el, enterRaw, exitRaw); ep != nil {
		defer ep.Recycle()
		t.Fatalf("close row survived a -latency filter it cannot satisfy: %v", ep)
	}

	if resolved, ok := el.fdState().get(dupSourceFd, execCommPid); ok {
		t.Fatalf("fd %d still resolves to %v after a dropped close: a later syscall "+
			"reusing that descriptor number would be labelled with the stale file",
			dupSourceFd, resolved)
	}
}

// TestFailedDupDoesNotRegisterAnFd pins the other direction of moving the
// mutations ahead of the filter: they now run on EVERY pair, not just surviving
// ones, so a failure return must not write to the fd table at all. Without the
// guard a failed dup would register fd -1 (or whatever the error code is) and
// point it at the source file.
func TestFailedDupDoesNotRegisterAnFd(t *testing.T) {
	const cachedName = "/tmp/dupsrc.txt"
	const dupFailureRet = int64(-24) // -EMFILE

	// No filter at all: this is about the failure guard, not the checkpoint.
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	el.fdState().set(dupSourceFd, execCommPid, file.NewFd(dupSourceFd, cachedName, syscall.O_RDONLY))

	_, enterRaw := makeEnterFdEvent(t, defaulTime, execCommPid, execCommTid, dupSourceFd,
		types.SYS_ENTER_DUP)
	_, exitRaw := makeExitRetEvent(t, defaulTime+openPairLatency, execCommPid, execCommTid,
		types.SYS_EXIT_DUP, dupFailureRet)
	ep := feedRawPair(t, el, enterRaw, exitRaw)
	if ep == nil {
		t.Fatal("an unfiltered failed dup row must still be emitted")
	}
	defer ep.Recycle()

	if resolved, ok := el.fdState().get(int32(dupFailureRet), execCommPid); ok {
		t.Fatalf("a failed dup registered fd %d as %v; failure returns must not "+
			"mutate the fd table", dupFailureRet, resolved)
	}
	// The source descriptor must be untouched.
	resolved, ok := el.fdState().get(dupSourceFd, execCommPid)
	if !ok || resolved == nil || resolved.Name() != cachedName {
		t.Fatalf("a failed dup disturbed the source fd %d: %v", dupSourceFd, resolved)
	}
}

// TestDroppedCloseRangeStillEvictsTheFds is the close_range half of the
// eviction rule. It was previously unpinned: moving applyCloseRangeState behind
// the checkpoint left the whole suite green, even though a stale entry after a
// dropped close_range mislabels every later reuse of those descriptor numbers.
func TestDroppedCloseRangeStillEvictsTheFds(t *testing.T) {
	const lowFd = int32(21)
	const highFd = int32(23)

	el := newFilteredEventLoop(t, dropsEveryPairOfLatency())
	for fd := lowFd; fd <= highFd; fd++ {
		el.fdState().set(fd, execCommPid, file.NewFd(fd, "/tmp/ranged.txt", syscall.O_RDONLY))
	}

	_, enterRaw := makeEnterTwoFdEvent(t, defaulTime, execCommPid, execCommTid,
		lowFd, highFd, 0, types.SYS_ENTER_CLOSE_RANGE)
	_, exitRaw := makeExitRetEvent(t, defaulTime+openPairLatency, execCommPid, execCommTid,
		types.SYS_EXIT_CLOSE_RANGE, 0)
	if ep := feedRawPair(t, el, enterRaw, exitRaw); ep != nil {
		defer ep.Recycle()
		t.Fatalf("close_range row survived a -latency filter it cannot satisfy: %v", ep)
	}

	for fd := lowFd; fd <= highFd; fd++ {
		if resolved, ok := el.fdState().get(fd, execCommPid); ok {
			t.Fatalf("fd %d still resolves to %v after a dropped close_range", fd, resolved)
		}
	}
}

// TestFailedPidfdGetfdDoesNotRegisterAnFd covers the one failure guard in this
// class that had no test: replacing pidfd_getfd's `newFd >= 0` condition with
// `true` left the entire suite green. Because the mutation now runs on every
// pair rather than only surviving ones, an unguarded failure would register the
// negative errno as a descriptor and re-point the row's File at it.
func TestFailedPidfdGetfdDoesNotRegisterAnFd(t *testing.T) {
	const pidfd = int32(19)
	const pidfdName = "pidfd:0"
	const failureRet = int64(-9) // -EBADF

	el := newFilteredEventLoop(t, globalfilter.Filter{})
	el.fdState().set(pidfd, execCommPid, file.NewFd(pidfd, pidfdName, -1))

	_, enterRaw := makeEnterFdEvent(t, defaulTime, execCommPid, execCommTid, pidfd,
		types.SYS_ENTER_PIDFD_GETFD)
	_, exitRaw := makeExitRetEvent(t, defaulTime+openPairLatency, execCommPid, execCommTid,
		types.SYS_EXIT_PIDFD_GETFD, failureRet)
	ep := feedRawPair(t, el, enterRaw, exitRaw)
	if ep == nil {
		t.Fatal("an unfiltered failed pidfd_getfd row must still be emitted")
	}
	defer ep.Recycle()

	if resolved, ok := el.fdState().get(int32(failureRet), execCommPid); ok {
		t.Fatalf("a failed pidfd_getfd registered fd %d as %v", failureRet, resolved)
	}
	// A failed transfer keeps reporting the source pidfd, which is what the
	// filter must judge it on.
	if ep.File == nil || ep.File.Name() != pidfdName {
		t.Fatalf("failed pidfd_getfd reported file %v, want the source %q", ep.File, pidfdName)
	}
}
