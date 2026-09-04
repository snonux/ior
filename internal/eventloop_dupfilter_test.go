package internal

import (
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
	if _, ok := el.fdState().get(dupSourceFd); !ok {
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

			resolved, ok := el.fdState().get(dupTargetFd)
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
	el.fdState().setProcFdCache(dupSourceFd, execCommPid,
		file.NewFd(dupSourceFd, cachedName, syscall.O_RDONLY))
	if _, ok := el.fdState().get(dupSourceFd); ok {
		t.Fatalf("fd %d must start out known only to the procfs cache", dupSourceFd)
	}

	if ep := feedFcntlPair(t, el, syscall.F_SETFL, syscall.O_NONBLOCK, 0); ep != nil {
		defer ep.Recycle()
		t.Fatalf("fcntl row survived a -latency filter it cannot satisfy: %v", ep)
	}

	resolved, ok := el.fdState().get(dupSourceFd)
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
	if fdFile.Flags() != file.Flags(syscall.O_NONBLOCK) {
		t.Fatalf("fd %d flags = %v, want %v", dupSourceFd, fdFile.Flags(),
			file.Flags(syscall.O_NONBLOCK))
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
	defer f.Close()
	transferredFd := int32(f.Fd())
	selfPid := uint32(os.Getpid())

	feedPidfdGetfd := func(t *testing.T, el *eventLoop) *event.Pair {
		t.Helper()
		el.fdState().set(pidfd, file.NewFd(pidfd, pidfdName, -1))
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
		resolved, ok := el.fdState().get(transferredFd)
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
		resolved, ok := el.fdState().get(transferredFd)
		if !ok || resolved == nil || resolved.Name() != path {
			t.Fatalf("transferred fd %d was not registered as %q", transferredFd, path)
		}
	})
}
