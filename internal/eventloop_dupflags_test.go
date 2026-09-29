package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

const dupFlagsFilename = "/tmp/dup-flags.txt"

func TestDuplicationReplacesTheCloseOnExecFlag(t *testing.T) {
	cases := []struct {
		name        string
		sourceFlags int32
		wantFlags   int32
		feed        func(t *testing.T, el *eventLoop) *event.Pair
	}{
		{
			name:        "dup clears O_CLOEXEC",
			sourceFlags: syscall.O_RDWR | syscall.O_CLOEXEC,
			wantFlags:   syscall.O_RDWR,
			feed: func(t *testing.T, el *eventLoop) *event.Pair {
				return feedFdPair(t, el, types.SYS_ENTER_DUP, types.SYS_EXIT_DUP,
					dupSourceFd, dupTargetFd, dupPairStart, dupPairStart+openPairLatency)
			},
		},
		{
			name:        "dup2 clears O_CLOEXEC",
			sourceFlags: syscall.O_RDWR | syscall.O_CLOEXEC,
			wantFlags:   syscall.O_RDWR,
			feed: func(t *testing.T, el *eventLoop) *event.Pair {
				return feedFdPair(t, el, types.SYS_ENTER_DUP2, types.SYS_EXIT_DUP2,
					dupSourceFd, dupTargetFd, dupPairStart, dupPairStart+openPairLatency)
			},
		},
		{
			name:        "fcntl F_DUPFD clears O_CLOEXEC",
			sourceFlags: syscall.O_RDWR | syscall.O_CLOEXEC,
			wantFlags:   syscall.O_RDWR,
			feed: func(t *testing.T, el *eventLoop) *event.Pair {
				return feedFcntlPair(t, el, syscall.F_DUPFD, 0, dupTargetFd)
			},
		},
		{
			name:        "dup3 without flags clears O_CLOEXEC",
			sourceFlags: syscall.O_RDWR | syscall.O_CLOEXEC,
			wantFlags:   syscall.O_RDWR,
			feed: func(t *testing.T, el *eventLoop) *event.Pair {
				return feedDup3Pair(t, el, 0, dupTargetFd)
			},
		},
		{
			name:        "dup3 with O_CLOEXEC sets O_CLOEXEC",
			sourceFlags: syscall.O_RDWR,
			wantFlags:   syscall.O_RDWR | syscall.O_CLOEXEC,
			feed: func(t *testing.T, el *eventLoop) *event.Pair {
				return feedDup3Pair(t, el, syscall.O_CLOEXEC, dupTargetFd)
			},
		},
		{
			name:        "fcntl F_DUPFD_CLOEXEC sets O_CLOEXEC",
			sourceFlags: syscall.O_RDWR,
			wantFlags:   syscall.O_RDWR | syscall.O_CLOEXEC,
			feed: func(t *testing.T, el *eventLoop) *event.Pair {
				return feedFcntlPair(t, el, syscall.F_DUPFD_CLOEXEC, 0, dupTargetFd)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			el.fdState().set(dupSourceFd, execCommPid,
				file.NewFd(dupSourceFd, dupFlagsFilename, tc.sourceFlags))

			dupPair := tc.feed(t, el)
			if dupPair == nil {
				t.Fatal("an unfiltered successful duplication must be emitted")
			}
			dupPair.Recycle()

			assertTrackedFdFlags(t, el, dupSourceFd, tc.sourceFlags)
			assertTrackedFdFlags(t, el, dupTargetFd, tc.wantFlags)

			readPair := feedFdPair(t, el, types.SYS_ENTER_READ, types.SYS_EXIT_READ,
				dupTargetFd, 1, writePairStart, writePairStart+openPairLatency)
			if readPair == nil {
				t.Fatal("an unfiltered read on the duplicate must be emitted")
			}
			defer readPair.Recycle()
			fdFile, ok := readPair.File.(*file.FdFile)
			if !ok {
				t.Fatalf("read on duplicated fd reported %T, want *file.FdFile", readPair.File)
			}
			if fdFile.Flags() != file.Flags(tc.wantFlags) {
				t.Fatalf("read on duplicated fd reported flags %v, want %v",
					fdFile.Flags(), file.Flags(tc.wantFlags))
			}
		})
	}
}

func TestDup2OntoItselfKeepsCloseOnExec(t *testing.T) {
	const sourceFlags = syscall.O_RDWR | syscall.O_CLOEXEC
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	el.fdState().set(dupSourceFd, execCommPid,
		file.NewFd(dupSourceFd, dupFlagsFilename, sourceFlags))

	ep := feedFdPair(t, el, types.SYS_ENTER_DUP2, types.SYS_EXIT_DUP2,
		dupSourceFd, dupSourceFd, dupPairStart, dupPairStart+openPairLatency)
	if ep == nil {
		t.Fatal("an unfiltered successful dup2 must be emitted")
	}
	defer ep.Recycle()

	assertTrackedFdFlags(t, el, dupSourceFd, sourceFlags)
}

func TestFailedDuplicationKeepsFdFlags(t *testing.T) {
	const failureRet = int64(-24) // -EMFILE
	cases := []struct {
		name string
		feed func(t *testing.T, el *eventLoop) *event.Pair
	}{
		{
			name: "dup",
			feed: func(t *testing.T, el *eventLoop) *event.Pair {
				return feedFdPair(t, el, types.SYS_ENTER_DUP, types.SYS_EXIT_DUP,
					dupSourceFd, failureRet, dupPairStart, dupPairStart+openPairLatency)
			},
		},
		{
			name: "dup2",
			feed: func(t *testing.T, el *eventLoop) *event.Pair {
				return feedFdPair(t, el, types.SYS_ENTER_DUP2, types.SYS_EXIT_DUP2,
					dupSourceFd, failureRet, dupPairStart, dupPairStart+openPairLatency)
			},
		},
		{
			name: "dup3 with O_CLOEXEC",
			feed: func(t *testing.T, el *eventLoop) *event.Pair {
				return feedDup3Pair(t, el, syscall.O_CLOEXEC, failureRet)
			},
		},
		{
			name: "fcntl F_DUPFD",
			feed: func(t *testing.T, el *eventLoop) *event.Pair {
				return feedFcntlPair(t, el, syscall.F_DUPFD, 0, failureRet)
			},
		},
		{
			name: "fcntl F_DUPFD_CLOEXEC",
			feed: func(t *testing.T, el *eventLoop) *event.Pair {
				return feedFcntlPair(t, el, syscall.F_DUPFD_CLOEXEC, 0, failureRet)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			const sourceFlags = syscall.O_RDWR | syscall.O_CLOEXEC
			el.fdState().set(dupSourceFd, execCommPid,
				file.NewFd(dupSourceFd, dupFlagsFilename, sourceFlags))

			ep := tc.feed(t, el)
			if ep == nil {
				t.Fatal("an unfiltered failed duplication must be emitted")
			}
			ep.Recycle()

			assertTrackedFdFlags(t, el, dupSourceFd, sourceFlags)
			if tracked, ok := el.fdState().get(int32(failureRet), execCommPid); ok {
				t.Fatalf("failed %s registered errno %d as fd metadata %v", tc.name, failureRet, tracked)
			}
			if len(el.fdState().files) != 1 {
				t.Fatalf("failed %s left %d tracked fds, want only the source", tc.name, len(el.fdState().files))
			}
		})
	}
}

func feedDup3Pair(t *testing.T, el *eventLoop, flags int32, ret int64) *event.Pair {
	t.Helper()
	_, enterRaw := makeEnterDup3Event(t, dupPairStart, execCommPid, execCommTid,
		dupSourceFd, flags)
	_, exitRaw := makeExitRetEvent(t, dupPairStart+openPairLatency, execCommPid, execCommTid,
		types.SYS_EXIT_DUP3, ret)
	return feedRawPair(t, el, enterRaw, exitRaw)
}

func assertTrackedFdFlags(t *testing.T, el *eventLoop, fd int32, want int32) {
	t.Helper()
	tracked, ok := el.fdState().get(fd, execCommPid)
	if !ok {
		t.Fatalf("fd %d was not tracked", fd)
	}
	fdFile, ok := tracked.(*file.FdFile)
	if !ok {
		t.Fatalf("fd %d resolved to %T, want *file.FdFile", fd, tracked)
	}
	if fdFile.Flags() != file.Flags(want) {
		t.Fatalf("fd %d flags = %v, want %v", fd, fdFile.Flags(), file.Flags(want))
	}
}
