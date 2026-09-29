package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

const (
	fcntlFdFlagsFd       = int32(79)
	fcntlFdFlagsFilename = "/tmp/fcntl-fd-flags.txt"
)

func TestFcntlDescriptorFlagCommandsResynchronizeCloseOnExec(t *testing.T) {
	const unrelatedDescriptorFlag = uint64(1 << 20)
	tests := []struct {
		name          string
		cmd           uint32
		arg           uint64
		ret           int64
		originalFlags int32
		wantFlags     int32
	}{
		{
			name:          "F_SETFD sets close-on-exec",
			cmd:           syscall.F_SETFD,
			arg:           syscall.FD_CLOEXEC | unrelatedDescriptorFlag,
			originalFlags: syscall.O_RDWR | syscall.O_APPEND,
			wantFlags:     syscall.O_RDWR | syscall.O_APPEND | syscall.O_CLOEXEC,
		},
		{
			name:          "F_SETFD clears close-on-exec",
			cmd:           syscall.F_SETFD,
			originalFlags: syscall.O_RDWR | syscall.O_APPEND | syscall.O_CLOEXEC,
			wantFlags:     syscall.O_RDWR | syscall.O_APPEND,
		},
		{
			name:          "F_GETFD sets stale close-on-exec",
			cmd:           syscall.F_GETFD,
			ret:           syscall.FD_CLOEXEC | int64(unrelatedDescriptorFlag),
			originalFlags: syscall.O_RDWR | syscall.O_NONBLOCK,
			wantFlags:     syscall.O_RDWR | syscall.O_NONBLOCK | syscall.O_CLOEXEC,
		},
		{
			name:          "F_GETFD clears stale close-on-exec",
			cmd:           syscall.F_GETFD,
			originalFlags: syscall.O_RDWR | syscall.O_NONBLOCK | syscall.O_CLOEXEC,
			wantFlags:     syscall.O_RDWR | syscall.O_NONBLOCK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			el.fdState().set(fcntlFdFlagsFd, execCommPid,
				file.NewFd(fcntlFdFlagsFd, fcntlFdFlagsFilename, tc.originalFlags))

			fcntlPair := feedFcntlDescriptorFlagPair(t, el, tc.cmd, tc.arg, tc.ret)
			if fcntlPair == nil {
				t.Fatal("an unfiltered successful fcntl must be emitted")
			}
			assertPairFdFlags(t, fcntlPair, fcntlFdFlagsFd, tc.wantFlags)
			fcntlPair.Recycle()
			assertTrackedFdFlags(t, el, fcntlFdFlagsFd, tc.wantFlags)

			readPair := feedFdPair(t, el, types.SYS_ENTER_READ, types.SYS_EXIT_READ,
				fcntlFdFlagsFd, 1, writePairStart, writePairStart+openPairLatency)
			if readPair == nil {
				t.Fatal("an unfiltered read after fcntl must be emitted")
			}
			defer readPair.Recycle()
			assertPairFdFlags(t, readPair, fcntlFdFlagsFd, tc.wantFlags)
		})
	}
}

func TestFailedFcntlDescriptorFlagCommandsKeepCloseOnExec(t *testing.T) {
	tests := []struct {
		name          string
		cmd           uint32
		arg           uint64
		originalFlags int32
	}{
		{name: "F_GETFD", cmd: syscall.F_GETFD, originalFlags: syscall.O_RDWR},
		{name: "F_SETFD", cmd: syscall.F_SETFD, originalFlags: syscall.O_RDWR | syscall.O_CLOEXEC},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			el.fdState().set(fcntlFdFlagsFd, execCommPid,
				file.NewFd(fcntlFdFlagsFd, fcntlFdFlagsFilename, tc.originalFlags))

			ep := feedFcntlDescriptorFlagPair(t, el, tc.cmd, tc.arg, -int64(syscall.EBADF))
			if ep == nil {
				t.Fatal("an unfiltered failed fcntl must remain observable")
			}
			defer ep.Recycle()
			assertPairFdFlags(t, ep, fcntlFdFlagsFd, tc.originalFlags)
			assertTrackedFdFlags(t, el, fcntlFdFlagsFd, tc.originalFlags)
		})
	}
}

func TestFcntlDescriptorFlagKnowledgeSurvivesUnknownStatusFlags(t *testing.T) {
	for _, tt := range []struct {
		name         string
		initialFlags int32
		wantAfterGet int32
	}{
		{name: "known procfs flags", initialFlags: syscall.O_RDWR, wantAfterGet: syscall.O_RDWR | syscall.O_CLOEXEC},
		{name: "unknown procfs flags", initialFlags: -1, wantAfterGet: -1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			el := newFilteredEventLoop(t, globalfilter.Filter{})
			el.fdState().setProcFdCache(fcntlFdFlagsFd, execCommPid,
				file.NewFd(fcntlFdFlagsFd, fcntlFdFlagsFilename, tt.initialFlags))

			getfdPair := feedFcntlDescriptorFlagPair(t, el, syscall.F_GETFD, 0, syscall.FD_CLOEXEC)
			if getfdPair == nil {
				t.Fatal("successful F_GETFD must be emitted")
			}
			assertPairFdFlags(t, getfdPair, fcntlFdFlagsFd, tt.wantAfterGet)
			getfdPair.Recycle()

			const statusFlags = syscall.O_RDWR | syscall.O_NONBLOCK
			getflPair := feedFcntlDescriptorFlagPair(t, el, syscall.F_GETFL, 0, statusFlags)
			if getflPair == nil {
				t.Fatal("successful F_GETFL must be emitted")
			}
			defer getflPair.Recycle()
			assertPairFdFlags(t, getflPair, fcntlFdFlagsFd, statusFlags|syscall.O_CLOEXEC)
			assertTrackedFdFlags(t, el, fcntlFdFlagsFd, statusFlags|syscall.O_CLOEXEC)
		})
	}
}

func TestMalformedPositiveFSetfdReturnKeepsCloseOnExec(t *testing.T) {
	const originalFlags = syscall.O_RDWR
	el := newFilteredEventLoop(t, globalfilter.Filter{})
	el.fdState().set(fcntlFdFlagsFd, execCommPid,
		file.NewFd(fcntlFdFlagsFd, fcntlFdFlagsFilename, originalFlags))
	var warning string
	el.SetWarningCallback(func(message string) { warning = message })

	if ep := feedFcntlDescriptorFlagPair(t, el, syscall.F_SETFD, syscall.FD_CLOEXEC, 1); ep != nil {
		defer ep.Recycle()
		t.Fatalf("malformed positive F_SETFD return was emitted: %v", ep)
	}
	assertTrackedFdFlags(t, el, fcntlFdFlagsFd, originalFlags)
	if warning != "Dropped malformed fcntl F_SETFD return value" {
		t.Fatalf("warning = %q, want malformed F_SETFD warning", warning)
	}
}

func TestDroppedFcntlDescriptorFlagCommandStillResynchronizesCloseOnExec(t *testing.T) {
	tests := []struct {
		name string
		cmd  uint32
		arg  uint64
		ret  int64
	}{
		{name: "F_SETFD", cmd: syscall.F_SETFD, arg: syscall.FD_CLOEXEC},
		{name: "F_GETFD", cmd: syscall.F_GETFD, ret: syscall.FD_CLOEXEC},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			el := newFilteredEventLoop(t, dropsEveryPairOfLatency())
			el.fdState().set(fcntlFdFlagsFd, execCommPid,
				file.NewFd(fcntlFdFlagsFd, fcntlFdFlagsFilename, syscall.O_RDWR))

			if ep := feedFcntlDescriptorFlagPair(t, el, tc.cmd, tc.arg, tc.ret); ep != nil {
				defer ep.Recycle()
				t.Fatalf("fcntl row survived a -latency filter it cannot satisfy: %v", ep)
			}
			assertTrackedFdFlags(t, el, fcntlFdFlagsFd, syscall.O_RDWR|syscall.O_CLOEXEC)
		})
	}
}

func feedFcntlDescriptorFlagPair(
	t *testing.T, el *eventLoop, cmd uint32, arg uint64, ret int64,
) *event.Pair {
	t.Helper()
	_, enterRaw := makeEnterFcntlEvent(t, dupPairStart, execCommPid, execCommTid,
		uint32(fcntlFdFlagsFd), cmd, arg)
	_, exitRaw := makeExitRetEvent(t, dupPairStart+openPairLatency, execCommPid, execCommTid,
		types.SYS_EXIT_FCNTL, ret)
	return feedRawPair(t, el, enterRaw, exitRaw)
}
