package internal

import (
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// These tests pin task cq2: the descriptor of io_uring_enter/io_uring_register
// is a registered-ring index when IORING_ENTER_REGISTERED_RING /
// IORING_REGISTER_USE_REGISTERED_RING is set, and io_uring_setup with
// IORING_SETUP_REGISTERED_FD_ONLY returns such an index. Reading those numbers
// as descriptors attributed the calls to whatever file sat at that fd (stdin
// for the usual index 0) and let the setup overwrite that fd's real entry.

const (
	// stdinFd/stdinName model a process whose fd 0 is an ordinary file, the
	// situation in which the bug was visible live.
	stdinFd   = int32(0)
	stdinName = "/etc/hostname"
	// realRingFd is where io_uring_setup without REGISTERED_FD_ONLY put the ring.
	realRingFd   = int32(3)
	realRingName = "anon_inode:[io_uring]"

	// Flag values are spelled out (not the production constants) so a wrong
	// constant in the implementation cannot cancel out against the test.
	enterGetEvents        = 1 << 0
	enterRegisteredRing   = 1 << 4
	registerRingFds       = 20
	registerUseRegistered = 1 << 31
	setupSqPoll           = 1 << 1
	setupRegisteredFdOnly = 1 << 15
	setupNoMmapWithRegFd  = 1<<14 | 1<<15
	ioUringPairStart      = defaulTime
)

// newIoUringEventLoop returns an event loop whose process has fd 0 bound to
// stdinName and the real ring on fd 3.
func newIoUringEventLoop(t *testing.T, filter globalfilter.Filter) *eventLoop {
	t.Helper()
	el := newFilteredEventLoop(t, filter)
	el.fdState().set(stdinFd, execCommPid, file.NewFd(stdinFd, stdinName, 0))
	el.fdState().set(realRingFd, execCommPid, file.NewFd(realRingFd, realRingName, 2))
	return el
}

// feedIoUringPair drives one io_uring enter/exit pair through the raw event
// path; it returns the emitted pair or nil when the filter dropped it.
func feedIoUringPair(t *testing.T, el *eventLoop, enterTrace, exitTrace types.TraceId,
	fd, cmd uint32, ret int64) *event.Pair {
	t.Helper()
	_, enterRaw := makeEnterIoUringEvent(t, ioUringPairStart, execCommPid, execCommTid, enterTrace, fd, cmd)
	_, exitRaw := makeExitRetEvent(t, ioUringPairStart+openPairLatency, execCommPid, execCommTid, exitTrace, ret)
	return feedRawPair(t, el, enterRaw, exitRaw)
}

func TestIoUringEnterAndRegisterResolveFdUnlessRegisteredIndex(t *testing.T) {
	tests := []struct {
		name      string
		enter     types.TraceId
		exit      types.TraceId
		fd        uint32
		cmd       uint32
		wantName  string
		wantIndex bool
	}{
		{"enter registered ring index 0", types.SYS_ENTER_IO_URING_ENTER, types.SYS_EXIT_IO_URING_ENTER,
			0, enterRegisteredRing, "io_uring:reg[0]", true},
		{"enter registered ring with other flags", types.SYS_ENTER_IO_URING_ENTER, types.SYS_EXIT_IO_URING_ENTER,
			2, enterRegisteredRing | enterGetEvents, "io_uring:reg[2]", true},
		{"enter real ring fd", types.SYS_ENTER_IO_URING_ENTER, types.SYS_EXIT_IO_URING_ENTER,
			uint32(realRingFd), enterGetEvents, realRingName, false},
		// A plain descriptor 0 stays a descriptor 0: only the flag changes
		// the meaning, so a real fd 0 call must keep resolving to the file.
		{"enter plain fd 0 without the flag", types.SYS_ENTER_IO_URING_ENTER, types.SYS_EXIT_IO_URING_ENTER,
			0, 0, stdinName, false},
		{"register via registered ring", types.SYS_ENTER_IO_URING_REGISTER, types.SYS_EXIT_IO_URING_REGISTER,
			0, registerUseRegistered | registerRingFds, "io_uring:reg[0]", true},
		{"register real ring fd", types.SYS_ENTER_IO_URING_REGISTER, types.SYS_EXIT_IO_URING_REGISTER,
			uint32(realRingFd), registerRingFds, realRingName, false},
		// Bit 4 of the enter flags is not special for register (its bit is
		// the top one of the opcode), and vice versa.
		{"register opcode with enter's flag bit", types.SYS_ENTER_IO_URING_REGISTER, types.SYS_EXIT_IO_URING_REGISTER,
			0, enterRegisteredRing, stdinName, false},
		{"enter flags with register's flag bit", types.SYS_ENTER_IO_URING_ENTER, types.SYS_EXIT_IO_URING_ENTER,
			0, registerUseRegistered, stdinName, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			el := newIoUringEventLoop(t, globalfilter.Filter{})
			ep := feedIoUringPair(t, el, tc.enter, tc.exit, tc.fd, tc.cmd, 0)
			if ep == nil {
				t.Fatal("unfiltered io_uring pair must be emitted")
			}
			defer ep.Recycle()
			if got := ep.File.Name(); got != tc.wantName {
				t.Errorf("file = %q, want %q", got, tc.wantName)
			}
			if tc.wantIndex && ep.File.FD() != -1 {
				t.Errorf("registered-ring row reports FD() = %d, want -1 (not a descriptor)", ep.File.FD())
			}
			// Neither call may ever change the fd table.
			assertFdNameTracked(t, el, stdinFd, stdinName)
			assertFdNameTracked(t, el, realRingFd, realRingName)
		})
	}
}

func TestIoUringSetupRegisteredFdOnlyDoesNotRegisterAnFd(t *testing.T) {
	tests := []struct {
		name     string
		flags    uint32
		ret      int64
		wantName string
	}{
		{"REGISTERED_FD_ONLY returns index 0", setupNoMmapWithRegFd, 0, "io_uring:reg[0]"},
		{"REGISTERED_FD_ONLY alone returns index 1", setupRegisteredFdOnly, 1, "io_uring:reg[1]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			el := newIoUringEventLoop(t, globalfilter.Filter{})
			ep := feedIoUringPair(t, el, types.SYS_ENTER_IO_URING_SETUP, types.SYS_EXIT_IO_URING_SETUP, 0xffffffff, tc.flags, tc.ret)
			if ep == nil {
				t.Fatal("unfiltered io_uring_setup pair must be emitted")
			}
			defer ep.Recycle()
			if got := ep.File.Name(); got != tc.wantName {
				t.Errorf("file = %q, want %q", got, tc.wantName)
			}
			// fd 0 still belongs to the file the process opened; the index
			// returned by setup must not have replaced it.
			assertFdNameTracked(t, el, stdinFd, stdinName)
		})
	}
}

func TestIoUringSetupWithoutRegisteredFdOnlyRegistersTheRingFd(t *testing.T) {
	for _, flags := range []uint32{0, setupSqPoll} {
		el := newIoUringEventLoop(t, globalfilter.Filter{})
		const ringFd = 9
		ep := feedIoUringPair(t, el, types.SYS_ENTER_IO_URING_SETUP, types.SYS_EXIT_IO_URING_SETUP, 0xffffffff, flags, ringFd)
		if ep == nil {
			t.Fatalf("flags %#x: unfiltered io_uring_setup pair must be emitted", flags)
		}
		fdFile, ok := ep.File.(*file.FdFile)
		if !ok {
			t.Fatalf("flags %#x: setup row file is %T, want the registered descriptor", flags, ep.File)
		}
		if fdFile.FD() != ringFd {
			t.Errorf("flags %#x: row fd = %d, want %d", flags, fdFile.FD(), ringFd)
		}
		if _, ok := el.fdState().get(ringFd, execCommPid); !ok {
			t.Errorf("flags %#x: ring fd %d was not registered", flags, ringFd)
		}
		ep.Recycle()
	}
}

// A failed REGISTERED_FD_ONLY setup has no ring at all: no label, no state.
func TestFailedIoUringSetupRegisteredFdOnlyTracksNothing(t *testing.T) {
	el := newIoUringEventLoop(t, globalfilter.Filter{})
	ep := feedIoUringPair(t, el, types.SYS_ENTER_IO_URING_SETUP, types.SYS_EXIT_IO_URING_SETUP,
		0xffffffff, setupNoMmapWithRegFd, -22) // -EINVAL
	if ep == nil {
		t.Fatal("a failed io_uring_setup must remain observable")
	}
	defer ep.Recycle()
	if ep.File != nil {
		t.Errorf("failed setup has file %q, want none", ep.File.Name())
	}
	assertFdNameTracked(t, el, stdinFd, stdinName)
}

// A -file filter for the file at fd 0 must not select registered-ring rows:
// before the fix they were labelled with that file and so matched.
func TestRegisteredRingRowIsNotSelectedByTheFileAtThatFd(t *testing.T) {
	filter := globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: stdinName}}

	el := newIoUringEventLoop(t, filter)
	if ep := feedIoUringPair(t, el, types.SYS_ENTER_IO_URING_ENTER, types.SYS_EXIT_IO_URING_ENTER,
		0, enterRegisteredRing, 1); ep != nil {
		defer ep.Recycle()
		t.Fatalf("registered-ring io_uring_enter matched -file %s: %v", stdinName, ep)
	}

	// Sanity: the same filter still selects a plain fd-0 call.
	ep := feedIoUringPair(t, el, types.SYS_ENTER_IO_URING_ENTER, types.SYS_EXIT_IO_URING_ENTER, 0, 0, 1)
	if ep == nil {
		t.Fatal("plain fd 0 io_uring_enter must still match the file filter")
	}
	ep.Recycle()

	// And the label itself is filterable.
	ringFilter := globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: "io_uring:reg["}}
	el = newIoUringEventLoop(t, ringFilter)
	ep = feedIoUringPair(t, el, types.SYS_ENTER_IO_URING_REGISTER, types.SYS_EXIT_IO_URING_REGISTER,
		0, registerUseRegistered, 0)
	if ep == nil {
		t.Fatal("registered-ring row must match its own label")
	}
	ep.Recycle()
}

func assertFdNameTracked(t *testing.T, el *eventLoop, fd int32, want string) {
	t.Helper()
	tracked, ok := el.fdState().get(fd, execCommPid)
	if !ok {
		t.Fatalf("fd %d is no longer tracked, want %q", fd, want)
	}
	if got := tracked.Name(); got != want {
		t.Fatalf("fd %d resolves to %q, want %q", fd, got, want)
	}
}
