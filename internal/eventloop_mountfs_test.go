package internal

import (
	"strings"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"

	"golang.org/x/sys/unix"
)

func TestHandleTwoFdExitUsesFirstDescriptor(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(81, 70, file.NewFd(81, "/proc/self/fd/81", -1))

	enter := &types.TwoFdEvent{
		EventType: types.ENTER_TWO_FD_EVENT,
		TraceId:   types.SYS_ENTER_MOVE_MOUNT,
		Time:      100,
		Pid:       70,
		Tid:       71,
		FdA:       81,
		FdB:       82,
		Extra:     0x2,
	}
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_MOVE_MOUNT,
		Time:      200,
		Ret:       0,
		Pid:       70,
		Tid:       71,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleTwoFdExit(ep, enter); !ok {
		t.Fatal("handleTwoFdExit returned false")
	}
	if ep.File == nil || ep.File.FD() != 81 {
		t.Fatalf("expected resolved descriptor 81, got file=%v", ep.File)
	}
}

func TestHandleTwoFdExitAppliesPairFilter(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{
		filter: globalfilter.Filter{
			Syscall: &globalfilter.StringFilter{Pattern: "openat"},
		},
	})

	enter := &types.TwoFdEvent{
		EventType: types.ENTER_TWO_FD_EVENT,
		TraceId:   types.SYS_ENTER_MOVE_MOUNT,
		Time:      100,
		Pid:       72,
		Tid:       73,
		FdA:       91,
		FdB:       92,
		Extra:     0,
	}
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_MOVE_MOUNT,
		Time:      200,
		Ret:       0,
		Pid:       72,
		Tid:       73,
	}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleTwoFdExit(ep, enter); ok {
		t.Fatal("handleTwoFdExit should reject pair due to filter mismatch")
	}
}

func TestInitRawHandlersRegistersTwoFdEvent(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	if _, ok := el.rawHandlers[types.ENTER_TWO_FD_EVENT]; !ok {
		t.Fatal("ENTER_TWO_FD_EVENT handler is not registered")
	}
}

func TestHandleOpenTreeExitTranslatesAndTracksDescriptorFlags(t *testing.T) {
	syscalls := []struct {
		name       string
		enterTrace types.TraceId
		exitTrace  types.TraceId
	}{
		{name: "open_tree", enterTrace: types.SYS_ENTER_OPEN_TREE, exitTrace: types.SYS_EXIT_OPEN_TREE},
		{name: "open_tree_attr", enterTrace: types.SYS_ENTER_OPEN_TREE_ATTR, exitTrace: types.SYS_EXIT_OPEN_TREE_ATTR},
	}

	flagCases := []struct {
		name       string
		rawFlags   int32
		wantFlags  int
		wantString string
	}{
		{
			name:       "without cloexec",
			rawFlags:   unix.OPEN_TREE_CLONE | unix.AT_EMPTY_PATH | unix.AT_NO_AUTOMOUNT | unix.AT_RECURSIVE | unix.AT_SYMLINK_NOFOLLOW,
			wantFlags:  unix.O_PATH,
			wantString: "O_PATH",
		},
		{
			name:       "with cloexec",
			rawFlags:   unix.OPEN_TREE_CLONE | unix.OPEN_TREE_CLOEXEC | unix.AT_EMPTY_PATH | unix.AT_NO_AUTOMOUNT | unix.AT_RECURSIVE | unix.AT_SYMLINK_NOFOLLOW,
			wantFlags:  unix.O_PATH | syscall.O_CLOEXEC,
			wantString: "O_CLOEXEC|O_PATH",
		},
	}
	for i, syscallCase := range syscalls {
		for _, flagCase := range flagCases {
			t.Run(syscallCase.name+"/"+flagCase.name, func(t *testing.T) {
				el := mustNewEventLoop(t, eventLoopConfig{})
				pid := uint32(700 + i)
				fd := int32(80 + i)
				enter := &types.OpenEvent{
					EventType: types.ENTER_OPEN_EVENT,
					TraceId:   syscallCase.enterTrace,
					Time:      100,
					Pid:       pid,
					Tid:       pid,
					Flags:     flagCase.rawFlags,
				}
				copy(enter.Filename[:], "/tmp/open-tree-target")
				exit := &types.RetEvent{
					EventType: types.EXIT_RET_EVENT,
					TraceId:   syscallCase.exitTrace,
					Time:      200,
					Pid:       pid,
					Tid:       pid,
					Ret:       int64(fd),
				}
				ep := &event.Pair{EnterEv: enter, ExitEv: exit}

				if ok := el.handleOpenExit(ep, enter); !ok {
					t.Fatal("handleOpenExit returned false")
				}
				tracked, ok := el.fdState().files[fdKey(pid, fd)]
				if !ok {
					t.Fatalf("pid %d fd %d was not tracked", pid, fd)
				}
				if got := int(tracked.Flags()); got != flagCase.wantFlags {
					t.Fatalf("tracked flags = %#x, want %#x", got, flagCase.wantFlags)
				}
				if got := tracked.Flags().String(); got != flagCase.wantString {
					t.Errorf("tracked flags string = %q, want %q (raw %#x)", got, flagCase.wantString, flagCase.rawFlags)
				}
				for _, falseFlag := range []string{"O_RDONLY", "O_WRONLY", "O_NOCTTY", "O_NONBLOCK"} {
					if got := tracked.Flags().String(); strings.Contains(got, falseFlag) {
						t.Errorf("tracked flags %q falsely contain %s (raw %#x)", got, falseFlag, flagCase.rawFlags)
					}
				}
				if ep.File != tracked {
					t.Fatal("pair does not retain the registered open_tree descriptor")
				}
			})
		}
	}
}

func TestOpenEventFlagsLeavesOpenFlagsUnchanged(t *testing.T) {
	want := int32(syscall.O_RDWR | syscall.O_CREAT | syscall.O_CLOEXEC)
	ev := &types.OpenEvent{TraceId: types.SYS_ENTER_OPENAT, Flags: want}
	if got := openEventFlags(ev); got != want {
		t.Fatalf("openEventFlags(openat) = %#x, want unchanged %#x", got, want)
	}
}
