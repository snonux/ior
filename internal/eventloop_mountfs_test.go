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

func TestHandleMoveMountExitReportsDestinationPath(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})

	enter := &types.TwoFdEvent{
		EventType:     types.ENTER_TWO_FD_EVENT,
		TraceId:       types.SYS_ENTER_MOVE_MOUNT,
		Time:          100,
		Pid:           70,
		Tid:           71,
		FdA:           81,
		FdB:           82,
		Extra:         0x2,
		OldnameStatus: types.PATH_READ_OK,
		NewnameStatus: types.PATH_READ_OK,
		SchemaVersion: types.TWO_FD_EVENT_SCHEMA_VERSION,
	}
	copy(enter.Oldname[:], "/source")
	copy(enter.Newname[:], "/destination")
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
	if ep.File == nil || ep.File.Name() != "/destination" {
		t.Fatalf("expected move_mount destination path, got file=%v", ep.File)
	}
	if ep.Oldname != "/source" {
		t.Fatalf("expected move_mount source path, got %q", ep.Oldname)
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

func TestOpenEventFlagsLeavesRegularOpenFlagsUnchanged(t *testing.T) {
	want := int32(syscall.O_RDWR | syscall.O_CREAT | syscall.O_CLOEXEC)
	for _, traceID := range []types.TraceId{
		types.SYS_ENTER_OPEN,
		types.SYS_ENTER_OPENAT,
		types.SYS_ENTER_OPENAT2,
	} {
		t.Run(traceID.String(), func(t *testing.T) {
			ev := &types.OpenEvent{TraceId: traceID, Flags: want}
			if got := openEventFlags(ev); got != want {
				t.Fatalf("openEventFlags(%s) = %#x, want unchanged %#x", traceID, got, want)
			}
		})
	}
}

func TestHandleFspickExitRegistersFilesystemContextBeforeFiltering(t *testing.T) {
	const (
		pid      = uint32(740)
		tid      = uint32(741)
		dirfd    = int32(42)
		fspickFD = int32(43)
	)
	base := t.TempDir()
	wantPath := base + "/selected-mount"

	newPair := func() (*event.Pair, *types.PathEvent) {
		enter := &types.PathEvent{
			EventType:      types.ENTER_PATH_EVENT,
			TraceId:        types.SYS_ENTER_FSPICK,
			Time:           100,
			Pid:            pid,
			Tid:            tid,
			Dirfd:          dirfd,
			PathnameStatus: types.PATH_READ_OK,
			Flags:          unix.FSPICK_CLOEXEC,
			SchemaVersion:  types.PATH_EVENT_SCHEMA_VERSION,
			TargetStatus:   types.PATH_TARGET_REQUIRED,
		}
		copy(enter.Pathname[:], "selected-mount")
		exit := &types.RetEvent{
			EventType: types.EXIT_RET_EVENT,
			TraceId:   types.SYS_EXIT_FSPICK,
			Time:      200,
			Pid:       pid,
			Tid:       tid,
			Ret:       int64(fspickFD),
		}
		return &event.Pair{EnterEv: enter, ExitEv: exit}, enter
	}

	t.Run("row and later fd consumer use selected path", func(t *testing.T) {
		el := mustNewEventLoop(t, eventLoopConfig{})
		el.fdState().set(dirfd, pid, file.NewFd(dirfd, base, syscall.O_DIRECTORY))
		ep, enter := newPair()
		if !el.handlePathExit(ep, enter) {
			t.Fatal("fspick pair was dropped")
		}
		if ep.File.Name() != wantPath || ep.File.FD() != fspickFD ||
			int(ep.File.Flags())&syscall.O_ACCMODE != syscall.O_RDWR ||
			!ep.File.Flags().Is(syscall.O_CLOEXEC) {
			t.Fatalf("fspick file = %q fd %d flags %s", ep.File.Name(), ep.File.FD(), ep.File.Flags())
		}

		fsconfig := &types.FdEvent{EventType: types.ENTER_FD_EVENT, TraceId: types.SYS_ENTER_FSCONFIG, Pid: pid, Tid: tid, Fd: fspickFD}
		fsconfigExit := &types.RetEvent{EventType: types.EXIT_RET_EVENT, TraceId: types.SYS_EXIT_FSCONFIG, Pid: pid, Tid: tid, Ret: 0}
		fsconfigPair := &event.Pair{EnterEv: fsconfig, ExitEv: fsconfigExit}
		if !el.handleFdExit(fsconfigPair, fsconfig) {
			t.Fatal("fsconfig pair was dropped")
		}
		if fsconfigPair.File.Name() != wantPath || fsconfigPair.File.FD() != fspickFD {
			t.Fatalf("fsconfig file = %q fd %d, want %q fd %d", fsconfigPair.File.Name(), fsconfigPair.File.FD(), wantPath, fspickFD)
		}
	})

	t.Run("registration survives a filtered fspick row", func(t *testing.T) {
		el := mustNewEventLoop(t, eventLoopConfig{filter: globalfilter.Filter{
			Syscall: &globalfilter.StringFilter{Pattern: "read"},
		}})
		el.fdState().set(dirfd, pid, file.NewFd(dirfd, base, syscall.O_DIRECTORY))
		ep, enter := newPair()
		if el.handlePathExit(ep, enter) {
			t.Fatal("fspick pair unexpectedly passed the syscall filter")
		}
		tracked, ok := el.fdState().get(fspickFD, pid)
		if !ok || tracked.Name() != wantPath ||
			int(tracked.Flags())&syscall.O_ACCMODE != syscall.O_RDWR ||
			!tracked.Flags().Is(syscall.O_CLOEXEC) {
			t.Fatalf("tracked fspick fd = %#v, want %q with O_RDWR|O_CLOEXEC", tracked, wantPath)
		}
	})
}
