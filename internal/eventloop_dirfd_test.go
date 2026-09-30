package internal

import (
	"encoding/binary"
	"path/filepath"
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"

	"golang.org/x/sys/unix"
)

func TestResolveDirfdPath(t *testing.T) {
	const (
		pid   = uint32(2100)
		dirfd = int32(17)
	)
	dir := t.TempDir()
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(dirfd, pid, file.NewFd(dirfd, dir, syscall.O_RDONLY|syscall.O_DIRECTORY))

	tests := []struct {
		name     string
		dirfd    int32
		pathname string
		wantName string
		wantFD   int32
	}{
		{name: "relative", dirfd: dirfd, pathname: "child/file", wantName: filepath.Join(dir, "child/file"), wantFD: dirfd},
		{name: "empty", dirfd: dirfd, pathname: "", wantName: dir, wantFD: dirfd},
		{name: "absolute", dirfd: dirfd, pathname: "/already/absolute", wantName: "/already/absolute", wantFD: -1},
		{name: "AT_FDCWD relative", dirfd: unix.AT_FDCWD, pathname: "cwd-relative", wantName: "cwd-relative", wantFD: -1},
		{name: "AT_FDCWD empty", dirfd: unix.AT_FDCWD, pathname: "", wantName: "", wantFD: -1},
		{name: "unresolved dirfd retains attribution", dirfd: -9, pathname: "relative", wantName: "relative", wantFD: -9},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := el.resolveDirfdPath(tc.dirfd, pid, tc.pathname)
			if got.Name() != tc.wantName {
				t.Fatalf("name = %q, want %q", got.Name(), tc.wantName)
			}
			if got.FD() != tc.wantFD {
				t.Fatalf("fd = %d, want %d", got.FD(), tc.wantFD)
			}
		})
	}
}

func TestHandleOpenExitResolvesRelativeDirfdAndRegistersReturnedFD(t *testing.T) {
	const (
		pid        = uint32(2200)
		dirfd      = int32(18)
		returnedFD = int32(19)
	)
	dir := t.TempDir()
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(dirfd, pid, file.NewFd(dirfd, dir, syscall.O_RDONLY|syscall.O_DIRECTORY))
	enter := &types.OpenEvent{
		EventType:     types.ENTER_OPEN_EVENT,
		TraceId:       types.SYS_ENTER_OPENAT,
		Pid:           pid,
		Tid:           pid,
		Dirfd:         dirfd,
		Flags:         syscall.O_RDONLY,
		SchemaVersion: types.OPEN_EVENT_SCHEMA_VERSION,
	}
	copy(enter.Filename[:], "relative.txt")
	exit := &types.RetEvent{EventType: types.EXIT_RET_EVENT, TraceId: types.SYS_EXIT_OPENAT, Pid: pid, Tid: pid, Ret: int64(returnedFD)}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleOpenExit(ep, enter); !ok {
		t.Fatal("handleOpenExit returned false")
	}
	want := filepath.Join(dir, "relative.txt")
	if ep.File.Name() != want || ep.File.FD() != returnedFD {
		t.Fatalf("file = %q fd %d, want %q fd %d", ep.File.Name(), ep.File.FD(), want, returnedFD)
	}
	tracked, ok := el.fdState().get(returnedFD, pid)
	if !ok || tracked.Name() != want {
		t.Fatalf("returned fd was not registered with resolved path: %#v, %v", tracked, ok)
	}
}

func TestHandleOpenExitDoesNotAttributeUnreadableOrInvalidEmptyNames(t *testing.T) {
	const (
		pid   = uint32(2250)
		dirfd = int32(19)
	)
	target := filepath.Join(t.TempDir(), "open-empty-target")
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(dirfd, pid, file.NewFd(dirfd, target, unix.O_PATH))

	for _, tc := range []struct {
		name     string
		traceID  types.TraceId
		status   uint32
		flags    int32
		ret      int64
		wantName string
		wantFD   int32
	}{
		{name: "failed non-null read", traceID: types.SYS_ENTER_OPENAT, status: types.PATH_READ_FAILED, ret: -int64(unix.EFAULT), wantFD: -1},
		{name: "NULL pointer", traceID: types.SYS_ENTER_OPENAT, status: types.PATH_READ_NULL, ret: -int64(unix.EFAULT), wantFD: -1},
		{name: "openat empty is invalid", traceID: types.SYS_ENTER_OPENAT, status: types.PATH_READ_OK, flags: unix.AT_EMPTY_PATH, ret: -int64(unix.ENOENT), wantFD: -1},
		{name: "open_tree empty with flag and success", traceID: types.SYS_ENTER_OPEN_TREE, status: types.PATH_READ_OK, flags: unix.AT_EMPTY_PATH, ret: 27, wantName: target, wantFD: 27},
		{name: "open_tree empty missing flag", traceID: types.SYS_ENTER_OPEN_TREE, status: types.PATH_READ_OK, ret: -int64(unix.ENOENT), wantFD: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enter := &types.OpenEvent{
				EventType:      types.ENTER_OPEN_EVENT,
				TraceId:        tc.traceID,
				Pid:            pid,
				Tid:            pid,
				Dirfd:          dirfd,
				Flags:          tc.flags,
				FilenameStatus: tc.status,
			}
			exit := &types.RetEvent{EventType: types.EXIT_RET_EVENT, Pid: pid, Tid: pid, Ret: tc.ret}
			ep := &event.Pair{EnterEv: enter, ExitEv: exit}
			if ok := el.handleOpenExit(ep, enter); !ok {
				t.Fatal("handleOpenExit returned false")
			}
			if ep.File.Name() != tc.wantName || ep.File.FD() != tc.wantFD {
				t.Fatalf("file = %q fd %d, want %q fd %d", ep.File.Name(), ep.File.FD(), tc.wantName, tc.wantFD)
			}
		})
	}
}

func TestHandlePathExitDistinguishesEmptyNullAndFailedPathReads(t *testing.T) {
	const (
		pid   = uint32(2300)
		dirfd = int32(20)
	)
	path := filepath.Join(t.TempDir(), "empty-path-target")
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(dirfd, pid, file.NewFd(dirfd, path, unix.O_PATH))

	for _, tc := range []struct {
		name     string
		traceID  types.TraceId
		status   uint32
		target   uint32
		flags    uint32
		ret      int64
		wantName string
		wantFD   int32
	}{
		{name: "statx valid empty with AT_EMPTY_PATH", traceID: types.SYS_ENTER_STATX, status: types.PATH_READ_OK, flags: unix.AT_EMPTY_PATH, ret: 0, wantName: path, wantFD: dirfd},
		{name: "statx NULL with AT_EMPTY_PATH", traceID: types.SYS_ENTER_STATX, status: types.PATH_READ_NULL, flags: unix.AT_EMPTY_PATH, ret: 0, wantName: path, wantFD: dirfd},
		{name: "statx missing AT_EMPTY_PATH", traceID: types.SYS_ENTER_STATX, status: types.PATH_READ_OK, ret: 0, wantFD: -1},
		{name: "statx unsuccessful", traceID: types.SYS_ENTER_STATX, status: types.PATH_READ_OK, flags: unix.AT_EMPTY_PATH, ret: -int64(unix.ENOENT), wantFD: -1},
		{name: "mkdirat never accepts empty", traceID: types.SYS_ENTER_MKDIRAT, status: types.PATH_READ_OK, flags: unix.AT_EMPTY_PATH, ret: 0, wantFD: -1},
		{name: "utimensat NULL means descriptor", traceID: types.SYS_ENTER_UTIMENSAT, status: types.PATH_READ_NULL, ret: 0, wantName: path, wantFD: dirfd},
		{name: "utimensat empty string with AT_EMPTY_PATH", traceID: types.SYS_ENTER_UTIMENSAT, status: types.PATH_READ_OK, flags: unix.AT_EMPTY_PATH, ret: 0, wantName: path, wantFD: dirfd},
		{name: "utimensat empty string missing AT_EMPTY_PATH", traceID: types.SYS_ENTER_UTIMENSAT, status: types.PATH_READ_OK, ret: 0, wantFD: -1},
		{name: "utimensat double OMIT skips NULL target", traceID: types.SYS_ENTER_UTIMENSAT, status: types.PATH_READ_NULL, target: types.PATH_TARGET_SKIPPED, flags: ^uint32(0), ret: 0, wantFD: -1},
		{name: "utimensat unreadable timestamps fail closed", traceID: types.SYS_ENTER_UTIMENSAT, status: types.PATH_READ_NULL, target: types.PATH_TARGET_UNKNOWN, flags: unix.AT_EMPTY_PATH, ret: 0, wantFD: -1},
		{name: "futimesat NULL means descriptor", traceID: types.SYS_ENTER_FUTIMESAT, status: types.PATH_READ_NULL, ret: 0, wantName: path, wantFD: dirfd},
		{name: "futimesat empty string is invalid", traceID: types.SYS_ENTER_FUTIMESAT, status: types.PATH_READ_OK, ret: 0, wantFD: -1},
		{name: "futimesat failed non-null is invalid", traceID: types.SYS_ENTER_FUTIMESAT, status: types.PATH_READ_FAILED, ret: 0, wantFD: -1},
		{name: "futimesat unknown status fails closed", traceID: types.SYS_ENTER_FUTIMESAT, status: 99, ret: 0, wantFD: -1},
		{name: "futimesat unsuccessful NULL is invalid", traceID: types.SYS_ENTER_FUTIMESAT, status: types.PATH_READ_NULL, ret: -int64(unix.EFAULT), wantFD: -1},
		{name: "failed non-null", traceID: types.SYS_ENTER_STATX, status: types.PATH_READ_FAILED, flags: unix.AT_EMPTY_PATH, ret: 0, wantFD: -1},
		{name: "unknown fails closed", traceID: types.SYS_ENTER_STATX, status: 99, flags: unix.AT_EMPTY_PATH, ret: 0, wantFD: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enter := &types.PathEvent{
				EventType:      types.ENTER_PATH_EVENT,
				TraceId:        tc.traceID,
				Pid:            pid,
				Tid:            pid,
				Dirfd:          dirfd,
				PathnameStatus: tc.status,
				TargetStatus:   tc.target,
				Flags:          tc.flags,
			}
			exit := &types.RetEvent{EventType: types.EXIT_RET_EVENT, TraceId: types.SYS_EXIT_STATX, Pid: pid, Tid: pid, Ret: tc.ret}
			ep := &event.Pair{EnterEv: enter, ExitEv: exit}

			if ok := el.handlePathExit(ep, enter); !ok {
				t.Fatal("handlePathExit returned false")
			}
			if ep.File.Name() != tc.wantName || ep.File.FD() != tc.wantFD {
				t.Fatalf("file = %q fd %d, want %q fd %d", ep.File.Name(), ep.File.FD(), tc.wantName, tc.wantFD)
			}
		})
	}
}

func TestHandlePathExitTargetStatusDisablesRelativeDirfdResolution(t *testing.T) {
	const (
		pid            = uint32(2325)
		trackedDirfd   = int32(22)
		untrackedDirfd = int32(99999)
	)
	target := filepath.Join(t.TempDir(), "tracked-target")
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(trackedDirfd, pid, file.NewFd(trackedDirfd, target, unix.O_PATH))

	for _, tc := range []struct {
		name         string
		dirfd        int32
		targetStatus uint32
	}{
		{name: "skipped with tracked dirfd", dirfd: trackedDirfd, targetStatus: types.PATH_TARGET_SKIPPED},
		{name: "unknown with tracked dirfd", dirfd: trackedDirfd, targetStatus: types.PATH_TARGET_UNKNOWN},
		{name: "future status with tracked dirfd", dirfd: trackedDirfd, targetStatus: 99},
		{name: "skipped with invalid dirfd", dirfd: untrackedDirfd, targetStatus: types.PATH_TARGET_SKIPPED},
		{name: "unknown with invalid dirfd", dirfd: untrackedDirfd, targetStatus: types.PATH_TARGET_UNKNOWN},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enter := &types.PathEvent{
				EventType:      types.ENTER_PATH_EVENT,
				TraceId:        types.SYS_ENTER_UTIMENSAT,
				Pid:            pid,
				Tid:            pid,
				Dirfd:          tc.dirfd,
				PathnameStatus: types.PATH_READ_OK,
				TargetStatus:   tc.targetStatus,
				Flags:          ^uint32(0),
			}
			copy(enter.Pathname[:], "ignored-relative-target")
			exit := &types.RetEvent{
				EventType: types.EXIT_RET_EVENT,
				TraceId:   types.SYS_EXIT_UTIMENSAT,
				Pid:       pid,
				Tid:       pid,
				Ret:       0,
			}
			ep := &event.Pair{EnterEv: enter, ExitEv: exit}

			if ok := el.handlePathExit(ep, enter); !ok {
				t.Fatal("handlePathExit returned false")
			}
			if ep.File.Name() != "ignored-relative-target" || ep.File.FD() != -1 {
				t.Fatalf("file = %q fd %d, want raw path with fd -1", ep.File.Name(), ep.File.FD())
			}
		})
	}
}

func TestHandlePathExitNewerAtEmptyPathCohort(t *testing.T) {
	const (
		pid   = uint32(2350)
		dirfd = int32(25)
	)
	target := filepath.Join(t.TempDir(), "newer-at-empty-target")
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(dirfd, pid, file.NewFd(dirfd, target, unix.O_PATH))

	traceIDs := []types.TraceId{
		types.SYS_ENTER_GETXATTRAT,
		types.SYS_ENTER_SETXATTRAT,
		types.SYS_ENTER_LISTXATTRAT,
		types.SYS_ENTER_REMOVEXATTRAT,
		types.SYS_ENTER_FILE_GETATTR,
		types.SYS_ENTER_FILE_SETATTR,
	}
	for _, traceID := range traceIDs {
		for _, tc := range []struct {
			name     string
			status   uint32
			flags    uint32
			ret      int64
			wantName string
			wantFD   int32
		}{
			{name: "valid empty", status: types.PATH_READ_OK, flags: unix.AT_EMPTY_PATH, ret: 0, wantName: target, wantFD: dirfd},
			{name: "NULL", status: types.PATH_READ_NULL, flags: unix.AT_EMPTY_PATH, ret: 0, wantName: target, wantFD: dirfd},
			{name: "missing flag", status: types.PATH_READ_OK, ret: 0, wantFD: -1},
			{name: "unsuccessful", status: types.PATH_READ_OK, flags: unix.AT_EMPTY_PATH, ret: -int64(unix.EINVAL), wantFD: -1},
			{name: "failed read", status: types.PATH_READ_FAILED, flags: unix.AT_EMPTY_PATH, ret: 0, wantFD: -1},
			{name: "unknown status", status: 99, flags: unix.AT_EMPTY_PATH, ret: 0, wantFD: -1},
		} {
			t.Run(traceID.Name()+"/"+tc.name, func(t *testing.T) {
				enter := &types.PathEvent{
					EventType:      types.ENTER_PATH_EVENT,
					TraceId:        traceID,
					Pid:            pid,
					Tid:            pid,
					Dirfd:          dirfd,
					PathnameStatus: tc.status,
					Flags:          tc.flags,
				}
				exit := &types.RetEvent{EventType: types.EXIT_RET_EVENT, Pid: pid, Tid: pid, Ret: tc.ret}
				ep := &event.Pair{EnterEv: enter, ExitEv: exit}
				if ok := el.handlePathExit(ep, enter); !ok {
					t.Fatal("handlePathExit returned false")
				}
				if ep.File.Name() != tc.wantName || ep.File.FD() != tc.wantFD {
					t.Fatalf("file = %q fd %d, want %q fd %d", ep.File.Name(), ep.File.FD(), tc.wantName, tc.wantFD)
				}
			})
		}
	}
}

func TestHandleNameExitResolvesBothDirectoryDescriptors(t *testing.T) {
	const (
		pid      = uint32(2400)
		oldDirfd = int32(21)
		newDirfd = int32(22)
	)
	oldDir := filepath.Join(t.TempDir(), "old")
	newDir := filepath.Join(t.TempDir(), "new")
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(oldDirfd, pid, file.NewFd(oldDirfd, oldDir, syscall.O_RDONLY|syscall.O_DIRECTORY))
	el.fdState().set(newDirfd, pid, file.NewFd(newDirfd, newDir, syscall.O_RDONLY|syscall.O_DIRECTORY))
	enter := &types.NameEvent{
		EventType: types.ENTER_NAME_EVENT,
		TraceId:   types.SYS_ENTER_RENAMEAT,
		Pid:       pid,
		Tid:       pid,
		Olddirfd:  oldDirfd,
		Newdirfd:  newDirfd,
	}
	copy(enter.Oldname[:], "before")
	copy(enter.Newname[:], "after")
	exit := &types.RetEvent{EventType: types.EXIT_RET_EVENT, TraceId: types.SYS_EXIT_RENAMEAT, Pid: pid, Tid: pid, Ret: 0}
	ep := &event.Pair{EnterEv: enter, ExitEv: exit}

	if ok := el.handleNameExit(ep, enter); !ok {
		t.Fatal("handleNameExit returned false")
	}
	if want := filepath.Join(oldDir, "before"); ep.Oldname != want {
		t.Fatalf("oldname = %q, want %q", ep.Oldname, want)
	}
	if want := filepath.Join(newDir, "after"); ep.File.Name() != want {
		t.Fatalf("newname = %q, want %q", ep.File.Name(), want)
	}
}

func TestHandleNameExitDistinguishesEachPathReadStatus(t *testing.T) {
	const (
		pid      = uint32(2450)
		oldDirfd = int32(21)
		newDirfd = int32(22)
	)
	oldDir := filepath.Join(t.TempDir(), "old")
	newDir := filepath.Join(t.TempDir(), "new")
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(oldDirfd, pid, file.NewFd(oldDirfd, oldDir, syscall.O_RDONLY|syscall.O_DIRECTORY))
	el.fdState().set(newDirfd, pid, file.NewFd(newDirfd, newDir, syscall.O_RDONLY|syscall.O_DIRECTORY))

	for _, tc := range []struct {
		name      string
		oldname   string
		newname   string
		oldStatus uint32
		newStatus uint32
		flags     uint32
		ret       int64
		wantOld   string
		wantNew   string
	}{
		{name: "linkat old empty with AT_EMPTY_PATH", newname: "dest", oldStatus: types.PATH_READ_OK, newStatus: types.PATH_READ_OK, flags: unix.AT_EMPTY_PATH, ret: 0, wantOld: oldDir, wantNew: filepath.Join(newDir, "dest")},
		{name: "linkat destination empty never resolves", oldname: "source", oldStatus: types.PATH_READ_OK, newStatus: types.PATH_READ_OK, flags: unix.AT_EMPTY_PATH, ret: 0, wantOld: filepath.Join(oldDir, "source")},
		{name: "linkat old empty missing flag", newname: "dest", oldStatus: types.PATH_READ_OK, newStatus: types.PATH_READ_OK, ret: 0, wantNew: filepath.Join(newDir, "dest")},
		{name: "linkat old empty unsuccessful", newname: "dest", oldStatus: types.PATH_READ_OK, newStatus: types.PATH_READ_OK, flags: unix.AT_EMPTY_PATH, ret: -int64(unix.ENOENT), wantNew: filepath.Join(newDir, "dest")},
		{name: "linkat old NULL is not AT_EMPTY_PATH", newname: "dest", oldStatus: types.PATH_READ_NULL, newStatus: types.PATH_READ_OK, flags: unix.AT_EMPTY_PATH, ret: 0, wantNew: filepath.Join(newDir, "dest")},
		{name: "old failed independently", newname: "dest", oldStatus: types.PATH_READ_FAILED, newStatus: types.PATH_READ_OK, flags: unix.AT_EMPTY_PATH, ret: 0, wantNew: filepath.Join(newDir, "dest")},
		{name: "new failed independently", oldname: "source", oldStatus: types.PATH_READ_OK, newStatus: types.PATH_READ_FAILED, flags: unix.AT_EMPTY_PATH, ret: 0, wantOld: filepath.Join(oldDir, "source")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enter := &types.NameEvent{
				EventType:     types.ENTER_NAME_EVENT,
				TraceId:       types.SYS_ENTER_LINKAT,
				Pid:           pid,
				Tid:           pid,
				Olddirfd:      oldDirfd,
				Newdirfd:      newDirfd,
				OldnameStatus: tc.oldStatus,
				NewnameStatus: tc.newStatus,
				Flags:         tc.flags,
			}
			copy(enter.Oldname[:], tc.oldname)
			copy(enter.Newname[:], tc.newname)
			exit := &types.RetEvent{EventType: types.EXIT_RET_EVENT, TraceId: types.SYS_EXIT_LINKAT, Pid: pid, Tid: pid, Ret: tc.ret}
			ep := &event.Pair{EnterEv: enter, ExitEv: exit}

			if ok := el.handleNameExit(ep, enter); !ok {
				t.Fatal("handleNameExit returned false")
			}
			if ep.Oldname != tc.wantOld || ep.File.Name() != tc.wantNew {
				t.Fatalf("names = %q -> %q, want %q -> %q", ep.Oldname, ep.File.Name(), tc.wantOld, tc.wantNew)
			}
		})
	}
}

func TestDirfdRelativeOpenDefersPathFilterUntilResolution(t *testing.T) {
	const (
		pid        = uint32(2500)
		dirfd      = int32(23)
		returnedFD = int64(24)
	)
	dir := t.TempDir()
	want := filepath.Join(dir, "relative.txt")
	el := newFilteredEventLoop(t, globalfilter.Filter{
		File: &globalfilter.StringFilter{Pattern: "^" + want + "$"},
	})
	el.fdState().set(dirfd, pid, file.NewFd(dirfd, dir, syscall.O_RDONLY|syscall.O_DIRECTORY))
	enter := &types.OpenEvent{
		EventType:     types.ENTER_OPEN_EVENT,
		TraceId:       types.SYS_ENTER_OPENAT,
		Time:          1,
		Pid:           pid,
		Tid:           pid,
		Dirfd:         dirfd,
		Flags:         syscall.O_RDONLY,
		SchemaVersion: types.OPEN_EVENT_SCHEMA_VERSION,
	}
	copy(enter.Filename[:], "relative.txt")
	copy(enter.Comm[:], "ioworkload")
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_OPENAT,
		Time:      2,
		Pid:       pid,
		Tid:       pid,
		Ret:       returnedFD,
	}
	enterRaw, err := enter.Bytes()
	if err != nil {
		t.Fatalf("encode open enter: %v", err)
	}
	exitRaw, err := exit.Bytes()
	if err != nil {
		t.Fatalf("encode open exit: %v", err)
	}
	out := make(chan *event.Pair, 1)
	el.processRawEvent(enterRaw, out)
	el.processRawEvent(exitRaw, out)

	select {
	case ep := <-out:
		defer ep.Recycle()
		if ep.File.Name() != want {
			t.Fatalf("file = %q, want %q", ep.File.Name(), want)
		}
	default:
		t.Fatal("resolved path filter dropped dirfd-relative open")
	}
}

func TestFaultedRelativeOpenFixupPromotesStatusBeforeDirfdResolution(t *testing.T) {
	const (
		pid        = uint32(2520)
		dirfd      = int32(26)
		returnedFD = int64(27)
	)
	dir := t.TempDir()
	want := filepath.Join(dir, "recovered-relative.txt")
	el := newFilteredEventLoop(t, globalfilter.Filter{
		File: &globalfilter.StringFilter{Pattern: "^" + want + "$"},
	})
	el.fdState().set(dirfd, pid, file.NewFd(dirfd, dir, syscall.O_RDONLY|syscall.O_DIRECTORY))
	enter := &types.OpenEvent{
		EventType:      types.ENTER_OPEN_EVENT,
		TraceId:        types.SYS_ENTER_OPENAT,
		Time:           1,
		Pid:            pid,
		Tid:            pid,
		Dirfd:          dirfd,
		Flags:          syscall.O_RDONLY,
		FilenameStatus: types.PATH_READ_FAILED,
		SchemaVersion:  types.OPEN_EVENT_SCHEMA_VERSION,
	}
	copy(enter.Comm[:], "ioworkload")
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_OPENAT,
		Time:      2,
		Pid:       pid,
		Tid:       pid,
		Ret:       returnedFD,
	}
	enterRaw, err := enter.Bytes()
	if err != nil {
		t.Fatalf("encode open enter: %v", err)
	}
	exitRaw, err := exit.Bytes()
	if err != nil {
		t.Fatalf("encode open exit: %v", err)
	}
	out := make(chan *event.Pair, 1)
	el.processRawEvent(enterRaw, out)
	el.processRawEvent(makeOpenNameFixupEvent(t, pid, types.SYS_ENTER_OPENAT, "recovered-relative.txt"), out)
	el.processRawEvent(exitRaw, out)

	select {
	case ep := <-out:
		defer ep.Recycle()
		openEv, ok := ep.EnterEv.(*types.OpenEvent)
		if !ok || openEv.FilenameStatus != types.PATH_READ_OK {
			t.Fatalf("fixed enter status = %#v, want PATH_READ_OK", ep.EnterEv)
		}
		if ep.File.Name() != want {
			t.Fatalf("file = %q, want %q", ep.File.Name(), want)
		}
	default:
		t.Fatal("fixed relative open was dropped by its resolved path filter")
	}
}

func TestLegacyKernelOpenPayloadKeepsOriginalPathAndFlags(t *testing.T) {
	const (
		pid        = uint32(2550)
		returnedFD = int64(25)
	)
	el := mustNewEventLoop(t, eventLoopConfig{})

	// The pre-i4 kernel layout is 304 bytes: flags at 24, filename at 28,
	// comm at 284, and four bytes of C tail padding. Its size used to collide
	// with the first widened layout, which silently shifted every field.
	enterRaw := make([]byte, 304)
	binary.LittleEndian.PutUint32(enterRaw[0:4], uint32(types.ENTER_OPEN_EVENT))
	binary.LittleEndian.PutUint32(enterRaw[4:8], uint32(types.SYS_ENTER_OPENAT))
	binary.LittleEndian.PutUint64(enterRaw[8:16], 1)
	binary.LittleEndian.PutUint32(enterRaw[16:20], pid)
	binary.LittleEndian.PutUint32(enterRaw[20:24], pid)
	binary.LittleEndian.PutUint32(enterRaw[24:28], syscall.O_CLOEXEC)
	copy(enterRaw[28:284], "legacy-relative")
	copy(enterRaw[284:300], "legacy-comm")

	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   types.SYS_EXIT_OPENAT,
		Time:      2,
		Pid:       pid,
		Tid:       pid,
		Ret:       returnedFD,
	}
	exitRaw, err := exit.Bytes()
	if err != nil {
		t.Fatalf("encode open exit: %v", err)
	}
	out := make(chan *event.Pair, 1)
	el.processRawEvent(enterRaw, out)
	el.processRawEvent(exitRaw, out)

	select {
	case ep := <-out:
		defer ep.Recycle()
		if ep.File.Name() != "legacy-relative" || ep.File.FD() != int32(returnedFD) ||
			int32(ep.File.Flags()) != syscall.O_CLOEXEC {
			t.Fatalf("legacy open decoded as name %q fd %d flags %v", ep.File.Name(), ep.File.FD(), ep.File.Flags())
		}
	default:
		t.Fatal("legacy kernel open payload was not paired")
	}
}

func TestRawPathFiltersDeferOnlyPathsThatNeedDirfdResolution(t *testing.T) {
	filter := globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: "^/resolved/path$"}}

	pathEv := &types.PathEvent{Dirfd: 7}
	copy(pathEv.Pathname[:], "relative")
	if !matchRawPathEvent(filter, pathEv) {
		t.Fatal("relative path_event with a concrete dirfd must defer its path filter")
	}
	pathEv.Dirfd = unix.AT_FDCWD
	if matchRawPathEvent(filter, pathEv) {
		t.Fatal("AT_FDCWD path_event must apply its raw path filter")
	}

	t.Run("non-required target applies raw relative path", func(t *testing.T) {
		for _, status := range []uint32{
			types.PATH_TARGET_SKIPPED,
			types.PATH_TARGET_UNKNOWN,
			99,
		} {
			pathEv := &types.PathEvent{
				TraceId:        types.SYS_ENTER_UTIMENSAT,
				Dirfd:          7,
				PathnameStatus: types.PATH_READ_OK,
				TargetStatus:   status,
			}
			copy(pathEv.Pathname[:], "ignored-relative-target")
			if matchRawPathEvent(filter, pathEv) {
				t.Fatalf("target status %d deferred a relative path that the kernel did not validate", status)
			}
			rawFilter := globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: "^ignored-relative-target$"}}
			if !matchRawPathEvent(rawFilter, pathEv) {
				t.Fatalf("target status %d did not retain the raw relative path", status)
			}
		}
	})

	nameEv := &types.NameEvent{Olddirfd: 8, Newdirfd: 9}
	copy(nameEv.Oldname[:], "old")
	copy(nameEv.Newname[:], "new")
	if !matchRawNameEvent(filter, nameEv) {
		t.Fatal("name_event with concrete dirfds must defer its path filter")
	}
	nameEv.Olddirfd = unix.AT_FDCWD
	nameEv.Newdirfd = unix.AT_FDCWD
	if matchRawNameEvent(filter, nameEv) {
		t.Fatal("AT_FDCWD name_event must apply its raw path filter")
	}

	t.Run("empty pathname uses exact syscall policy", func(t *testing.T) {
		pathEv := &types.PathEvent{
			TraceId:        types.SYS_ENTER_STATX,
			Dirfd:          7,
			PathnameStatus: types.PATH_READ_OK,
			Flags:          unix.AT_EMPTY_PATH,
		}
		if !matchRawPathEvent(filter, pathEv) {
			t.Fatal("statx empty path with AT_EMPTY_PATH must defer to descriptor resolution")
		}
		pathEv.Flags = 0
		if matchRawPathEvent(filter, pathEv) {
			t.Fatal("statx empty path without AT_EMPTY_PATH must apply the raw empty path filter")
		}
		pathEv.TraceId = types.SYS_ENTER_MKDIRAT
		pathEv.Flags = unix.AT_EMPTY_PATH
		if matchRawPathEvent(filter, pathEv) {
			t.Fatal("mkdirat empty path must never defer to descriptor resolution")
		}
		pathEv.TraceId = types.SYS_ENTER_STATX
		pathEv.PathnameStatus = types.PATH_READ_FAILED
		if matchRawPathEvent(filter, pathEv) {
			t.Fatal("failed non-NULL pathname read must not defer as AT_EMPTY_PATH")
		}

		pathEv.TraceId = types.SYS_ENTER_UTIMENSAT
		pathEv.PathnameStatus = types.PATH_READ_NULL
		pathEv.Flags = 0
		if !matchRawPathEvent(filter, pathEv) {
			t.Fatal("utimensat NULL pathname must defer to descriptor resolution")
		}
		pathEv.PathnameStatus = types.PATH_READ_OK
		if matchRawPathEvent(filter, pathEv) {
			t.Fatal("utimensat empty string without AT_EMPTY_PATH must not defer")
		}
		pathEv.Flags = unix.AT_EMPTY_PATH
		if !matchRawPathEvent(filter, pathEv) {
			t.Fatal("utimensat empty string with AT_EMPTY_PATH must defer")
		}
		pathEv.PathnameStatus = types.PATH_READ_NULL
		pathEv.TargetStatus = types.PATH_TARGET_SKIPPED
		pathEv.Flags = ^uint32(0)
		if matchRawPathEvent(filter, pathEv) {
			t.Fatal("utimensat double-UTIME_OMIT NULL pathname must not defer")
		}
		pathEv.TargetStatus = types.PATH_TARGET_UNKNOWN
		if matchRawPathEvent(filter, pathEv) {
			t.Fatal("utimensat unreadable timestamp metadata must fail closed")
		}

		pathEv.TraceId = types.SYS_ENTER_FUTIMESAT
		pathEv.PathnameStatus = types.PATH_READ_NULL
		pathEv.TargetStatus = types.PATH_TARGET_REQUIRED
		pathEv.Flags = 0
		if !matchRawPathEvent(filter, pathEv) {
			t.Fatal("futimesat NULL pathname must defer to descriptor resolution")
		}
		pathEv.PathnameStatus = types.PATH_READ_OK
		if matchRawPathEvent(filter, pathEv) {
			t.Fatal("futimesat empty string must not defer to descriptor resolution")
		}
		pathEv.PathnameStatus = types.PATH_READ_FAILED
		if matchRawPathEvent(filter, pathEv) {
			t.Fatal("futimesat failed non-NULL pathname read must not defer")
		}
		pathEv.PathnameStatus = 99
		if matchRawPathEvent(filter, pathEv) {
			t.Fatal("futimesat unknown pathname status must fail closed")
		}
	})

	t.Run("newer at-empty cohort defers only trusted flagged paths", func(t *testing.T) {
		for _, traceID := range []types.TraceId{
			types.SYS_ENTER_GETXATTRAT,
			types.SYS_ENTER_SETXATTRAT,
			types.SYS_ENTER_LISTXATTRAT,
			types.SYS_ENTER_REMOVEXATTRAT,
			types.SYS_ENTER_FILE_GETATTR,
			types.SYS_ENTER_FILE_SETATTR,
		} {
			for _, status := range []uint32{types.PATH_READ_OK, types.PATH_READ_NULL} {
				ev := &types.PathEvent{TraceId: traceID, Dirfd: 7, PathnameStatus: status, Flags: unix.AT_EMPTY_PATH}
				if !matchRawPathEvent(filter, ev) {
					t.Fatalf("%s status %d with AT_EMPTY_PATH did not defer", traceID.Name(), status)
				}
				ev.Flags = 0
				if matchRawPathEvent(filter, ev) {
					t.Fatalf("%s status %d without AT_EMPTY_PATH deferred", traceID.Name(), status)
				}
			}
			for _, status := range []uint32{types.PATH_READ_FAILED, 99} {
				ev := &types.PathEvent{TraceId: traceID, Dirfd: 7, PathnameStatus: status, Flags: unix.AT_EMPTY_PATH}
				if matchRawPathEvent(filter, ev) {
					t.Fatalf("%s untrusted status %d deferred", traceID.Name(), status)
				}
			}
		}
	})

	t.Run("linkat permits only the old empty side", func(t *testing.T) {
		nameEv := &types.NameEvent{
			TraceId:       types.SYS_ENTER_LINKAT,
			Olddirfd:      8,
			Newdirfd:      unix.AT_FDCWD,
			OldnameStatus: types.PATH_READ_OK,
			NewnameStatus: types.PATH_READ_OK,
			Flags:         unix.AT_EMPTY_PATH,
		}
		copy(nameEv.Newname[:], "/raw-destination")
		if !matchRawNameEvent(filter, nameEv) {
			t.Fatal("linkat old empty path with AT_EMPTY_PATH must defer")
		}
		nameEv.Flags = 0
		if matchRawNameEvent(filter, nameEv) {
			t.Fatal("linkat old empty path without AT_EMPTY_PATH must not defer")
		}

		nameEv.Flags = unix.AT_EMPTY_PATH
		nameEv.Olddirfd = unix.AT_FDCWD
		copy(nameEv.Oldname[:], "/raw-source")
		nameEv.Newdirfd = 9
		if matchRawNameEvent(filter, nameEv) {
			t.Fatal("linkat empty destination must never defer to its descriptor")
		}
	})
}

// newExecPair builds an exec enter/exit pair as BPF reports it: plain execve
// carries dirfd -1 and no flags, execveat its real dirfd and flags word. The
// filename counts as read successfully (PATH_READ_OK, which is also the zero
// value test tables leave in their status column); callers override
// FilenameStatus for the NULL and failed-read cases.
func newExecPair(traceID types.TraceId, pid uint32, dirfd, flags int32, name string, ret int64) (*types.ExecEvent, *types.RetEvent) {
	enter := &types.ExecEvent{
		EventType:      types.ENTER_EXEC_EVENT,
		TraceId:        traceID,
		Time:           1,
		Pid:            pid,
		Tid:            pid,
		Dirfd:          dirfd,
		Flags:          flags,
		FilenameStatus: types.PATH_READ_OK,
		SchemaVersion:  types.EXEC_EVENT_SCHEMA_VERSION,
	}
	copy(enter.Filename[:], name)
	copy(enter.Comm[:], "launcher")
	exit := &types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   traceID - 1,
		Time:      2,
		Pid:       pid,
		Tid:       pid,
		Ret:       ret,
	}
	return enter, exit
}

func TestHandleExecExitResolvesDirfdAndEmptyPath(t *testing.T) {
	const (
		pid    = uint32(2700)
		dirfd  = int32(30)
		progfd = int32(31)
		failed = int64(-int64(syscall.ENOENT))
	)
	dir := t.TempDir()
	prog := filepath.Join(dir, "prog")
	el := mustNewEventLoop(t, eventLoopConfig{})
	el.fdState().set(dirfd, pid, file.NewFd(dirfd, dir, syscall.O_RDONLY|syscall.O_DIRECTORY))
	el.fdState().set(progfd, pid, file.NewFd(progfd, prog, syscall.O_RDONLY))

	tests := []struct {
		name     string
		traceID  types.TraceId
		dirfd    int32
		flags    int32
		filename string
		status   uint32
		ret      int64
		wantName string
		wantFD   int32
	}{
		{name: "execveat relative to dirfd", traceID: types.SYS_ENTER_EXECVEAT, dirfd: dirfd, filename: "ls", wantName: filepath.Join(dir, "ls"), wantFD: dirfd},
		{name: "failed execveat keeps resolved path", traceID: types.SYS_ENTER_EXECVEAT, dirfd: dirfd, filename: "ls", ret: failed, wantName: filepath.Join(dir, "ls"), wantFD: dirfd},
		{name: "fexecve AT_EMPTY_PATH names the descriptor", traceID: types.SYS_ENTER_EXECVEAT, dirfd: progfd, flags: unix.AT_EMPTY_PATH, wantName: prog, wantFD: progfd},
		{name: "failed fexecve reports no path", traceID: types.SYS_ENTER_EXECVEAT, dirfd: progfd, flags: unix.AT_EMPTY_PATH, ret: failed, wantName: "", wantFD: -1},
		// Task 9p2: an empty name only means "the descriptor itself" when BPF
		// actually observed "" or NULL. An unreadable name leaves the same
		// empty buffer but is missing data, so it must not borrow the fd's
		// identity. A successful NULL AT_EMPTY_PATH execveat can only have
		// run the descriptor; a failed one reports no path.
		{name: "AT_EMPTY_PATH with unreadable name reports no path", traceID: types.SYS_ENTER_EXECVEAT, dirfd: progfd, flags: unix.AT_EMPTY_PATH, status: types.PATH_READ_FAILED, wantName: "", wantFD: -1},
		{name: "AT_EMPTY_PATH with NULL name names the descriptor", traceID: types.SYS_ENTER_EXECVEAT, dirfd: progfd, flags: unix.AT_EMPTY_PATH, status: types.PATH_READ_NULL, wantName: prog, wantFD: progfd},
		{name: "failed AT_EMPTY_PATH with NULL name reports no path", traceID: types.SYS_ENTER_EXECVEAT, dirfd: progfd, flags: unix.AT_EMPTY_PATH, status: types.PATH_READ_NULL, ret: failed, wantName: "", wantFD: -1},
		{name: "execve NULL name reports no path", traceID: types.SYS_ENTER_EXECVE, dirfd: -1, flags: unix.AT_EMPTY_PATH, status: types.PATH_READ_NULL, wantName: "", wantFD: -1},
		{name: "unknown filename status fails closed", traceID: types.SYS_ENTER_EXECVEAT, dirfd: progfd, flags: unix.AT_EMPTY_PATH, status: 99, wantName: "", wantFD: -1},
		{name: "empty name without AT_EMPTY_PATH", traceID: types.SYS_ENTER_EXECVEAT, dirfd: progfd, wantName: "", wantFD: -1},
		{name: "absolute name ignores dirfd", traceID: types.SYS_ENTER_EXECVEAT, dirfd: dirfd, filename: "/usr/bin/true", wantName: "/usr/bin/true", wantFD: -1},
		{name: "execveat AT_FDCWD stays relative", traceID: types.SYS_ENTER_EXECVEAT, dirfd: unix.AT_FDCWD, filename: "ls", wantName: "ls", wantFD: -1},
		{name: "execve dirfd -1 means AT_FDCWD", traceID: types.SYS_ENTER_EXECVE, dirfd: -1, filename: "./prog", wantName: "./prog", wantFD: -1},
		{name: "execve ignores AT_EMPTY_PATH bits", traceID: types.SYS_ENTER_EXECVE, dirfd: -1, flags: unix.AT_EMPTY_PATH, wantName: "", wantFD: -1},
		{name: "invalid dirfd keeps name and attribution", traceID: types.SYS_ENTER_EXECVEAT, dirfd: -9, filename: "ls", ret: -int64(syscall.EBADF), wantName: "ls", wantFD: -9},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enter, exit := newExecPair(tc.traceID, pid, tc.dirfd, tc.flags, tc.filename, tc.ret)
			enter.FilenameStatus = tc.status
			ep := &event.Pair{EnterEv: enter, ExitEv: exit}
			if ok := el.handleExecExit(ep, enter); !ok {
				t.Fatal("handleExecExit returned false")
			}
			if ep.File.Name() != tc.wantName || ep.File.FD() != tc.wantFD {
				t.Fatalf("file = %q fd %d, want %q fd %d", ep.File.Name(), ep.File.FD(), tc.wantName, tc.wantFD)
			}
		})
	}
}

// TestFexecveResolvesCloexecDescriptorBeforeExecRecord drives the real ring
// buffer order of a successful fexecve: enter, then the sched_process_exec
// control record (which evicts the O_CLOEXEC descriptor from the fd table),
// then the exit. The row must still name the program the descriptor held.
func TestFexecveResolvesCloexecDescriptorBeforeExecRecord(t *testing.T) {
	// Beyond any pid_max, so no procfs fallback can supply a name by accident.
	const (
		pid    = uint32(0x7ffffff0)
		progfd = int32(5)
	)
	prog := filepath.Join(t.TempDir(), "prog")
	for _, tc := range []struct {
		name     string
		filename string
		flags    int32
		want     string
	}{
		{name: "fexecve AT_EMPTY_PATH", flags: unix.AT_EMPTY_PATH, want: prog},
		{name: "execveat relative to cloexec dirfd", filename: "ls", want: filepath.Join(prog, "ls")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := mustNewEventLoop(t, eventLoopConfig{})
			el.fdState().set(progfd, pid, file.NewFd(progfd, prog, syscall.O_RDONLY|syscall.O_CLOEXEC))
			enter, exit := newExecPair(types.SYS_ENTER_EXECVEAT, pid, progfd, tc.flags, tc.filename, 0)
			enterRaw, err := enter.Bytes()
			if err != nil {
				t.Fatalf("encode exec enter: %v", err)
			}
			exitRaw, err := exit.Bytes()
			if err != nil {
				t.Fatalf("encode exec exit: %v", err)
			}
			out := make(chan *event.Pair, 1)
			el.processRawEvent(enterRaw, out)
			el.processRawEvent(makeProcessExecEvent(t, 2, pid, pid, "prog"), out)
			if _, ok := el.fdState().get(progfd, pid); ok {
				t.Fatal("exec record did not drop the O_CLOEXEC descriptor; ordering not exercised")
			}
			el.processRawEvent(exitRaw, out)

			select {
			case ep := <-out:
				defer ep.Recycle()
				if ep.File.Name() != tc.want || ep.File.FD() != progfd {
					t.Fatalf("file = %q fd %d, want %q fd %d", ep.File.Name(), ep.File.FD(), tc.want, progfd)
				}
			default:
				t.Fatal("exec pair was not emitted")
			}
		})
	}
}

// runRawExec feeds an exec pair through processRawEvent in ring-buffer order,
// running between after the enter record, and returns the emitted pair (nil
// when none was emitted).
func runRawExec(t *testing.T, el *eventLoop, enter *types.ExecEvent, exit *types.RetEvent, between func()) *event.Pair {
	t.Helper()
	enterRaw, err := enter.Bytes()
	if err != nil {
		t.Fatalf("encode exec enter: %v", err)
	}
	return runRawExecRecords(t, el, enterRaw, exit, between)
}

// runRawExecRecords is runRawExec for an already encoded (possibly truncated)
// enter record.
func runRawExecRecords(t *testing.T, el *eventLoop, enterRaw []byte, exit *types.RetEvent, between func()) *event.Pair {
	t.Helper()
	exitRaw, err := exit.Bytes()
	if err != nil {
		t.Fatalf("encode exec exit: %v", err)
	}
	out := make(chan *event.Pair, 1)
	el.processRawEvent(enterRaw, out)
	if between != nil {
		between()
	}
	el.processRawEvent(exitRaw, out)
	select {
	case ep := <-out:
		return ep
	default:
		return nil
	}
}

// TestRawExecEnterSnapshotRespectsOutcomeAndIsolation drives the enter-time
// snapshot path (storeEnter) end to end, where ep.File is already set when
// handleExecExit runs: a failed fexecve must still withdraw the descriptor
// attribution, and fd-table changes after the enter must not leak into the
// row.
func TestRawExecEnterSnapshotRespectsOutcomeAndIsolation(t *testing.T) {
	const (
		pid    = uint32(0x7ffffff1)
		progfd = int32(6)
		flags  = int32(syscall.O_RDONLY)
	)
	prog := filepath.Join(t.TempDir(), "prog")
	tests := []struct {
		name     string
		filename string
		atFlags  int32
		status   uint32
		ret      int64
		between  func(el *eventLoop)
		wantName string
		wantFD   int32
	}{
		{name: "successful fexecve", atFlags: unix.AT_EMPTY_PATH, wantName: prog, wantFD: progfd},
		{name: "failed fexecve reports no path", atFlags: unix.AT_EMPTY_PATH, ret: -int64(syscall.EACCES), wantName: "", wantFD: -1},
		// The enter-time snapshot must not attribute an unreadable name to the
		// descriptor either, even though the exec itself succeeded.
		{name: "unreadable name with AT_EMPTY_PATH reports no path", atFlags: unix.AT_EMPTY_PATH, status: types.PATH_READ_FAILED, wantName: "", wantFD: -1},
		{name: "failed execveat keeps relative resolution", filename: "ls", ret: -int64(syscall.ENOENT), wantName: filepath.Join(prog, "ls"), wantFD: progfd},
		{name: "fd replaced after enter", atFlags: unix.AT_EMPTY_PATH, wantName: prog, wantFD: progfd,
			between: func(el *eventLoop) {
				el.fdState().set(progfd, pid, file.NewFd(progfd, "/replaced", syscall.O_WRONLY))
			}},
		{name: "tracked fd mutated in place after enter", atFlags: unix.AT_EMPTY_PATH, wantName: prog, wantFD: progfd,
			between: func(el *eventLoop) {
				tracked, ok := el.fdState().get(progfd, pid)
				if !ok {
					t.Fatal("descriptor not tracked")
				}
				tracked.(*file.FdFile).SetFlags(syscall.O_WRONLY)
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			el := mustNewEventLoop(t, eventLoopConfig{})
			el.fdState().set(progfd, pid, file.NewFd(progfd, prog, flags))
			enter, exit := newExecPair(types.SYS_ENTER_EXECVEAT, pid, progfd, tc.atFlags, tc.filename, tc.ret)
			enter.FilenameStatus = tc.status
			var between func()
			if tc.between != nil {
				between = func() { tc.between(el) }
			}
			ep := runRawExec(t, el, enter, exit, between)
			if ep == nil {
				t.Fatal("exec pair was not emitted")
			}
			defer ep.Recycle()
			if ep.File.Name() != tc.wantName || ep.File.FD() != tc.wantFD {
				t.Fatalf("file = %q fd %d, want %q fd %d", ep.File.Name(), ep.File.FD(), tc.wantName, tc.wantFD)
			}
			if tc.wantFD == progfd && int32(ep.File.Flags()) != flags {
				t.Fatalf("flags = %#x, want enter-time %#x", int32(ep.File.Flags()), flags)
			}
		})
	}
}

// TestRawExecRecordLayoutsCarryFilenameStatus feeds exec enter records of both
// released wire layouts through processRawEvent (task 9p2). A 312-byte v1
// record whose AT_EMPTY_PATH name BPF could not read must not name the
// descriptor, while a legacy 304-byte record from an older BPF object has no
// status and keeps the pre-9p2 behaviour: its "" names the descriptor.
func TestRawExecRecordLayoutsCarryFilenameStatus(t *testing.T) {
	const (
		pid    = uint32(0x7ffffff2)
		progfd = int32(7)
	)
	prog := filepath.Join(t.TempDir(), "prog")
	tests := []struct {
		name     string
		status   uint32
		size     int
		wantName string
		wantFD   int32
	}{
		{name: "v1 read failed", status: types.PATH_READ_FAILED, size: 312, wantName: "", wantFD: -1},
		{name: "v1 read ok", status: types.PATH_READ_OK, size: 312, wantName: prog, wantFD: progfd},
		{name: "legacy layout", status: types.PATH_READ_FAILED, size: 304, wantName: prog, wantFD: progfd},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			el := mustNewEventLoop(t, eventLoopConfig{})
			el.fdState().set(progfd, pid, file.NewFd(progfd, prog, syscall.O_RDONLY))
			enter, exit := newExecPair(types.SYS_ENTER_EXECVEAT, pid, progfd, unix.AT_EMPTY_PATH, "", 0)
			enter.FilenameStatus = tc.status
			enterRaw, err := enter.Bytes()
			if err != nil {
				t.Fatalf("encode exec enter: %v", err)
			}
			if len(enterRaw) != 312 {
				t.Fatalf("exec_event v1 encodes to %d bytes, want 312", len(enterRaw))
			}
			// The legacy layout is the v1 prefix: dropping the status and
			// schema words also drops the FAILED status set above.
			ep := runRawExecRecords(t, el, enterRaw[:tc.size], exit, nil)
			if ep == nil {
				t.Fatal("exec pair was not emitted")
			}
			defer ep.Recycle()
			if ep.File.Name() != tc.wantName || ep.File.FD() != tc.wantFD {
				t.Fatalf("file = %q fd %d, want %q fd %d", ep.File.Name(), ep.File.FD(), tc.wantName, tc.wantFD)
			}
		})
	}
}
