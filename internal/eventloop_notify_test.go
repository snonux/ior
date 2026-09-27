package internal

import (
	"syscall"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"

	"golang.org/x/sys/unix"
)

const (
	notifyGroupFD = int32(21)
	notifyDirFD   = int32(22)
	notifyFlags   = syscall.O_RDWR | syscall.O_NONBLOCK | syscall.O_CLOEXEC
)

func TestNotificationRowsKeepBothIdentities(t *testing.T) {
	tests := []struct {
		name, path, want string
		fanotify         bool
		dirfd            int32
		status, flags    uint32
		ret              int64
	}{
		{name: "inotify absolute", path: "/watch/file", want: "/watch/file", ret: 81},
		{name: "inotify relative", path: "watched", want: "watched", ret: 81},
		{name: "inotify failed watch", path: "/missing", want: "/missing", ret: -int64(syscall.ENOENT)},
		{name: "fanotify absolute ignores dfd", fanotify: true, dirfd: -1, path: "/watch/file", want: "/watch/file"},
		{name: "fanotify relative", fanotify: true, dirfd: notifyDirFD, path: "child", want: "/watch/dir/child"},
		{name: "fanotify cwd", fanotify: true, dirfd: unix.AT_FDCWD, path: "child", want: "child"},
		{name: "fanotify null", fanotify: true, dirfd: notifyDirFD, status: types.PATH_READ_NULL, want: "/watch/dir"},
		{name: "fanotify empty", fanotify: true, dirfd: notifyDirFD, ret: -int64(syscall.ENOENT)},
		{name: "fanotify empty even if success", fanotify: true, dirfd: notifyDirFD},
		{name: "fanotify failed null", fanotify: true, dirfd: notifyDirFD, status: types.PATH_READ_NULL, ret: -int64(syscall.EPERM)},
		{name: "fanotify null cwd is invalid", fanotify: true, dirfd: unix.AT_FDCWD, status: types.PATH_READ_NULL, ret: -int64(syscall.EBADF)},
		{name: "fanotify failed read", fanotify: true, dirfd: notifyDirFD, status: types.PATH_READ_FAILED},
		{name: "fanotify unknown read", fanotify: true, dirfd: notifyDirFD, status: 99},
		{name: "fanotify flush ignores relative target", fanotify: true, dirfd: notifyDirFD, path: "ignored", flags: unix.FAN_MARK_FLUSH, want: "notifyfd:"},
		{name: "fanotify flush ignores null target", fanotify: true, dirfd: notifyDirFD, status: types.PATH_READ_NULL, flags: unix.FAN_MARK_FLUSH, want: "notifyfd:"},
		{name: "fanotify flush ignores absolute target", fanotify: true, dirfd: notifyDirFD, path: "/ignored", flags: unix.FAN_MARK_FLUSH, want: "notifyfd:"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			el := newNotificationLoop(t, globalfilter.Filter{})
			enter := notificationEnter(tc.fanotify, tc.path)
			enter.Dirfd, enter.PathnameStatus, enter.Flags = tc.dirfd, tc.status, tc.flags
			pair := feedNotification(t, el, enter, tc.ret)
			if pair == nil {
				t.Fatal("notification pair was dropped")
			}
			defer pair.Recycle()
			if pair.File.Name() != tc.want || pair.File.FD() != notifyGroupFD || int(pair.File.Flags()) != notifyFlags {
				t.Fatalf("file = %q fd %d flags %#x; want %q fd %d flags %#x", pair.File.Name(), pair.File.FD(), pair.File.Flags(), tc.want, notifyGroupFD, notifyFlags)
			}
			if pair.Bytes != 0 || pair.EnterEv.GetTraceId().Family() != types.FamilyIPC {
				t.Fatalf("notification must stay non-byte IPC: %+v", pair)
			}
			if got := pair.ExitEv.(*types.RetEvent).Ret; got != tc.ret {
				t.Fatalf("ret = %d, want %d", got, tc.ret)
			}
			assertNotificationStateUnchanged(t, el)
		})
	}
}

func TestNotificationPairFiltersUseResolvedTargetAndGroupFD(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		fd         int64
		want       bool
	}{
		{name: "joined path and group fd", path: "^/watch/dir/child$", fd: int64(notifyGroupFD), want: true},
		{name: "target dirfd is not group fd", path: "^/watch/dir/child$", fd: int64(notifyDirFD)},
		{name: "group label is not watched path", path: "notifyfd:", fd: int64(notifyGroupFD)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el := newNotificationLoop(t, globalfilter.Filter{File: &globalfilter.StringFilter{Pattern: tc.path}, FD: &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: tc.fd}})
			enter := notificationEnter(true, "child")
			pair := feedNotification(t, el, enter, 0)
			if pair != nil {
				defer pair.Recycle()
			}
			if (pair != nil) != tc.want {
				t.Fatalf("emitted = %v, want %v", pair != nil, tc.want)
			}
			assertNotificationStateUnchanged(t, el)
		})
	}
}

func TestLegacyNotificationPayloadsKeepOriginalSemantics(t *testing.T) {
	for _, fanotify := range []bool{false, true} {
		el := newNotificationLoop(t, globalfilter.Filter{})
		var raw []byte
		var exitID types.TraceId
		wantFD, wantPath := notifyGroupFD, "notifyfd:"
		if fanotify {
			_, raw = makeEnterPathEvent(t, defaulTime, execCommPid, execCommTid, "/legacy/watch", types.SYS_ENTER_FANOTIFY_MARK)
			raw = raw[:280] // Original path_event prefix, before dirfd metadata.
			exitID, wantFD, wantPath = types.SYS_EXIT_FANOTIFY_MARK, -1, "/legacy/watch"
		} else {
			_, raw = makeEnterFdEvent(t, defaulTime, execCommPid, execCommTid, notifyGroupFD, types.SYS_ENTER_INOTIFY_ADD_WATCH)
			exitID = types.SYS_EXIT_INOTIFY_ADD_WATCH
		}
		_, exit := makeExitRetEvent(t, defaulTime+100, execCommPid, execCommTid, exitID, 0)
		out := make(chan *event.Pair, 1)
		el.processRawEvent(raw, out)
		el.processRawEvent(exit, out)
		select {
		case pair := <-out:
			if pair.File.FD() != wantFD || pair.File.Name() != wantPath {
				t.Errorf("legacy fanotify=%v: fd=%d path=%q", fanotify, pair.File.FD(), pair.File.Name())
			}
			pair.Recycle()
		default:
			t.Fatalf("legacy fanotify=%v dropped", fanotify)
		}
	}
}

func newNotificationLoop(t *testing.T, filter globalfilter.Filter) *eventLoop {
	t.Helper()
	el := newFilteredEventLoop(t, filter)
	el.fdState().set(notifyGroupFD, execCommPid, file.NewFd(notifyGroupFD, "notifyfd:", notifyFlags))
	el.fdState().set(notifyDirFD, execCommPid, file.NewFd(notifyDirFD, "/watch/dir", syscall.O_RDONLY|syscall.O_DIRECTORY))
	// A different process with the same fd numbers must not supply attribution.
	el.fdState().set(notifyGroupFD, execCommPid+1, file.NewFd(notifyGroupFD, "other-group", syscall.O_RDONLY))
	el.fdState().set(notifyDirFD, execCommPid+1, file.NewFd(notifyDirFD, "/wrong/process", syscall.O_RDONLY))
	return el
}

func notificationEnter(fanotify bool, pathname string) *types.FdPathEvent {
	traceID := types.SYS_ENTER_INOTIFY_ADD_WATCH
	if fanotify {
		traceID = types.SYS_ENTER_FANOTIFY_MARK
	}
	ev := &types.FdPathEvent{EventType: types.ENTER_FD_PATH_EVENT, TraceId: traceID,
		Time: defaulTime, Pid: execCommPid, Tid: execCommTid, Fd: notifyGroupFD,
		Dirfd: notifyDirFD, SchemaVersion: types.FD_PATH_EVENT_SCHEMA_VERSION}
	copy(ev.Pathname[:], pathname)
	return ev
}

func feedNotification(t *testing.T, el *eventLoop, enter *types.FdPathEvent, ret int64) *event.Pair {
	t.Helper()
	exitID := types.SYS_EXIT_INOTIFY_ADD_WATCH
	if enter.TraceId == types.SYS_ENTER_FANOTIFY_MARK {
		exitID = types.SYS_EXIT_FANOTIFY_MARK
	}
	_, exit := makeExitRetEvent(t, defaulTime+100, enter.Pid, enter.Tid, exitID, ret)
	out := make(chan *event.Pair, 1)
	el.processRawEvent(eventBytes(t, enter), out)
	el.processRawEvent(exit, out)
	select {
	case pair := <-out:
		return pair
	default:
		return nil
	}
}

func assertNotificationStateUnchanged(t *testing.T, el *eventLoop) {
	t.Helper()
	for fd, want := range map[int32]string{notifyGroupFD: "notifyfd:", notifyDirFD: "/watch/dir"} {
		got, ok := el.fdState().get(fd, execCommPid)
		if !ok || got.Name() != want {
			t.Fatalf("fd %d state changed: %v", fd, got)
		}
	}
	if _, ok := el.fdState().get(81, execCommPid); ok {
		t.Fatal("inotify watch descriptor incorrectly registered as an fd")
	}
}
