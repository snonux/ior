package internal

import (
	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"

	"golang.org/x/sys/unix"
)

// handleFdPathExit reports the watched target with the notification group fd.
// Neither the target dirfd nor an inotify watch descriptor replaces that fd;
// adding a watch must not rename the group's entry in the global fd table.
func (e *eventLoop) handleFdPathExit(ep *event.Pair, ev *types.FdPathEvent) bool {
	if _, ok := ep.ExitEv.(*types.RetEvent); !ok {
		e.recyclePair(ep, "Dropped malformed notification exit event")
		return false
	}
	group := e.resolveOnExit(ep, ev.Fd, ev.Pid)
	pathname := types.StringValue(ev.Pathname[:])
	if ev.TraceId == types.SYS_ENTER_FANOTIFY_MARK {
		if ev.Flags&unix.FAN_MARK_FLUSH != 0 {
			// FLUSH operates on the group and ignores pathname and dfd.
			ep.File = group
			return e.finishPairForTid(ep, ev.Tid)
		}
		// NULL means fdget(dfd), whereas a non-NULL empty string fails with
		// ENOENT. A failed nofault read cannot be treated as either case.
		allowEmpty := retEventSucceeded(ep) && ev.PathnameStatus == types.PATH_READ_NULL && ev.Dirfd >= 0
		pathname = e.resolveCapturedDirfdPath(ev.Dirfd, ev.Pid, pathname, ev.PathnameStatus, allowEmpty).Name()
	}
	ep.File = file.NewFd(ev.Fd, pathname, int32(group.Flags()))
	return e.finishPairForTid(ep, ev.Tid)
}
