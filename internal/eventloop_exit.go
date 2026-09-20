package internal

import (
	"fmt"
	"math"
	"os"
	"syscall"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

// These raw CLOEXEC/NONBLOCK values come from distinct Linux UAPI flag words.
// Keep them named separately even where their values coincide: merging them
// would recreate the assumption that made syscall-specific bits look like
// open(2) flags.
const (
	fanotifyCloexecFlag  = int32(1)
	fanotifyNonblockFlag = int32(2)
	memfdCloexecFlag     = int32(1)
	fsopenCloexecFlag    = int32(1)
	fsmountCloexecFlag   = int32(1)
)

type eventfdFlagMasks struct {
	cloexec  int32
	nonblock int32
}

var eventfdOpenFlagMasks = map[types.TraceId]eventfdFlagMasks{
	types.SYS_ENTER_EPOLL_CREATE1:  {cloexec: syscall.O_CLOEXEC},
	types.SYS_ENTER_INOTIFY_INIT1:  {cloexec: syscall.O_CLOEXEC, nonblock: syscall.O_NONBLOCK},
	types.SYS_ENTER_FANOTIFY_INIT:  {cloexec: fanotifyCloexecFlag, nonblock: fanotifyNonblockFlag},
	types.SYS_ENTER_EVENTFD2:       {cloexec: syscall.O_CLOEXEC, nonblock: syscall.O_NONBLOCK},
	types.SYS_ENTER_MEMFD_CREATE:   {cloexec: memfdCloexecFlag},
	types.SYS_ENTER_MEMFD_SECRET:   {cloexec: syscall.O_CLOEXEC},
	types.SYS_ENTER_USERFAULTFD:    {cloexec: syscall.O_CLOEXEC, nonblock: syscall.O_NONBLOCK},
	types.SYS_ENTER_SIGNALFD4:      {cloexec: syscall.O_CLOEXEC, nonblock: syscall.O_NONBLOCK},
	types.SYS_ENTER_TIMERFD_CREATE: {cloexec: syscall.O_CLOEXEC, nonblock: syscall.O_NONBLOCK},
	types.SYS_ENTER_PIDFD_OPEN:     {nonblock: syscall.O_NONBLOCK},
	types.SYS_ENTER_FSMOUNT:        {cloexec: fsmountCloexecFlag},
	types.SYS_ENTER_FSOPEN:         {cloexec: fsopenCloexecFlag},
}

func (e *eventLoop) initRuntimeEventKinds() {
	if e.exitHandlers == nil {
		e.exitHandlers = make(map[types.EventType]runtimeExitHandler)
	}
	if len(e.exitHandlers) != 0 {
		return
	}
	for _, kind := range runtimeEventKinds() {
		e.exitHandlers[kind.enterEventType] = kind.exit
	}
}

// handleTracepointExit routes a completed enter/exit pair to the runtime
// handler registered for the enter event kind.
func (e *eventLoop) handleTracepointExit(ep *event.Pair) bool {
	e.initRuntimeEventKinds()
	eventType, ok := eventTypeForRuntimeEvent(ep.EnterEv)
	if !ok {
		e.recyclePair(ep, "Dropped malformed enter event")
		return false
	}
	handler, ok := e.exitHandlers[eventType]
	if !ok {
		e.recyclePair(ep, "Dropped malformed enter event")
		return false
	}
	return handler(e, ep)
}

func eventTypeForRuntimeEvent(ev event.Event) (types.EventType, bool) {
	typed, ok := ev.(interface{ GetEventType() types.EventType })
	if !ok {
		return 0, false
	}
	return typed.GetEventType(), true
}

func (e *eventLoop) handleOpenExit(ep *event.Pair, openEv *types.OpenEvent) bool {
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed open exit event")
		return false
	}

	comm := types.StringValue(openEv.Comm[:])
	ep.Comm = comm
	if fd := int32(retEvent.Ret); fd >= 0 {
		fdFile := file.NewFd(fd, types.StringValue(openEv.Filename[:]), openEv.Flags)
		e.fdState().set(fd, openEv.Pid, fdFile)
		ep.File = fdFile
	} else {
		// Keep path information for failed opens so error scenarios remain observable.
		ep.File = file.NewPathname(openEv.Filename[:])
	}
	// The payload comm is read by BPF from task->comm at event time, so it is
	// authoritative: it retires any procfs lookup still in flight for this tid
	// (setCachedFromKernel bumps the rename generation). Like the fd
	// registration above this is global state, so it is updated before the
	// filter: a row this run does not want must still leave the fd table and
	// the comm cache correct for the rows it does want.
	e.setCachedCommFromKernel(openEv.Tid, comm)
	// The raw enter filter (MatchOpenEvent) only covers the comm and path
	// dimensions, so without this checkpoint -syscall/-family/-fd/-ret/
	// -latency/-bytes and non-equality -pid/-tid reached open rows nowhere.
	// The full pair filter is safe: ep.Comm and ep.File.Name() are the very
	// payload bytes MatchOpenEvent already matched, so the two can never
	// disagree, and there is no oldname/newname asymmetry to preserve.
	return e.finishPair(ep)
}

func (e *eventLoop) handleExecExit(ep *event.Pair, execEv *types.ExecEvent) bool {
	if _, ok := ep.ExitEv.(*types.RetEvent); !ok {
		e.recyclePair(ep, "Dropped malformed exec exit event")
		return false
	}
	// execEv is the sys_enter_execve payload, so its comm is the name of the
	// program that *called* execve - correct for this row, wrong for the tid
	// from here on. On a SUCCESSFUL execve it is deliberately not written into
	// the comm cache: the authoritative post-exec name arrives as a
	// PROCESS_EXEC_EVENT control record (handleProcessExecEvent), and seeding
	// the pre-exec name here would re-introduce exactly the stale label that
	// record exists to prevent.
	ep.Comm = types.StringValue(execEv.Comm[:])
	ep.File = file.NewPathname(execEv.Filename[:])
	e.cacheCommOfFailedExec(ep, execEv)
	return e.finishPair(ep)
}

// cacheCommOfFailedExec warms the comm cache from a *failed* execve.
//
// sched_process_exec only fires once the kernel has committed to the new
// program, so a failing execve (ENOENT, EACCES, ELOOP, ...) produces no control
// record at all. The task keeps running under its old name, which is precisely
// the name the sys_enter_execve payload carries, so caching it here is both
// correct and useful: for a tid whose lookup has not landed yet this is a free,
// exact label. A successful execve must never take this path, which is why the
// syscall's return value gates it.
//
// Like handleOpenExit this is a kernel-sourced name and goes in as such, so a
// resolver worker descheduled with an older name cannot land on top of it.
func (e *eventLoop) cacheCommOfFailedExec(ep *event.Pair, execEv *types.ExecEvent) {
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok || retEv.Ret >= 0 {
		return
	}
	e.setCachedCommFromKernel(execEv.GetTid(), types.StringValue(execEv.Comm[:]))
}

func (e *eventLoop) handleNameExit(ep *event.Pair, nameEv *types.NameEvent) bool {
	// File.Name() resolves to the "new" path (newname); surface the captured
	// source path (oldname, at args[1] for the AT-variants) separately on the
	// Pair so it reaches the output schema rather than living only in the
	// TUI String() repr ("old:... ->new:..."). MatchPair's file dimension
	// picks Oldname up as the alternate value (Candidate.OldFileValue), so
	// the plain finishPairForTid applies every dimension here without
	// dropping the rows a `-path <oldname>` filter legitimately selected - the
	// raw enter filter (MatchNameEvent) already matched them on the oldname.
	ep.File = file.NewOldnameNewname(nameEv.Oldname[:], nameEv.Newname[:])
	ep.Oldname = types.StringValue(nameEv.Oldname[:])
	return e.finishPairForTid(ep, nameEv.GetTid())
}

func (e *eventLoop) handlePathExit(ep *event.Pair, pathEv *types.PathEvent) bool {
	if pathEv.GetTraceId().Name() == sysEnterNameToHandleAtName {
		retEv, ok := ep.ExitEv.(*types.RetEvent)
		if !ok || retEv.Ret < 0 {
			ep.Recycle()
			return false
		}
		e.pendingHandleState().set(pathEv.GetTid(), types.StringValue(pathEv.Pathname[:]))
		ep.Recycle()
		return false
	}

	if ep.Is(types.SYS_ENTER_CREAT) {
		retEvent, ok := ep.ExitEv.(*types.RetEvent)
		if !ok {
			e.recyclePair(ep, "Dropped malformed creat exit event")
			return false
		}
		if fd := int32(retEvent.Ret); fd >= 0 {
			// creat(pathname, mode) == open(pathname, O_CREAT|O_WRONLY|O_TRUNC,
			// mode): on success it returns a new fd, so register the fd->path
			// mapping just like handleOpenExit does for open/openat/openat2.
			fdFile := file.NewFd(fd, types.StringValue(pathEv.Pathname[:]),
				syscall.O_CREAT|syscall.O_WRONLY|syscall.O_TRUNC)
			e.fdState().set(fd, pathEv.Pid, fdFile)
			ep.File = fdFile
		} else {
			// Failed creat (-1): keep the path so error scenarios stay
			// observable, mirroring handleOpenExit's failed-open branch.
			ep.File = file.NewPathname(pathEv.Pathname[:])
		}
	} else {
		ep.File = file.NewPathname(pathEv.Pathname[:])
	}
	// ep.File carries the very pathname matchRawPathEvent already matched, so
	// the full pair filter is safe here: unlike the rename kinds it cannot
	// disagree with the raw match. The rename kinds' widening lives inside
	// MatchPair's file dimension now (Candidate.OldFileValue), not in a
	// separate checkpoint variant.
	return e.finishPairForTid(ep, pathEv.GetTid())
}

// handleFdExit processes exit events for fd-based syscalls. It resolves the fd
// to a file, applies the close state transition, applies the dup/pidfd_getfd
// fd-transfer operation and only then filters the pair. close_range is not
// handled here: it carries (first, last, flags) and is routed through
// handleTwoFdExit so the upper bound and flags are honoured.
//
// The state work runs BEFORE the filter for the same reason it does in
// handleOpenExit: the fd table is global, so a row this run does not want must
// still leave it correct for the rows it does want. With the transfer applied
// after the checkpoint, a dup/dup2 row dropped by -path or -comm left the
// duplicated descriptor unregistered and every later read/write/close on it
// resolved to no path (or, when the target fd number was already tracked, to
// the *previous* file). For pidfd_getfd the ordering was also a filter-input
// bug: ep.File was re-pointed at the transferred file after the filter had
// already judged the pair on the source pidfd, so the value filtered on and the
// value printed genuinely differed.
func (e *eventLoop) handleFdExit(ep *event.Pair, fdEv *types.FdEvent) bool {
	fd := fdEv.Fd
	ep.File = e.fdState().resolve(fd, fdEv.Pid)
	e.applyFdCloseState(ep, fd, fdEv.Pid)
	ep.Comm = e.comm(fdEv.GetTid())
	if ok := e.applyFdTransferOp(ep, fdEv); !ok {
		return false
	}
	return e.finishPair(ep)
}

// applyFdCloseState updates fd-tracking state for the close syscall. On Linux,
// close releases the descriptor even when it later reports errors such as
// EINTR or EIO; only EBADF means that fd was not an open descriptor. Keeping
// any other return leaves a stale fd->path entry that can mislabel a later use
// of the same descriptor number. A malformed exit event leaves state unchanged.
func (e *eventLoop) applyFdCloseState(ep *event.Pair, fd int32, pid uint32) {
	if !ep.Is(types.SYS_ENTER_CLOSE) {
		return
	}
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok || retEv.Ret == -int64(syscall.EBADF) {
		return
	}
	e.fdState().delete(fd, pid)
	e.fdState().deleteProcFdCache(fd, pid)
}

// applyFdTransferOp handles dup/dup2 and pidfd_getfd fd-transfer operations.
// Returns false if the pair should be dropped due to a malformed event.
//
// It runs before the pair filter (see handleFdExit): the fd registration is
// global state, and for pidfd_getfd the ep.File it assigns is the file the row
// reports, so it has to be in place before the filter reads it.
func (e *eventLoop) applyFdTransferOp(ep *event.Pair, fdEv *types.FdEvent) bool {
	if ep.Is(types.SYS_ENTER_DUP) || ep.Is(types.SYS_ENTER_DUP2) {
		fdFile, ok := ep.File.(*file.FdFile)
		if !ok {
			e.recyclePair(ep, "Dropped malformed dup source event")
			return false
		}
		retEvent, ok := ep.ExitEv.(*types.RetEvent)
		if !ok {
			e.recyclePair(ep, "Dropped malformed dup exit event")
			return false
		}
		e.registerDup(fdFile, fdEv.Pid, int32(retEvent.Ret), 0)
	}
	if ep.Is(types.SYS_ENTER_PIDFD_GETFD) {
		retEv, ok := ep.ExitEv.(*types.RetEvent)
		if !ok {
			e.recyclePair(ep, "Dropped malformed pidfd_getfd exit event")
			return false
		}
		if newFd := int32(retEv.Ret); newFd >= 0 {
			transferredFile := file.NewFdWithPid(newFd, fdEv.Pid)
			e.fdState().set(newFd, fdEv.Pid, transferredFile)
			ep.File = transferredFile
		}
	}
	return true
}

// handleDup3Exit registers the duplicated descriptor before filtering the pair,
// for the reason spelled out on handleFdExit: the fd table must stay correct
// for the rows the run does want even when this row is dropped.
func (e *eventLoop) handleDup3Exit(ep *event.Pair, dup3Ev *types.Dup3Event) bool {
	fd := int32(dup3Ev.Fd)
	ep.File = e.fdState().resolve(fd, dup3Ev.Pid)
	ep.Comm = e.comm(dup3Ev.GetTid())

	fdFile, ok := ep.File.(*file.FdFile)
	if !ok {
		e.recyclePair(ep, "Dropped malformed dup3 source event")
		return false
	}
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed dup3 exit event")
		return false
	}
	e.registerDup(fdFile, dup3Ev.Pid, int32(retEvent.Ret), dup3Ev.Flags&syscall.O_CLOEXEC)
	return e.finishPair(ep)
}

func (e *eventLoop) handleOpenByHandleAtExit(ep *event.Pair, openByHandleEv *types.OpenByHandleAtEvent) bool {
	tid := openByHandleEv.GetTid()
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.pendingHandleState().delete(tid)
		e.recyclePair(ep, "Dropped malformed open_by_handle_at exit event")
		return false
	}

	fd := int32(retEvent.Ret)
	if fd < 0 {
		e.pendingHandleState().delete(tid)
		ep.Recycle()
		return false
	}

	if pathname, ok := e.pendingHandleState().consume(tid); ok {
		fdFile := file.NewFd(fd, pathname, openByHandleEv.Flags)
		e.fdState().set(fd, openByHandleEv.Pid, fdFile)
		ep.File = fdFile
	} else {
		fdFile := file.NewFdWithPid(fd, openByHandleEv.Pid)
		if fdFile.Flags() == file.Flags(-1) {
			fdFile.SetFlags(openByHandleEv.Flags)
		}
		e.fdState().set(fd, openByHandleEv.Pid, fdFile)
		ep.File = fdFile
	}
	// This kind has no raw enter filter at all (see rawRuntimeEvents), so
	// without a checkpoint here NO filter dimension - comm included - was ever
	// applied to an open_by_handle_at row, and a run filtered by -comm could
	// emit rows carrying a different comm. The full pair filter is the right
	// checkpoint: ep.File is in both branches exactly the name the row reports
	// (the cached name_to_handle_at pathname, or the /proc/<pid>/fd readlink),
	// so filter and displayed value can never disagree, and unlike the rename
	// kinds there is no raw match to contradict. Applying -path to a
	// procfs-resolved name is also not new: every fd-based kind already does
	// that (handleFdExit -> fdTracker.resolve -> file.NewFdWithPid, then
	// finishPair).
	return e.finishPairForTid(ep, tid)
}

func (e *eventLoop) handleSocketExit(ep *event.Pair, socketEv *types.SocketEvent) bool {
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed socket exit event")
		return false
	}

	if fd := int32(retEvent.Ret); fd >= 0 {
		fdFile := file.NewFd(fd, socketDescriptorName(socketEv.Family, socketEv.Type, socketEv.Protocol), -1)
		e.fdState().set(fd, socketEv.Pid, fdFile)
		ep.File = fdFile
	}
	ep.Comm = e.comm(socketEv.GetTid())
	return e.finishPair(ep)
}

func (e *eventLoop) handleSocketpairExit(ep *event.Pair, socketpairEv *types.SocketpairEvent) bool {
	exitEv, ok := ep.ExitEv.(*types.SocketpairEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed socketpair exit event")
		return false
	}

	family := exitEv.Family
	typ := exitEv.Type
	protocol := exitEv.Protocol
	if family < 0 {
		family = socketpairEv.Family
	}
	if typ < 0 {
		typ = socketpairEv.Type
	}
	if protocol < 0 {
		protocol = socketpairEv.Protocol
	}

	if exitEv.Ret == 0 {
		if exitEv.Sv0 >= 0 {
			fdFile := file.NewFd(exitEv.Sv0, socketDescriptorName(family, typ, protocol), -1)
			e.fdState().set(exitEv.Sv0, socketpairEv.Pid, fdFile)
			ep.File = fdFile
		}
		if exitEv.Sv1 >= 0 {
			fdFile := file.NewFd(exitEv.Sv1, socketDescriptorName(family, typ, protocol), -1)
			e.fdState().set(exitEv.Sv1, socketpairEv.Pid, fdFile)
			if ep.File == nil {
				ep.File = fdFile
			}
		}
	}
	ep.Comm = e.comm(socketpairEv.GetTid())
	return e.finishPair(ep)
}

func (e *eventLoop) handleAcceptExit(ep *event.Pair, acceptEv *types.AcceptEvent) bool {
	exitEv, ok := ep.ExitEv.(*types.AcceptEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed accept exit event")
		return false
	}

	listening := e.fdState().resolve(acceptEv.Fd, acceptEv.Pid)
	if fd := int32(exitEv.Ret); fd >= 0 {
		fdFile := file.NewFd(fd, acceptedSocketDescriptorName(listening), -1)
		e.fdState().set(fd, acceptEv.Pid, fdFile)
		ep.File = fdFile
	} else {
		ep.File = listening
	}
	ep.Comm = e.comm(acceptEv.GetTid())
	return e.finishPair(ep)
}

func socketDescriptorName(family, typ, protocol int32) string {
	return fmt.Sprintf("socket:%d:%d:%d", family, typ, protocol)
}

func acceptedSocketDescriptorName(listening file.File) string {
	if listening == nil {
		return "socket:accepted"
	}
	name := listening.Name()
	if name == "" {
		return "socket:accepted"
	}
	return name
}

func (e *eventLoop) handlePipeExit(ep *event.Pair, pipeEv *types.PipeEvent) bool {
	exitEv, ok := ep.ExitEv.(*types.PipeEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed pipe exit event")
		return false
	}

	flags := exitEv.Flags
	if flags == 0 {
		flags = pipeEv.Flags
	}
	if exitEv.Ret == 0 {
		name := pipeDescriptorName(flags, exitEv.Fd0, exitEv.Fd1)
		if exitEv.Fd0 >= 0 {
			fdFile := file.NewFd(exitEv.Fd0, name, flags|syscall.O_RDONLY)
			e.fdState().set(exitEv.Fd0, pipeEv.Pid, fdFile)
			ep.File = fdFile
		}
		if exitEv.Fd1 >= 0 {
			fdFile := file.NewFd(exitEv.Fd1, name, flags|syscall.O_WRONLY)
			e.fdState().set(exitEv.Fd1, pipeEv.Pid, fdFile)
			if ep.File == nil {
				ep.File = fdFile
			}
		}
	}
	ep.Comm = e.comm(pipeEv.GetTid())
	return e.finishPair(ep)
}

func (e *eventLoop) handleEventfdExit(ep *event.Pair, eventfdEv *types.EventfdEvent) bool {
	exitEv, ok := ep.ExitEv.(*types.EventfdEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed eventfd exit event")
		return false
	}

	flags := exitEv.Flags
	if flags == 0 {
		flags = eventfdEv.Flags
	}
	if fd := int32(exitEv.Ret); fd >= 0 {
		if eventfdReusesExistingFD(eventfdEv.GetTraceId(), eventfdEv.Fd) {
			ep.File = e.fdState().resolve(fd, eventfdEv.Pid)
		} else {
			fdFile := file.NewFd(
				fd,
				eventfdDescriptorName(eventfdEv.GetTraceId(), flags),
				eventfdOpenFlags(eventfdEv.GetTraceId(), flags),
			)
			e.fdState().set(fd, eventfdEv.Pid, fdFile)
			ep.File = fdFile
		}
	}
	ep.Comm = e.comm(eventfdEv.GetTid())
	return e.finishPair(ep)
}

func eventfdOpenFlags(traceID types.TraceId, rawFlags int32) int32 {
	masks := eventfdOpenFlagMasks[traceID]
	var flags int32
	if masks.cloexec != 0 && rawFlags&masks.cloexec != 0 {
		flags |= syscall.O_CLOEXEC
	}
	if masks.nonblock != 0 && rawFlags&masks.nonblock != 0 {
		flags |= syscall.O_NONBLOCK
	}
	return flags
}

func eventfdReusesExistingFD(traceID types.TraceId, fd int32) bool {
	return fd >= 0 && (traceID == types.SYS_ENTER_SIGNALFD || traceID == types.SYS_ENTER_SIGNALFD4)
}

func (e *eventLoop) handleEpollCtlExit(ep *event.Pair, epollCtlEv *types.EpollCtlEvent) bool {
	// File resolves to the epoll instance (epfd); the decoded op/target-fd/events
	// are surfaced separately via ep.Epoll so consumers can see which descriptor
	// was registered and the operation performed.
	ep.File = e.fdState().resolve(epollCtlEv.Epfd, epollCtlEv.Pid)
	ep.Epoll = event.EpollCtl{
		Op:       epollCtlEv.Op,
		TargetFD: epollCtlEv.Fd,
		Events:   epollCtlEv.Events,
	}
	ep.HasEpoll = true
	return e.finishPairForTid(ep, epollCtlEv.GetTid())
}

func (e *eventLoop) handlePollExit(ep *event.Pair, pollEv *types.PollEvent) bool {
	return e.finishPairForTid(ep, pollEv.GetTid())
}

func (e *eventLoop) handleTwoFdExit(ep *event.Pair, twoFdEv *types.TwoFdEvent) bool {
	ep.File = e.fdState().resolve(twoFdEv.FdA, twoFdEv.Pid)
	if ep.Is(types.SYS_ENTER_CLOSE_RANGE) {
		e.applyCloseRangeState(ep, twoFdEv)
	}
	return e.finishPairForTid(ep, twoFdEv.GetTid())
}

// closeRangeCloexec mirrors CLOSE_RANGE_CLOEXEC from <linux/close_range.h>: when
// set, close_range only marks the descriptors close-on-exec instead of closing
// them, so the fds stay open and must remain tracked.
const closeRangeCloexec = 1 << 2

// applyCloseRangeState evicts the fds closed by a successful close_range. The
// enter event carries (first, last, flags) in fd_a/fd_b/extra. fd_b is an __s32
// view of the unsigned "last" argument, so a negative value (e.g. ~0U meaning
// "close everything from first up") is treated as having no upper bound.
func (e *eventLoop) applyCloseRangeState(ep *event.Pair, ev *types.TwoFdEvent) {
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok || retEv.Ret != 0 {
		return
	}
	if ev.Extra&closeRangeCloexec != 0 {
		e.fdState().addFlagsRange(ev.FdA, ev.FdB, ev.Pid, syscall.O_CLOEXEC)
		return
	}
	e.fdState().closeRange(ev.FdA, ev.FdB, ev.Pid)
	e.fdState().deleteProcFdCacheRange(ev.FdA, ev.FdB, ev.Pid)
}

func (e *eventLoop) handleMemExit(ep *event.Pair, memEv *types.MemEvent) bool {
	return e.finishPairForTid(ep, memEv.GetTid())
}

func (e *eventLoop) handleSleepExit(ep *event.Pair, sleepEv *types.SleepEvent) bool {
	return e.finishPairForTid(ep, sleepEv.GetTid())
}

func (e *eventLoop) handleKeyctlExit(ep *event.Pair, keyctlEv *types.KeyctlEvent) bool {
	return e.finishPairForTid(ep, keyctlEv.GetTid())
}

func (e *eventLoop) handlePtraceExit(ep *event.Pair, ptraceEv *types.PtraceEvent) bool {
	return e.finishPairForTid(ep, ptraceEv.GetTid())
}

func (e *eventLoop) handlePerfOpenExit(ep *event.Pair, perfOpenEv *types.PerfOpenEvent) bool {
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed perf_event_open exit event")
		return false
	}

	if fd := int32(retEvent.Ret); fd >= 0 {
		fdFile := file.NewFd(fd, perfDescriptorName(perfOpenEv), -1)
		e.fdState().set(fd, perfOpenEv.Pid, fdFile)
		ep.File = fdFile
	}
	ep.Comm = e.comm(perfOpenEv.GetTid())
	return e.finishPair(ep)
}

func pipeDescriptorName(flags, fd0, fd1 int32) string {
	return fmt.Sprintf("pipe:%d:%d:%d", flags, fd0, fd1)
}

func eventfdDescriptorName(traceID types.TraceId, flags int32) string {
	switch traceID {
	case types.SYS_ENTER_EPOLL_CREATE, types.SYS_ENTER_EPOLL_CREATE1:
		return fmt.Sprintf("epollfd:%d", flags)
	case types.SYS_ENTER_INOTIFY_INIT, types.SYS_ENTER_INOTIFY_INIT1:
		return fmt.Sprintf("inotifyfd:%d", flags)
	case types.SYS_ENTER_FANOTIFY_INIT:
		return fmt.Sprintf("fanotifyfd:%d", flags)
	case types.SYS_ENTER_LANDLOCK_CREATE_RULESET:
		return fmt.Sprintf("landlockfd:%d", flags)
	case types.SYS_ENTER_FSOPEN:
		return fmt.Sprintf("fsopenfd:%d", flags)
	case types.SYS_ENTER_MEMFD_CREATE:
		return fmt.Sprintf("memfd:%d", flags)
	case types.SYS_ENTER_MEMFD_SECRET:
		return fmt.Sprintf("memfd-secret:%d", flags)
	case types.SYS_ENTER_USERFAULTFD:
		return fmt.Sprintf("userfaultfd:%d", flags)
	case types.SYS_ENTER_SIGNALFD, types.SYS_ENTER_SIGNALFD4:
		return fmt.Sprintf("signalfd:%d", flags)
	case types.SYS_ENTER_TIMERFD_CREATE:
		return fmt.Sprintf("timerfd:%d", flags)
	case types.SYS_ENTER_PIDFD_OPEN:
		return fmt.Sprintf("pidfd:%d", flags)
	default:
		return fmt.Sprintf("eventfd:%d", flags)
	}
}

func perfDescriptorName(perfOpenEv *types.PerfOpenEvent) string {
	return fmt.Sprintf(
		"perf:%d:%d:%d:%d:%d",
		perfOpenEv.AttrType,
		perfOpenEv.Config,
		perfOpenEv.TargetPid,
		perfOpenEv.Cpu,
		perfOpenEv.GroupFd,
	)
}

func (e *eventLoop) handleNullExit(ep *event.Pair, nullEv *types.NullEvent) bool {
	if ep.Is(types.SYS_ENTER_IO_URING_SETUP) {
		retEvent, ok := ep.ExitEv.(*types.RetEvent)
		if !ok {
			e.recyclePair(ep, "Dropped malformed io_uring_setup exit event")
			return false
		}
		if fd := int32(retEvent.Ret); fd >= 0 {
			fdFile := file.NewFdWithPid(fd, nullEv.Pid)
			e.fdState().set(fd, nullEv.Pid, fdFile)
			ep.File = fdFile
		}
	}
	if ep.Is(types.SYS_ENTER_GETCWD) {
		retEvent, ok := ep.ExitEv.(*types.RetEvent)
		if !ok {
			e.recyclePair(ep, "Dropped malformed getcwd exit event")
			return false
		}
		if retEvent.Ret > 0 {
			cwd, err := os.Readlink(procTidPathPrefix(nullEv.GetTid()) + "/cwd")
			switch {
			case err == nil:
				ep.File = file.NewPathname([]byte(cwd))
			case !isTransientProcError(err):
				e.notifyWarning(fmt.Sprintf("failed to resolve cwd for tid %d: %v", nullEv.GetTid(), err))
			}
		}
	}
	ep.Comm = e.comm(nullEv.GetTid())
	return e.finishPair(ep)
}

// handleFcntlExit applies the fd-state effect of the command (F_GETFL flag
// resynchronization, F_SETFL flag update, F_DUPFD/F_DUPFD_CLOEXEC descriptor
// registration) before filtering the pair - see handleFdExit for why the
// ordering matters. The flag commands belong to the same class even though no
// filter dimension reads flags: for a descriptor known only to the procfs
// cache they promote the entry into the fd table, so behind the checkpoint a
// dropped row left that promotion, and the new flags with it, unrecorded.
func (e *eventLoop) handleFcntlExit(ep *event.Pair, fcntlEv *types.FcntlEvent) bool {
	ep.Comm = e.comm(fcntlEv.GetTid())
	fd := int32(fcntlEv.Fd)
	ep.File = e.fdState().resolve(fd, fcntlEv.Pid)
	if !e.applyFcntlFdState(ep, fcntlEv, fd) {
		return false
	}
	return e.finishPair(ep)
}

// applyFcntlFdState performs the fd-table side effects of one fcntl command.
// It reports whether ep is still alive; a false return means the pair was
// malformed and has already been recycled.
func (e *eventLoop) applyFcntlFdState(ep *event.Pair, fcntlEv *types.FcntlEvent, fd int32) bool {
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed fcntl exit event")
		return false
	}
	// Syscall returned a negative errno, nothing was changed with the fd.
	if retEvent.Ret < 0 {
		return true
	}

	fdFile, ok := ep.File.(*file.FdFile)
	if !ok {
		e.recyclePair(ep, "Dropped malformed fcntl file event")
		return false
	}

	// See fcntl(2) for implementation details
	switch fcntlEv.Cmd {
	case syscall.F_GETFL:
		// Unlike F_SETFL's partial update, a successful F_GETFL return is the
		// kernel's complete authoritative flag word. Replace even an unknown or
		// stale word, and promote a procfs-resolved entry into the fd table so
		// later rows inherit it. Linux returns this value as an int; reject a
		// malformed raw event that cannot be represented by FdFile's int32 word.
		if retEvent.Ret > math.MaxInt32 {
			e.recyclePair(ep, "Dropped malformed fcntl F_GETFL return value")
			return false
		}
		fdFile.SetFlags(int32(retEvent.Ret))
		ep.File = fdFile
		e.fdState().set(fd, fcntlEv.Pid, fdFile)
	case syscall.F_SETFL:
		// F_SETFL changes the settable status flags only; the access mode and
		// the creation flags stay exactly as open(2) set them. Merge, do not
		// replace: callers do F_GETFL then OR, so arg carries the access mode
		// too, and masking it out of the stored word made an O_RDWR descriptor
		// report O_RDONLY on the fcntl row and on every later row for that fd.
		const canChange = syscall.O_APPEND | syscall.O_ASYNC | syscall.O_DIRECT | syscall.O_NOATIME | syscall.O_NONBLOCK
		fdFile.MergeFlags(int32(canChange), int32(fcntlEv.Arg))
		ep.File = fdFile
		e.fdState().set(fd, fcntlEv.Pid, fdFile)
	case syscall.F_DUPFD:
		e.registerDup(fdFile, fcntlEv.Pid, int32(retEvent.Ret), 0)
	case syscall.F_DUPFD_CLOEXEC:
		e.registerDup(fdFile, fcntlEv.Pid, int32(retEvent.Ret), syscall.O_CLOEXEC)
	}
	return true
}

func (e *eventLoop) registerDup(fdFile *file.FdFile, pid uint32, newFd, extraFlags int32) {
	if newFd < 0 {
		return
	}
	// dup2(oldfd, oldfd) succeeds without creating a descriptor or changing
	// its close-on-exec flag. Every other successful caller creates a distinct
	// descriptor.
	if newFd == fdFile.FD() {
		return
	}
	duppedFdFile := fdFile.Dup(newFd)
	// The duplicate shares the source's open file description and therefore
	// its status flags, but FD_CLOEXEC belongs to the descriptor itself. The
	// kernel clears it for dup/dup2/F_DUPFD and sets it only when dup3 or
	// F_DUPFD_CLOEXEC requests O_CLOEXEC.
	duppedFdFile.MergeFlags(syscall.O_CLOEXEC, extraFlags)
	e.fdState().set(newFd, pid, duppedFdFile)
}

// finishPairForTid is the one finish path for every runtime kind. The
// rename-like (name-carrying) kinds need no variant of their own any more:
// the oldname-OR-newname widening of the file dimension - exactly the
// semantics of the raw enter filter these pairs already passed
// (Filter.MatchNameEvent) - is part of MatchPair itself
// (Candidate.OldFileValue), so the plain checkpoint cannot disagree with it.
// Until e1 this left the name kinds unfiltered entirely; the widening used
// to live in a separate finishPairEitherName/MatchPairEitherName pair of
// methods each caller had to remember to pick, and picking the plain one was
// exactly how a `-path <oldname>` row counted in one stage went missing in the
// next.
func (e *eventLoop) finishPairForTid(ep *event.Pair, tid uint32) bool {
	ep.Comm = e.comm(tid)
	return e.finishPair(ep)
}

func (e *eventLoop) finishPair(ep *event.Pair) bool {
	if e.Filter().MatchPair(ep) {
		return true
	}
	ep.Recycle()
	return false
}

// recyclePair notifies about the problem described by warning, then returns ep
// to the pool. It is a convenience helper used throughout the exit handlers to
// keep the error path concise.
func (e *eventLoop) recyclePair(ep *event.Pair, warning string) {
	e.notifyWarning(warning)
	ep.Recycle()
}

func applyRetBytes(ep *event.Pair) {
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		return
	}
	ep.Bytes = bytesFromRet(retEv)
}

func applyAddressSpaceBytes(ep *event.Pair) {
	if ep == nil {
		return
	}
	memEv, ok := ep.EnterEv.(*types.MemEvent)
	if !ok {
		return
	}
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok || retEv.Ret < 0 {
		return
	}
	ep.AddressSpaceBytes = addressSpaceBytesFromMem(memEv)
}

func applyRequestedSleepNs(ep *event.Pair) {
	if ep == nil {
		return
	}
	sleepEv, ok := ep.EnterEv.(*types.SleepEvent)
	if !ok {
		return
	}
	ep.RequestedSleepNs = sleepEv.RequestedNs
}

// dropMalformedRawEvent records a warning when a raw BPF event cannot be
// decoded, keeping the error visible without crashing the event loop.
func (e *eventLoop) dropMalformedRawEvent(evType types.EventType, raw []byte) {
	e.notifyWarning(fmt.Sprintf("Dropped malformed raw event type %d (len=%d)", evType, len(raw)))
}

// bytesFromRet extracts the number of bytes transferred from a RetEvent.
// Returns 0 for nil events, errors (Ret <= 0), or unclassified syscalls.
func bytesFromRet(retEv *types.RetEvent) uint64 {
	if retEv == nil || retEv.Ret <= 0 {
		return 0
	}
	switch retEv.RetType {
	case types.READ_CLASSIFIED, types.WRITE_CLASSIFIED, types.TRANSFER_CLASSIFIED:
		return uint64(retEv.Ret)
	default:
		return 0
	}
}

func addressSpaceBytesFromMem(memEv *types.MemEvent) uint64 {
	if memEv == nil {
		return 0
	}
	switch memEv.GetTraceId() {
	case types.SYS_ENTER_MUNMAP:
		return memEv.Length
	case types.SYS_ENTER_MREMAP:
		if memEv.Length > memEv.Length2 {
			return memEv.Length
		}
		return memEv.Length2
	default:
		return 0
	}
}
