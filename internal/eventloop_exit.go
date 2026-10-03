package internal

import (
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"syscall"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/textsafe"
	"ior/internal/types"

	"golang.org/x/sys/unix"
)

// These raw CLOEXEC/NONBLOCK values come from distinct Linux UAPI flag words.
// Keep them named separately even where their values coincide: merging them
// would recreate the assumption that made syscall-specific bits look like
// open(2) flags.
const (
	memfdCloexecFlag = int32(1)
	// Despite memfd_secret(2) naming FD_CLOEXEC, Linux validates and forwards
	// O_CLOEXEC in mm/secretmem.c.
	memfdSecretCloexecFlag = int32(syscall.O_CLOEXEC)
	// Linux reserves the low four bits of socket(2)'s type word for the
	// descriptor kind; SOCK_NONBLOCK and SOCK_CLOEXEC live above this mask.
	linuxSocketTypeMask = int32(0xf)
)

type eventfdOpenFlagSpec struct {
	accessMode int32
	implicit   int32
	cloexec    int32
	nonblock   int32
}

var eventfdOpenFlagSpecs = map[types.TraceId]eventfdOpenFlagSpec{
	types.SYS_ENTER_EPOLL_CREATE:  {accessMode: syscall.O_RDWR},
	types.SYS_ENTER_EPOLL_CREATE1: {accessMode: syscall.O_RDWR, cloexec: syscall.O_CLOEXEC},
	types.SYS_ENTER_INOTIFY_INIT:  {accessMode: syscall.O_RDONLY},
	types.SYS_ENTER_INOTIFY_INIT1: {accessMode: syscall.O_RDONLY, cloexec: syscall.O_CLOEXEC, nonblock: syscall.O_NONBLOCK},
	types.SYS_ENTER_EVENTFD:       {accessMode: syscall.O_RDWR},
	types.SYS_ENTER_EVENTFD2:      {accessMode: syscall.O_RDWR, cloexec: syscall.O_CLOEXEC, nonblock: syscall.O_NONBLOCK},
	types.SYS_ENTER_MEMFD_CREATE:  {accessMode: syscall.O_RDWR, cloexec: memfdCloexecFlag},
	types.SYS_ENTER_MEMFD_SECRET:  {accessMode: syscall.O_RDWR, cloexec: memfdSecretCloexecFlag},
	// userfaultfd's access mode is kernel-version dependent: the 5.14 audit
	// host exposes O_RDWR, while newer mainline kernels create it O_RDONLY.
	// Keep the measured host behavior until the generation kernel is verified.
	types.SYS_ENTER_USERFAULTFD:    {accessMode: syscall.O_RDWR, cloexec: syscall.O_CLOEXEC, nonblock: syscall.O_NONBLOCK},
	types.SYS_ENTER_SIGNALFD:       {accessMode: syscall.O_RDWR},
	types.SYS_ENTER_SIGNALFD4:      {accessMode: syscall.O_RDWR, cloexec: syscall.O_CLOEXEC, nonblock: syscall.O_NONBLOCK},
	types.SYS_ENTER_TIMERFD_CREATE: {accessMode: syscall.O_RDWR, cloexec: syscall.O_CLOEXEC, nonblock: syscall.O_NONBLOCK},
	types.SYS_ENTER_PIDFD_OPEN:     {accessMode: syscall.O_RDWR, implicit: syscall.O_CLOEXEC, nonblock: syscall.O_NONBLOCK},
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
// handler registered for the enter event kind, and reports whether the pair
// is still a row (the handler applies the pair filter last, finishPair).
//
// The handler runs for every pair, also one the filter then drops: a
// descriptor table belongs to the process while -comm judges the thread, and
// -path judges the name the handler has yet to find. So what the handler
// counted for the file identity line is booked here by the row's fate
// (fdTracker.bookDroppedRow, task e23).
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
	t := e.fdState()
	t.noteExit(ep)
	stale, rejected := t.staleBindings, t.rejectedAnswers
	if handler(e, ep) {
		return true
	}
	t.bookDroppedRow(stale, rejected)
	return false
}

func eventTypeForRuntimeEvent(ev event.Event) (types.EventType, bool) {
	typed, ok := ev.(interface{ GetEventType() types.EventType })
	if !ok {
		return 0, false
	}
	return typed.GetEventType(), true
}

// fdFromRet validates the syscall error window before narrowing a successful
// descriptor return to the int32 representation used by the fd tracker.
func fdFromRet(ret int64) (int32, bool) {
	if event.IsErrnoRet(ret) {
		return 0, false
	}
	if ret < 0 || ret > math.MaxInt32 {
		return 0, false
	}
	fd := int32(ret)
	return fd, fd >= 0
}

func (e *eventLoop) handleOpenExit(ep *event.Pair, openEv *types.OpenEvent) bool {
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed open exit event")
		return false
	}

	comm := types.StringValue(openEv.Comm[:])
	filename := e.resolveCapturedDirfdPath(openEv.Dirfd, openEv.Pid,
		types.StringValue(openEv.Filename[:]), openEv.FilenameStatus,
		openEventAllowsEmptyPath(openEv, !event.IsErrnoRet(retEvent.Ret)))
	ep.Comm = comm
	if fd, ok := fdFromRet(retEvent.Ret); ok {
		fdFile := fdFileNamedAs(fd, filename, openEventFlags(openEv))
		e.fdState().identifyOpened(fdFile, retEvent)
		e.fdState().set(fd, openEv.Pid, fdFile)
		ep.File = fdFile
	} else {
		// Keep path information for failed opens so error scenarios remain observable.
		ep.File = filename
	}
	// The open's payload comm (task->comm at the enter record) already updated
	// the comm cache when the enter record arrived (seedCommFromEnterPayload),
	// in ring order with any task_rename record. It is deliberately not written
	// again here: the exit is processed later, and a rename that landed between
	// enter and exit would be overwritten with the pre-rename name. Like the fd
	// registration above that global state is settled before the filter, so a
	// row this run does not want still leaves the fd table correct.
	// The raw enter filter (MatchOpenEvent) only covers the comm and path
	// dimensions, so without this checkpoint -syscall/-family/-fd/-ret/
	// -latency/-bytes and non-equality -pid/-tid reached open rows nowhere.
	// Absolute and AT_FDCWD paths carry the value MatchOpenEvent already
	// checked. A concrete dirfd-relative path deferred that dimension until
	// this checkpoint, where ep.File carries the resolved value.
	return e.finishPair(ep)
}

func openEventFlags(openEv *types.OpenEvent) int32 {
	switch openEv.GetTraceId() {
	case types.SYS_ENTER_OPEN_TREE, types.SYS_ENTER_OPEN_TREE_ATTR:
		flags := int32(unix.O_PATH)
		if openEv.Flags&int32(unix.OPEN_TREE_CLOEXEC) != 0 {
			flags |= syscall.O_CLOEXEC
		}
		return flags
	default:
		return openEv.Flags
	}
}

func (e *eventLoop) handleExecExit(ep *event.Pair, execEv *types.ExecEvent) bool {
	if _, ok := ep.ExitEv.(*types.RetEvent); !ok {
		e.recyclePair(ep, "Dropped malformed exec exit event")
		return false
	}
	// execEv is the sys_enter_execve payload, so its comm is the name of the
	// program that *called* execve - correct for this row. The comm cache is
	// not touched here: seedCommFromEnterPayload recorded that name at enter,
	// and on a SUCCESSFUL execve the authoritative post-exec name arrives as a
	// PROCESS_EXEC_EVENT control record (handleProcessExecEvent) after it. A
	// write at exit would put the pre-exec name back on top of that record.
	ep.Comm = types.StringValue(execEv.Comm[:])
	ep.File = e.execTarget(ep, execEv)
	// The exec enter has no raw filter, so the path dimension is applied here
	// against the resolved target rather than the captured relative name.
	return e.finishPair(ep)
}

// execTarget returns the file an exec pair reports. execveat(dirfd, "ls")
// names the program relative to dirfd, and glibc's fexecve is
// execveat(fd, "", AT_EMPTY_PATH), which names the descriptor itself; both
// resolve through the fd table like the open family does.
//
// The resolution normally happened at enter time (storeEnter) and arrives as
// ep.File, because a successful exec's control record drops FD_CLOEXEC
// descriptors - fexecve's included - before the exit is processed. Callers
// that built the pair without passing through storeEnter get the same
// resolution here, against the current table. The one fact enter time could
// not know is the outcome: an empty name only stands for the descriptor when
// the kernel accepted it, so a failed empty-name exec reports no path. Its read
// status decides the rest: an empty name read as "" (PATH_READ_OK) or passed
// as NULL (PATH_READ_NULL) may name the descriptor, while one BPF could not
// read (PATH_READ_FAILED) or with an unknown future status reports no path,
// whatever the flags.
func (e *eventLoop) execTarget(ep *event.Pair, execEv *types.ExecEvent) file.File {
	if types.StringValue(execEv.Filename[:]) == "" &&
		!execEventAllowsEmptyPath(execEv, retEventSucceeded(ep)) {
		return file.NewPathname(nil)
	}
	if ep.File != nil {
		return ep.File
	}
	return e.resolveExecTarget(execEv)
}

// snapshotExecTarget resolves an exec enter's target for storeEnter. It
// optimistically allows AT_EMPTY_PATH for an empty or NULL name (execTarget
// withdraws that when the syscall fails; an unreadable name never gets it)
// and copies a tracked descriptor so later fd-table updates cannot change
// what this pending pair reports.
func (e *eventLoop) snapshotExecTarget(execEv *types.ExecEvent) file.File {
	target := e.resolveExecTarget(execEv)
	if fdFile, ok := target.(*file.FdFile); ok {
		return fdFile.Detach()
	}
	return target
}

// resolveExecTarget applies dirfd semantics to an exec's captured filename,
// allowing an empty name whenever an execveat asked for AT_EMPTY_PATH and BPF
// actually observed it (a read "" or a NULL pointer).
//
// The filename read status (exec_event v1, task 9p2) separates a real ""
// from an unreadable name, which also leaves an empty buffer:
// resolveCapturedDirfdPath never gives a PATH_READ_FAILED name the dirfd's
// identity. Legacy records from an older BPF object carry no status and are
// decoded as PATH_READ_OK, keeping the previous best guess for them.
func (e *eventLoop) resolveExecTarget(execEv *types.ExecEvent) file.File {
	return e.resolveCapturedDirfdPath(execEventDirfd(execEv), execEv.Pid,
		types.StringValue(execEv.Filename[:]), execEv.FilenameStatus,
		execEventAllowsEmptyPath(execEv, true))
}

// execEventDirfd returns the directory descriptor an exec resolved its
// filename against. Only execveat has one; BPF fills plain execve's dirfd
// with -1, which would otherwise be looked up as a real descriptor, so it is
// mapped to AT_FDCWD - the semantics execve(2) actually has.
func execEventDirfd(execEv *types.ExecEvent) int32 {
	if execEv.TraceId != types.SYS_ENTER_EXECVEAT {
		return unix.AT_FDCWD
	}
	return execEv.Dirfd
}

// execEventAllowsEmptyPath reports whether an empty exec filename names the
// dirfd itself: only for a successful execveat carrying AT_EMPTY_PATH whose
// name BPF observed as "" (PATH_READ_OK) or as a NULL pointer
// (PATH_READ_NULL). Kernels that reject a NULL name fail the syscall, so a
// *successful* NULL AT_EMPTY_PATH execveat can only have run the descriptor,
// just as pathEventAllowsEmptyPath accepts NULL for statx/newfstatat. A
// failed read (PATH_READ_FAILED) is missing data, not AT_EMPTY_PATH, and an
// unknown status fails closed.
func execEventAllowsEmptyPath(execEv *types.ExecEvent, succeeded bool) bool {
	status := execEv.FilenameStatus
	return succeeded && execEv.TraceId == types.SYS_ENTER_EXECVEAT &&
		(status == types.PATH_READ_OK || status == types.PATH_READ_NULL) &&
		execEv.Flags&unix.AT_EMPTY_PATH != 0
}

func (e *eventLoop) handleNameExit(ep *event.Pair, nameEv *types.NameEvent) bool {
	// File.Name() resolves to the "new" path (newname); surface the captured
	// source path (oldname, at args[1] for the AT-variants) separately on the
	// Pair so it reaches the output schema rather than living only in the
	// TUI String() repr ("old:... ->new:..."). MatchPair's file dimension
	// picks Oldname up as the alternate value (Candidate.OldFileValue), so
	// the plain finishPairForTid applies every dimension here without
	// dropping the rows a `-path <oldname>` filter legitimately selected - the
	// raw enter filter (MatchNameEvent) already matched them on the oldname,
	// unless a dirfd-relative name deferred that dimension to this checkpoint.
	succeeded := retEventSucceeded(ep)
	oldname := e.resolveCapturedDirfdPath(nameEv.Olddirfd, nameEv.Pid,
		types.StringValue(nameEv.Oldname[:]), nameEv.OldnameStatus,
		nameEventAllowsEmptyPath(nameEv, true, succeeded)).Name()
	newname := e.resolveCapturedDirfdPath(nameEv.Newdirfd, nameEv.Pid,
		types.StringValue(nameEv.Newname[:]), nameEv.NewnameStatus,
		nameEventAllowsEmptyPath(nameEv, false, succeeded)).Name()
	ep.File = file.NewOldnameNewname([]byte(oldname), []byte(newname))
	ep.Oldname = oldname
	return e.finishPairForTid(ep, nameEv.GetTid())
}

// handlePathExit finishes a pathname-only syscall pair. name_to_handle_at is
// never emitted itself (see recordNameToHandleAt in eventloop_handle.go);
// fspick and creat create a descriptor on success and register it in the fd
// table; every other path syscall simply carries its resolved pathname.
func (e *eventLoop) handlePathExit(ep *event.Pair, pathEv *types.PathEvent) bool {
	if isNameToHandleAt(pathEv) {
		return e.recordNameToHandleAt(ep, pathEv)
	}

	pathname := e.resolvePathEvent(pathEv, pathEventAllowsEmptyPath(pathEv, retEventSucceeded(ep)))
	switch {
	case ep.Is(types.SYS_ENTER_FSPICK):
		if !e.attachPathExitFd(ep, pathEv, pathname, "fspick", fspickFdFlags(pathEv.Flags)) {
			return false
		}
	case ep.Is(types.SYS_ENTER_CREAT):
		// creat(pathname, mode) == open(pathname, O_CREAT|O_WRONLY|O_TRUNC,
		// mode): on success it returns a new fd, so register the fd->path
		// mapping just like handleOpenExit does for open/openat/openat2.
		if !e.attachPathExitFd(ep, pathEv, pathname, "creat",
			syscall.O_CREAT|syscall.O_WRONLY|syscall.O_TRUNC) {
			return false
		}
	default:
		ep.File = pathname
	}
	// Absolute and AT_FDCWD paths carry the value matchRawPathEvent already
	// matched. Concrete dirfd-relative paths defer the path dimension until
	// this checkpoint, where ep.File carries the resolved value.
	return e.finishPairForTid(ep, pathEv.GetTid())
}

// fspickFdFlags returns the tracked flags of an fspick descriptor. fspick
// returns a read/write filesystem-context descriptor; its userspace flags word
// controls only close-on-exec, so preserve the kernel-selected access mode as
// well as that optional bit.
func fspickFdFlags(fspickFlags uint32) int32 {
	flags := int32(syscall.O_RDWR)
	if fspickFlags&unix.FSPICK_CLOEXEC != 0 {
		flags |= syscall.O_CLOEXEC
	}
	return flags
}

// attachPathExitFd sets ep.File for a path syscall that returns a new
// descriptor on success (fspick, creat). A successful return registers the
// fd->path mapping with fdFlags; a failed one keeps the plain path so error
// scenarios stay observable, mirroring handleOpenExit's failed-open branch.
// It reports whether ep is still alive; a malformed exit event is recycled
// (the log message names syscallName) and false is returned.
func (e *eventLoop) attachPathExitFd(ep *event.Pair, pathEv *types.PathEvent,
	pathname file.File, syscallName string, fdFlags int32) bool {
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed "+syscallName+" exit event")
		return false
	}
	fd, ok := fdFromRet(retEvent.Ret)
	if !ok {
		ep.File = pathname
		return true
	}
	fdFile := fdFileNamedAs(fd, pathname, fdFlags)
	// creat's exit says which file it opened; fspick's reports none.
	e.fdState().identifyOpened(fdFile, retEvent)
	e.fdState().set(fd, pathEv.Pid, fdFile)
	ep.File = fdFile
	return true
}

// fdFileNamedAs builds the descriptor fd that is named after resolved: the
// file a pathname resolved to (resolveDirfdPath), or the descriptor another
// one takes its name from (fsmountFdFile). The name is copied, and with it
// the mark that says ior cannot vouch for it - it came from a look at procfs
// rather than from a traced call, or is a pathname below a directory ior
// has no name for (FdFile.NameFromProcFS, task 523): a name does not get
// better by being given to another descriptor, or by having a pathname
// appended. Without it the fd table entry of an openat below a dirfd ior
// did not see being opened passed for a traced name, and a file handle
// taken through that entry was filed under it for every later open
// (takenHandleName).
func fdFileNamedAs(fd int32, resolved file.File, flags int32) *file.FdFile {
	return fdFileNamedAfter(fd, resolved.Name(), flags, resolved)
}

// fdFileNamedAfter is fdFileNamedAs for a name that is not source's own but
// was built from it (a pathname joined to it).
func fdFileNamedAfter(fd int32, name string, flags int32, source file.File) *file.FdFile {
	fdFile := file.NewFd(fd, name, flags)
	if namedFromProcfs(source) {
		fdFile.MarkNameFromProcFS()
	}
	return fdFile
}

// maxCapturedPathname is the longest pathname the BPF side captures: the
// MAX_FILENAME_LENGTH buffer minus its NUL terminator.
const maxCapturedPathname = types.MAX_FILENAME_LENGTH - 1

// trimCutPathname drops the half of a multi-byte character that the BPF
// byte-wise capture cut off the end of a pathname which filled its buffer.
// It must run on the captured name itself, before a dirfd join appends the
// name to a directory: afterwards the joined string is longer than the limit
// and the cut is no longer recognisable as one. A pathname shorter than the
// limit was not cut, so its bytes (even an odd trailing one) are left alone.
func trimCutPathname(pathname string) string {
	if len(pathname) != maxCapturedPathname {
		return pathname
	}
	return textsafe.TrimPartialRune(pathname)
}

// resolveDirfdPath resolves one pathname against its directory descriptor.
// Absolute paths and AT_FDCWD retain their captured form. A concrete dirfd is
// resolved exactly once: an empty path represents that descriptor itself,
// while a relative path is joined to the descriptor's resolved directory.
// A pathname cut mid-character by the capture limit is repaired first
// (trimCutPathname) so the garbage half-rune neither appears in the resolved
// name nor ends up in the middle of a joined path. That holds only for names
// that pass through here. Names that bypass it keep the raw 255-byte cut and
// may show a stray lead byte (for example "\xc3") in TUI/plain output:
// inotify_add_watch targets (handleFdPathExit, non-fanotify branch), eventfd
// identity names, events that do not need a target path, and non-OK path
// statuses. Parquet and CSV output stay valid regardless, because
// textsafe.SanitizePath trims the cut itself.
//
// Where the name came from travels with it (task 523). The directory is
// whatever fdTracker.resolve answers: an fd table entry, or - for a dirfd ior
// did not see being opened - the /proc/<pid>/fd link as it is now, which is
// a newer file once the task closed and reused the number. An answer that
// is such a look at procfs, or a table entry that was one, carries the mark
// (FdFile.NameFromProcFS), and so does what is returned for it: the
// directory itself for an empty pathname, and the joined name. The bare
// pathname left when the directory has no name is marked whatever the
// directory is - procfs without an answer, or a table entry ior tracks
// without a name (an openat whose filename BPF could not read): nothing
// vouches for it either way (unvouchedBarePathname). An absolute or
// AT_FDCWD pathname is the caller's own and a pathname-only file, which has
// no mark; a name joined to a tracked, unmarked, named directory has none
// either. The exit handlers that store the result pass the mark on
// (fdFileNamedAs).
func (e *eventLoop) resolveDirfdPath(dirfd int32, pid uint32, pathname string) file.File {
	pathname = trimCutPathname(pathname)
	if !dirfdPathNeedsResolution(dirfd, pathname) {
		return file.NewPathname([]byte(pathname))
	}

	dir := e.fdState().resolve(dirfd, pid)
	if pathname == "" {
		return dir
	}
	if dir.Name() == "" {
		return unvouchedBarePathname(dirfd, pathname, int32(dir.Flags()))
	}
	return fdFileNamedAfter(dirfd, filepath.Join(dir.Name(), pathname), int32(dir.Flags()), dir)
}

// unvouchedBarePathname is what resolveDirfdPath answers for a pathname
// below a directory ior has no name for: the pathname alone, marked
// (FdFile.NameFromProcFS) wherever the directory came from. The mark is
// about the name, not about procfs: "below.txt" is all a row can show, but
// it is not the file's name, and unmarked it reads as a path relative to
// the working directory, which a file handle taken through the descriptor
// was then filed under.
func unvouchedBarePathname(dirfd int32, pathname string, flags int32) *file.FdFile {
	bare := file.NewFd(dirfd, pathname, flags)
	bare.MarkNameFromProcFS()
	return bare
}

// resolveCapturedDirfdPath applies dirfd semantics only when BPF observed a
// valid pathname string (including an empty one) or an actual NULL argument.
// A failed non-NULL nofault read also leaves a zero-filled buffer, but that is
// missing data rather than AT_EMPTY_PATH and must never acquire the dirfd's
// identity. Unknown future status values fail closed for the same reason.
func (e *eventLoop) resolveCapturedDirfdPath(
	dirfd int32,
	pid uint32,
	pathname string,
	status uint32,
	allowEmpty bool,
) file.File {
	if status != types.PATH_READ_OK && status != types.PATH_READ_NULL {
		return file.NewPathname([]byte(pathname))
	}
	if pathname == "" && !allowEmpty {
		return file.NewPathname(nil)
	}
	if pathname != "" && status != types.PATH_READ_OK {
		return file.NewPathname([]byte(pathname))
	}
	return e.resolveDirfdPath(dirfd, pid, pathname)
}

// resolvePathEvent resolves a path_event against its dirfd only when the
// kernel actually had to validate the syscall target. utimensat can return
// success without touching the pathname, dirfd, or flags when both timestamps
// are UTIME_OMIT; unreadable timestamp metadata also leaves that fact unknown.
// In either case the captured pathname is useful evidence, but attributing it
// to a descriptor would claim kernel validation that never happened. Unknown
// future target states fail closed for the same reason.
func (e *eventLoop) resolvePathEvent(ev *types.PathEvent, allowEmpty bool) file.File {
	if ev == nil {
		return file.NewPathname(nil)
	}
	pathname := types.StringValue(ev.Pathname[:])
	if !pathEventTargetRequired(ev) {
		return file.NewPathname([]byte(pathname))
	}
	return e.resolveCapturedDirfdPath(ev.Dirfd, ev.Pid, pathname, ev.PathnameStatus, allowEmpty)
}

func pathEventTargetRequired(ev *types.PathEvent) bool {
	return ev != nil && ev.TargetStatus == types.PATH_TARGET_REQUIRED
}

func retEventSucceeded(ep *event.Pair) bool {
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	return ok && !event.IsErrnoRet(retEv.Ret)
}

func openEventAllowsEmptyPath(ev *types.OpenEvent, succeeded bool) bool {
	if ev == nil || !succeeded || ev.FilenameStatus != types.PATH_READ_OK || ev.Flags&unix.AT_EMPTY_PATH == 0 {
		return false
	}
	return ev.TraceId == types.SYS_ENTER_OPEN_TREE || ev.TraceId == types.SYS_ENTER_OPEN_TREE_ATTR
}

func pathEventAllowsEmptyPath(ev *types.PathEvent, succeeded bool) bool {
	if ev == nil || !succeeded {
		return false
	}
	status := ev.PathnameStatus
	switch ev.TraceId {
	case types.SYS_ENTER_STATX, types.SYS_ENTER_NEWFSTATAT:
		return (status == types.PATH_READ_OK || status == types.PATH_READ_NULL) &&
			ev.Flags&unix.AT_EMPTY_PATH != 0
	case types.SYS_ENTER_FACCESSAT2, types.SYS_ENTER_FCHMODAT2, types.SYS_ENTER_FCHOWNAT,
		types.SYS_ENTER_MOUNT_SETATTR, types.SYS_ENTER_NAME_TO_HANDLE_AT:
		return status == types.PATH_READ_OK && ev.Flags&unix.AT_EMPTY_PATH != 0
	case types.SYS_ENTER_GETXATTRAT, types.SYS_ENTER_SETXATTRAT, types.SYS_ENTER_LISTXATTRAT,
		types.SYS_ENTER_REMOVEXATTRAT, types.SYS_ENTER_FILE_GETATTR, types.SYS_ENTER_FILE_SETATTR:
		return (status == types.PATH_READ_OK || status == types.PATH_READ_NULL) &&
			ev.Flags&unix.AT_EMPTY_PATH != 0
	case types.SYS_ENTER_FSPICK:
		return status == types.PATH_READ_OK && ev.Flags&unix.FSPICK_EMPTY_PATH != 0
	case types.SYS_ENTER_READLINKAT:
		return status == types.PATH_READ_OK
	case types.SYS_ENTER_UTIMENSAT:
		return ev.TargetStatus == types.PATH_TARGET_REQUIRED && (status == types.PATH_READ_NULL ||
			(status == types.PATH_READ_OK && ev.Flags&unix.AT_EMPTY_PATH != 0))
	case types.SYS_ENTER_FUTIMESAT:
		return status == types.PATH_READ_NULL
	default:
		return false
	}
}

func nameEventAllowsEmptyPath(ev *types.NameEvent, oldSide, succeeded bool) bool {
	return ev != nil && succeeded && oldSide && ev.TraceId == types.SYS_ENTER_LINKAT &&
		ev.OldnameStatus == types.PATH_READ_OK && ev.Flags&unix.AT_EMPTY_PATH != 0
}

func dirfdPathNeedsResolution(dirfd int32, pathname string) bool {
	return dirfd != unix.AT_FDCWD && !filepath.IsAbs(pathname)
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
	// The record says which file fd named at enter; the name must be that
	// file's (eventloop_fileident.go).
	ident := e.fdState().rowIdent(fdEv)
	ep.File = e.resolveIdentifiedOnExit(ep, fd, fdEv.Pid, ident)
	e.applyFdCloseState(ep, fd, fdEv.Pid, ident)
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
//
// ident is the file the close row says it closed (0 = unknown). What a close
// releases is that file, not whatever the number names by the time its row is
// processed: another thread's open can return the number, and be processed,
// before this close's exit record is (task 603). So what is known to describe
// a later file stays (fdTracker.closeIdentified).
func (e *eventLoop) applyFdCloseState(ep *event.Pair, fd int32, pid uint32, ident uint32) {
	if !ep.Is(types.SYS_ENTER_CLOSE) {
		return
	}
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok || retEv.Ret == -int64(syscall.EBADF) {
		return
	}
	e.fdState().closeIdentified(fd, pid, ident, ep.EnterEv.GetTime())
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
		if newFd, ok := fdFromRet(retEvent.Ret); ok {
			e.registerDup(fdFile, fdEv.Pid, newFd, 0)
		}
	}
	if ep.Is(types.SYS_ENTER_PIDFD_GETFD) {
		retEv, ok := ep.ExitEv.(*types.RetEvent)
		if !ok {
			e.recyclePair(ep, "Dropped malformed pidfd_getfd exit event")
			return false
		}
		if newFd, ok := fdFromRet(retEv.Ret); ok {
			// The transferred descriptor lives in this process's table but
			// ior saw no open for it, so its name can only come from procfs,
			// read now - after the syscall. That answer is right for this
			// row's filter and printout, but it must not be stored: the
			// program may close and reuse the number before this event is
			// processed, and a stored answer would label every later row on
			// it (across exec too, close-on-exec being known clear) with the
			// wrong file. Forget whatever the number held before and let its
			// first later use resolve it afresh.
			e.fdState().forget(newFd, fdEv.Pid)
			ep.File = file.NewFdWithPid(newFd, fdEv.Pid)
		}
	}
	return true
}

// handleDup3Exit registers the duplicated descriptor before filtering the pair,
// for the reason spelled out on handleFdExit: the fd table must stay correct
// for the rows the run does want even when this row is dropped.
//
// The record says which file the old descriptor named at enter (task d23), so
// the source is resolved like a dup/dup2 row's (resolveIdentifiedOnExit): an
// fd table entry of another file is a stale binding and is dropped, one bound
// after the call entered leaves the row unnamed. Either way the source is no
// longer the table's entry, and registerDup then copies nothing: the new
// number is resolved from procfs on its own first use. Before, dup3 copied
// whatever the table held for the old number onto the new one, unchecked.
func (e *eventLoop) handleDup3Exit(ep *event.Pair, dup3Ev *types.Dup3Event) bool {
	fd := int32(dup3Ev.Fd)
	ident := e.fdState().dup3Ident(dup3Ev)
	ep.File = e.resolveIdentifiedOnExit(ep, fd, dup3Ev.Pid, ident)
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
	if newFd, ok := fdFromRet(retEvent.Ret); ok {
		e.registerDup(fdFile, dup3Ev.Pid, newFd, dup3Ev.Flags&syscall.O_CLOEXEC)
	}
	return e.finishPair(ep)
}

// handleOpenByHandleAtExit finishes an open_by_handle_at pair. The file is
// named by the handle the enter record carries (openedHandleName); see
// "Naming an open_by_handle_at" in eventloop_handle.go.
func (e *eventLoop) handleOpenByHandleAtExit(ep *event.Pair, openByHandleEv *types.OpenByHandleAtEvent) bool {
	tid := openByHandleEv.GetTid()
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed open_by_handle_at exit event")
		return false
	}

	name, named := e.openedHandleName(openByHandleEv)
	if fd, ok := fdFromRet(retEvent.Ret); ok {
		fdFile := e.fdState().openedHandleFile(name, named, openByHandleEv, fd, retEvent)
		e.fdState().identifyOpened(fdFile, retEvent)
		e.fdState().set(fd, openByHandleEv.Pid, fdFile)
		ep.File = fdFile
	} else {
		// A failed call (EPERM, EBADF, ESTALE, ...) is still a row, exactly
		// like a failed open in handleOpenExit: it used to be recycled here,
		// so it never reached any sink and was never counted as an error or
		// in "syscalls after filter".
		ep.File = failedHandleFile(name)
	}
	// This kind has no raw enter filter at all (see rawSyscallEvents), so
	// without a checkpoint here NO filter dimension - comm included - was ever
	// applied to an open_by_handle_at row, and a run filtered by -comm could
	// emit rows carrying a different comm. The full pair filter is the right
	// checkpoint: ep.File is in every branch exactly the name the row reports
	// (the pathname the handle was taken of, the /proc/<pid>/fd readlink for
	// a handle ior has no name for, or for a failed call that pathname or an
	// empty one), so filter and displayed value can never disagree, and
	// unlike the rename kinds there is no raw match to contradict. Applying
	// -path to a procfs-resolved name is also not new: every fd-based kind
	// already does that (handleFdExit -> fdTracker.resolve ->
	// file.NewFdWithPid, then finishPair). A failed row carries no descriptor
	// (FD() is -1, as for a failed open's pathname), so -path matches it only
	// through the handle's name and -fd never matches it.
	return e.finishPairForTid(ep, tid)
}

func (e *eventLoop) handleSocketExit(ep *event.Pair, socketEv *types.SocketEvent) bool {
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed socket exit event")
		return false
	}

	if fd, ok := fdFromRet(retEvent.Ret); ok {
		fdFile := file.NewFd(fd, socketDescriptorName(socketEv.Family, socketEv.Type, socketEv.Protocol), socketOpenFlags(socketEv.Type))
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
			fdFile := file.NewFd(exitEv.Sv0, socketDescriptorName(family, typ, protocol), socketOpenFlags(typ))
			e.fdState().set(exitEv.Sv0, socketpairEv.Pid, fdFile)
			ep.File = fdFile
		}
		if exitEv.Sv1 >= 0 {
			fdFile := file.NewFd(exitEv.Sv1, socketDescriptorName(family, typ, protocol), socketOpenFlags(typ))
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

	listening := e.resolveOnExit(ep, acceptEv.Fd, acceptEv.Pid)
	if fd, ok := fdFromRet(exitEv.Ret); ok {
		fdFile := file.NewFd(fd, acceptedSocketDescriptorName(listening), acceptOpenFlags(acceptEv))
		e.fdState().set(fd, acceptEv.Pid, fdFile)
		ep.File = fdFile
	} else {
		ep.File = listening
	}
	ep.Comm = e.comm(acceptEv.GetTid())
	return e.finishPair(ep)
}

func socketDescriptorName(family, typ, protocol int32) string {
	return fmt.Sprintf("socket:%d:%d:%d", family, typ&linuxSocketTypeMask, protocol)
}

func socketOpenFlags(rawType int32) int32 {
	return socketCreationFlags(rawType)
}

func acceptOpenFlags(acceptEv *types.AcceptEvent) int32 {
	if acceptEv.GetTraceId() == types.SYS_ENTER_ACCEPT {
		return syscall.O_RDWR
	}
	if acceptEv.Flags < 0 {
		return -1
	}
	return socketCreationFlags(acceptEv.Flags)
}

func socketCreationFlags(rawFlags int32) int32 {
	flags := int32(syscall.O_RDWR)
	if rawFlags&syscall.SOCK_NONBLOCK != 0 {
		flags |= syscall.O_NONBLOCK
	}
	if rawFlags&syscall.SOCK_CLOEXEC != 0 {
		flags |= syscall.O_CLOEXEC
	}
	return flags
}

// acceptedSocketDescriptorName names the descriptor accept returned.
//
// Only the synthetic class name that socket()/socketpair() produce
// ("socket:<family>:<type>:<protocol>") is inherited: an accepted socket really
// has the listener's family/type/protocol, so the class is accurate and the
// name stays stable. A procfs identity ("socket:[<inode>]", what readlink on
// /proc/<pid>/fd gives for a listener ior did not see created) must NOT be
// copied: the inode belongs to the listening socket, and every accepted
// connection is a different socket with its own inode, so copying it made each
// connection's reads/writes/close look like traffic on the listener. For that
// case (and an unknown listener) the generic "socket:accepted" is used rather
// than a per-connection procfs lookup, which would cost a readlink for every
// accept and can lose the race against a fast close.
func acceptedSocketDescriptorName(listening file.File) string {
	if listening == nil {
		return acceptedSocketGenericName
	}
	name := listening.Name()
	if !isSyntheticSocketName(name) {
		return acceptedSocketGenericName
	}
	return name
}

// acceptedSocketGenericName is the class name of an accepted connection whose
// listener gives no inheritable class.
const acceptedSocketGenericName = "socket:accepted"

// isSyntheticSocketName reports whether name is an ior-made socket class name
// ("socket:<family>:<type>:<protocol>" or the generic accepted name) rather
// than a procfs identity such as "socket:[75019555]" or a non-socket name.
func isSyntheticSocketName(name string) bool {
	rest, ok := strings.CutPrefix(name, "socket:")
	return ok && rest != "" && !strings.HasPrefix(rest, "[")
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

// handleEventfdExit records the descriptor returned by the fd-creating
// syscalls grouped under the eventfd payload (eventfd, epoll_create, memfd,
// landlock_create_ruleset, ...). A non-zero-flag landlock_create_ruleset call
// (ABI query or invalid flags) returns a version/errata number or an error
// rather than an fd, so it is labelled without touching the fd table:
// registering its return value would clobber the name of a real descriptor
// that happens to share that number.
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
	identity := ""
	identityKnown := eventfdEv.FilenameStatus == types.PATH_READ_OK
	if identityKnown {
		identity = types.StringValue(eventfdEv.Filename[:])
	}
	descriptorName := eventfdDescriptorName(eventfdEv.GetTraceId(), flags, identity, identityKnown)
	fd, retIsFd := fdFromRet(exitEv.Ret)
	switch {
	case isLandlockRulesetProbe(eventfdEv.GetTraceId(), flags):
		ep.File = file.NewPathname([]byte(landlockProbeName(flags)))
	case retIsFd:
		ep.File = e.registerEventfdResult(eventfdEv, fd, flags, descriptorName)
	case identityKnown && eventfdCarriesIdentity(eventfdEv.GetTraceId()):
		ep.File = file.NewPathname([]byte(descriptorName))
	}
	ep.Comm = e.comm(eventfdEv.GetTid())
	return e.finishPair(ep)
}

// registerEventfdResult attributes the returned fd and records it in the fd
// table. signalfd updating an existing fd keeps that fd's metadata, and
// fsmount inherits the name of the fs-context fd it was created from.
func (e *eventLoop) registerEventfdResult(eventfdEv *types.EventfdEvent, fd, flags int32, descriptorName string) file.File {
	traceID := eventfdEv.GetTraceId()
	// Both resolves below only run for a successful exit (fd is the return
	// value), so EBADF cannot occur and plain resolve is right (contrast
	// resolveOnExit).
	if eventfdReusesExistingFD(traceID, eventfdEv.Fd) {
		return e.fdState().resolve(fd, eventfdEv.Pid)
	}
	openFlags := eventfdOpenFlags(traceID, flags)
	fdFile := file.NewFd(fd, descriptorName, openFlags)
	if traceID == types.SYS_ENTER_FSMOUNT && eventfdEv.Fd >= 0 {
		context := e.fdState().resolve(eventfdEv.Fd, eventfdEv.Pid)
		className := eventfdDescriptorName(traceID, flags, "", false)
		fdFile = fsmountFdFile(fd, context, className, openFlags)
	}
	e.fdState().set(fd, eventfdEv.Pid, fdFile)
	return fdFile
}

// fsmountFdFile builds the descriptor fd an fsmount(fsfd) returned. It is
// named after context, the fs-context descriptor it was made from as the fd
// table or, for an fsfd ior did not see being opened, /proc/<pid>/fd calls
// that one now. The name is copied together with its procfs mark
// (fdFileNamedAs): an fsmount descriptor is an O_PATH one on the root of
// the new mount, so name_to_handle_at(fd, "", AT_EMPTY_PATH) succeeds on it,
// and an unmarked copy of the lagging link of a reused fsfd number was filed
// as the handle's name for every opener (found in the task 523 review). A
// context without a name leaves className, the call's class name
// ("fsmountfd:<flags>", eventfdDescriptorName), which is ior's own and
// carries no mark.
func fsmountFdFile(fd int32, context file.File, className string, openFlags int32) *file.FdFile {
	if context.Name() == "" {
		return file.NewFd(fd, className, openFlags)
	}
	return fdFileNamedAs(fd, context, openFlags)
}

// isLandlockRulesetProbe reports whether a landlock_create_ruleset call is a
// non-zero-flag call (ABI query or invalid flags) and so cannot have returned
// a ruleset fd. The kernel only creates a ruleset when flags is
// 0; LANDLOCK_CREATE_RULESET_VERSION or _ERRATA return the ABI version or the
// errata bitmask instead (libraries such as go-landlock and the Rust landlock
// crate probe this at startup), and any other non-zero flags fail with
// -EINVAL. Checking flags != 0 rather than the known query bits keeps future
// query flags out of the fd table too.
func isLandlockRulesetProbe(traceID types.TraceId, flags int32) bool {
	return traceID == types.SYS_ENTER_LANDLOCK_CREATE_RULESET && flags != 0
}

// landlockProbeName labels a non-zero-flag landlock_create_ruleset row (ABI
// query or invalid flags); it is a pathname-style label rather than an fd
// because no descriptor was created.
func landlockProbeName(flags int32) string {
	return fmt.Sprintf("landlock-probe:%d", flags)
}

func eventfdOpenFlags(traceID types.TraceId, rawFlags int32) int32 {
	spec, ok := eventfdOpenFlagSpecs[traceID]
	if !ok {
		return -1
	}
	flags := spec.accessMode | spec.implicit
	if spec.cloexec != 0 && rawFlags&spec.cloexec != 0 {
		flags |= syscall.O_CLOEXEC
	}
	if spec.nonblock != 0 && rawFlags&spec.nonblock != 0 {
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
	ep.File = e.resolveOnExit(ep, epollCtlEv.Epfd, epollCtlEv.Pid)
	ep.Epoll = event.EpollCtl{
		Op:       epollCtlEv.Op,
		TargetFD: epollCtlEv.Fd,
		Events:   epollCtlEv.Events,
	}
	ep.HasEpoll = true
	return e.finishPairForTid(ep, epollCtlEv.GetTid())
}

func (e *eventLoop) handlePollExit(ep *event.Pair, pollEv *types.PollEvent) bool {
	ep.Nfds = pollEv.Nfds
	ep.TimeoutNs = pollEv.TimeoutNs
	if pollEv.Fd >= 0 {
		ep.File = e.resolveOnExit(ep, pollEv.Fd, pollEv.Pid)
	}
	return e.finishPairForTid(ep, pollEv.GetTid())
}

func (e *eventLoop) handleTwoFdExit(ep *event.Pair, twoFdEv *types.TwoFdEvent) bool {
	if ep.Is(types.SYS_ENTER_KCMP) {
		e.applyKcmpFile(ep, twoFdEv)
		return e.finishPairForTid(ep, twoFdEv.GetTid())
	}
	if ep.Is(types.SYS_ENTER_MOVE_MOUNT) {
		// The legacy two_fd payload predates pathname capture. Preserve its
		// original source-fd attribution rather than manufacturing two empty
		// pathnames from absent fields.
		if twoFdEv.SchemaVersion == 0 {
			ep.File = e.resolveOnExit(ep, twoFdEv.FdA, twoFdEv.Pid)
			return e.finishPairForTid(ep, twoFdEv.GetTid())
		}
		e.applyMoveMountPaths(ep, twoFdEv)
		return e.finishPairForTid(ep, twoFdEv.GetTid())
	}
	ep.File = e.resolveOnExit(ep, twoFdEv.FdA, twoFdEv.Pid)
	if ep.Is(types.SYS_ENTER_CLOSE_RANGE) {
		e.applyCloseRangeState(ep, twoFdEv)
	}
	return e.finishPairForTid(ep, twoFdEv.GetTid())
}

func (e *eventLoop) applyMoveMountPaths(ep *event.Pair, ev *types.TwoFdEvent) {
	succeeded := retEventSucceeded(ep)
	oldname := e.resolveCapturedDirfdPath(ev.FdA, ev.Pid,
		types.StringValue(ev.Oldname[:]), ev.OldnameStatus,
		succeeded && ev.Extra&unix.MOVE_MOUNT_F_EMPTY_PATH != 0).Name()
	newname := e.resolveCapturedDirfdPath(ev.FdB, ev.Pid,
		types.StringValue(ev.Newname[:]), ev.NewnameStatus,
		succeeded && ev.Extra&unix.MOVE_MOUNT_T_EMPTY_PATH != 0).Name()
	ep.File = file.NewOldnameNewname([]byte(oldname), []byte(newname))
	ep.Oldname = oldname
}

// closeRangeCloexec mirrors CLOSE_RANGE_CLOEXEC from <linux/close_range.h>: when
// set, close_range only marks the descriptors close-on-exec instead of closing
// them, so the fds stay open and must remain tracked.
const closeRangeCloexec = 1 << 2

// closeRangeUnshare mirrors CLOSE_RANGE_UNSHARE: the caller first gets a private
// copy of its descriptor table, then the range is closed (or marked) in that
// copy only. For a single-threaded process that shares its table through
// CLONE_FILES that ends the sharing; the kernel privatises only the calling
// *thread's* table, so applyCloseRangeState acts on it for a thread-group leader
// only. See fdTracker.unshareFiles and the file comment of eventloop_fdshare.go
// for what is and is not modelled.
const closeRangeUnshare = 1 << 1

// applyCloseRangeState evicts the fds closed by a successful close_range. The
// enter event carries (first, last, flags) in fd_a/fd_b/extra. fd_b is an __s32
// view of the unsigned "last" argument, so a negative value (e.g. ~0U meaning
// "close everything from first up") is treated as having no upper bound.
func (e *eventLoop) applyCloseRangeState(ep *event.Pair, ev *types.TwoFdEvent) {
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok || retEv.Ret != 0 {
		return
	}
	if ev.Extra&closeRangeUnshare != 0 {
		if ev.Tid != ev.Pid {
			// A worker thread privatises only its own table and applies the
			// range to that copy; the tgid's table - the one the tracker keys by,
			// still used by every other thread and by any CLONE_FILES process -
			// is untouched. Nothing here may change it: no detach, no un-blind,
			// and no range either (it would drop entries the other users still
			// have). The unsharing thread's later rows on those numbers keep the
			// tracked name: the per-thread table is not modelled (AGENTS.md).
			return
		}
		// A leader is taken to own the table alone (unshareFiles). Before the
		// range is applied: it acts on the private copy, and the former
		// sharers keep every descriptor the range covers.
		e.fdState().unshareFiles(ev.Pid)
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

func (e *eventLoop) handleMmapExit(ep *event.Pair, mmapEv *types.MmapEvent) bool {
	if mmapEv.Flags&syscall.MAP_ANON != 0 {
		ep.File = file.NewAnonymousMapping()
	} else {
		ep.File = e.resolveOnExit(ep, mmapEv.Fd, mmapEv.Pid)
	}
	return e.finishPairForTid(ep, mmapEv.GetTid())
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

	if fd, ok := fdFromRet(retEvent.Ret); ok {
		flags := int32(syscall.O_RDWR)
		if perfOpenEv.Flags&unix.PERF_FLAG_FD_CLOEXEC != 0 {
			flags |= syscall.O_CLOEXEC
		}
		fdFile := file.NewFd(fd, perfDescriptorName(perfOpenEv), flags)
		e.fdState().set(fd, perfOpenEv.Pid, fdFile)
		ep.File = fdFile
	}
	ep.Comm = e.comm(perfOpenEv.GetTid())
	return e.finishPair(ep)
}

func pipeDescriptorName(flags, fd0, fd1 int32) string {
	return fmt.Sprintf("pipe:%d:%d:%d", flags, fd0, fd1)
}

func eventfdDescriptorName(traceID types.TraceId, flags int32, identity string, identityKnown bool) string {
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
		if !identityKnown {
			return fmt.Sprintf("fsopenfd:%d", flags)
		}
		return "fsopen:" + identity
	case types.SYS_ENTER_FSMOUNT:
		// The mount descriptor's own class name, with the flags word
		// (FSMOUNT_CLOEXEC) as fsopenfd shows fsopen's. It names the fd only
		// when there is no fs-context name to copy (fsmountFdFile) or no
		// fsfd in the record (legacy payload); before task 823 it fell to
		// the default "eventfd:<flags>" and such rows read eventfd:0.
		return fmt.Sprintf("fsmountfd:%d", flags)
	case types.SYS_ENTER_MEMFD_CREATE:
		if !identityKnown {
			return fmt.Sprintf("memfd:%d", flags)
		}
		return "memfd:" + identity
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

func eventfdCarriesIdentity(traceID types.TraceId) bool {
	return traceID == types.SYS_ENTER_MEMFD_CREATE || traceID == types.SYS_ENTER_FSOPEN
}

const (
	bpfMapCreate         = uint32(0)
	bpfProgLoad          = uint32(5)
	bpfObjGet            = uint32(7)
	bpfProgGetFdByID     = uint32(13)
	bpfMapGetFdByID      = uint32(14)
	bpfRawTracepointOpen = uint32(17)
	bpfBtfLoad           = uint32(18)
	bpfBtfGetFdByID      = uint32(19)
	bpfLinkCreate        = uint32(28)
	bpfLinkGetFdByID     = uint32(30)
	bpfEnableStats       = uint32(32)
	bpfIterCreate        = uint32(33)
	bpfTokenCreate       = uint32(36)

	// bpfCommonAttrs is BPF_COMMON_ATTRS (1 << 16) from uapi linux/bpf.h. Since
	// the 7.0 generation kernels sys_bpf() accepts this flag OR-ed into cmd to
	// say "the extra attr_common/size_common arguments are present"; libbpf sets
	// it on BPF_PROG_LOAD (tools/lib/bpf/bpf.c). The kernel strips it before
	// dispatching, so the real command lives in the low 16 bits only.
	bpfCommonAttrs = uint32(1 << 16)
)

// bpfBaseCommand strips the BPF_COMMON_ATTRS flag so a flagged command such as
// BPF_PROG_LOAD|BPF_COMMON_ATTRS (0x10005) is classified exactly like the plain
// one, instead of falling through to the fail-closed "unknown command" path
// that neither registers the returned fd nor names it.
func bpfBaseCommand(cmd uint32) uint32 {
	return cmd &^ bpfCommonAttrs
}

func (e *eventLoop) handleBpfExit(ep *event.Pair, bpfEv *types.BpfEvent) bool {
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed bpf exit event")
		return false
	}
	cmd := bpfBaseCommand(bpfEv.Cmd)
	if fd, ok := fdFromRet(retEvent.Ret); ok && bpfCommandReturnsFD(cmd) {
		resolved := file.NewFdWithPid(fd, bpfEv.Pid)
		fdFile := file.NewFd(fd, "bpf:"+bpfCommandName(cmd), int32(resolved.Flags()))
		e.fdState().set(fd, bpfEv.Pid, fdFile)
		ep.File = fdFile
	}
	ep.Comm = e.comm(bpfEv.GetTid())
	return e.finishPair(ep)
}

// bpfCommandReturnsFD expects a command already stripped by bpfBaseCommand.
func bpfCommandReturnsFD(cmd uint32) bool {
	switch cmd {
	case bpfMapCreate, bpfProgLoad, bpfObjGet, bpfProgGetFdByID, bpfMapGetFdByID,
		bpfRawTracepointOpen, bpfBtfLoad, bpfBtfGetFdByID, bpfLinkCreate,
		bpfLinkGetFdByID, bpfEnableStats, bpfIterCreate, bpfTokenCreate:
		return true
	default:
		return false
	}
}

// bpfCommandName expects a command already stripped by bpfBaseCommand.
func bpfCommandName(cmd uint32) string {
	switch cmd {
	case bpfMapCreate:
		return "map_create"
	case bpfProgLoad:
		return "prog_load"
	case bpfObjGet:
		return "obj_get"
	case bpfProgGetFdByID:
		return "prog_get_fd_by_id"
	case bpfMapGetFdByID:
		return "map_get_fd_by_id"
	case bpfRawTracepointOpen:
		return "raw_tracepoint_open"
	case bpfBtfLoad:
		return "btf_load"
	case bpfBtfGetFdByID:
		return "btf_get_fd_by_id"
	case bpfLinkCreate:
		return "link_create"
	case bpfLinkGetFdByID:
		return "link_get_fd_by_id"
	case bpfEnableStats:
		return "enable_stats"
	case bpfIterCreate:
		return "iter_create"
	case bpfTokenCreate:
		return "token_create"
	default:
		return fmt.Sprintf("cmd_%d", cmd)
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
	if ep.Is(types.SYS_ENTER_GETCWD) {
		retEvent, ok := ep.ExitEv.(*types.RetEvent)
		if !ok {
			e.recyclePair(ep, "Dropped malformed getcwd exit event")
			return false
		}
		// The path was captured kernel-side from the output buffer and put on
		// the pair by the fixup record that precedes this exit
		// (applyCapturedOutputPath); here it is only validated against ret.
		ep.File = finishGetcwdPath(ep.File, retEvent.Ret)
	}
	ep.Comm = e.comm(nullEv.GetTid())
	return e.finishPair(ep)
}

// handleFcntlExit applies the fd-state effect of the command (F_GETFL/F_GETFD
// resynchronization, F_SETFL/F_SETFD flag update, F_DUPFD/F_DUPFD_CLOEXEC
// descriptor registration) before filtering the pair - see handleFdExit for
// why the ordering matters. The flag commands belong to the same class even
// though no filter dimension reads flags: they change the state of the fd
// table entry, or of the procfs cache entry of a descriptor known only to the
// cache (storeFcntlFdFile), so behind the checkpoint a dropped row left the
// new flags unrecorded.
//
// ioctl shares the fcntl_event layout (fd, cmd, arg), so its pairs arrive here
// too. They are routed by trace ID to applyIoctlFdState: an ioctl request
// number is not an fcntl command, and one that happens to equal F_SETFD or
// F_DUPFD must not be interpreted as one.
//
// The io_uring calls also use this record layout (see handleIoUringExit) and are
// routed away before any fd lookup, because their fd may be a registered-ring
// index rather than a descriptor.
func (e *eventLoop) handleFcntlExit(ep *event.Pair, fcntlEv *types.FcntlEvent) bool {
	switch fcntlEv.TraceId {
	case types.SYS_ENTER_IO_URING_ENTER, types.SYS_ENTER_IO_URING_REGISTER, types.SYS_ENTER_IO_URING_SETUP:
		return e.handleIoUringExit(ep, fcntlEv)
	}
	ep.Comm = e.comm(fcntlEv.GetTid())
	fd := int32(fcntlEv.Fd)
	ep.File = e.resolveOnExit(ep, fd, fcntlEv.Pid)
	apply := e.applyFcntlFdState
	if ep.Is(types.SYS_ENTER_IOCTL) {
		apply = e.applyIoctlFdState
	}
	if !apply(ep, fcntlEv, fd) {
		return false
	}
	return e.finishPair(ep)
}

// ioctlFioclex and ioctlFionclex are FIOCLEX and FIONCLEX from
// <asm-generic/ioctls.h> (x86_64 and arm64 use the generic values;
// golang.org/x/sys/unix does not export them). The kernel handles both in
// do_vfs_ioctl before any driver sees the request, so they behave identically
// for every descriptor type.
const (
	ioctlFionclex = 0x5450
	ioctlFioclex  = 0x5451
)

// applyIoctlFdState performs the fd-table side effect of the only ioctl
// requests that change tracked descriptor state: FIOCLEX sets and FIONCLEX
// clears close-on-exec, exactly like fcntl F_SETFD. Without this, an fd marked
// via FIOCLEX kept its name across execve (fdTracker.dropOnExec keeps entries
// whose close-on-exec is known clear) and one cleared via FIONCLEX was dropped.
// Every other request, and any failed call, leaves the fd table untouched. It
// reports whether ep is still alive, like applyFcntlFdState.
func (e *eventLoop) applyIoctlFdState(ep *event.Pair, ioctlEv *types.FcntlEvent, fd int32) bool {
	var cloexec int32
	switch ioctlEv.Cmd {
	case ioctlFioclex:
		cloexec = syscall.O_CLOEXEC
	case ioctlFionclex:
		cloexec = 0
	default:
		return true
	}
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed ioctl exit event")
		return false
	}
	if retEvent.Ret != 0 {
		// A negative errno changed nothing; any other value is not a return
		// FIOCLEX/FIONCLEX can produce, so do not trust the event either.
		return true
	}
	fdFile, ok := ep.File.(*file.FdFile)
	if !ok {
		e.recyclePair(ep, "Dropped malformed ioctl file event")
		return false
	}
	// Same translation as F_SETFD: the descriptor flag lives in the model's
	// O_CLOEXEC bit, and the entry is stored the same way (a procfs answer
	// keeps the state in the cache, see storeFcntlFdFile).
	fdFile.MergeFlags(syscall.O_CLOEXEC, cloexec)
	e.storeFcntlFdFile(ep, fdFile, fd, ioctlEv.Pid)
	return true
}

// applyFcntlFdState performs the fd-table side effects of one fcntl command.
// It reports whether ep is still alive; a false return means the pair was
// malformed and has already been recycled. The per-command semantics (see
// fcntl(2)) live in the applyFcntl* helpers below.
func (e *eventLoop) applyFcntlFdState(ep *event.Pair, fcntlEv *types.FcntlEvent, fd int32) bool {
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed fcntl exit event")
		return false
	}
	// Syscall returned a negative errno, nothing was changed with the fd.
	if event.IsErrnoRet(retEvent.Ret) {
		return true
	}

	fdFile, ok := ep.File.(*file.FdFile)
	if !ok {
		e.recyclePair(ep, "Dropped malformed fcntl file event")
		return false
	}

	switch fcntlEv.Cmd {
	case syscall.F_GETFL, syscall.F_SETFL:
		return e.applyFcntlStatusFlags(ep, fcntlEv, fdFile, fd, retEvent.Ret)
	case syscall.F_GETFD, syscall.F_SETFD:
		return e.applyFcntlDescriptorFlags(ep, fcntlEv, fdFile, fd, retEvent.Ret)
	case syscall.F_DUPFD:
		if newFd, ok := fdFromRet(retEvent.Ret); ok {
			e.registerDup(fdFile, fcntlEv.Pid, newFd, 0)
		}
	case syscall.F_DUPFD_CLOEXEC:
		if newFd, ok := fdFromRet(retEvent.Ret); ok {
			e.registerDup(fdFile, fcntlEv.Pid, newFd, syscall.O_CLOEXEC)
		}
	}
	return true
}

// applyFcntlStatusFlags handles F_GETFL and F_SETFL, which read or change the
// open-file-description status-flag word. The word lives in the description
// object every duplicate of fdFile shares (task nr2), so updating it through
// this one entry is seen through all of them. It reports whether ep is still
// alive; a malformed F_GETFL return value recycles the pair.
func (e *eventLoop) applyFcntlStatusFlags(ep *event.Pair, fcntlEv *types.FcntlEvent,
	fdFile *file.FdFile, fd int32, ret int64) bool {
	if fcntlEv.Cmd == syscall.F_GETFL {
		// Unlike F_SETFL's partial update, a successful F_GETFL return is the
		// kernel's complete authoritative status-flag word. FD_CLOEXEC is a
		// separate descriptor flag that F_GETFL cannot report, so preserve its
		// O_CLOEXEC representation while replacing every other bit. Linux
		// returns the status word as an int; reject a malformed raw event that
		// cannot be represented by FdFile's int32 word.
		if ret > math.MaxInt32 {
			e.recyclePair(ep, "Dropped malformed fcntl F_GETFL return value")
			return false
		}
		fdFile.SetStatusFlags(int32(ret))
	} else {
		// F_SETFL changes the settable status flags only; the access mode and
		// the open-only flags (O_CREAT, ...) stay as open(2) reported them, until
		// an F_GETFL replaces the word with the kernel's. Merge, do not
		// replace: callers do F_GETFL then OR, so arg carries the access mode
		// too, and masking it out of the stored word made an O_RDWR descriptor
		// report O_RDONLY on the fcntl row and on every later row for that fd.
		const canChange = syscall.O_APPEND | syscall.O_ASYNC | syscall.O_DIRECT | syscall.O_NOATIME | syscall.O_NONBLOCK
		fdFile.MergeFlags(int32(canChange), int32(fcntlEv.Arg))
	}
	e.storeFcntlFdFile(ep, fdFile, fd, fcntlEv.Pid)
	return true
}

// applyFcntlDescriptorFlags handles F_GETFD and F_SETFD. FD_CLOEXEC is a
// descriptor flag, not part of the F_GETFL status-flag word; the file model
// carries it as O_CLOEXEC so every row can render the descriptor's complete
// tracked state. Both commands translate FD_CLOEXEC into that bit without
// disturbing the status word. It reports whether ep is still alive;
// a malformed F_SETFD return value recycles the pair.
func (e *eventLoop) applyFcntlDescriptorFlags(ep *event.Pair, fcntlEv *types.FcntlEvent,
	fdFile *file.FdFile, fd int32, ret int64) bool {
	// F_GETFD's return value is the authoritative descriptor-flag word;
	// F_SETFD (which currently controls only FD_CLOEXEC) takes it from arg
	// and must return 0 on success.
	fdFlags := uint64(ret)
	if fcntlEv.Cmd == syscall.F_SETFD {
		if ret != 0 {
			e.recyclePair(ep, "Dropped malformed fcntl F_SETFD return value")
			return false
		}
		fdFlags = fcntlEv.Arg
	}
	cloexec := int32(0)
	if fdFlags&syscall.FD_CLOEXEC != 0 {
		cloexec = syscall.O_CLOEXEC
	}
	fdFile.MergeFlags(syscall.O_CLOEXEC, cloexec)
	e.storeFcntlFdFile(ep, fdFile, fd, fcntlEv.Pid)
	return true
}

// storeFcntlFdFile publishes a descriptor whose flags an fcntl or an ioctl
// FIOCLEX/FIONCLEX just changed on the pair, and stores it again in the fd
// table when that is where it came from, so the exec-time close-on-exec drop
// and later rows for that fd see the new state.
//
// A procfs answer is not promoted into the fd table (task a23). It was read
// when the loop got to the row, possibly after the number was closed and
// reused, and the fcntl_event record has no identity word to check it
// against; in the table it passed for a traced binding - dup and dup3 copied
// it to another number (registerDup) and a later row of the file actually
// behind the number dropped it as a "stale fd binding". The flag change is
// not lost: fdFile is the cached answer itself, so the cache keeps the new
// state, and the exec-time drop applies the same close-on-exec rule to cached
// answers (dropOnExec). What later rows lose is what the table gives beyond
// the cache - a dup of the descriptor is not copied but resolved from procfs
// on its own first use, the answer is subject to the cache's identity checks
// and re-reads and stays out of the table's LRU - and an answer that was not
// cached (procfs had none, or it changed under the read) keeps the change
// for this row only. The row itself is still named after the answer, as
// every row without an identity is.
func (e *eventLoop) storeFcntlFdFile(ep *event.Pair, fdFile *file.FdFile, fd int32, pid uint32) {
	ep.File = fdFile
	if e.fdState().tracksExactly(fd, pid, fdFile) {
		e.fdState().set(fd, pid, fdFile)
	}
}

// registerDup models a successful descriptor-duplicating syscall (dup, dup2,
// dup3, F_DUPFD*). fdFile is what the source descriptor resolved to.
//
// The copy is only as trustworthy as the source. A source held in the fd table
// was named by a traced syscall, so its name is right. A source that resolve
// answered from procfs (a descriptor opened before ior attached, or by a
// syscall outside the traced set such as pipe/socket) was read when this exit
// event was processed, which lags the syscall: the program may already have
// closed that number and reused it. Copying such an answer onto newFd would
// bind the wrong file to it for its whole life, and, with close-on-exec known
// clear, past execve. So for a procfs-resolved source no copy is registered;
// newFd's stale entries are dropped instead and it is resolved lazily on its
// own first use, which is the same lagging read but for the number the program
// is actually using.
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
	if !e.fdState().tracksExactly(fdFile.FD(), pid, fdFile) {
		e.fdState().forget(newFd, pid)
		return
	}
	duppedFdFile := fdFile.Dup(newFd)
	// FdFile.Dup shares the source's open file description object, so the
	// status flags (O_APPEND, O_NONBLOCK, ...) stay one word across both
	// numbers: an F_SETFL through either is seen through both, as in the kernel
	// (task nr2). FD_CLOEXEC belongs to the descriptor itself. The kernel
	// clears it for dup/dup2/F_DUPFD and sets it only when dup3 or
	// F_DUPFD_CLOEXEC requests O_CLOEXEC, and it is not shared.
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
	ep.Bytes = bytesFromRet(ep)
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

// bytesFromRet extracts the number of bytes transferred from a paired return.
// Two families of syscalls return something other than the bytes moved, so the
// captured enter payload corrects the raw return value:
//
//   - A zero-capacity xattr read is a size probe: its positive return describes
//     the required capacity, but no bytes were copied. Older payloads carry no
//     explicit requested-size validity and therefore retain their historical
//     byte count.
//   - recvfrom/recvmsg honour MSG_PEEK and MSG_TRUNC (see receivedBytes).
func bytesFromRet(ep *event.Pair) uint64 {
	if ep == nil {
		return 0
	}
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok || retEv == nil || retEv.Ret <= 0 || isZeroSizeProbe(ep.EnterEv) {
		return 0
	}
	switch retEv.RetType {
	case types.READ_CLASSIFIED, types.WRITE_CLASSIFIED, types.TRANSFER_CLASSIFIED:
		return receivedBytes(ep.EnterEv, uint64(retEv.Ret))
	default:
		return 0
	}
}

// receivedBytes corrects the return value of a successful recvfrom/recvmsg
// for the flags captured at sys_enter; every other syscall passes ret through.
//
//   - MSG_PEEK copies data without consuming it, so nothing was received yet:
//     the next non-peek call returns the same bytes and is the one to count.
//     Netlink clients (iproute2, libnl, systemd's sd-netlink) peek every
//     datagram once to size the buffer, then read it again, which counted each
//     reply twice.
//   - MSG_TRUNC makes the return the datagram's real length even when it did
//     not fit, so at most the buffer capacity was copied. The capacity comes
//     from the enter event (recvfrom's size, or the sum of recvmsg's iovec
//     lengths). When it is unknown - an older BPF object, or a recvmsg whose
//     iovec could not be read - the raw return is kept, the historical count.
//
// MSG_PEEK wins over MSG_TRUNC: the combination is the standard "how big is
// the next datagram" probe and copies nothing that is consumed.
func receivedBytes(enterEv event.Event, ret uint64) uint64 {
	fdEv, ok := enterEv.(*types.FdEvent)
	if !ok || (fdEv.TraceId != types.SYS_ENTER_RECVFROM && fdEv.TraceId != types.SYS_ENTER_RECVMSG) {
		return ret
	}
	if fdEv.Flags&unix.MSG_PEEK != 0 {
		return 0
	}
	if fdEv.Flags&unix.MSG_TRUNC != 0 && fdEv.SizeValid != 0 && ret > fdEv.Size {
		return fdEv.Size
	}
	return ret
}

// isZeroSizeProbe reports a call whose captured buffer capacity is zero, so it
// cannot have copied anything: the xattr size probe, and for recvfrom/recvmsg
// a zero-length buffer (the MSG_PEEK|MSG_TRUNC size probe; receivedBytes
// handles the non-zero-capacity cases).
func isZeroSizeProbe(enterEv event.Event) bool {
	switch ev := enterEv.(type) {
	case *types.FdEvent:
		return ev.SizeValid != 0 && ev.Size == 0
	case *types.PathEvent:
		return ev.SizeValid != 0 && ev.Size == 0
	default:
		return false
	}
}
