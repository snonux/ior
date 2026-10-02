package internal

import (
	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

// Naming an open_by_handle_at.
//
// The call opens a file by an opaque handle and passes no pathname, so the row
// can only be named after the file if ior knows which pathname that handle was
// taken of. Both ends carry the handle itself (internal/c/handle.c):
//
//   - a successful name_to_handle_at reports the handle the kernel returned in
//     a FILE_HANDLE_EVENT control record just ahead of its exit record, and
//     recordNameToHandleAt files the call's pathname under it;
//   - the enter record of open_by_handle_at carries the handle it opens, and
//     handleOpenByHandleAtExit looks the name up by it.
//
// The handle is the key (handleKey), so the lookup is exact: it does not
// matter which thread or process took the handle, how many handles a thread
// holds or in which order it opens them, whether the call fails, or what the
// returned descriptor number points at by the time the event loop gets there.
//
// It replaces a guess (tasks j03, l03, m03). The records used to carry no
// handle, so the pathname was parked per thread - the thread's last
// name_to_handle_at - and checked against /proc/<pid>/fd/<fd> when the exit
// was handled: by inode, by link text, by the descriptor's flags and kind.
// That look at procfs describes the number as it is when the loop gets there,
// not the file the call opened, and a number the task had closed and reused
// with the same flags named the row, and the fd table entry behind it, after
// the newer file; a failed call had no descriptor to check at all, and a
// handle opened by another thread was never matched. None of that checking is
// left: a handle ior knows is named by its pathname, and one it does not know
// is named from procfs without a second opinion, like any descriptor ior did
// not see being created.
//
// What the name is. It is the pathname of the name_to_handle_at, resolved as
// every path event is (resolvePathEvent): joined with a dirfd ior knows by
// name, or, for AT_EMPTY_PATH, whatever ior calls that descriptor - its traced
// name ("memfd:x", "pidfd:0", the directory of an O_TMPFILE open, a relative
// path as the task spelled it) or its /proc link. The opened descriptor is the
// same file, so it gets the same name as the descriptor the handle was taken
// through; nothing has to be comparable with anything any more.
//
// What is still wrong, and accepted:
//
//   - The name is the one the handle was taken by. A file renamed or unlinked
//     since keeps its old pathname on the row, as an fd table entry keeps the
//     name its descriptor was opened by.
//   - The mount is not part of the key, so two filesystems that encode
//     different files as the same type and bytes share an entry and the later
//     name_to_handle_at wins (see handleKeyOf for why the mount cannot be had,
//     and how far apart the encodings keep real handles).
//   - A handle ior did not see being taken - taken before the trace started,
//     by a task outside a -pid/-tid scope, by a call the enter filter shed
//     (-path, -comm), or whose control record was lost to ring-buffer
//     backpressure - and one that could not be read (handleKeyOf) are named
//     from procfs, with the lag every procfs-resolved descriptor has: a number
//     the task closed and reused before the loop reads it shows the newer
//     file. A failed call with such a handle has an empty name.
//   - An entry evicted by the LRU cap is such an unknown handle again.

// handleKeyOf builds the key of the handle in a record's handle fields. ok is
// false when the record identifies no handle: a status other than
// FILE_HANDLE_OK (an object that predates the capture, a NULL or unreadable
// pointer, an oversized handle_bytes), a zero handle_bytes, which no file has
// and the kernel rejects, and a byte count beyond the field, which the BPF
// side never submits as OK and is refused here so that a foreign producer
// cannot make the slice below run past the array.
//
// Only the first handleBytes bytes are copied; the rest of the key stays
// zero. BPF zero-fills the field as well, but equality of two keys must not
// depend on what a producer left behind the handle.
//
// The key has no mount in it. name_to_handle_at does return a mount ID, but
// open_by_handle_at is given a mount FD, and turning that into a mount ID
// takes either /proc/<pid>/fdinfo - the lagging look at a descriptor number
// this design exists to get rid of - or walking the task's file table in BPF.
// A mount ID would also be the wrong identity: a handle is valid on every
// mount of its filesystem, so a handle taken through one bind mount and
// opened through another would stop matching. The residual is a collision of
// type and bytes across filesystems. The common encodings make that remote -
// ext4, xfs, tmpfs and their kin put the inode number and a 32-bit random
// generation in the bytes, btrfs adds its root - and what it costs is a row
// named after the file that took such a handle last.
func handleKeyOf(status, handleBytes uint32, handleType int32, fHandle *[types.IOR_MAX_HANDLE_SZ]byte) (key handleKey, ok bool) {
	if status != types.FILE_HANDLE_OK || handleBytes == 0 || handleBytes > types.IOR_MAX_HANDLE_SZ {
		return handleKey{}, false
	}
	key.handleType = handleType
	key.size = handleBytes
	copy(key.bytes[:], fHandle[:handleBytes])
	return key, true
}

// handleFileHandleEvent parks the handle a successful name_to_handle_at
// returned until the call's exit record arrives (recordNameToHandleAt).
//
// The kernel reserves this control record before the exit record of the same
// call and the ring buffer preserves that order, so the call's enter event is
// still pending here. The record is only accepted for such a pending
// name_to_handle_at enter: without one the pair was shed at enter (the raw
// path filter, -comm) or its enter was lost, and no exit handler will ever
// name the handle. Records of other tids interleave between this one and the
// exit, which is why the handle is parked per tid rather than kept in one
// slot.
//
// Like every control record it never becomes a row, and it owns the event it
// is handed, so it must recycle it.
func (e *eventLoop) handleFileHandleEvent(ev *types.FileHandleEvent) {
	defer ev.Recycle()
	key, ok := handleKeyOf(ev.HandleStatus, ev.HandleBytes, ev.HandleType, &ev.FHandle)
	if !ok {
		return
	}
	pair, ok := e.pairs.pending(ev.Tid)
	if !ok {
		return
	}
	pathEv, ok := pair.EnterEv.(*types.PathEvent)
	if !ok || pathEv.GetTraceId() != ev.GetTraceId() || !isNameToHandleAt(pathEv) {
		return
	}
	e.handleState().park(ev.Tid, key, ev.Time)
}

// isNameToHandleAt reports whether pathEv is the enter of a name_to_handle_at.
func isNameToHandleAt(pathEv *types.PathEvent) bool {
	return pathEv.GetTraceId().Name() == sysEnterNameToHandleAtName
}

// recordNameToHandleAt files the resolved pathname of a successful
// name_to_handle_at under the handle the call returned, so that an
// open_by_handle_at of that handle can name the file it opens. The pair itself
// is always recycled (never emitted); it always returns false so the caller
// drops it.
//
// The parked handle is claimed before anything else and on every path, a
// failed call included: this exit ends the only call it can belong to. No
// handle means no name is filed - the call failed (also the EOVERFLOW a caller
// provokes to learn the handle size, which returns no handle), the control
// record was lost or never emitted (an older BPF object, an unreadable
// buffer), or it belonged to another call (claim).
func (e *eventLoop) recordNameToHandleAt(ep *event.Pair, pathEv *types.PathEvent) bool {
	defer ep.Recycle()
	handles := e.handleState()
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		handles.dropTaken(pathEv.GetTid())
		return false
	}
	key, taken := handles.claim(pathEv.GetTid(), retEv.GetTime())
	if !taken || event.IsErrnoRet(retEv.Ret) {
		return false
	}
	pathname := e.resolvePathEvent(pathEv, pathEventAllowsEmptyPath(pathEv, true))
	handles.store(key, pathname.Name())
	return false
}

// openedHandleName returns the pathname the handle of an open_by_handle_at was
// taken of. named is false when the enter record identifies no handle
// (handleKeyOf) or ior has no name for it.
func (e *eventLoop) openedHandleName(openByHandleEv *types.OpenByHandleAtEvent) (name string, named bool) {
	key, ok := handleKeyOf(openByHandleEv.HandleStatus, openByHandleEv.HandleBytes,
		openByHandleEv.HandleType, &openByHandleEv.FHandle)
	if !ok {
		return "", false
	}
	return e.handleState().lookup(key)
}

// openedHandleFile returns the file the descriptor a successful
// open_by_handle_at returned is labelled with, on the row and in the fd table.
//
// A named handle gives the descriptor that name, and procfs is not asked: the
// handle says which file was opened, while /proc/<pid>/fd/<fd> says what the
// number is by now. The flags are the ones the event captured at enter (what
// the caller asked for).
//
// An unnamed one falls back to procfs, name and flags alike (procFdFile).
func openedHandleFile(name string, named bool, pid uint32, fd int32, eventFlags int32) *file.FdFile {
	if named {
		return file.NewFd(fd, name, eventFlags)
	}
	return procFdFile(pid, fd, eventFlags)
}

// failedHandleFile returns the file a FAILED open_by_handle_at row reports: a
// descriptor-less pathname, the same shape handleOpenExit gives a failed open,
// so the row is emitted, filtered and counted like any other error row. The
// name is the handle's, or empty when ior has none; there is no descriptor
// procfs could be asked about.
func failedHandleFile(name string) file.File {
	return file.NewPathname([]byte(name))
}

// procFdFile names a descriptor ior has no handle name for from procfs. An
// unreadable descriptor yields an unnamed file, and unreadable flags are
// replaced by the event's (what the caller asked for).
func procFdFile(pid uint32, fd int32, eventFlags int32) *file.FdFile {
	fdFile := file.NewFdWithPid(fd, pid)
	if fdFile.Flags() == file.Flags(-1) {
		fdFile.SetFlags(eventFlags)
	}
	return fdFile
}
