package internal

import (
	"syscall"

	"ior/internal/event"
	"ior/internal/file"
)

// Procfs hygiene for fd-syscall exits that answered EBADF (task ir2).
//
// EBADF is the kernel saying "that number is not an open descriptor of the
// caller". Two things follow for the procfs side of fd resolution:
//
//   - whatever the procfs cache holds for (pid, fd) is stale and is evicted;
//   - reading /proc/<pid>/fd/<fd> cannot succeed, so it is not attempted. A
//     failing readlink is not free (path formatting, a PathError and a file
//     object, ~3.8 us against ~50 ns for a cache hit), and an EBADF stream is
//     exactly the hot shape: a close loop over a closed range, the closefrom
//     idiom fcntl(F_GETFD) sweeping ~1000 numbers per process, a library
//     probing for free descriptors. Before this shortcut such a loop cost
//     2-3x more per event than when failures were cached (which was the bug).
//
// Only the procfs cache is touched, never the fd table: its entries come from
// traced syscalls, and with several threads per process an EBADF exit can be
// processed after a later traced open of the same number, so erasing the table
// entry could drop a correct name. A table entry that IS present is therefore
// still used to label the row - unless it was bound after the call entered
// (task a23, resolveAfterEBADF), which is exactly that later open.
//
// Known gaps, all bounded and deliberate:
//   - an fd-table entry whose close event was lost (ring overflow) stays
//     stale after an EBADF, because the table is left alone as above;
//   - a syscall whose EBADF can concern a descriptor other than the one the
//     row is labelled by has its row unnamed when the labelled fd is valid but
//     has no fd-table entry (the next non-EBADF event on it resolves it from
//     procfs as usual). Those are epoll_ctl (labelled by epfd, EBADF for the
//     target fd), dup2/dup3 (labelled by oldfd, EBADF for an out-of-range
//     newfd), the transfer cohort sendfile, splice, tee and copy_file_range
//     (labelled by the destination fd, EBADF for the source), pidfd_getfd
//     (labelled by the pidfd, EBADF for a bad targetfd in the other process)
//     and fanotify_mark (labelled by the group fd, EBADF for a bad dirfd;
//     handleFdPathExit resolves the group through resolveOnExit and builds the
//     row from the captured pathname, so the row keeps that name and only its
//     flags become unknown, -1). The same shape arises for read/write and friends on
//     an open fd with the wrong access mode, which the kernel also answers with
//     EBADF. close_range is not on the list: it never returns EBADF;
//   - dirfd-relative path syscalls resolve their directory through
//     resolveDirfdPath, which has no exit record and is not shortened;
//   - successful events for a number that procfs cannot answer (a process
//     that already exited, a descriptor closed before the event is processed)
//     are still not cached and cost one failing readlink each. No per-pid
//     "dead" marker is kept: a failing readlink cannot tell a dead process
//     from a closed fd, and telling them apart needs a second procfs access
//     per failure, which costs about what it would save.

// exitedEBADF reports whether the pair's exit record carries -EBADF. Every
// exit kind with a ret field (event.RetCarrier) is covered, not only the
// generic RetEvent, so accept and the eventfd family are included.
func exitedEBADF(ep *event.Pair) bool {
	carrier, ok := ep.ExitEv.(event.RetCarrier)
	return ok && carrier.GetRet() == -int64(syscall.EBADF)
}

// resolveOnExit is the one place fd-resolving exit handlers turn a descriptor
// number into a file.File. An EBADF exit never reads procfs (see the comment
// above); neither does a close or close_range, whose descriptor is already
// released when the row is processed (eventloop_procfs_close.go). Every other
// exit resolves as usual (fd table, procfs cache, procfs).
func (e *eventLoop) resolveOnExit(ep *event.Pair, fd int32, pid uint32) file.File {
	if exitedEBADF(ep) {
		return e.fdState().resolveAfterEBADF(fd, pid, ep.EnterEv.GetTime())
	}
	if closesDescriptor(ep) {
		return e.fdState().resolveClosing(fd, pid, ep.EnterEv.GetTime())
	}
	return e.fdState().resolve(fd, pid)
}

// resolveAfterEBADF is resolve for a descriptor the kernel just reported as not
// open, by a call that entered at enterNs (boot clock): it evicts the
// procfs-cache entry, prefers the fd-table entry, and otherwise returns an
// unnamed file with unknown flags without touching procfs.
//
// An fd-table entry bound after the call entered (FdFile.BoundAt, task a23)
// does not name the row: the number was not open, or was another file, when
// the call looked at it - another thread's open, dup or pipe returned it
// later and was processed first. The row is unnamed and the entry stays (the
// table is never touched here, see above). In a run without file identities
// nothing has a binding time and the entry names the row as before.
func (t *fdTracker) resolveAfterEBADF(fd int32, pid uint32, enterNs uint64) file.File {
	t.deleteProcFdCache(fd, pid)
	if fdFile, ok := t.get(fd, pid); ok && !boundAfter(fdFile, enterNs) {
		return fdFile
	}
	return file.NewFd(fd, "", -1)
}
