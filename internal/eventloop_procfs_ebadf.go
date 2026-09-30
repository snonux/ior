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
//     object, ~4.5 us against ~50 ns for a cache hit), and an EBADF stream is
//     exactly the hot shape: a close loop over a closed range, the closefrom
//     idiom fcntl(F_GETFD) sweeping ~1000 numbers per process, a library
//     probing for free descriptors. Before this shortcut such a loop cost
//     2-3x more per event than when failures were cached (which was the bug).
//
// Only the procfs cache is touched, never the fd table: its entries come from
// traced syscalls, and with several threads per process an EBADF exit can be
// processed after a later traced open of the same number, so erasing the table
// entry could drop a correct name. A table entry that IS present is therefore
// still used to label the row.
//
// Known gaps, all bounded and deliberate:
//   - an fd-table entry whose close event was lost (ring overflow) stays
//     stale after an EBADF, because the table is left alone as above;
//   - a syscall with a second descriptor argument (epoll_ctl, dup2/dup3's new
//     fd, close_range) can answer EBADF because of the OTHER number, so its
//     row may lack the name of a perfectly valid fd that has no table entry;
//     the next non-EBADF event on it resolves it from procfs as usual;
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
// number into a file.File. A non-EBADF exit resolves as usual (fd table, procfs
// cache, procfs); an EBADF exit never reads procfs (see the comment above).
func (e *eventLoop) resolveOnExit(ep *event.Pair, fd int32, pid uint32) file.File {
	if exitedEBADF(ep) {
		return e.fdState().resolveAfterEBADF(fd, pid)
	}
	return e.fdState().resolve(fd, pid)
}

// resolveAfterEBADF is resolve for a descriptor the kernel just reported as not
// open: it evicts the procfs-cache entry, prefers the fd-table entry, and
// otherwise returns an unnamed file with unknown flags without touching procfs.
func (t *fdTracker) resolveAfterEBADF(fd int32, pid uint32) file.File {
	t.deleteProcFdCache(fd, pid)
	if fdFile, ok := t.get(fd, pid); ok {
		return fdFile
	}
	return file.NewFd(fd, "", -1)
}
