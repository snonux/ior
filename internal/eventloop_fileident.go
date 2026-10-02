package internal

import (
	"fmt"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

// Naming a descriptor by the file it was, not by its number (task 603).
//
// A row is labelled by looking its descriptor number up: in the fd table,
// which ior builds from the traced opens, dups, pipes, ..., or else in
// /proc/<pid>/fd. Both answer for the *number*, and both can describe another
// file than the one the call used:
//
//   - The fd table goes stale when the number is rebound by something the
//     trace does not see: io_uring's IORING_OP_CLOSE and IORING_OP_OPENAT
//     (live, task or2: after such a close and reopen of fd 4 every pread64
//     was reported on the old file), a close or open outside the trace set, a
//     lost record, a thread working on a private table after
//     unshare(CLONE_FILES).
//   - procfs is read when the event loop reaches the row, which lags the
//     kernel, so after a close and reuse of the number it names the reuser
//     (task yz2: a write to a pre-attach descriptor followed at once by
//     close() and pipe() was reported as a write to the new pipe, and the
//     answer was cached for the number).
//
// The single-descriptor enter records (fd_event: read, write, close, fsync,
// ...) therefore say which file the number named when the call entered, and
// the exits of the open kinds which file they returned (the low 32 bits of
// the inode number, 0 = unknown; internal/c/fileident.c). A tracked or cached
// file remembers the same about itself (file.FdFile.Ident), and a row is
// given a name only when the two do not contradict each other:
//
//   - fd table entry, identity unknown: the entry takes the row's identity
//     (the first row that uses a descriptor whose creating call reported
//     none: a socket, a pipe end, an entry registered from procfs).
//   - fd table entry of another file: the binding is stale. The entry is
//     dropped and the row is resolved as for an untracked descriptor.
//   - procfs-cache entry of another file: if it was read after the row's
//     call entered, the number has been reused since and procfs can no
//     longer name the row's file - the row stays unnamed, the entry stays
//     for the rows of the file it does describe. If it was read before, the
//     entry is the stale one and procfs is read again.
//   - fresh procfs answer of another file: cached for later rows (it is what
//     the number holds now) but not used for this one, which stays unnamed.
//   - a close row (task jr2 keeps procfs away from those) may use a cache
//     entry of the same file whenever it was read, and never one of another
//     file, even when it was read before the close.
//
// An unnamed row keeps the row's own identity, so it is not mistaken for an
// unusable descriptor. "Unknown" on either side contradicts nothing: such a
// row is resolved exactly as before the identity existed. That covers a
// kernel without the capture (before 6.2), an object built before it, a run
// that switched it off, the records without an identity word (fd_size_event,
// fcntl_event, dup3_event, ...: recvfrom, ioctl, mmap, ... rows) and a file
// procfs could not stat.
//
// What the identity cannot tell apart, so those stale bindings still go
// unnoticed: files with equal inode numbers on different filesystems, and
// the descriptors that share the kernel's one anonymous inode (eventfd,
// epoll, io_uring, timerfd, ...). An entry that takes its identity from the
// first row was not checked against that row: a number rebound invisibly
// between its creating call and its first use keeps the old name.

// trustFileIdents tells the loop whether the loaded BPF object writes the
// file identity words (trace setup, before the loop starts): only an object
// that has the IOR_FILE_IDENT global and had it switched on does. Otherwise
// those bytes are stale padding and must not be read, and no row is checked.
func (e *eventLoop) trustFileIdents(captured bool) {
	e.fdState().identOn = captured
}

// rowIdent returns the identity fdEv's record carries for its descriptor, or
// 0 when the run does not capture identities. A wide or compact fd record
// has no identity word and decodes with 0.
func (t *fdTracker) rowIdent(fdEv *types.FdEvent) uint32 {
	if !t.identOn {
		return 0
	}
	return fdEv.FileIdent
}

// identifyOpened records which file the descriptor f was registered for is,
// from the identity the exit record of its open carries.
func (t *fdTracker) identifyOpened(f *file.FdFile, exit *types.RetEvent) {
	if t.identOn {
		f.SetIdent(exit.FileIdent)
	}
}

// readProcFd resolves (pid, fd) from procfs, recording which file the answer
// describes when the run compares identities (two extra stat calls next to
// the readlink and the fdinfo read).
func (t *fdTracker) readProcFd(fd int32, pid uint32) *file.FdFile {
	if t.identOn {
		return file.NewFdWithPidIdent(fd, pid)
	}
	return file.NewFdWithPid(fd, pid)
}

// resolveIdentifiedOnExit is resolveOnExit for a row that says which file its
// descriptor named (ident, 0 = unknown): see the file comment for the rules.
//
// A known identity also means the descriptor was open when the call entered,
// so an EBADF there is the call's own (a read on a write-only descriptor),
// not "no such descriptor", and the row is named like any other.
func (e *eventLoop) resolveIdentifiedOnExit(ep *event.Pair, fd int32, pid uint32, ident uint32) file.File {
	if ident == 0 {
		return e.resolveOnExit(ep, fd, pid)
	}
	t := e.fdState()
	t.reconcileBinding(fd, pid, ident)
	enterNs := ep.EnterEv.GetTime()
	if closesDescriptor(ep) {
		return t.resolveClosingIdent(fd, pid, enterNs, ident)
	}
	return t.resolveIdent(fd, pid, ident, enterNs)
}

// reconcileBinding compares the fd table entry of (pid, fd) with the identity
// a row reports for the number: an entry without one takes it, an entry of
// another file is dropped as stale.
func (t *fdTracker) reconcileBinding(fd int32, pid uint32, ident uint32) {
	key := t.key(pid, fd)
	fdFile, ok := t.files[key].(*file.FdFile)
	if !ok || fdFile == nil {
		return
	}
	switch known := fdFile.Ident(); {
	case known == 0:
		fdFile.SetIdent(ident)
	case known != ident:
		t.removeFileKey(key)
		t.staleBindings++
	}
}

// resolveIdent is resolve for a row whose call entered at enterNs (boot
// clock) on the file ident. Call reconcileBinding first: an fd table entry is
// returned as it is.
func (t *fdTracker) resolveIdent(fd int32, pid uint32, ident uint32, enterNs uint64) file.File {
	if tracked, ok := t.get(fd, pid); ok {
		return tracked
	}
	if cached, ok := t.cachedProcFdFile(fd, pid); ok {
		if describes(cached, ident) {
			return cached
		}
		if readNs, stamped := t.cachedProcFdReadAt(fd, pid); stamped && readNs > enterNs {
			// Read after the call entered and already another file: the
			// number was reused since, and a new read can only be later.
			return t.rejectAnswer(fd, ident)
		}
		t.deleteProcFdCache(fd, pid)
	}
	discovered := t.readProcFd(fd, pid)
	if discovered.Name() == "" {
		// Not cached, as in resolve. The row keeps its own identity.
		discovered.SetIdent(ident)
		return discovered
	}
	t.setProcFdCacheRead(fd, pid, discovered, bootClockNs())
	if !describes(discovered, ident) {
		return t.rejectAnswer(fd, ident)
	}
	return discovered
}

// resolveClosingIdent is resolveClosing for a close row of the file ident:
// the fd table entry (reconciled by the caller), else a procfs-cache entry of
// that same file, else nothing. A cache entry whose file is unknown falls
// back to the read-time rule of task jr2 (cacheReadBefore).
func (t *fdTracker) resolveClosingIdent(fd int32, pid uint32, closeNs uint64, ident uint32) file.File {
	if tracked, ok := t.get(fd, pid); ok {
		return tracked
	}
	if cached, ok := t.cachedProcFdFile(fd, pid); ok {
		switch cached.Ident() {
		case ident:
			return cached
		case 0:
			if t.cacheReadBefore(fd, pid, closeNs) {
				return cached
			}
		default:
			t.rejectedAnswers++
		}
	}
	return unnamedFile(fd, ident)
}

// describes reports whether a procfs answer may name a row of the file ident:
// it describes that file, or it could not be told which file it describes.
func describes(answer *file.FdFile, ident uint32) bool {
	known := answer.Ident()
	return known == 0 || known == ident
}

// rejectAnswer counts a procfs answer that describes another file than the
// row's and returns the unnamed file the row gets instead.
func (t *fdTracker) rejectAnswer(fd int32, ident uint32) file.File {
	t.rejectedAnswers++
	return unnamedFile(fd, ident)
}

// unnamedFile is the file of a row whose descriptor named the file ident but
// for which ior has no name: no name, unknown flags, and the identity.
func unnamedFile(fd int32, ident uint32) *file.FdFile {
	f := file.NewFd(fd, "", -1)
	f.SetIdent(ident)
	return f
}

// fileIdentStatLine reports what the identity check changed in this run:
// the fd table entries dropped because the number had come to name another
// file, and the procfs answers not used because they described another file
// than the row's. Empty when neither happened, like the other conditional
// lines. stats() reads the counters only after the event-loop goroutine that
// writes them has finished.
func (e *eventLoop) fileIdentStatLine() string {
	t := e.fdState()
	if t.staleBindings == 0 && t.rejectedAnswers == 0 {
		return ""
	}
	return fmt.Sprintf(
		"\tfile identity: %d stale fd bindings dropped, %d procfs answers for another file not used\n",
		t.staleBindings, t.rejectedAnswers,
	)
}
