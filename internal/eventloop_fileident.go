package internal

import (
	"fmt"
	"math"
	"time"

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
//   - fd table entry of that file: the row is named after it.
//   - fd table entry that was bound after the row's call entered (FdFile.
//     BoundAt: the exit time of the open, dup, pipe, ... that made it) and is
//     of another file or does not know its file: the row may belong to the
//     file the number named before - a read that blocked on it while another
//     thread closed the number and an open returned it again. The entry is
//     the newer knowledge and stays; only the row is left unnamed.
//   - older fd table entry, identity unknown: the entry takes the row's
//     identity (the first row that uses a descriptor whose creating call
//     reported none: a socket, a pipe end, an entry registered from procfs).
//   - older fd table entry of another file: the binding is stale. The entry
//     is dropped and the row is resolved as for an untracked descriptor.
//   - procfs-cache entry of another file: if it was read after the row's
//     call entered, the number has been reused since and procfs can no
//     longer name the row's file - the row stays unnamed, the entry stays
//     for the rows of the file it does describe. If it was read before, the
//     entry is the stale one and procfs is read again - but for rows of one
//     file, or once rows of a second file were refused too, at most once per
//     identRereadIntervalNs, because a thread on a private descriptor table
//     gets the same other file every time.
//   - fresh procfs answer of another file: cached for later rows (it is what
//     the number holds now) but not used for this one, which stays unnamed.
//     An answer that changed while it was read (the name differs on a second
//     readlink, or fdinfo had gone) is read once more and, if torn again,
//     neither cached nor used: it describes no one file.
//   - a close row (task jr2 keeps procfs away from those) uses a cache entry
//     only if it was read before the close began, as jr2 has it, and never
//     one that describes another file. An equal identity does not replace
//     the read time: see below for the files it cannot tell apart.
//   - a close forgets the number's entries (applyFdCloseState), except what
//     describes a later file: an fd table entry bound after the close
//     entered, a procfs answer of another file read after it.
//
// An unnamed row keeps the row's own identity, so it is not mistaken for an
// unusable descriptor. "Unknown" on either side contradicts nothing: such a
// row is resolved exactly as before the identity existed. That covers a
// kernel without the capture (no bpf_rdonly_cast kfunc: mainline before
// 6.2), an object built before it, a run that switched it off, the records
// without an identity word (fd_size_event, fcntl_event, dup3_event, ...:
// recvfrom, ioctl, mmap, ... rows) and a procfs answer whose fdinfo has no
// inode line.
//
// What the identity cannot tell apart, so those stale bindings still go
// unnoticed and such an answer still passes:
//
//   - the descriptors that share the kernel's one anonymous inode (eventfd,
//     epoll, io_uring, timerfd, ...; pipes and sockets have their own);
//   - a file created after another was unlinked and freed, on a filesystem
//     that reuses the inode number at once (ext4, xfs);
//   - files with equal inode numbers on different filesystems (tmpfs mounts
//     all count from the same start), and in different subvolumes or
//     snapshots of one btrfs filesystem (a snapshot keeps the numbers);
//   - two inode numbers that differ only above bit 31.
//
// An entry that takes its identity from the first row was not checked against
// that row: a number rebound invisibly between its creating call and its
// first use keeps the old name.

// trustFileIdents tells the loop whether the loaded BPF object writes the
// file identity words (trace setup, before the loop starts): only an object
// that has the IOR_FILE_IDENT global and had it switched on does, which setup
// does only on a kernel that has the kfunc the capture needs
// (fileIdentCaptureWanted). Otherwise those bytes are stale padding, or
// zeroes nobody could match, and must not be read, and no row is checked.
// It also notes whether ior's procfs read times are on the records' clock
// (fdTracker.readClockUnknown, identReadAt).
func (e *eventLoop) trustFileIdents(captured bool) {
	t := e.fdState()
	t.identOn = captured
	t.readClockUnknown = captured && ownBootClockDomain().warning != ""
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

// readProcFd resolves (pid, fd) from procfs and reports whether the answer may
// be cached. In a run that compares identities the answer records which file
// it describes (the number comes with the fdinfo read; one more readlink
// checks that the name still holds), and an answer that changed under the
// read is read once more: it mixes two files, so it has no identity, and
// cached as "unknown" it would contradict nothing and name every later row of
// the number. If the second reading is torn as well it is returned as not
// cacheable. A run without identities reads and caches as it always did.
func (t *fdTracker) readProcFd(fd int32, pid uint32) (*file.FdFile, bool) {
	if !t.identOn {
		return file.NewFdWithPid(fd, pid), true
	}
	read := t.readFdIdent
	if read == nil {
		read = file.NewFdWithPidIdent
	}
	answer, stable := read(fd, pid)
	if !stable {
		answer, stable = read(fd, pid)
	}
	return answer, stable
}

// noteExit remembers the exit time of the pair whose handler is about to run:
// the time set stamps a new fd table entry with (stampBinding). Every entry
// is created by the exit handler of the call that bound the number, and that
// call's exit record is the first moment a row of the new file can follow.
// Nothing is kept in a run without identities, where nobody reads the stamp.
func (t *fdTracker) noteExit(ep *event.Pair) {
	if t.identOn && ep.ExitEv != nil {
		t.bindNs = ep.ExitEv.GetTime()
	}
}

// stampBinding records on a new fd table entry when its number was bound
// (file.FdFile.BoundAt): at the exit of the pair being handled, or, for a
// procfs answer that is promoted into the table (an fcntl on an untracked
// descriptor), when procfs was read (readNs, known), which is when the
// number was seen to name the file. A promoted answer without a usable read
// time (identReadAt: none, the failed-clock sentinel, or a clock of unknown
// offset) takes the exit time like any other entry: a stamp in the records'
// future would make the entry outlive every close and refuse every row as
// older than it, while the exit time is at worst too early, and too early
// only costs a procfs read (a lagging row of the number's previous file then
// drops the entry, and procfs, which records the identity, names the rows).
//
// set does not call this for an object the key already held (a flag change),
// so a fork's copy, which does not come through set, stays unstamped, i.e.
// older than every row of the child. An object that has a time keeps it: one
// that was evicted from the table and comes back through a flag change on an
// in-flight row is the same binding. A duplicate arrives without one
// (FdFile.Dup) and so gets the dup's.
func (t *fdTracker) stampBinding(f file.File, readNs uint64, known bool) {
	fdFile, isFd := f.(*file.FdFile)
	if !t.identOn || !isFd || fdFile == nil || fdFile.BoundAt() != 0 {
		return
	}
	if known {
		fdFile.SetBoundAt(readNs)
		return
	}
	fdFile.SetBoundAt(t.bindNs)
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
	enterNs := ep.EnterEv.GetTime()
	if tracked, ok := t.trackedFile(fd, pid, ident, enterNs); ok {
		return tracked
	}
	if closesDescriptor(ep) {
		return t.resolveUntrackedClosing(fd, pid, enterNs, ident)
	}
	return t.resolveUntracked(fd, pid, ident, enterNs)
}

// trackedFile returns what the fd table says about a row on (pid, fd) that
// reports the file ident and whose call entered at enterNs, in the one lookup
// a row on a tracked descriptor costs anyway (get); false means the table has
// no entry (any more) and the row is to be resolved as untracked.
//
// An entry of that file names the row. One that disagrees - it is of another
// file, or does not know its file - is judged by age:
//
//   - bound after the row's call entered: the row may be of the file the
//     number named before (a read that blocked on file X while another thread
//     closed the number and an open returned it for file Y is processed after
//     that open). The entry is the newer knowledge and stays untouched; the
//     row is left unnamed, and nothing is counted. Naming such a row after an
//     entry of unknown identity would be a guess, and letting the entry take
//     the row's identity would make every row of the entry's real file look
//     like a stale binding.
//   - bound before, identity unknown: the entry takes the row's.
//   - bound before, another file: the binding is stale and is dropped.
func (t *fdTracker) trackedFile(fd int32, pid uint32, ident uint32, enterNs uint64) (file.File, bool) {
	tracked, ok := t.get(fd, pid)
	if !ok {
		return nil, false
	}
	fdFile, isFd := tracked.(*file.FdFile)
	if !isFd || fdFile == nil {
		return tracked, true
	}
	known := fdFile.Ident()
	switch {
	case known == ident:
		return tracked, true
	case fdFile.BoundAt() > enterNs:
		return unnamedFile(fd, ident), true
	case known == 0:
		fdFile.SetIdent(ident)
		return tracked, true
	}
	t.delete(fd, pid)
	t.staleBindings++
	return nil, false
}

// boundAfter reports whether the fd table entry f was bound after ns: it
// describes a file the number came to name later than that.
func boundAfter(f file.File, ns uint64) bool {
	fdFile, isFd := f.(*file.FdFile)
	return isFd && fdFile != nil && fdFile.BoundAt() > ns
}

// closeIdentified forgets what a close(2) of (pid, fd) released: the close
// entered at enterNs and its record says it closed the file ident (0 =
// unknown). That is everything ior holds for the number, except what is known
// to describe a file the number came to name after the close entered - the
// close cannot have released that:
//
//   - an fd table entry bound after enterNs (another thread's open, dup or
//     pipe returned the number and was processed before this close's exit);
//   - a procfs answer that was read after enterNs and describes a file other
//     than ident. An answer of the closed file, of an unknown file, or one
//     without a usable read time (identReadAt) goes as before: it may be the
//     closed descriptor's, and at worst it is read again.
//
// Each map is looked up once and left alone when it has no entry, so this
// costs no more than the two unconditional removals it replaces. In a run
// without identities nothing has a binding time or an identity, and both
// entries always go.
func (t *fdTracker) closeIdentified(fd int32, pid uint32, ident uint32, enterNs uint64) {
	key := t.key(pid, fd)
	if tracked, ok := t.files[key]; ok && !boundAfter(tracked, enterNs) {
		t.removeFileKey(key)
	}
	if cached, ok := t.procFdCache[key]; ok && !t.answerOfLaterFile(key, cached, ident, enterNs) {
		t.deleteCacheKey(key)
	}
}

// answerOfLaterFile reports whether the procfs answer cached under key is
// known to describe a file the number came to name after enterNs, when a
// call on the file ident entered: it is of another file - both identities
// known - and was read after that.
func (t *fdTracker) answerOfLaterFile(key uint64, cached *file.FdFile, ident uint32, enterNs uint64) bool {
	if ident == 0 || describes(cached, ident) {
		return false
	}
	readNs, stamped := t.identReadAt(key)
	return stamped && readNs > enterNs
}

// identReadAt returns the read time of the procfs answer cached under key
// for the comparisons of this file that keep state because of it - an
// answer kept through a close (answerOfLaterFile), not read again
// (worthReadingAgain), an entry's binding time (stampBinding) - or false
// where it has none they may use. All three treat a read time later than
// the row as "the number came to name this file later", so a time that is
// too late makes the state permanent, while "no read time" only costs a
// procfs read. Left out, therefore:
//
//   - the sentinel of a failed clock read (bootClockNs: math.MaxUint64),
//     which is later than every record;
//   - every read time while the offset of ior's time namespace is unknown
//     (fdTracker.readClockUnknown): 0 is assumed then, and in a namespace
//     whose clock runs ahead of the host's every reading is in the records'
//     future.
//
// Without a read time the re-reads are not rationed either: with a failing
// clock or an unknown offset a thread on a private table pays a procfs read
// for each of its rows. The close row's rule (cacheReadBefore, task jr2)
// reads the stamps directly: it only ever withholds a name for one row, and
// the sentinel falls on that side; what an unknown offset does to it is
// what the boot-clock warning says.
func (t *fdTracker) identReadAt(key uint64) (uint64, bool) {
	readNs, stamped := t.procFdReadAt[key]
	if !stamped || readNs == math.MaxUint64 || t.readClockUnknown {
		return 0, false
	}
	return readNs, true
}

// identRereadIntervalNs bounds how often procfs is read again for rows of one
// file on a number for which procfs keeps showing another file. That state is
// permanent for a thread working on a private descriptor table
// (unshare(CLONE_FILES)): /proc/<tgid>/fd shows the leader's table, so every
// row of that thread would otherwise drop the cached answer and pay two
// readlinks and an fdinfo read to get the same answer back. A tenth of a
// second of record time keeps that to ten reads a second per descriptor and
// delays a name by at most that long should procfs come to show the row's
// file after all (the number flapping between two files).
const identRereadIntervalNs = 100 * uint64(time.Millisecond)

// resolveUntracked is resolve for a row on a descriptor the fd table has no
// (valid) entry for, whose call entered at enterNs (boot clock) on the file
// ident: a procfs answer, cached or fresh, that does not describe another
// file.
func (t *fdTracker) resolveUntracked(fd int32, pid uint32, ident uint32, enterNs uint64) file.File {
	note := ident // what a refusal of the fresh answer is noted for
	if cached, ok := t.cachedProcFdFile(fd, pid); ok {
		if describes(cached, ident) {
			return cached
		}
		if !t.worthReadingAgain(fd, pid, ident, enterNs) {
			return t.rejectAnswer(fd, ident)
		}
		// Taken before the deletion forgets the old answer's note.
		note = t.nextRefusal(t.key(pid, fd), ident)
		t.deleteProcFdCache(fd, pid)
	}
	discovered, stable := t.readProcFd(fd, pid)
	if discovered.Name() == "" {
		// Not cached, as in resolve. The row keeps its own identity.
		discovered.SetIdent(ident)
		return discovered
	}
	if !stable {
		// The number was rebound under both readings: the answer describes
		// no one file. It is neither cached nor believed.
		return unnamedFile(fd, ident)
	}
	t.setProcFdCacheRead(fd, pid, discovered, bootClockNs())
	if !describes(discovered, ident) {
		t.noteRefusal(fd, pid, note)
		return t.rejectAnswer(fd, ident)
	}
	return discovered
}

// worthReadingAgain decides what to do about a cached procfs answer that
// describes another file than ident, the file of a row whose call entered at
// enterNs: true means the answer is the stale side and procfs is read again.
//
//   - Read after the call entered and already another file: the number was
//     reused since, and a new read can only be later still. Not read again;
//     the entry stays for the rows of the file it does describe.
//   - Read before, but read and refused, less than identRereadIntervalNs
//     earlier, for a row of this very file - or for rows of more than one
//     file (refusedSeveral): procfs disagrees with these rows persistently.
//     Not read again yet.
//   - Otherwise (also an entry without a usable read time, identReadAt):
//     read again.
func (t *fdTracker) worthReadingAgain(fd int32, pid uint32, ident uint32, enterNs uint64) bool {
	key := t.key(pid, fd)
	readNs, stamped := t.identReadAt(key)
	if !stamped {
		return true
	}
	if readNs > enterNs {
		return false
	}
	refused, noted := t.refusedFor[key]
	rationed := noted && (refused == ident || refused == refusedSeveral)
	return !rationed || enterNs-readNs >= identRereadIntervalNs
}

// refusedSeveral is the refusal note of a cache key whose answers were
// refused for rows of two or more files. One identity per key is not enough
// to ration those: two threads on private tables that use the number for two
// files (or the main table's file and a private one's) alternate, and each
// row would find the other's note and read procfs again. Identities in the
// note are never 0 (a row without one is not checked).
const refusedSeveral = 0

// nextRefusal returns what to note for key should the answer read again for
// a row of the file ident be refused too: ident when the answer being
// replaced was refused for that file or not at all, refusedSeveral once two
// files have been refused. It is read before the old answer goes, because
// that forgets its note.
func (t *fdTracker) nextRefusal(key uint64, ident uint32) uint32 {
	refused, noted := t.refusedFor[key]
	if !noted || refused == ident {
		return ident
	}
	return refusedSeveral
}

// noteRefusal remembers that the procfs answer just cached for (pid, fd) was
// read for a row of the file note (or rows of several files,
// refusedSeveral) and describes another one (worthReadingAgain). The note
// lives and dies with the cache entry (storeProcFdCache, deleteCacheKey), so
// it is only taken when the entry was stored: a blind table keeps none.
func (t *fdTracker) noteRefusal(fd int32, pid uint32, note uint32) {
	key := t.key(pid, fd)
	if _, cached := t.procFdCache[key]; !cached {
		return
	}
	if t.refusedFor == nil {
		t.refusedFor = make(map[uint64]uint32)
	}
	t.refusedFor[key] = note
}

// forgetRefusal drops the note of noteRefusal for a cache key whose entry is
// replaced or removed. The map is empty in almost every run, and then this
// costs a length check.
func (t *fdTracker) forgetRefusal(key uint64) {
	if len(t.refusedFor) != 0 {
		delete(t.refusedFor, key)
	}
}

// resolveUntrackedClosing is resolveClosing for a close row of the file ident
// on a descriptor without a (valid) fd table entry: a procfs-cache entry that
// was read before the close began (task jr2, cacheReadBefore) and does not
// describe another file, else nothing.
//
// The identity only ever excludes an answer here. It cannot stand in for the
// read time: an answer of the same identity read after the close began may
// well be of the file that took the number since, because the identity does
// not tell every two files apart (every eventfd, epoll and io_uring
// descriptor has the kernel's one anonymous inode; ext4 and xfs hand a freed
// inode number to the next file; see the file comment). Live shape: an
// untracked eventfd is closed, an epoll descriptor takes the number, a
// lagging row caches "anon_inode:[eventpoll]" - with the same identity.
func (t *fdTracker) resolveUntrackedClosing(fd int32, pid uint32, closeNs uint64, ident uint32) file.File {
	if cached, ok := t.cachedProcFdFile(fd, pid); ok {
		if !describes(cached, ident) {
			t.rejectedAnswers++
		} else if t.cacheReadBefore(fd, pid, closeNs) {
			return cached
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
