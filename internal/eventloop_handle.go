package internal

import (
	"path/filepath"
	"strings"

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
// matter which thread took the handle, how many handles a thread holds or in
// which order it opens them, whether the call fails, or what the returned
// descriptor number points at by the time the event loop gets there.
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
// is named from procfs, like any descriptor ior did not see being created.
// One rule of the old check survives there (task 423, reachableByHandle): a
// link that reads as a socket, a pipe or a generic anonymous inode is not
// believed, because no file handle opens one. It refuses an answer; it does
// not pick one.
//
// What the name is (takenHandleName). A name is filed for every later open of
// the handle, so it has to be one ior got from a traced call, not from a look
// at procfs:
//
//   - an absolute pathname is filed as the caller gave it;
//   - a pathname relative to a dirfd is joined with what the fd table calls
//     that descriptor, and an empty pathname with AT_EMPTY_PATH is that name
//     itself - a traced name ("memfd:x", "pidfd:0", the directory of an
//     O_TMPFILE open, a relative path as the task spelled it);
//   - a descriptor ior did not see being opened has only a /proc link, read
//     when the loop handles the exit. That is the lagging look this design
//     removed from the open: a task that closed the descriptor and reused the
//     number in the meantime would have the NEWER file filed under the
//     handle, and every later open of it, by any process, named after the
//     wrong file. No name is filed then; the absolute name the handle
//     already has stays, the taker's own scoped name ends
//     (handleTracker.store), and without a name the open falls back like
//     one of an unknown handle.
//   - a table entry is no better than that /proc link when its name was
//     made from one, and says so (FdFile.NameFromProcFS, the mark of a name
//     ior cannot vouch for). The entries that carry it are the ones whose
//     name is the look itself or was built from it:
//       - the look a call stored: an open_by_handle_at of an unknown handle
//         (procFdFile, the unnamed answer included) and an io_uring_setup
//         (an fcntl or an ioctl FIOCLEX/FIONCLEX on a procfs-resolved
//         descriptor promoted the answer until task a23; it now stays in
//         the procfs cache, storeFcntlFdFile);
//       - a duplicate (registerDup) or a forked child's copy (inherit) of
//         a marked entry - FdFile.Dup copies the mark - and a table moved
//         to another pid, which moves the entries themselves;
//       - since task 523, a descriptor opened by a pathname that was
//         resolved against a marked name: openat, openat2, open_tree,
//         open_tree_attr and fspick below a dirfd ior did not see being
//         opened or below a marked entry, or of that dirfd itself with an
//         empty pathname (resolveDirfdPath, fdFileNamedAs);
//       - an fsmount descriptor named after an fs-context descriptor of
//         either kind (fsmountFdFile).
//     One marked name is not a look at procfs at all: the bare pathname of
//     a descriptor opened below a directory ior has no name for, be that
//     procfs without an answer or a table entry with an empty name
//     (unvouchedBarePathname). No name is filed through a marked entry.
//     Every other call that stores a descriptor names it without a look at
//     procfs - from its own arguments (socket, socketpair, pipe, the
//     eventfd family, perf_event_open, bpf, an open by an absolute or
//     AT_FDCWD pathname), from an unmarked table entry, or, for accept,
//     from a listener's class name only when that is ior's own
//     ("socket:<family>:<type>:<protocol>", never a "socket:[N]" link) -
//     and is unmarked. bpf does read /proc/<pid>/fdinfo, for the flags.
//
// Whom the name is given to (handleName, handleEntry). An absolute pathname
// names every open of the handle. A name that is not one - relative to the
// taker's working directory, which ior does not track, or a descriptor name
// without a path - means nothing in another process, so it names only the
// opens of the process that took the handle; any other opener falls back.
// Such a scoped name is kept next to the absolute name of the handle, not in
// its place: the process that took it is named by its own take and everyone
// else still by the absolute one (handleTracker.store has the reasoning). It
// lives as long as its process: the group-dead exit record drops it, and so
// does the task record of a new process that is handed the pid (dropScoped).
// An execve does not - same pid, same working directory, same file behind
// the handle.
//
// What is still wrong, and accepted:
//
//   - The name is the one the handle was taken by. A file renamed or unlinked
//     since keeps its old pathname on the row, as an fd table entry keeps the
//     name its descriptor was opened by. A relative name likewise survives a
//     chdir of its process. It does not survive the process, unless both its
//     group-dead exit record and the task record of the pid's next owner are
//     lost; a forked child, which does share the working directory, is not
//     given its creator's scoped names and falls back.
//   - An absolute pathname is a path in the taker's root and mount namespace.
//     ior tracks neither (no path row does), so an opener in another mount
//     namespace or chroot - a container opening a handle the host took, or
//     the reverse - gets a row named with the taker's view of the path.
//   - The mount is not part of the key, so two filesystems that encode
//     different files as the same type and bytes share an entry and the later
//     name_to_handle_at wins. That is not far-fetched for every encoding (see
//     handleKeyOf for why the mount cannot be had and which handles collide).
//   - A handle ior did not see being taken is named from procfs, with the lag
//     every procfs-resolved descriptor has: a number the task closed and
//     reused before the loop reads it shows the newer file. A newer file of
//     a kind no handle can open is recognised (reachableByHandle), and, in a
//     run that captures file identities, any newer file whose inode number
//     differs in its low 32 bits from the one the exit record reports (task
//     a23); the row and the fd table entry are then unnamed, as when procfs
//     has no answer. Without the capture a reuse by a file, a directory, a
//     pidfd or a namespace still names the row after the newer one, and with
//     it one the identity cannot tell apart does. The unnamed entry stays
//     until its close is processed (procFdFile). A failed call with such a
//     handle has an empty name. That is a handle taken before the
//     trace started; by a task outside a -pid/-tid scope; by a call the enter
//     filter shed (-path, -comm); by a call BPF did not report - sampled out
//     (the N-1 of 1-in-N), aggregate-only (rate 0), or with the enter or exit
//     probe of name_to_handle_at not attached (detached at runtime, a failed
//     attach); one whose control record was lost to ring-buffer backpressure;
//     one that could not be read (handleKeyOf); and one taken through a
//     descriptor only procfs could name (above).
//   - The fd table is trusted for every entry that is not marked. The mark
//     says where a name came from, not whether it is right, and an unmarked
//     entry outlives what made it true: the fd table itself can be behind
//     (a close ior did not see, a number reused through an untraced call),
//     and a take through such an entry files the old name. The mark also
//     changes no row: a row on a marked descriptor shows the lagging name,
//     or the bare pathname, as before; only the handle names refuse it.
//   - The absolute name of a handle survives a scoped take of it (task 523).
//     If the file was renamed in between, the processes that are not the
//     scoped taker keep the old pathname where they used to fall back to
//     procfs. That is the stale name of the first residual, no staler than
//     without the second take. Only one scoped name is kept per handle: a
//     second process taking it by a scoped name displaces the first one's,
//     and the first is named by the absolute name, or falls back.
//   - The absolute name survives a take ior has no name for as well
//     (handleTracker.store has the reasoning; until the task 523 review
//     such a take dropped the entry). The cost is the same stale name: if
//     the file was renamed before that take, or the take was of another
//     filesystem's file with an equal handle, every opener keeps the older
//     pathname - as it would had nobody taken the handle again. Dropping
//     the entry was no way out of a wrong name either: the fallback is the
//     lagging look at procfs. The taker's own scoped name does end with
//     such a take.
//   - An entry evicted by the LRU cap is such an unknown handle again.
//   - An IOR_BPF_OBJECT built before task k03 emits no handle record and a
//     handle-less open record, so every open_by_handle_at is named from
//     procfs. That is NOT the pre-k03 behaviour, which named the row from the
//     thread's last name_to_handle_at: the per-tid stash was deleted with the
//     arbitration it needed, not kept as a fallback. Such an object loses the
//     names of failed calls and of descriptors already closed when the loop
//     looks; it is the one place where an older object does not degrade to
//     what it did before.

// handleKeyOf builds the key of the handle in a record's handle fields. ok is
// false when the record identifies no handle: a status other than
// FILE_HANDLE_OK (an object that predates the capture - see the last residual
// above -, a NULL or unreadable pointer, an oversized handle_bytes), a zero
// handle_bytes, which no file has and the kernel rejects, and a byte count
// beyond the field, which the BPF side never submits as OK and is refused
// here so that a foreign producer cannot make the slice below run past the
// array.
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
// opened through another would stop matching.
//
// The residual is a collision of type and bytes across filesystems, and for
// some encodings it is ordinary rather than remote. A handle only has to be
// unique within its filesystem, and what the common ones put in it (handles
// taken on Linux 7.2, x86_64):
//
//   - ext4, type 1: inode number and i_generation, 8 bytes. The generation of
//     an ordinary file is random, but the root directory is inode 2 with
//     generation 0 on every ext4 filesystem - the same handle.
//   - tmpfs, type 1: a random generation and the inode number, 12 bytes.
//   - btrfs, type 77: object ID, root (subvolume) ID and the generation, 20
//     bytes. The generation is the transaction that created the inode, a
//     small counter, not a random number: two btrfs filesystems of similar
//     history hand out equal triples (their top directories first of all).
//   - cgroup (kernfs), type 254: the 64-bit node ID, 8 bytes. The root is
//     node 1 on cgroup2 and on every cgroup v1 hierarchy.
//   - FUSE: node ID and generation as the server assigns them; servers that
//     count node IDs from 1 with generation 0 would collide between mounts
//     (not verified).
//
// What a collision costs is a row named after the file that took such a
// handle last. A program that takes handles on two filesystems that collide
// gets that; one that works on a single filesystem, the usual case, does not.
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
// still pending here - if it arrived. The record is accepted only for the
// pending enter of ITS call (ownsPendingEnter): the pathname that will be
// filed under the handle is that enter's. Records of other tids interleave
// between this one and the exit, which is why the handle is parked per tid
// rather than kept in one slot.
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
	if !ok || !ownsPendingEnter(ev, pair.EnterEv) {
		return
	}
	e.handleState().park(ev.Tid, key, ev.Time)
}

// ownsPendingEnter reports whether enterEv, the enter pending for the tid of
// the handle record ev, is the enter of the call that returned the handle.
//
// Being a name_to_handle_at enter is not enough. The pending enter can be an
// earlier call's: its exit record was lost, so it stayed pending, and the
// enter of the call this record belongs to never got here - lost too, or
// shed by the raw path filter (-path). The record and the exit behind it
// would then file the EARLIER call's pathname under this call's handle, and
// the entry would misname every open of that handle until it is replaced. So
// the record carries the time of its own enter (BPF takes it from the enter
// state, where the enter handler put the clock read it also stamped the enter
// record with), and only an enter with exactly that time is its own. Two
// enters of one tid are a whole syscall apart; a clock too coarse to tell
// them apart leaves this check blind, which is accepted (see claim).
//
// Without a pending enter at all the pair was shed at enter or its enter was
// lost, and no exit handler will ever name the handle.
func ownsPendingEnter(ev *types.FileHandleEvent, enterEv event.Event) bool {
	pathEv, ok := enterEv.(*types.PathEvent)
	if !ok || pathEv.GetTraceId() != ev.GetTraceId() || !isNameToHandleAt(pathEv) {
		return false
	}
	return pathEv.GetTime() == ev.EnterTime
}

// isNameToHandleAt reports whether pathEv is the enter of a name_to_handle_at.
func isNameToHandleAt(pathEv *types.PathEvent) bool {
	return pathEv.GetTraceId().Name() == sysEnterNameToHandleAtName
}

// recordNameToHandleAt files the name of a successful name_to_handle_at under
// the handle the call returned, so that an open_by_handle_at of that handle
// can name the file it opens. The pair itself is always recycled (never
// emitted); it always returns false so the caller drops it.
//
// The parked handle is given up before anything else and on every path, a
// failed call and a malformed exit record included: this exit ends the only
// call it can belong to. No handle means no name is filed - the call failed
// (also the EOVERFLOW a caller provokes to learn the handle size, which
// returns no handle), the control record was lost or never emitted (an older
// BPF object, an unreadable buffer), or it belonged to another call (claim).
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
	handles.store(key, newHandleName(e.takenHandleName(pathEv), pathEv.Pid))
	return false
}

// takenHandleName returns the name to file the handle of a successful
// name_to_handle_at under, or "" when ior has none it can vouch for (store
// then files nothing; of what the handle was known as, only the taker's own
// scoped name goes). See "What the name is" at the top of this file.
//
// It resolves the pathname as resolvePathEvent does for the row of any other
// path syscall, with one difference: the dirfd is looked up in the fd table
// only (fdTracker.get), never read from procfs (fdTracker.resolve), and a
// table entry whose name ior cannot vouch for - one that was itself named
// from procfs, or built from such a name, or a bare pathname below an
// unnamed directory - is refused. A row may show what procfs says now; a
// name that will label other calls may not.
func (e *eventLoop) takenHandleName(pathEv *types.PathEvent) string {
	if !pathEventTargetRequired(pathEv) || pathEv.PathnameStatus != types.PATH_READ_OK {
		return ""
	}
	pathname := trimCutPathname(types.StringValue(pathEv.Pathname[:]))
	if pathname == "" && !pathEventAllowsEmptyPath(pathEv, true) {
		return ""
	}
	if !dirfdPathNeedsResolution(pathEv.Dirfd, pathname) {
		return pathname
	}
	dir, tracked := e.fdState().get(pathEv.Dirfd, pathEv.Pid)
	if !tracked || namedFromProcfs(dir) || dir.Name() == "" {
		return ""
	}
	if pathname == "" {
		return dir.Name()
	}
	return filepath.Join(dir.Name(), pathname)
}

// namedFromProcfs reports whether f is a descriptor whose name ior cannot
// vouch for (FdFile.NameFromProcFS): a /proc/<pid>/fd link ior read, or a
// name built from one, rather than the name a traced call gave it - or the
// bare pathname of a descriptor opened below a directory without a name.
// Such entries do get into the fd table; "What the name is" at the top of
// this file lists every way.
//
// It has two callers, and they are all that reacts to the mark:
// takenHandleName, which refuses the name, and fdFileNamedAfter, which
// passes the mark on to a name built from f. Rows are named as before.
func namedFromProcfs(f file.File) bool {
	fdFile, ok := f.(*file.FdFile)
	return ok && fdFile.NameFromProcFS()
}

// openedHandleName returns the name the handle of an open_by_handle_at was
// taken of. named is false when the enter record identifies no handle
// (handleKeyOf), ior has no name for it, or the only name it has is one
// that holds in another process (handleEntry.nameFor).
func (e *eventLoop) openedHandleName(openByHandleEv *types.OpenByHandleAtEvent) (name string, named bool) {
	key, ok := handleKeyOf(openByHandleEv.HandleStatus, openByHandleEv.HandleBytes,
		openByHandleEv.HandleType, &openByHandleEv.FHandle)
	if !ok {
		return "", false
	}
	return e.handleState().lookup(key, openByHandleEv.Pid)
}

// openedHandleFile returns the file the descriptor fd a successful
// open_by_handle_at (enter record ev, exit record exit) returned is labelled
// with, on the row and in the fd table.
//
// A named handle gives the descriptor that name, and procfs is not asked: the
// handle says which file was opened, while /proc/<pid>/fd/<fd> says what the
// number is by now. The flags are the ones the event captured at enter (what
// the caller asked for).
//
// An unnamed one falls back to procfs, name and flags alike, unless what
// procfs shows is something no handle can open, or another file than the one
// the exit record says the call opened (procFdFile).
func (t *fdTracker) openedHandleFile(name string, named bool, ev *types.OpenByHandleAtEvent,
	fd int32, exit *types.RetEvent) *file.FdFile {
	if named {
		return file.NewFd(fd, name, ev.Flags)
	}
	opened := uint32(0)
	if t.identOn {
		opened = exit.FileIdent
	}
	return t.procFdFile(ev.Pid, fd, ev.Flags, opened)
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
// unreadable descriptor yields an unnamed file, and so does one whose link
// reads as something no file handle can open (reachableByHandle): the number
// was closed and reused before the loop looked. Unknown flags are replaced by
// the event's (what the caller asked for); the fdinfo of a reused number is
// the newer file's and is not used either.
//
// In a run that captures file identities the exit record says which file the
// call opened (opened, 0 = unknown), and the answer is read with the inode
// number of its fdinfo (readProcFd, task a23). An answer of another file is
// a file that reused the number and is refused like the deny list's kinds,
// and counted (rejectedAnswers); so is one that changed under both readings,
// which describes no one file. This catches what the deny list cannot: a
// reuse by a regular file, a directory, a pidfd or a namespace. It cannot
// tell apart what the identity cannot (eventloop_fileident.go): the low 32
// bits of the inode number on whatever filesystem. Without the capture, or
// with an fdinfo that has no inode line, the deny list is all there is.
//
// The unnamed file is what the row reports and what the fd table keeps, as
// for the unreadable descriptor. Keeping nothing instead would send the next
// row on the number back to procfs, which would then give that row the very
// name refused here; and until the close of the call's own descriptor comes
// up in the ring the rows on the number are that descriptor's, whose name
// ior does not have. The entry is marked as a look at procfs like any other
// answer of this function (FdFile.NameFromProcFS).
//
// The price is that the unnamed entry lasts as long as any table entry: the
// rows on the number stay unnamed, with this call's flags, until a close of
// the number is processed (the next row then asks procfs afresh) or the LRU
// cap evicts the entry - also when the close was never seen and the number
// is somebody else's by now. The entry kept for "procfs had no answer" has
// the same exposure.
func (t *fdTracker) procFdFile(pid uint32, fd int32, eventFlags int32, opened uint32) *file.FdFile {
	fdFile, stable := t.readProcFd(fd, pid)
	if !reachableByHandle(fdFile.Name()) {
		fdFile = file.NewUnresolvedFd(fd)
	} else if opened != 0 && (!stable || !describes(fdFile, opened)) {
		t.rejectedAnswers++
		fdFile = file.NewUnresolvedFd(fd)
	}
	if fdFile.Flags() == file.Flags(-1) {
		fdFile.SetFlags(eventFlags)
	}
	return fdFile
}

// pidfdLinkText is the /proc/<pid>/fd link of a pidfd, as Linux 7.2.5 spells
// it. pidfs has export operations, so it is the one "anon_inode:" link a
// file handle can open. A kernel that spelled the link "pidfd:[N]" instead
// would not need the exemption: that text passes the deny list below.
const pidfdLinkText = "anon_inode:[pidfd]"

// handleLessLinkPrefixes are the /proc/<pid>/fd link texts of descriptors
// that no open_by_handle_at can have returned: sockets ("socket:[N]",
// sockfs), pipes ("pipe:[N]", pipefs) and the kernel's generic anonymous
// inodes ("anon_inode:[eventfd]", "anon_inode:[eventpoll]",
// "anon_inode:inotify", ...). pidfdLinkText shares the last prefix and is
// exempted by reachableByHandle.
var handleLessLinkPrefixes = []string{"socket:[", "pipe:[", "anon_inode:"}

// reachableByHandle reports whether a descriptor whose /proc link reads
// target can be the result of an open_by_handle_at at all.
//
// A file handle can only be decoded on a filesystem with export operations,
// and sockfs, pipefs and the generic anonymous-inode filesystem have none. A
// link of one of those kinds under the returned number is therefore proof
// that the number was closed and reused, and the row must not be named after
// it. This is the one rule of the procfs arbitration tasks j03 to m03 had
// that is kept (task 423): it does not guess which file the call opened, it
// only refuses an answer that cannot be it.
//
// It is a deny list. Every other link text - a path, a pidfd, a namespace
// ("net:[N]", "mnt:[N]", "ipc:[N]", "uts:[N]", "pid:[N]", "user:[N]",
// "cgroup:[N]", "time:[N]"; nsfs has export operations) and anything a
// future kernel adds outside the three prefixes - is believed, so a new
// exportable object is at worst named too readily, never denied its name.
// One whose link starts with "anon_inode:" would be denied and need its own
// exemption, as the pidfd did. The exemption is the exact text, not a
// prefix: pidfs names its dentry itself, so nothing is ever appended to it.
// An unreadable link (the empty text) passes; the caller already has an
// unnamed file for it.
//
// That the three filesystems have no export operations is kernel knowledge
// ior cannot ask for at run time. Checked on Linux 7.2.5 (x86_64) with
// name_to_handle_at(fd, "", AT_EMPTY_PATH): EOPNOTSUPP for a socket, both
// ends of a pipe, eventfd, epoll, timerfd, signalfd and inotify; success for
// a pidfd and for every /proc/self/ns/* descriptor. The tests in
// eventloop_handle_reach_test.go ask the kernel they run on again and fail
// if one of the denied kinds turns out to be exportable.
func reachableByHandle(target string) bool {
	if target == pidfdLinkText {
		return true
	}
	for _, prefix := range handleLessLinkPrefixes {
		if strings.HasPrefix(target, prefix) {
			return false
		}
	}
	return true
}
