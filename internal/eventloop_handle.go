package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"ior/internal/file"
)

// handleVerdict is the outcome of checking a stashed name_to_handle_at
// pathname against the descriptor an open_by_handle_at actually returned.
type handleVerdict int

const (
	// handleUnverified: nothing can contradict the stashed name. Either the
	// stash is empty, or procfs could not describe the descriptor at all (the
	// task exited or the number was already closed) and the stashed path
	// could not be compared by inode either.
	handleUnverified handleVerdict = iota
	// handleMatches: the descriptor and the pathname are the same file - the
	// same inode, or, when the pathname no longer exists, the same name as
	// the descriptor's /proc link.
	handleMatches
	// handleMismatch: the descriptor procfs shows NOW is demonstrably not the
	// file the stashed pathname names. That alone does not say which handle was
	// opened: either the stash belongs to a different handle, or the number was
	// closed and reused since the call returned and procfs describes a later
	// file. confirmedHandleFd decides which of the two to assume.
	handleMismatch
)

// deletedSuffix is what procfs appends to the link text of an unlinked file.
const deletedSuffix = " (deleted)"

// handleFdProbe is one look at /proc/<pid>/fd/<fd>: its inode (stat follows
// the magic link) and its link text (readlink), taken back to back so the two
// describe the same descriptor as closely as userspace can manage.
//
// The probe is a look at the task's fd table NOW, not at the moment the
// open_by_handle_at returned: the loop handles the exit record some time after
// the syscall (a ring-buffer poll at best, much longer under load), and a task
// that closed the descriptor meanwhile has usually handed the number to its
// next open. The probe then describes that newer file, and ior cannot hold the
// descriptor still (there is no pidfd_getfd in this path). The same holds, on
// a far smaller scale, between the two syscalls of the probe itself. So a
// probe that contradicts the stash is believed only when confirmedHandleFd
// finds the descriptor still there, of a kind a handle can open, with the
// flags the call asked for; a reuse that check cannot see (a path, pidfd or
// namespace descriptor with the same flags) names the row after the newer
// file - the exposure every procfs-resolved fd row has anyway.
type handleFdProbe struct {
	info    os.FileInfo
	statErr error
	target  string
	linkErr error
}

func probeHandleFd(pid uint32, fd int32) handleFdProbe {
	procPath := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	var p handleFdProbe
	p.info, p.statErr = os.Stat(procPath)
	p.target, p.linkErr = os.Readlink(procPath)
	return p
}

// classifyHandlePath compares the descriptor in probe with the file the
// stashed pathname names. The BPF events carry neither the handle bytes
// (name_to_handle_at's f_handle output argument) nor a pointer to them, so the
// stash cannot be keyed by handle; file identity is the only lever userspace
// has to tell which handle an open_by_handle_at opened.
//
// Two comparisons, strongest first:
//
//  1. Inode. Both stat calls follow symlinks on purpose, and the pathname is
//     also tried without following: name_to_handle_at takes the handle of the
//     final symlink itself unless AT_SYMLINK_FOLLOW is set, and the stash does
//     not keep that flag, so either identity counts. os.SameFile compares
//     dev+ino, which survives hard links and symlinked spellings.
//  2. Link text, when the pathname cannot be stat'ed (the file was deleted or
//     renamed after its handle was taken - the classic use of handles - or the
//     path does not exist in ior's mount namespace): the descriptor's
//     /proc/<pid>/fd link, minus a trailing " (deleted)", is compared with the
//     stash. The same deleted file matches; a different file is a mismatch
//     even though the stashed path is gone. That is what lets a deleted or
//     renamed stash still tell that the OTHER handle was opened. A live file
//     whose own name ends in " (deleted)" is indistinguishable from an
//     unlinked one here, but such a file is stat-able and takes path 1.
//
// Stashes that are not absolute are compared by link text only, and there are
// two kinds of them:
//
//   - A relative PATH (AT_FDCWD with a relative name is stored as given).
//     os.Stat would resolve it against ior's working directory, which says
//     nothing about the task's, and the link of a file on a mounted filesystem
//     is an absolute path, so a relative path stash is a mismatch whenever the
//     link is readable. The row is then named from procfs if confirmedHandleFd
//     confirms the descriptor, and after the relative stash, as the task
//     spelled it, if not.
//   - A non-path name resolved from a descriptor: name_to_handle_at(pidfd, "",
//     AT_EMPTY_PATH), the normal way to take a pidfs handle, stashes the
//     pidfd's own link text "anon_inode:[pidfd]", and a namespace descriptor
//     stashes "net:[N]" and the like. Such a stash CAN match: it equals the
//     link text of the descriptor its handle opens (every pidfd reads
//     "anon_inode:[pidfd]", so it matches any pidfd, not only its own
//     process's), and the stashed name is then used and consumed like any
//     other match.
//
// Mount namespaces: the stash is the string the task passed, procfs is read
// from ior's own namespace. When ior's namespace has a DIFFERENT file at the
// stashed path (a container's /etc/passwd), the inodes differ and the verdict
// is mismatch; when the path is absent, the link text differs from it, also a
// mismatch. Either way procfs wins as long as confirmedHandleFd confirms the
// descriptor (the normal case: it is still open with the call's flags),
// exactly as it does for every other fd row ior resolves, at the price that
// the stash is left unconsumed (it is overwritten by the thread's next
// name_to_handle_at or evicted with the task). An unconfirmed descriptor, and
// one procfs cannot describe at all, leave the row to the stash, which is
// then consumed.
//
// Stalls: os.Stat/Lstat of the stashed path run on the event-loop goroutine,
// and a stale NFS or FUSE path could block them. open_by_handle_at is the NFS
// server's syscall (and used by backup/indexing daemons), which makes a hung
// export plausible, but the stat only runs when an open_by_handle_at pair is
// handled, which is rare; the stall is accepted rather than moving the check
// off-loop and racing the event order.
func classifyHandlePath(probe handleFdProbe, pathname string) handleVerdict {
	if pathname == "" {
		return handleUnverified
	}
	if filepath.IsAbs(pathname) && probe.statErr == nil {
		if verdict, decided := compareHandleInodes(probe.info, pathname); decided {
			return verdict
		}
	}
	return compareHandleLinkText(probe, pathname)
}

// compareHandleInodes reports whether the descriptor is the file at pathname.
// decided is false when pathname cannot be stat'ed at all, leaving the
// decision to the link-text comparison.
func compareHandleInodes(fdInfo os.FileInfo, pathname string) (verdict handleVerdict, decided bool) {
	followed, followErr := os.Stat(pathname)
	if followErr == nil && os.SameFile(fdInfo, followed) {
		return handleMatches, true
	}
	direct, directErr := os.Lstat(pathname)
	if directErr == nil && os.SameFile(fdInfo, direct) {
		return handleMatches, true
	}
	if followErr != nil && directErr != nil {
		return handleUnverified, false
	}
	return handleMismatch, true
}

func compareHandleLinkText(probe handleFdProbe, pathname string) handleVerdict {
	if probe.linkErr != nil {
		return handleUnverified
	}
	if strings.TrimSuffix(probe.target, deletedSuffix) == pathname {
		return handleMatches
	}
	return handleMismatch
}

// openedHandleFile returns the file an open_by_handle_at that returned fd
// should be labelled with.
//
// The stash is one slot per TID - the thread's last name_to_handle_at - but a
// thread may take several handles and open them in any order, so the slot is
// only a hypothesis about which handle was opened. procfs is asked what the
// descriptor is, and that answer is only a hypothesis too: it shows the number
// as it is when the loop handles the exit, possibly after the task closed the
// descriptor and opened another file under it (see handleFdProbe).
//
//   - no stash (or an empty one): the row is named from procfs.
//   - match or unverifiable: the stashed name is used and consumed (the
//     unverifiable case is the legacy behaviour, for a descriptor procfs
//     cannot answer for).
//   - mismatch, and the descriptor procfs showed can be the one this call
//     returned (confirmedHandleFd): the stash belongs to a different handle,
//     so it is neither used nor consumed (its own open may still come) and
//     the row is named from procfs.
//   - mismatch, but that descriptor is gone again, is of a kind no handle can
//     open (a socket, a pipe, an eventfd: see reachableByHandle) or was opened
//     with other flags than this call's: procfs described, or most likely
//     described, a later file under a reused number, which says nothing about
//     this call. That is treated as the unverifiable case, so the stashed name
//     is used and consumed. Without this a short-lived descriptor (open the
//     handle, use it, close it, open the next file) was named after whatever
//     the task opened next, and the fd table entry passed that name on to the
//     rows that followed. It is a guess, and confirmedHandleFd names the case
//     in which it is wrong.
//
// Flags differ by branch on purpose. A stash-named row has no procfs view it
// trusts, so it carries the flags the event captured at enter (what the
// caller asked for). A procfs-named row takes the kernel's own view from
// /proc/<pid>/fdinfo - the flags the descriptor really has; only the row of a
// call without a stash falls back to the event's when fdinfo is unreadable.
func (e *eventLoop) openedHandleFile(tid, pid uint32, fd int32, eventFlags int32) *file.FdFile {
	handles := e.pendingHandleState()
	pathname, stashed := handles.peek(tid)
	if !stashed || pathname == "" {
		// An empty name is no stash (set never stores one; this also covers a
		// hand-built tracker): consuming it would yield an unnamed row even
		// when procfs can name the descriptor.
		return procFdFile(pid, fd, eventFlags)
	}
	probe := probeHandleFd(pid, fd)
	if classifyHandlePath(probe, pathname) == handleMismatch {
		if procFile, ok := confirmedHandleFd(probe, pid, fd, eventFlags); ok {
			return procFile
		}
	}
	handles.delete(tid)
	return file.NewFd(fd, pathname, eventFlags)
}

// confirmedHandleFd returns the procfs-named file for a descriptor whose probe
// contradicted the stash, provided the descriptor can still be the one the
// open_by_handle_at returned: its link was readable and names an object a file
// handle can open at all (reachableByHandle), its fdinfo still is readable,
// and its fixed flags are the ones the call asked for (sameFixedFlags, over
// the flags fixedFlagsMask picks for the link text).
//
// ok is false when any of that fails, and the caller then names the row after
// the stash and consumes it. The reasoning is a likelihood, not a proof. A
// link no handle can produce and differing flags do prove a reuse: the
// descriptor is not the one this call produced. A link or fdinfo that vanished
// between the probe's syscalls only says the descriptor the probe glimpsed was
// closed within microseconds; most likely the number is changing hands and the
// glimpse was of a later file, but it can just as well have been the call's
// OWN descriptor, closed by the task at that moment.
//
// The losing case is therefore a stash that does not belong to the opened
// handle (stale, or one of several: a daemon that calls name_to_handle_at only
// for mount IDs and opens handles it got elsewhere) combined with the call's
// own descriptor closing mid-probe. Readlink succeeded but fdinfo is gone: the
// row had the correct procfs name within reach and carries the wrong stash
// instead. Stat succeeded but readlink failed: the row would have been unnamed
// and carries the wrong stash. Both times the stash is consumed, so its own
// open is named from procfs later. That is accepted because the common
// pattern - take a handle and open it on the same thread - is strictly better
// off: there the stash IS the opened file, and a vanished descriptor used to
// cost the row its name or give it a later file's.
//
// The name is the probe's link text, not a fresh readlink: the name the
// verdict was based on is the name the row carries. Only the flags are read
// now, from fdinfo.
func confirmedHandleFd(probe handleFdProbe, pid uint32, fd int32, eventFlags int32) (procFile *file.FdFile, ok bool) {
	if probe.linkErr != nil || !reachableByHandle(probe.target) {
		return nil, false
	}
	procFile = file.NewFdWithProcName(fd, pid, probe.target)
	if !sameFixedFlags(procFile.Flags(), eventFlags, fixedFlagsMask(probe.target)) {
		return nil, false
	}
	return procFile, true
}

// handleKindFlags are the open flags that say what kind of descriptor an open
// produced; handleFixedFlags adds the access mode. Both are a chosen subset of
// the flags a descriptor keeps for its whole life - set by the open and out of
// reach of fcntl(F_SETFL) (which changes only O_APPEND, O_ASYNC, O_DIRECT,
// O_NOATIME and O_NONBLOCK) and of F_SETFD (O_CLOEXEC) - not the full list:
// O_SYNC and O_DSYNC are just as immutable and are left out, because O_SYNC is
// encoded as O_DSYNC|__O_SYNC and the few bits here already tell the reuses
// seen in practice apart. O_LARGEFILE is left out because the kernel forces it
// on for 64-bit callers whatever they pass, and the creation flags (O_CREAT,
// O_EXCL, O_NOCTTY, O_TRUNC) because the kernel does not keep them.
const (
	handleKindFlags  = syscall.O_DIRECTORY | syscall.O_NOFOLLOW | unix.O_PATH
	handleFixedFlags = syscall.O_ACCMODE | handleKindFlags
)

// pidfdLinkText is the /proc/<pid>/fd link text of a pidfd. It reads like one
// of the kernel's generic anonymous inodes but lives on pidfs, which has
// export operations, so it is the one "anon_inode:" target a file handle can
// open.
const pidfdLinkText = "anon_inode:[pidfd]"

// handleLessLinkPrefixes are the /proc/<pid>/fd link texts of descriptors that
// no open_by_handle_at can have returned: sockets ("socket:[N]", sockfs),
// pipes ("pipe:[N]", pipefs) and the kernel's generic anonymous inodes
// ("anon_inode:[eventfd]", "anon_inode:[eventpoll]", "anon_inode:inotify",
// ...). pidfdLinkText shares the last prefix and is exempted by
// reachableByHandle.
var handleLessLinkPrefixes = []string{"socket:[", "pipe:[", "anon_inode:"}

// reachableByHandle reports whether a descriptor whose /proc link reads target
// can be the result of an open_by_handle_at at all.
//
// A file handle can only be decoded on a filesystem with export operations,
// and sockfs, pipefs and the generic anonymous-inode filesystem have none. So
// a link of one of those kinds under the returned number is proof that the
// number was closed and reused, whatever its flags say: without this rule a
// plain O_RDONLY call whose number went to a socket, eventfd or epoll
// descriptor (all O_RDWR, which the kind-flag mask of a non-path target does
// not look at) had its row and fd table entry named "socket:[N]" or
// "anon_inode:[eventfd]" and left the stash unconsumed.
//
// It is a deny list: every other link text - an absolute path, a pidfd, a
// namespace ("net:[N]", "mnt:[N]", "ipc:[N]", "uts:[N]", "pid:[N]",
// "user:[N]", "cgroup:[N]", "time:[N]"; nsfs has export operations) and
// anything a future kernel may add outside the three denied prefixes - stays
// eligible and is judged by its flags, so such a new exportable object is at
// worst believed too readily, never denied its row. A new exportable object
// whose link starts with "anon_inode:" would be denied and need its own
// exemption, as the pidfd did: pidfs became exportable under exactly that
// prefix. The exemption is the exact text, not a prefix: pidfs names its
// dentry dynamically, so the kernel never appends " (deleted)" or anything
// else to it.
//
// That those three filesystems have no export operations is kernel knowledge,
// not something ior can ask at run time. It was checked on Linux 7.2.5
// (x86_64) with name_to_handle_at(fd, "", AT_EMPTY_PATH): EOPNOTSUPP for a
// socket, both ends of a pipe, eventfd, epoll, timerfd, signalfd and inotify;
// success for a pidfd and for every /proc/self/ns/* descriptor.
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

// fixedFlagsMask returns the fixed flags a descriptor whose /proc link reads
// target must share with the open_by_handle_at request to be taken for the
// call's own. It is only asked about targets reachableByHandle lets through.
//
// An absolute path is a file on a mounted filesystem, where the kernel stores
// the access mode exactly as requested, so all of handleFixedFlags count.
// For the non-path targets a handle can open ("anon_inode:[pidfd]", "net:[N]"
// and the other namespaces) only handleKindFlags are compared. pidfs is why:
// it picks the access mode itself - a pidfs handle opened with O_RDONLY shows
// O_RDWR in fdinfo, O_WRONLY shows 03 - so a differing access mode proves
// nothing there and would hand a genuine pidfd row to an unrelated stash;
// pidfs refuses O_DIRECTORY, O_NOFOLLOW and O_PATH outright, so a genuine open
// still passes. nsfs does not need the smaller mask (it keeps O_RDONLY and a
// requested O_PATH and refuses the write modes with EPERM, observed on 7.2.5,
// so a genuine namespace open would pass the full mask too); it gets it only
// to keep one rule for every non-path target.
//
// The price is narrow: a number reused by a pidfd or a namespace descriptor is
// not told apart by its access mode, only by a kind flag the request carried
// (usually none), so such a reuse is believed and names the row - for a
// namespace descriptor that includes an O_RDWR path request, which the full
// mask would have rejected. Sockets, pipes and the other anonymous inodes, the
// reuses that matter in practice, never get this far.
func fixedFlagsMask(target string) int32 {
	if filepath.IsAbs(target) {
		return handleFixedFlags
	}
	return handleKindFlags
}

// sameFixedFlags reports whether a descriptor with procFlags (the flags from
// /proc/<pid>/fdinfo) can be the one an open_by_handle_at called with the
// requested flags returned: within mask (see fixedFlagsMask) its flags are
// what that call must have produced.
//
// Unknown flags (-1, fdinfo unreadable) confirm nothing and report false. The
// explicit check is what guarantees that: -1 has every bit set, which the
// comparison below rejects under handleFixedFlags (no request keeps both
// O_PATH and an access mode) but would accept under handleKindFlags for a
// request carrying all three kind flags.
//
// It is one-sided evidence. Differing flags prove that the number was closed
// and reused since the syscall returned; equal flags do not prove the opposite
// (the task may have reopened the number with the same flags - as a path, or
// under the kind mask as a pidfd or namespace descriptor), and nothing short
// of the handle bytes, which the BPF events do not carry, could tell those
// apart.
func sameFixedFlags(procFlags file.Flags, requested, mask int32) bool {
	if procFlags == file.Flags(-1) {
		return false
	}
	want := requested & mask
	if want&unix.O_PATH != 0 {
		// An O_PATH open ignores the access mode and stores none.
		want &^= syscall.O_ACCMODE
	}
	return int32(procFlags)&mask == want
}

// failedHandleFile returns the file a FAILED open_by_handle_at row reports:
// a descriptor-less pathname, the same shape handleOpenExit gives a failed
// open, so the row is emitted, filtered and counted like any other error row.
//
// The name is the thread's stashed name_to_handle_at path, or empty when there
// is none. There is no descriptor to verify it against (openedHandleFile's
// procfs check needs one), so this is the same unverifiable case as a closed
// descriptor: the stash is the best available hypothesis - right for the usual
// one-handle-then-open sequence and for ESTALE after the file was deleted, but
// possibly another handle's path when the thread took several (the events carry
// no handle bytes to tell them apart). The stash is consumed, as it was when
// failed calls were dropped: a thread that retries after a failure gets its
// successful row named from procfs instead, which describes the real file.
func (e *eventLoop) failedHandleFile(tid uint32) file.File {
	handles := e.pendingHandleState()
	pathname, _ := handles.peek(tid)
	handles.delete(tid)
	return file.NewPathname([]byte(pathname))
}

// procFdFile names a descriptor nothing is stashed for from procfs. An
// unreadable descriptor yields an unnamed file, and unreadable flags are
// replaced by the event's (what the caller asked for).
func procFdFile(pid uint32, fd int32, eventFlags int32) *file.FdFile {
	fdFile := file.NewFdWithPid(fd, pid)
	if fdFile.Flags() == file.Flags(-1) {
		fdFile.SetFlags(eventFlags)
	}
	return fdFile
}
