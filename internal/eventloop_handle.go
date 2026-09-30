package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	// handleMismatch: the descriptor is demonstrably not the file the stashed
	// pathname names, so the handle that was opened is not the one the stash
	// belongs to.
	handleMismatch
)

// deletedSuffix is what procfs appends to the link text of an unlinked file.
const deletedSuffix = " (deleted)"

// handleFdProbe is one look at /proc/<pid>/fd/<fd>: its inode (stat follows
// the magic link) and its link text (readlink), taken back to back so the two
// describe the same descriptor as closely as userspace can manage.
//
// The window between the two syscalls is not zero: the traced task could close
// the number and reuse it for another file in those microseconds, and ior
// cannot hold the descriptor still (there is no pidfd_getfd in this path). The
// consequence is bounded - at worst one row is named after the newer file, the
// same exposure every procfs-resolved fd row has anyway, since the event is
// already stale by the time the loop handles it.
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
// Relative stashes (AT_FDCWD with a relative name is stored as given) are
// compared by link text only: os.Stat would resolve them against ior's working
// directory, which says nothing about the task's, and procfs links are
// absolute, so a relative stash is always a mismatch and the row is named
// from procfs.
//
// Mount namespaces: the stash is the string the task passed, procfs is read
// from ior's own namespace. When ior's namespace has a DIFFERENT file at the
// stashed path (a container's /etc/passwd), the inodes differ and the verdict
// is mismatch; when the path is absent, the link text differs from it, also a
// mismatch. Either way procfs wins, exactly as it does for every other fd row
// ior resolves, at the price that the stash is left unconsumed (it is
// overwritten by the thread's next name_to_handle_at or evicted with the
// task). Only a descriptor procfs cannot describe at all is unverifiable.
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
// only a hypothesis about which handle was opened. The descriptor is the
// ground truth and is checked first:
//
//   - no stash (or an empty one): the row is named from procfs.
//   - match or unverifiable: the stashed name is used and consumed (the
//     unverifiable case is the legacy behaviour, for a descriptor procfs
//     cannot answer for).
//   - mismatch: the stash belongs to a different handle, so it is neither used
//     nor consumed (its own open may still come) and the row is named from
//     procfs, which describes the descriptor that really was opened.
//
// Flags differ by branch on purpose. A stash-named row has no procfs view it
// trusts, so it carries the flags the event captured at enter (what the
// caller asked for). A procfs-named row takes the kernel's own view from
// /proc/<pid>/fdinfo - the flags the descriptor really has - and only falls
// back to the event's when fdinfo is unreadable.
func (e *eventLoop) openedHandleFile(tid, pid uint32, fd int32, eventFlags int32) *file.FdFile {
	handles := e.pendingHandleState()
	pathname, stashed := handles.peek(tid)
	if !stashed || pathname == "" {
		// An empty name is no stash (set never stores one; this also covers a
		// hand-built tracker): consuming it would yield an unnamed row even
		// when procfs can name the descriptor.
		return procFdFile(nil, pid, fd, eventFlags)
	}
	probe := probeHandleFd(pid, fd)
	if classifyHandlePath(probe, pathname) == handleMismatch {
		return procFdFile(&probe, pid, fd, eventFlags)
	}
	handles.delete(tid)
	return file.NewFd(fd, pathname, eventFlags)
}

// procFdFile names the descriptor from procfs. A probe that already holds the
// link text supplies it (one readlink decides both the verdict and the name);
// with no probe, or a probe whose readlink failed, procfs is asked afresh and
// an unreadable descriptor yields an unnamed file carrying the event's flags.
func procFdFile(probe *handleFdProbe, pid uint32, fd int32, eventFlags int32) *file.FdFile {
	var fdFile *file.FdFile
	if probe != nil && probe.linkErr == nil {
		fdFile = file.NewFdWithProcName(fd, pid, probe.target)
	} else {
		fdFile = file.NewFdWithPid(fd, pid)
	}
	if fdFile.Flags() == file.Flags(-1) {
		fdFile.SetFlags(eventFlags)
	}
	return fdFile
}
