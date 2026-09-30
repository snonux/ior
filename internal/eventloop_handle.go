package internal

import (
	"fmt"
	"os"
)

// handleVerdict is the outcome of checking a stashed name_to_handle_at
// pathname against the descriptor an open_by_handle_at actually returned.
type handleVerdict int

const (
	// handleUnverified: the descriptor or the pathname could not be stat'ed
	// (the task exited, the number was already closed, the file was deleted
	// after the handle was taken, or the path is not visible from ior's mount
	// namespace). Nothing contradicts the stashed name.
	handleUnverified handleVerdict = iota
	// handleMatches: the descriptor and the pathname are the same inode.
	handleMatches
	// handleMismatch: both could be stat'ed and they are different files, so
	// the handle that was opened is not the one the stashed pathname named.
	handleMismatch
)

// classifyHandlePath compares the file behind /proc/<pid>/fd/<fd> with the
// file the stashed pathname names. The BPF events carry neither the handle
// bytes (name_to_handle_at's f_handle output argument) nor a pointer to them,
// so the stash cannot be keyed by handle; file identity is the only lever
// userspace has to tell which handle an open_by_handle_at opened.
//
// Both stat calls follow symlinks on purpose, and the pathname is also tried
// without following: name_to_handle_at takes the handle of the final symlink
// itself unless AT_SYMLINK_FOLLOW is set, and the stash does not keep that
// flag, so either identity counts as a match. os.SameFile compares dev+ino,
// which survives hard links and symlinked spellings of the same file.
func classifyHandlePath(pid uint32, fd int32, pathname string) handleVerdict {
	fdInfo, err := os.Stat(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil || pathname == "" {
		return handleUnverified
	}
	followed, followErr := os.Stat(pathname)
	if followErr == nil && os.SameFile(fdInfo, followed) {
		return handleMatches
	}
	direct, directErr := os.Lstat(pathname)
	if directErr == nil && os.SameFile(fdInfo, direct) {
		return handleMatches
	}
	if followErr != nil && directErr != nil {
		return handleUnverified
	}
	return handleMismatch
}

// claimPendingHandlePath returns the name_to_handle_at pathname an
// open_by_handle_at that returned fd should be labelled with, or false when
// the row must be named from the descriptor itself (procfs).
//
// The stash is one slot per TID - the thread's last name_to_handle_at - but a
// thread may take several handles and open them in any order, so the slot is
// only a hypothesis about which handle was opened. The descriptor is the
// ground truth and is checked first:
//
//   - match or unverifiable: the stashed name is used and consumed. The
//     unverifiable case is the legacy behaviour and covers names procfs cannot
//     give (deleted file, exited task, closed descriptor).
//   - mismatch: the stash belongs to a different handle, so it is neither used
//     nor consumed (its own open may still come) and the caller names the row
//     from procfs, which describes the descriptor that really was opened.
func (e *eventLoop) claimPendingHandlePath(tid, pid uint32, fd int32) (string, bool) {
	handles := e.pendingHandleState()
	pathname, ok := handles.peek(tid)
	if !ok {
		return "", false
	}
	if classifyHandlePath(pid, fd, pathname) == handleMismatch {
		return "", false
	}
	handles.delete(tid)
	return pathname, true
}
