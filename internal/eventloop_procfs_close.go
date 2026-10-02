package internal

import (
	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

// Close rows never read procfs (task jr2).
//
// close(2) and close_range(2) label their row by the descriptor they release.
// When that descriptor is not in the fd table (opened before ior attached,
// created by an untraced syscall, evicted by the LRU cap, or held in a table
// ior has given up tracking, see below) the generic resolver falls back to
// readlink(/proc/<pid>/fd/<fd>). For every other syscall that is a fair
// answer, since the descriptor is still open while the row is being
// processed. For a close it cannot be: the descriptor is gone by then, so the
// read either fails (an unnamed row) or, when the program already reused the
// number (close(3); pipe() -> 3), names the file that replaced it. That is a
// wrong row, and it was the common shape in practice: live, close(3) of
// pipe:[75140025] was reported as pipe:[75140884], the pipe created next on
// fd 3.
//
// Resolving at the *enter* record does not help. User space consumes the
// enter record after the kernel has nearly always finished the close (the
// same reason storeEnter gives for an untracked exec dirfd). Measured with a
// workload that opens 200 files before ior attaches, then closes each one and
// creates a pipe right after (which reuses the number), three runs per
// variant:
//
//                                correct name   reuser's pipe   unnamed
//  exit-time procfs (old)         0 / 600        181 / 600      419 / 600
//  enter-time procfs (prototype)  0 / 600         29 / 600      571 / 600
//
// An enter-time read never once saw the closed file and still picked up the
// reusing pipe (without the pipes both variants left all 600 rows unnamed).
// Only BPF could see the file before the close takes effect (its
// sys_enter_close program runs before the descriptor is released).
// bpf_d_path is not callable from tracepoints, so that needs a dentry walk in
// the kernel program for every close, and it is left as a follow-up.
//
// So a closing row is labelled from what ior learned *before* the close:
//
//   - the fd-table entry (a traced open/dup/pipe...), unchanged from before;
//   - else the procfs-cache entry, but only when its readlink returned before
//     the close began: the entry's read stamp (fdTracker.procFdReadAt, the
//     host's boot clock read after the readlink, see bootClockNs) is earlier
//     than the close's enter time. The cache is evicted by every close,
//     close_range and EBADF of the number, so such an entry describes the
//     descriptor this close releases.
//     The stamp matters because the cache is filled at processing time, which
//     lags the kernel: live, a write to the file just before its close was
//     processed after the close and the pipe that reused the number, so the
//     write read and cached the pipe and the close row repeated it. A later
//     stamp, or none, says nothing about the closed descriptor and the entry
//     is ignored;
//   - else nothing: the fd number with an empty name and unknown flags, the
//     same as an EBADF row. An honest blank beats the name of another file.
//
// A blind table (eventloop_fdshare.go: the process shares its table with a
// CLONE_FILES child the trace cannot see, so ior stopped tracking it) keeps
// neither fd-table entries nor cache answers, so every close row of such a
// process is unnamed, even for a descriptor ior saw being opened. Before jr2
// those rows were read from procfs after the close, i.e. empty or wrong, so
// this loses no correct name.
//
// Dropping the readlink also takes one procfs read (~4-13 us) off every close
// of an untracked descriptor.
//
// Which pairs count as a close (closesDescriptor): close, whatever it returns
// (EBADF rows take the EBADF path first; a close that returns EINTR or EIO did
// release the descriptor, see applyFdCloseState), and close_range unless it
// closes nothing. close_range with CLOSE_RANGE_CLOEXEC only marks its
// descriptors; a close_range that fails (EINVAL for first > last or unknown
// flags, ENOMEM while unsharing) returns before releasing any. Both leave
// the descriptors open, so their rows keep the ordinary resolution, procfs
// included, and applyCloseRangeState leaves the tracked state alone for a
// failed one as well.

// closesDescriptor reports whether the pair releases the descriptor its row is
// labelled by: close, and close_range without CLOSE_RANGE_CLOEXEC that did not
// fail. It looks at the enter record's concrete type (the payloads close and
// close_range are decoded into), so a pair without an enter record is simply
// not a close.
func closesDescriptor(ep *event.Pair) bool {
	switch ev := ep.EnterEv.(type) {
	case *types.FdEvent:
		return ev.TraceId == types.SYS_ENTER_CLOSE
	case *types.TwoFdEvent:
		return ev.TraceId == types.SYS_ENTER_CLOSE_RANGE &&
			ev.Extra&closeRangeCloexec == 0 && !exitFailed(ep)
	default:
		return false
	}
}

// exitFailed reports whether the pair's exit record carries an error return.
// A pair without a decoded return value is not known to have failed, so a
// close_range in that shape still counts as a close: an unnamed row at worst,
// never a name read after the descriptor may have been released.
func exitFailed(ep *event.Pair) bool {
	carrier, ok := ep.ExitEv.(event.RetCarrier)
	return ok && carrier.GetRet() < 0
}

// resolveClosing is resolve without the procfs read, for a row whose syscall
// entered at closeNs (boot clock): the fd-table entry, else a procfs-cache
// entry read before closeNs, else an unnamed file with unknown flags. It does
// not change either map; the close state transition (applyFdCloseState,
// applyCloseRangeState) evicts the entries afterwards.
func (t *fdTracker) resolveClosing(fd int32, pid uint32, closeNs uint64) file.File {
	if fdFile, ok := t.get(fd, pid); ok {
		return fdFile
	}
	if fd >= 0 {
		if cached, ok := t.cachedProcFdFile(fd, pid); ok && t.cacheReadBefore(fd, pid, closeNs) {
			return cached
		}
	}
	return file.NewFd(fd, "", -1)
}

// cacheReadBefore reports whether the procfs-cache entry for (pid, fd) was read
// before closeNs. An entry without a read time counts as read at an unknown
// time, i.e. not before.
func (t *fdTracker) cacheReadBefore(fd int32, pid uint32, closeNs uint64) bool {
	readNs, ok := t.cachedProcFdReadAt(fd, pid)
	// User-space boot clock vs BPF stamps: both on the host's boot clock,
	// bootClockNs takes a time namespace's boottime offset out of its reading
	// (bootclock.go). Uncorrected, an offset decided every comparison here.
	return ok && readNs < closeNs
}
