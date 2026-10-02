package file

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// File identity (task 603).
//
// A descriptor number says nothing about which file it names: the number is
// reused, and ior learns about a file either from a traced call (which a
// later untraced close and reopen silently outdates) or from /proc/<pid>/fd
// (read when the event loop gets to the row, possibly after the number was
// reused). The BPF handlers therefore report which file a descriptor named
// when its call entered (ior_file_ident in internal/c/fileident.c), and an
// FdFile remembers the same thing about the file its name describes, so the
// two can be compared (internal/eventloop_fileident.go).
//
// The identity is the low 32 bits of the file's inode number: what the kernel
// program can read cheaply and what /proc/<pid>/fdinfo/<fd> prints for a
// descriptor. 0 means "unknown" - no capture on this kernel or in this run,
// an fdinfo without the number, the rare inode whose low word is 0 - and an
// unknown identity never contradicts anything.

// IdentOfInode returns the identity of the file with inode number ino, the
// user-space counterpart of ior_file_ident.
func IdentOfInode(ino uint64) uint32 {
	return uint32(ino)
}

// Ident returns the identity of the file f's name describes, or 0 when it is
// not known. A nil FdFile describes no file: the procfs cache can hold one
// (fdTracker.copyTable skips them), and the comparison must not trip on it.
func (f *FdFile) Ident() uint32 {
	if f == nil {
		return 0
	}
	return f.ident
}

// SetIdent records which file f's name describes. Dup and Detach copy it with
// the name: a duplicate or an inherited descriptor is the same file.
func (f *FdFile) SetIdent(ident uint32) {
	f.ident = ident
}

// appendUnnamed appends what a file without a name is rendered as. "E:name"
// (empty name) is the descriptor ior knows nothing about: one that was not
// open (EBADF), or any unnamed descriptor in a run without identities. When
// the row's record said which file the descriptor was, but neither a traced
// call nor procfs could name it - the process had exited or closed and
// reused the number before the event loop got to the row (tasks as2, yz2), or
// the row is the close of a descriptor ior never saw opened (task xz2) - the
// identity is all ior has and is shown instead: "E:ino:<n>", n being the low
// 32 bits of the inode number. It tells rows on different unnamed files
// apart and is enough to look the file up while it exists (find -inum).
// Name() stays empty either way, so filters and aggregations see no name.
func (f *FdFile) appendUnnamed(dst []byte) []byte {
	if f.ident == 0 {
		return append(dst, "E:name"...)
	}
	dst = append(dst, "E:ino:"...)
	return strconv.AppendUint(dst, uint64(f.ident), 10)
}

// BoundAt returns when the fd table bound f's number to the file f describes:
// the time of the exit record of the call that made the binding (an open, a
// dup, a pipe, ...), on the boot clock of the record timestamps, or 0 when
// that is not known. A row whose call entered before that time may have used
// the file the number named earlier (a read that blocked while another thread
// closed the number and an open returned it again), so such a row says
// nothing against the entry (fdTracker.trackedFile in
// internal/eventloop_fileident.go). 0 counts as older than every row: an
// entry of unknown age is judged as before the time existed.
func (f *FdFile) BoundAt() uint64 {
	return f.boundNs
}

// SetBoundAt records when f's number was bound to its file; see BoundAt. Dup
// resets it, because a duplicate is a new binding made at the time of the
// dup, which the caller knows (fdTracker.set stamps an entry that has none).
// A fork's copy keeps none on purpose: no row of the child can have entered
// before the fork, so every row is younger than its bindings, which is what
// 0 says. Detach copies it with everything else; nobody asks a snapshot.
func (f *FdFile) SetBoundAt(ns uint64) {
	f.boundNs = ns
}

// NewFdWithPidIdent is NewFdWithPid that also records which file it read the
// name of, and reports whether the answer is one consistent reading of the
// descriptor. The identity comes from the "ino:" line of
// /proc/<pid>/fdinfo/<fd>, the read that supplies the flags anyway: procfs
// prints the i_ino of the open file there, the very number the kernel program
// reports, and reading it never touches the file's filesystem. (stat(2) on
// the descriptor link would: it can block on an unreachable NFS server, is
// refused on a FUSE mount of another user, and reports what the filesystem's
// getattr says, which need not be i_ino.)
//
// The link is read again afterwards, because the reads are not atomic: a
// number closed and reused in between would pair one file's name with
// another file's flags and identity, which is exactly the mix-up the identity
// exists to catch. stable is false when that happened - the link reads
// differently or not at all the second time, or fdinfo could not be read
// although the link had just been: the number was rebound while it was being
// read, and the answer describes no one file. Such an answer has no identity
// and must not be cached (fdTracker.readProcFd reads once more). An fdinfo
// without the line (kernels before 5.14) is a consistent answer of unknown
// identity. A descriptor that is not open is "stable": there is no answer,
// name and flags are what NewFdWithPid returns.
func NewFdWithPidIdent(fd int32, pid uint32) (f *FdFile, stable bool) {
	return newFdWithIdentIn(procDir(pid), fd)
}

// newFdWithIdentIn is NewFdWithPidIdent on the procfs directory dir of the
// process (a test supplies its own).
func newFdWithIdentIn(dir string, fd int32) (*FdFile, bool) {
	link := fmt.Sprintf("%s/fd/%d", dir, fd)
	name, err := os.Readlink(link)
	if err != nil {
		return NewUnresolvedFd(fd), true
	}
	f, fdinfo, readable := newFdFromProc(fd, dir, name)
	if !readable {
		return f, false
	}
	ident, stable := identOfAnswer(fdinfo, link, name)
	f.ident = ident
	return f, stable
}

// identOfAnswer returns the identity to record with a procfs answer and
// whether the answer held: the descriptor link still reads as name, the name
// the answer carries. The identity is that of the inode fdinfo (its content,
// data) names, 0 when the answer did not hold or fdinfo has no such line.
func identOfAnswer(data []byte, link, name string) (uint32, bool) {
	if again, err := os.Readlink(link); err != nil || again != name {
		return 0, false
	}
	ino, ok := parseInodeFromFdInfo(data)
	if !ok {
		return 0, true
	}
	return IdentOfInode(ino), true
}

// parseInodeFromFdInfo returns the inode number of the "ino:" line of an
// fdinfo file, or false when there is none or it is malformed.
func parseInodeFromFdInfo(data []byte) (uint64, bool) {
	for line := range strings.SplitSeq(string(data), "\n") {
		value, ok := strings.CutPrefix(line, "ino:")
		if !ok {
			continue
		}
		ino, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		return ino, err == nil
	}
	return 0, false
}
