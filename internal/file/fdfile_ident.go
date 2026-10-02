package file

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
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
// program can read cheaply and what stat(2) reports for a procfs descriptor
// link. 0 means "unknown" - no capture on this kernel or in this run, a file
// procfs could not stat, the rare inode whose low word is 0 - and an unknown
// identity never contradicts anything.

// IdentOfInode returns the identity of the file with inode number ino, the
// user-space counterpart of ior_file_ident.
func IdentOfInode(ino uint64) uint32 {
	return uint32(ino)
}

// Ident returns the identity of the file f's name describes, or 0 when it is
// not known.
func (f *FdFile) Ident() uint32 {
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

// NewFdWithPidIdent is NewFdWithPid that also records which file it read the
// name of. The link is stat'ed before and after the readlink and the identity
// is kept only when both agree: the three calls are not atomic, and a number
// closed and reused in between would otherwise pair one file's name with
// another file's identity, which is exactly the mix-up the identity exists to
// catch. A disagreement, or a link stat cannot follow, leaves the identity
// unknown and the name as NewFdWithPid would have returned it.
func NewFdWithPidIdent(fd int32, pid uint32) *FdFile {
	link := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	before := statIdent(link)
	name, err := os.Readlink(link)
	if err != nil {
		return NewUnresolvedFd(fd)
	}
	f := NewFdWithProcName(fd, pid, name)
	if before != 0 && statIdent(link) == before {
		f.ident = before
	}
	return f
}

// statIdent returns the identity of the file path leads to (following a
// procfs descriptor link to the open file itself, whatever its kind: a pipe,
// a socket and a deleted file can all be stat'ed this way), or 0 when it
// cannot be stat'ed.
func statIdent(path string) uint32 {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0
	}
	return IdentOfInode(st.Ino)
}
