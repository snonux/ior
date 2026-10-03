package internal

import (
	"ior/internal/file"
	"ior/internal/types"
)

// The name of last resort for a close row (task xz2).
//
// A close is named from what ior learned before it: the fd table entry of a
// traced open, or a procfs answer read before the close began
// (eventloop_procfs_close.go, eventloop_fileident.go). A descriptor that was
// opened before the trace, or by a call outside the trace set, and was never
// used by a traced call before its close has neither, and procfs cannot be
// asked any more: the row was unnamed ("E:ino:<n>" since task 603, "E:name"
// before).
//
// On a kernel that captures file identities the kernel program now says what
// the closed file was called, read from the file itself while the close
// entered: the last path component only (internal/c/fdname.c says why not
// more), in an fd_name_event that decodes into the close's FdEvent
// (types.FdEvent.LeafName). leafNamed gives that name to a close row that
// would otherwise have none, as "*/foo.log" (file.NewFdLeaf).
//
// It never replaces a name. A row named by its fd table entry keeps the full
// path the open was traced with, and one named by a procfs answer read
// before the close keeps that; both say more than a last component. The
// component is not used to check them either: a file renamed since its open
// is still correctly reported under the name it was opened as.
//
// Unlike a procfs answer the component cannot describe another file: it was
// read from the file the descriptor named when the close entered, by the
// task that closed it. So it also names the rows the identity rules leave
// unnamed on purpose - an fd table entry bound after the close entered, a
// cached answer of another file or one read too late - and the close rows of
// a table ior stopped tracking (a blind table). What it can be is out of
// date: the name of a file that was renamed while the close was entering.
//
// No name is captured, and the row stays unnamed, for a pipe, a socket, an
// anonymous-inode file, a memfd and the root directory of a filesystem
// (nothing below a directory), for close_range (a range, not a file), for a
// close of a number that was not open (EBADF), and on a kernel without the
// identity capture or in a run with IOR_FILE_IDENT=0.

// leafNamed returns the file of a row whose enter record fdEv carries the
// last path component of its descriptor's file: resolved, the file the
// ordinary rules found, when that has a name, else a file named by the
// component alone, with the row's identity ident (0 = unknown) and unknown
// flags. A record without a component (its string read failed, or the name
// is empty) leaves resolved as it is.
func leafNamed(resolved file.File, fdEv *types.FdEvent, ident uint32) file.File {
	if resolved != nil && resolved.Name() != "" {
		return resolved
	}
	leaf, cut := fdEv.LeafName()
	if leaf == "" {
		return resolved
	}
	return file.NewFdLeaf(fdEv.Fd, leaf, cut, ident)
}
