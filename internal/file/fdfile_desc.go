package file

// Open file descriptions (task nr2).
//
// Linux separates a descriptor from the open file description it refers to.
// dup(2), dup2, dup3, fcntl(F_DUPFD*) and fork all create a second descriptor
// for the *same* description, so the file offset and the status flags (the
// access mode, O_APPEND, O_NONBLOCK, ...) are one object seen through both
// numbers: fcntl(dup, F_SETFL, O_APPEND) turns O_APPEND on for the original
// too. FD_CLOEXEC is the exception, it is stored with the descriptor. A second
// open(2) of the same path makes a new description that shares nothing.
//
// FdFile used to carry its whole flag word by value and Dup copied it, so a
// F_SETFL on one descriptor updated one table entry and left every duplicate
// reporting the old word (live evidence: a write on the original showed
// O_WRONLY|O_CREAT|O_TRUNC while the kernel returned 0106001, and a later dup of
// the original inherited the stale word even after F_GETFL had refreshed it).
// openFileDesc is the shared object; Dup is the one operation that shares it.

// openFileDesc is the part of a descriptor's state that all duplicates of one
// open file description share: the status word as open(2) and F_SETFL left it
// (access mode, creation flags, status flags). It never carries O_CLOEXEC, which
// belongs to the descriptor (FdFile.closeOnExec). status is unknownFlag until
// procfs, an open() event or F_GETFL supplies it.
//
// Only the single event-loop goroutine mutates it; a row that leaves that
// goroutine gets a Detach()ed copy, which owns a private openFileDesc.
type openFileDesc struct {
	status Flags
}

// fdWithDesc is the allocation unit of an FdFile that owns its description: the
// FdFile and its openFileDesc in one object, so creating a descriptor (one per
// traced open and one per emitted row, through Detach) costs one allocation, not
// two. FdFile.desc points at the sibling field. A duplicate's desc pointer
// into this object keeps it alive, which is harmless: the original FdFile it
// also holds is small (a name and a few words).
type fdWithDesc struct {
	FdFile
	own openFileDesc
}

// newFdFile allocates an FdFile that owns a new open file description with an
// unknown status word; the caller sets the word.
func newFdFile(fd int32, name string) *FdFile {
	w := &fdWithDesc{FdFile: FdFile{fd: fd, name: name}, own: openFileDesc{status: unknownFlag}}
	w.desc = &w.own
	return &w.FdFile
}

// description returns the open file description f refers to. A zero FdFile
// (never built by a constructor) gets a fresh one holding O_RDONLY, which is
// what its zero flag word has always meant.
func (f *FdFile) description() *openFileDesc {
	if f.desc == nil {
		f.desc = &openFileDesc{}
	}
	return f.desc
}

// status is the shared status word, without FD_CLOEXEC.
func (f *FdFile) status() Flags {
	if f.desc == nil {
		return 0
	}
	return f.desc.status
}

// Dup models a descriptor created by dup, dup2, dup3, fcntl(F_DUPFD*) or fork:
// a new FdFile on descriptor number fd that refers to the same open file
// description as f. The status word is shared, so a later F_SETFL/F_GETFL
// through either descriptor is seen through both; the name is copied. FD_CLOEXEC
// is copied as a starting value only and is the caller's to set on the new
// descriptor (dup/dup2/F_DUPFD clear it, dup3(O_CLOEXEC) and F_DUPFD_CLOEXEC
// set it, a fork keeps it): the two descriptors never share it.
func (f *FdFile) Dup(fd int32) *FdFile {
	dup := *f
	dup.fd = fd
	dup.desc = f.description()
	return &dup
}

// Detach returns an independent snapshot of f on the same descriptor number: it
// shares nothing with f, so what f's description or descriptor goes through
// later (a F_SETFL through a duplicate, a close-on-exec change) cannot reach
// it. A pair that is emitted (printed, aggregated, kept for the TUI) must
// report the descriptor as it was when its syscall returned, which is why the
// event loop detaches the file of every pair it freezes (and of a pending exec
// target). Use Dup, not Detach, to model a second descriptor.
func (f *FdFile) Detach() *FdFile {
	w := &fdWithDesc{FdFile: *f, own: openFileDesc{status: f.status()}}
	w.desc = &w.own
	return &w.FdFile
}
