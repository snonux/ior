package file

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"ior/internal/types"
)

// File is the common interface for file-like syscall payload representations.
//
// Implementations may represent a live file descriptor-backed handle (FdFile),
// partial path metadata, or a descriptor-free anonymous memory mapping.
//
// Semantics:
//   - Name returns the best single-path identifier for the event. For
//     rename-like events this is the "new" path; for pathname-only events it is
//     the observed pathname.
//   - Flags returns open flags when known, otherwise unknownFlag.
//   - FD returns the tracked file descriptor when one exists, otherwise -1.
//   - String returns a human-readable representation suitable for TUI/CSV use
//     and should remain informative even when Name or FD are unavailable.
type File interface {
	String() string
	Name() string
	Flags() Flags
	FD() int32
}

// StringAppender is the optional allocation-free companion of File.String,
// implemented by every File in this package. The -plain output renders one
// CSV row per syscall into a reused byte buffer; building each file column
// with String() would allocate a string per row only to copy it into that
// buffer.
//
// AppendString appends exactly String()'s text to dst and returns the
// extended slice. When text is non-nil, every traced path component (a
// name, an old/new name) is passed through it - the -escape rewriting of
// attacker-controlled bytes - while the fixed decoration around the paths
// ("%(fd,flags)", "old:", "pathname:") is appended verbatim. That equals
// text(String()) for any per-rune escaper, because the decoration is plain
// printable ASCII that such an escaper leaves alone.
type StringAppender interface {
	AppendString(dst []byte, text func(string) string) []byte
}

// appendText appends s to dst, passing it through text first when non-nil.
func appendText(dst []byte, s string, text func(string) string) []byte {
	if text != nil {
		s = text(s)
	}
	return append(dst, s...)
}

// FdFile represents a file descriptor-backed file reference.
//
// The kernel splits what a descriptor knows into two layers, and FdFile
// mirrors the split (task nr2): the status word lives in the open file
// description, which every duplicate of the descriptor (dup, dup2, dup3,
// F_DUPFD, and the copy a fork inherits) shares through desc. The word holds
// the access mode and O_APPEND/O_NONBLOCK/... and, as open() reported them
// until F_GETFL replaces the word with the kernel's, the open-only flags
// O_CREAT/O_TRUNC/.... FD_CLOEXEC belongs to the descriptor alone and stays
// in the FdFile. Name and number are per descriptor too: the number
// is the table slot, and the name is what that slot was opened (or last
// resolved) as. See fdfile_desc.go for the sharing operations.
type FdFile struct {
	fd               int32
	name             string
	desc             *openFileDesc
	closeOnExecKnown bool
	closeOnExec      bool
	flagsFromProcFS  bool
}

// NewFd constructs an FdFile from explicit descriptor metadata.
func NewFd(fd int32, name string, flags int32) *FdFile {
	f := newFdFile(fd, name)
	f.SetFlags(flags)
	return f
}

// NewFdWithPid resolves descriptor metadata from /proc/<pid>/fd.
func NewFdWithPid(fd int32, pid uint32) *FdFile {
	name, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	if err != nil {
		return unresolvedFd(fd)
	}
	return NewFdWithProcName(fd, pid, name)
}

// NewFdWithProcName is NewFdWithPid for a caller that has already read the
// /proc/<pid>/fd/<fd> link itself: name is that link text and is used as is,
// so the name the caller inspected is the name the row carries (a second
// readlink could see a different file if the descriptor was closed and reused
// in between). Only the flags still come from /proc/<pid>/fdinfo/<fd>.
func NewFdWithProcName(fd int32, pid uint32, name string) *FdFile {
	f := newFdFile(fd, name)
	flags, err := readFlagsFromFdInfo(fd, pid)
	if err != nil {
		f.SetFlags(-1)
	} else {
		f.SetFlags(int32(flags))
	}
	f.flagsFromProcFS = true

	return f
}

// unresolvedFd is the descriptor procfs could not answer for: no name and
// unknown flags.
func unresolvedFd(fd int32) *FdFile {
	f := newFdFile(fd, "")
	f.SetFlags(-1)
	f.flagsFromProcFS = true
	return f
}

func readFlagsFromFdInfo(fd int32, pid uint32) (Flags, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", pid, fd))
	if err != nil {
		return unknownFlag, err
	}
	return parseFlagsFromFdInfo(data)
}

func parseFlagsFromFdInfo(data []byte) (Flags, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "flags:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return unknownFlag, fmt.Errorf("malformed flags line in fdinfo: %q", line)
			}
			flags, err := strconv.ParseUint(fields[1], 8, 32)
			return Flags(flags), err
		}
	}
	if err := scanner.Err(); err != nil {
		return unknownFlag, err
	}
	return unknownFlag, fmt.Errorf("flags field not found in fdinfo")
}

// Name returns the file's path, or the empty string when it was never
// resolved (e.g. a name whose sys_enter read faulted and never recovered).
func (f *FdFile) Name() string {
	return f.name
}

// String renders the file for the plain-mode CSV row: the name (or "E:name"
// when empty) followed by "%(fd,flags)".
func (f *FdFile) String() string {
	// The scratch buffer stays on the stack, so String costs only the string copy.
	var scratch [128]byte
	return string(f.AppendString(scratch[:0], nil))
}

// AppendString implements StringAppender.
func (f *FdFile) AppendString(dst []byte, text func(string) string) []byte {
	if len(f.name) == 0 {
		dst = append(dst, "E:name"...) // Empty name string
	} else {
		dst = appendText(dst, f.name, text)
	}
	dst = append(dst, "%("...)
	dst = strconv.AppendInt(dst, int64(f.fd), 10)
	dst = append(dst, ',')
	dst = f.Flags().AppendTo(dst)
	return append(dst, ')')
}

// Flags returns the file's open-flags word.
func (f *FdFile) Flags() Flags {
	// Keep a partially known word unknown. Returning O_CLOEXEC alone when the
	// status word is unavailable would make its zero access-mode bits look like
	// an authoritative O_RDONLY. The separately remembered descriptor bit is
	// folded in when F_GETFL later supplies the status word.
	status := f.status()
	if status == unknownFlag {
		return unknownFlag
	}
	// FD_CLOEXEC is this descriptor's own state, the status word is the
	// shared open file description's: the row shows the pair as one word. An
	// unknown FD_CLOEXEC keeps the historical clear representation.
	if f.closeOnExecKnown && f.closeOnExec {
		return status | syscall.O_CLOEXEC
	}
	return status
}

// CloseOnExec reports the descriptor's FD_CLOEXEC state: set is the flag's
// value and known says whether that value was ever observed. The state is
// tracked apart from the status-flag word because it belongs to the
// descriptor, not the open file description, and can be learned (F_GETFD,
// F_SETFD, ioctl FIOCLEX/FIONCLEX, dup3, F_DUPFD_CLOEXEC, close_range
// CLOSE_RANGE_CLOEXEC) while the status word is still unknown. Callers
// deciding whether the descriptor survives execve(2) must treat !known as
// "may have been closed".
func (f *FdFile) CloseOnExec() (set, known bool) {
	return f.closeOnExec, f.closeOnExecKnown
}

// FD returns the descriptor number the metadata was recorded for.
func (f *FdFile) FD() int32 {
	return f.fd
}

// SetFlags replaces a complete combined flag word outright: the status part
// goes into the open file description (so every duplicate sees it), the
// O_CLOEXEC bit into this descriptor. Use SetStatusFlags for F_GETFL and
// MergeFlags for partial updates.
func (f *FdFile) SetFlags(flags int32) {
	if Flags(flags) == unknownFlag {
		f.description().status = unknownFlag
		f.closeOnExecKnown = false
		f.closeOnExec = false
		return
	}
	f.description().status = Flags(flags &^ syscall.O_CLOEXEC)
	f.closeOnExecKnown = true
	f.closeOnExec = flags&syscall.O_CLOEXEC != 0
}

// SetStatusFlags replaces the status word reported by F_GETFL, in the shared
// open file description, while retaining this descriptor's separately learned
// FD_CLOEXEC state (the kernel's word cannot carry it). While that descriptor
// bit is still unknown, Flags keeps the historical clear representation; a
// later F_GETFD will make it authoritative.
func (f *FdFile) SetStatusFlags(flags int32) {
	f.description().status = Flags(flags &^ syscall.O_CLOEXEC)
}

// AddFlags ORs the given bits into the flag word: the O_CLOEXEC bit into this
// descriptor, every other bit into the shared open file description.
func (f *FdFile) AddFlags(flags int32) {
	if flags&syscall.O_CLOEXEC != 0 {
		f.closeOnExecKnown = true
		f.closeOnExec = true
	}
	desc := f.description()
	if desc.status == unknownFlag {
		return
	}
	desc.status = Flags(int32(desc.status) | flags&^syscall.O_CLOEXEC)
}

// MergeFlags replaces only the bits selected by mask with the corresponding
// bits of flags and leaves every other bit of the current flag word intact.
//
// This is the update shape fcntl(2) F_SETFL has: it changes the settable
// status flags only, while the access mode (O_RDONLY/O_WRONLY/O_RDWR) and the
// open-only flags (O_CREAT, O_TRUNC, ...) keep the values open(2) was called
// with (the kernel itself forgets the open-only ones, which F_GETFL then drops
// from the word, see SetStatusFlags). Callers
// typically pass the full word they got from F_GETFL, so a plain SetFlags of
// arg&mask would mask the access mode away and make a read-write descriptor
// report as read-only for the rest of its life.
//
// The mask's O_CLOEXEC bit updates this descriptor only (F_SETFD); every other
// selected bit is a status bit and changes the open file description, so a
// F_SETFL through one descriptor is seen through all its duplicates, as in the
// kernel.
//
// Status flags that are not known at all are left unknown: with no base word
// there is nothing to merge into, and materialising one from the masked bits
// alone would assert an access mode (O_RDONLY is the zero value) that was never
// observed. Descriptor-level O_CLOEXEC knowledge is still retained separately
// and is folded in when SetStatusFlags supplies that base word.
func (f *FdFile) MergeFlags(mask, flags int32) {
	if mask&syscall.O_CLOEXEC != 0 {
		f.closeOnExecKnown = true
		f.closeOnExec = flags&syscall.O_CLOEXEC != 0
	}
	desc := f.description()
	if desc.status == unknownFlag {
		return
	}
	statusMask := mask &^ syscall.O_CLOEXEC
	desc.status = Flags((int32(desc.status) &^ statusMask) | (flags & statusMask))
}

type oldnameNewnameFile struct {
	Oldname, Newname string
}

// NewOldnameNewname creates a file representation for rename-like syscalls.
func NewOldnameNewname(oldname, newname []byte) oldnameNewnameFile {
	return oldnameNewnameFile{types.StringValue(oldname), types.StringValue(newname)}
}

func (f oldnameNewnameFile) Name() string {
	return f.Newname
}

func (f oldnameNewnameFile) Flags() Flags {
	return unknownFlag
}

func (f oldnameNewnameFile) FD() int32 {
	return -1
}

func (f oldnameNewnameFile) String() string {
	// The scratch buffer stays on the stack, so String costs only the string copy.
	var scratch [128]byte
	return string(f.AppendString(scratch[:0], nil))
}

// AppendString implements StringAppender.
func (f oldnameNewnameFile) AppendString(dst []byte, text func(string) string) []byte {
	dst = append(dst, "old:"...)
	dst = appendText(dst, f.Oldname, text)
	dst = append(dst, " ->new:"...)
	dst = appendText(dst, f.Newname, text)
	dst = append(dst, "%("...)
	dst = f.Flags().AppendTo(dst)
	return append(dst, ')')
}

type pathnameFile struct {
	Pathname string
}

// NewPathname creates a path-only file representation.
func NewPathname(pathname []byte) pathnameFile {
	return pathnameFile{types.StringValue(pathname)}
}

func (f pathnameFile) Name() string {
	return f.Pathname
}

func (f pathnameFile) Flags() Flags {
	return unknownFlag
}

func (f pathnameFile) FD() int32 {
	return -1
}

func (f pathnameFile) String() string {
	// The scratch buffer stays on the stack, so String costs only the string copy.
	var scratch [128]byte
	return string(f.AppendString(scratch[:0], nil))
}

// AppendString implements StringAppender.
func (f pathnameFile) AppendString(dst []byte, text func(string) string) []byte {
	dst = append(dst, "pathname:"...)
	dst = appendText(dst, f.Pathname, text)
	dst = append(dst, "%("...)
	dst = f.Flags().AppendTo(dst)
	return append(dst, ')')
}

type anonymousMappingFile struct{}

// NewAnonymousMapping creates the file representation for an mmap mapping
// whose MAP_ANONYMOUS flag makes the descriptor argument irrelevant.
func NewAnonymousMapping() anonymousMappingFile {
	return anonymousMappingFile{}
}

func (anonymousMappingFile) Name() string {
	return "anon"
}

func (anonymousMappingFile) Flags() Flags {
	return unknownFlag
}

func (anonymousMappingFile) FD() int32 {
	return -1
}

func (anonymousMappingFile) String() string {
	return "anon"
}

// AppendString implements StringAppender.
func (anonymousMappingFile) AppendString(dst []byte, _ func(string) string) []byte {
	return append(dst, "anon"...)
}

// registeredRingFile names an io_uring instance addressed through the task's
// registered-ring table rather than the file descriptor table.
//
// io_uring_enter(IORING_ENTER_REGISTERED_RING), io_uring_register with
// IORING_REGISTER_USE_REGISTERED_RING and a ring created with
// IORING_SETUP_REGISTERED_FD_ONLY all pass or return a small index into that
// table (io_uring_register_ring_fd() in liburing; typically 0). The number
// looks like a descriptor but names no entry of the fd table: resolving it
// there attributes the call to whatever file happens to sit at that fd
// (stdin for index 0). The index is all that is known about the ring, so the
// row is labelled with it.
type registeredRingFile struct {
	index int32
}

// NewRegisteredRing creates the file representation for an io_uring ring that
// is addressed by its registered-ring index instead of a file descriptor.
func NewRegisteredRing(index int32) registeredRingFile {
	return registeredRingFile{index: index}
}

func (f registeredRingFile) Name() string {
	return string(f.AppendString(nil, nil))
}

func (registeredRingFile) Flags() Flags {
	return unknownFlag
}

// FD reports -1: the index is not a descriptor, and callers that key state on
// FD() must not mistake it for one.
func (registeredRingFile) FD() int32 {
	return -1
}

func (f registeredRingFile) String() string {
	return f.Name()
}

// AppendString implements StringAppender, rendering "io_uring:reg[<index>]".
func (f registeredRingFile) AppendString(dst []byte, _ func(string) string) []byte {
	dst = append(dst, "io_uring:reg["...)
	dst = strconv.AppendInt(dst, int64(f.index), 10)
	return append(dst, ']')
}

// --- compile-time interface satisfaction assertions ---
//
// *FdFile is the primary public implementation of File used throughout the
// codebase. The assertion causes a build error if FdFile drifts out of sync
// with the File interface contract.

var _ File = (*FdFile)(nil)
var _ File = anonymousMappingFile{}
var _ File = registeredRingFile{}

var _ StringAppender = (*FdFile)(nil)
var _ StringAppender = oldnameNewnameFile{}
var _ StringAppender = pathnameFile{}
var _ StringAppender = anonymousMappingFile{}
var _ StringAppender = registeredRingFile{}
