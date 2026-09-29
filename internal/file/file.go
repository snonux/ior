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

// FdFile represents a file descriptor-backed file reference.
type FdFile struct {
	fd               int32
	name             string
	flags            Flags
	closeOnExecKnown bool
	closeOnExec      bool
	flagsFromProcFS  bool
}

// NewFd constructs an FdFile from explicit descriptor metadata.
func NewFd(fd int32, name string, flags int32) *FdFile {
	f := &FdFile{
		fd:   fd,
		name: name,
	}
	f.SetFlags(flags)
	return f
}

// NewFdWithPid resolves descriptor metadata from /proc/<pid>/fd.
func NewFdWithPid(fd int32, pid uint32) *FdFile {
	f := &FdFile{
		fd: fd,
	}
	var err error

	procPath := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	f.name, err = os.Readlink(procPath)
	if err != nil {
		f.name = ""
		f.SetFlags(-1)
		f.flagsFromProcFS = true
		return f
	}

	flags, err := readFlagsFromFdInfo(fd, pid)
	if err != nil {
		f.SetFlags(-1)
	} else {
		f.SetFlags(int32(flags))
	}
	f.flagsFromProcFS = true

	return f
}

// Dup copies the FdFile metadata onto descriptor number fd. Callers modelling
// a descriptor-creating syscall must apply descriptor-specific flag semantics
// to the copy; unlike status flags, O_CLOEXEC is not shared by duplicates.
// This method is also used to detach metadata before a pair is emitted.
func (f *FdFile) Dup(fd int32) *FdFile {
	dupFd := *f
	dupFd.fd = fd
	return &dupFd
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
	var sb strings.Builder

	if len(f.name) == 0 {
		sb.WriteString("E:name") // Empty name string
	} else {
		sb.WriteString(f.name)
	}
	sb.WriteString("%(")
	sb.WriteString(strconv.FormatInt(int64(f.fd), 10))
	sb.WriteString(",")
	sb.WriteString(f.Flags().String())
	sb.WriteString(")")

	return sb.String()
}

// Flags returns the file's open-flags word.
func (f *FdFile) Flags() Flags {
	// Keep a partially known word unknown. Returning O_CLOEXEC alone when the
	// status word is unavailable would make its zero access-mode bits look like
	// an authoritative O_RDONLY. The separately remembered descriptor bit is
	// folded in when F_GETFL later supplies the status word.
	return f.flags
}

// FD returns the descriptor number the metadata was recorded for.
func (f *FdFile) FD() int32 {
	return f.fd
}

// SetFlags replaces a complete combined flag word outright. Use SetStatusFlags
// for F_GETFL and MergeFlags for partial updates.
func (f *FdFile) SetFlags(flags int32) {
	f.flags = Flags(flags)
	if f.flags == unknownFlag {
		f.closeOnExecKnown = false
		f.closeOnExec = false
		return
	}
	f.closeOnExecKnown = true
	f.closeOnExec = flags&syscall.O_CLOEXEC != 0
}

// SetStatusFlags replaces the status word reported by F_GETFL while retaining
// any separately learned FD_CLOEXEC state. When that descriptor bit is still
// unknown, the flattened output keeps the historical clear representation;
// a later F_GETFD will make it authoritative.
func (f *FdFile) SetStatusFlags(flags int32) {
	flags &^= syscall.O_CLOEXEC
	if f.closeOnExecKnown && f.closeOnExec {
		flags |= syscall.O_CLOEXEC
	}
	f.flags = Flags(flags)
}

// AddFlags ORs the given bits into the flag word.
func (f *FdFile) AddFlags(flags int32) {
	if flags&syscall.O_CLOEXEC != 0 {
		f.closeOnExecKnown = true
		f.closeOnExec = true
	}
	if f.flags == unknownFlag {
		return
	}
	f.flags = Flags(int32(f.flags) | flags)
}

// MergeFlags replaces only the bits selected by mask with the corresponding
// bits of flags and leaves every other bit of the current flag word intact.
//
// This is the update shape fcntl(2) F_SETFL has: it changes the settable
// status flags only, while the access mode (O_RDONLY/O_WRONLY/O_RDWR) and the
// creation flags of the descriptor keep the values open(2) gave them. Callers
// typically pass the full word they got from F_GETFL, so a plain SetFlags of
// arg&mask would mask the access mode away and make a read-write descriptor
// report as read-only for the rest of its life.
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
	if f.flags == unknownFlag {
		return
	}
	f.flags = Flags((int32(f.flags) &^ mask) | (flags & mask))
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
	var sb strings.Builder

	sb.WriteString("old:")
	sb.WriteString(f.Oldname)
	sb.WriteString(" ->new:")
	sb.WriteString(f.Newname)
	sb.WriteString("%(")
	sb.WriteString(f.Flags().String())
	sb.WriteString(")")

	return sb.String()
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
	var sb strings.Builder

	sb.WriteString("pathname:")
	sb.WriteString(f.Pathname)
	sb.WriteString("%(")
	sb.WriteString(f.Flags().String())
	sb.WriteString(")")

	return sb.String()
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

// --- compile-time interface satisfaction assertions ---
//
// *FdFile is the primary public implementation of File used throughout the
// codebase. The assertion causes a build error if FdFile drifts out of sync
// with the File interface contract.

var _ File = (*FdFile)(nil)
var _ File = anonymousMappingFile{}
