package file

import (
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// Flags is a file's open-flags word (O_RDONLY, O_CREAT, ...), the raw int
// as the kernel reports it; -1 (unknownFlag) marks a descriptor whose flags
// could not be determined from procfs.
type Flags int32

// linuxOLargefile is the Linux amd64 kernel flag exposed by F_GETFL and
// /proc/<pid>/fdinfo. The userspace O_LARGEFILE constant is zero on amd64,
// so neither syscall.O_LARGEFILE nor unix.O_LARGEFILE can identify this bit.
const linuxOLargefile = 0x8000

var flagsToHumanCache sync.Map
var unknownFlag = Flags(-1)

type flagName struct {
	mask  int
	value int
	name  string
}

var flagsToHuman = []flagName{
	{mask: syscall.O_ACCMODE, value: syscall.O_WRONLY, name: "O_WRONLY"},
	{mask: syscall.O_ACCMODE, value: syscall.O_RDWR, name: "O_RDWR"},
	{mask: syscall.O_ACCMODE, value: syscall.O_ACCMODE, name: "O_ACCMODE"},
	{mask: syscall.O_APPEND, value: syscall.O_APPEND, name: "O_APPEND"},
	{mask: syscall.O_ASYNC, value: syscall.O_ASYNC, name: "O_ASYNC"},
	{mask: syscall.O_CLOEXEC, value: syscall.O_CLOEXEC, name: "O_CLOEXEC"},
	{mask: syscall.O_CREAT, value: syscall.O_CREAT, name: "O_CREAT"},
	{mask: syscall.O_DIRECT, value: syscall.O_DIRECT, name: "O_DIRECT"},
	// Broader masks distinguish each composite from its subset; list it first.
	{mask: unix.O_TMPFILE, value: unix.O_TMPFILE, name: "O_TMPFILE"},
	{mask: unix.O_TMPFILE, value: syscall.O_DIRECTORY, name: "O_DIRECTORY"},
	{mask: syscall.O_SYNC, value: syscall.O_SYNC, name: "O_SYNC"},
	{mask: syscall.O_SYNC, value: syscall.O_DSYNC, name: "O_DSYNC"},
	{mask: syscall.O_EXCL, value: syscall.O_EXCL, name: "O_EXCL"},
	{mask: linuxOLargefile, value: linuxOLargefile, name: "O_LARGEFILE"},
	{mask: syscall.O_NOATIME, value: syscall.O_NOATIME, name: "O_NOATIME"},
	{mask: syscall.O_NOCTTY, value: syscall.O_NOCTTY, name: "O_NOCTTY"},
	{mask: syscall.O_NOFOLLOW, value: syscall.O_NOFOLLOW, name: "O_NOFOLLOW"},
	// O_NDELAY is the same bit on Linux, so use the canonical O_NONBLOCK name.
	{mask: syscall.O_NONBLOCK, value: syscall.O_NONBLOCK, name: "O_NONBLOCK"},
	{mask: unix.O_PATH, value: unix.O_PATH, name: "O_PATH"},
	{mask: syscall.O_TRUNC, value: syscall.O_TRUNC, name: "O_TRUNC"},
}

// Is reports whether every bit of flag is set in the word. An unknown
// flags word (-1) matches nothing.
func (f Flags) Is(flag int) bool {
	if f == unknownFlag {
		return false
	}
	if int(f)&flag == flag {
		return true
	}
	return false
}

// BuildString appends the flag word's human-readable form to sb, using a
// per-value cache so hot render paths avoid re-stringifying.
func (f Flags) BuildString(sb *strings.Builder) {
	if cached, ok := flagsToHumanCache.Load(f); ok {
		str, _ := cached.(string)
		sb.WriteString(str)
		return
	}
	str := f.String()
	cached, loaded := flagsToHumanCache.LoadOrStore(f, str)
	if loaded {
		str, _ = cached.(string)
	}
	sb.WriteString(str)
}

// String renders the flag word as a pipe-separated list of open(2) flag
// names ("O_RDWR|O_CREAT"), or "O_NONE" for the unknown word. Because
// O_RDONLY is zero, it is emitted explicitly when the access-mode bits are
// clear. O_PATH descriptors omit it because they have no usable access mode.
func (f Flags) String() string {
	// 64 bytes hold every realistic combination, so the scratch buffer stays
	// on the stack and String costs only the final string copy.
	var scratch [64]byte
	return string(f.AppendTo(scratch[:0]))
}

// AppendTo appends the String form of the flag word to dst and returns the
// extended slice. It is the single renderer behind String and the -plain
// per-row hot path, which appends into a reused buffer: it walks the small
// flagsToHuman table directly, so it needs neither the []string plus
// strings.Join that String used to build per call nor a cache lookup, and it
// allocates nothing beyond growth of dst.
func (f Flags) AppendTo(dst []byte) []byte {
	if f == unknownFlag {
		return append(dst, "O_NONE"...)
	}
	sep := false
	if int(f)&syscall.O_ACCMODE == syscall.O_RDONLY && int(f)&unix.O_PATH == 0 {
		dst = append(dst, "O_RDONLY"...)
		sep = true
	}

	for _, toHuman := range flagsToHuman {
		if int(f)&toHuman.mask != toHuman.value {
			continue
		}
		if sep {
			dst = append(dst, '|')
		}
		dst = append(dst, toHuman.name...)
		sep = true
	}

	return dst
}
