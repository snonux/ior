package file

import (
	"os"
	"strings"
	"sync"
	"syscall"
)

// Flags is a file's open-flags word (O_RDONLY, O_CREAT, ...), the raw int
// as the kernel reports it; -1 (unknownFlag) marks a descriptor whose flags
// could not be determined from procfs.
type Flags int32

var flagsToHumanCache sync.Map
var unknownFlag = Flags(-1)

type tuple struct {
	syscallNr int
	str       string
}

var flagsToHuman = []tuple{
	{-1, "O_NONE"},
	{syscall.O_RDONLY, "O_RDONLY"},
	{syscall.O_WRONLY, "O_WRONLY"},
	{syscall.O_RDWR, "O_RDWR"},
	{syscall.O_ACCMODE, "O_ACCMODE"},
	{syscall.O_APPEND, "O_APPEND"},
	{syscall.O_ASYNC, "O_ASYNC"},
	{syscall.O_CLOEXEC, "O_CLOEXEC"},
	{syscall.O_CREAT, "O_CREAT"},
	{syscall.O_DIRECT, "O_DIRECT"},
	{syscall.O_DIRECTORY, "O_DIRECTORY"},
	{syscall.O_DSYNC, "O_DSYNC"},
	{syscall.O_EXCL, "O_EXCL"},
	{syscall.O_NOATIME, "O_NOATIME"},
	{syscall.O_NOCTTY, "O_NOCTTY"},
	{syscall.O_NOFOLLOW, "O_NOFOLLOW"},
	{syscall.O_NONBLOCK, "O_NONBLOCK"},
	{syscall.O_SYNC, "O_SYNC"},
	{syscall.O_TRUNC, "O_TRUNC"},
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
// names ("O_RDONLY|O_CREAT"), or "O_NONE" for the unknown word.
func (f Flags) String() string {
	var strs []string

	if f == -1 {
		return "O_NONE"
	}

	if int(f)&(os.O_WRONLY|os.O_RDWR) == 0 {
		// Must be read only then
		strs = append(strs, "O_RDONLY")
	}
	for _, toHuman := range flagsToHuman[2:] {
		if int(f)&toHuman.syscallNr == toHuman.syscallNr {
			strs = append(strs, toHuman.str)
		}
	}
	if len(strs) == 0 {
		strs = append(strs, "O_RDONLY")
	}

	return strings.Join(strs, "|")
}
