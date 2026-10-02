package internal

import (
	"bytes"
	"encoding/binary"
	"os"
	"sync"
)

// Does the running kernel have the kfunc the file identity capture needs
// (task 603)?
//
// The kernel program's walk is compiled in only where bpf_rdonly_cast
// resolves (internal/c/fileident.c): elsewhere every identity is 0. User
// space has to know that too, or it compares identities that cannot exist
// (fileIdentCaptureWanted). Three ways to find out were weighed:
//
//   - /proc/kallsyms lists the kfunc, but reading it means the kernel formats
//     every symbol: 220 ms of system time here (445k lines), on every trace
//     start, and more on a larger kernel.
//   - Watching the records - "the first N identity words were all 0, so the
//     kernel captures none" - needs no kernel source at all but is unsound:
//     0 is a legitimate identity of a call on a number that is not open, and
//     a program that closes every possible descriptor after fork produces
//     thousands of those in a row. A wrong guess would switch the check off
//     for the rest of the run, silently.
//   - The kernel's BTF names every kfunc, and it is the very table libbpf
//     resolves the weak ksym against when it loads the object: the two cannot
//     disagree. /sys/kernel/btf/vmlinux is a 7 MB read (a few milliseconds)
//     and the name is a plain string in its string section.
//
// So the BTF is searched, once per process (a TUI session reloads the object
// on every trace restart). The search is for the name as a whole string in
// the string section, not for a BTF_KIND_FUNC of that name: walking the type
// section would add a parser for no gain, since no kernel calls anything
// else bpf_rdonly_cast. Only this one term of ior_file_ident_supported is
// checked; the other two (struct kiocb exists, ki_filp at offset 0) hold on
// every kernel, and if one ever does not, the capture reports 0 and ior
// behaves as before this check existed: correct, with the extra readlink.

// kernelBTFPath is where the kernel publishes its own BTF.
const kernelBTFPath = "/sys/kernel/btf/vmlinux"

// fileIdentKfunc is the kfunc internal/c/fileident.c declares as a weak ksym.
const fileIdentKfunc = "bpf_rdonly_cast"

// kernelHasFileIdentKfunc reports whether the running kernel has
// fileIdentKfunc, read from its BTF once per process.
var kernelHasFileIdentKfunc = sync.OnceValue(func() bool {
	return btfFileNamesSymbol(kernelBTFPath, fileIdentKfunc)
})

// btfFileNamesSymbol is btfNamesSymbol of the BTF file at path. A file that
// cannot be read counts as naming the symbol: then nothing is known, and
// assuming the capture works is the choice that keeps every row correct (an
// identity that never arrives contradicts nothing; a capture switched off by
// mistake would lose the check).
func btfFileNamesSymbol(path, name string) bool {
	blob, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	return btfNamesSymbol(blob, name)
}

// btfMagic opens a BTF blob; the header that follows is version, flags (one
// byte each), hdr_len, type_off, type_len, str_off, str_len (four bytes
// each), the offsets counted from the end of the header.
const (
	btfMagic        = 0xeb9f
	btfHeaderMinLen = 24
)

// btfNamesSymbol reports whether the string section of the BTF blob holds
// name as a whole string. A blob it cannot make sense of (truncated, another
// byte order, offsets past the end) counts as naming it, for the reason
// btfFileNamesSymbol gives.
func btfNamesSymbol(blob []byte, name string) bool {
	if len(blob) < btfHeaderMinLen || binary.LittleEndian.Uint16(blob) != btfMagic {
		return true
	}
	headerLen := uint64(binary.LittleEndian.Uint32(blob[4:]))
	start := headerLen + uint64(binary.LittleEndian.Uint32(blob[16:]))
	end := start + uint64(binary.LittleEndian.Uint32(blob[20:]))
	if start > end || end > uint64(len(blob)) {
		return true
	}
	// Every string is NUL-terminated and the section opens with the empty
	// string, so a whole string is the name between two NULs.
	return bytes.Contains(blob[start:end], []byte("\x00"+name+"\x00"))
}
