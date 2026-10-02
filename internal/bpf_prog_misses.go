package internal

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The part of the kernel's struct bpf_prog_info (include/uapi/linux/bpf.h)
// ior reads: the __u64 recursion_misses, which lies at byte 208 on every
// architecture (the struct is laid out with explicit 64-bit alignment).
// Asking for no more than this prefix is what an older kernel is asked too:
// it fills what it knows and reports the length it filled.
const (
	bpfProgInfoMissesOffset = 208
	bpfProgInfoMissesEnd    = bpfProgInfoMissesOffset + 8
)

// bpfObjInfoAttr is the bpf_attr of BPF_OBJ_GET_INFO_BY_FD: the object's fd,
// the size of the caller's buffer (in) and of what the kernel wrote (out),
// and the buffer.
type bpfObjInfoAttr struct {
	fd      uint32
	infoLen uint32
	info    uint64
}

// progRecursionMisses reads how often the kernel skipped the loaded program
// behind fd instead of running it (see skippedRunCounter for when it does).
// reported is false on a kernel whose bpf_prog_info ends before the field.
//
// The call is one bpf(2) of the kind that reads an object's description. It
// is not a map operation and does not raise bpf_prog_active (only the map
// operations of kernel/bpf/syscall.c call bpf_disable_instrumentation), so
// reading the evidence never causes the skips it counts.
func progRecursionMisses(fd int) (misses uint64, reported bool, err error) {
	var info [bpfProgInfoMissesEnd]byte
	attr := bpfObjInfoAttr{
		fd:      uint32(fd),
		infoLen: uint32(len(info)),
		info:    uint64(uintptr(unsafe.Pointer(&info[0]))),
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(&info)
	if errno != 0 {
		return 0, false, fmt.Errorf("read the info of bpf program fd %d: %w", fd, errno)
	}
	misses, reported = decodeProgRecursionMisses(info[:], attr.infoLen)
	return misses, reported, nil
}

// decodeProgRecursionMisses takes recursion_misses out of a bpf_prog_info
// buffer of which the kernel filled the first infoLen bytes. A kernel that
// filled less than the field's end does not know the field, and the zeroes
// behind what it filled are not a count: reported is false then.
func decodeProgRecursionMisses(info []byte, infoLen uint32) (misses uint64, reported bool) {
	if infoLen < bpfProgInfoMissesEnd || len(info) < bpfProgInfoMissesEnd {
		return 0, false
	}
	return binary.NativeEndian.Uint64(info[bpfProgInfoMissesOffset:bpfProgInfoMissesEnd]), true
}

// skippedRunsCountedSince is the first kernel whose classic tracepoint
// programs count a skipped run: before Linux 6.7 trace_call_bpf returned
// without running the programs and without a word, and recursion_misses only
// ever moved for trampoline and raw tracepoint programs. A zero read from
// such a kernel is not a count either.
var skippedRunsCountedSince = [2]int{6, 7}

// kernelCountsSkippedRuns reports whether the kernel release (uname -r, such
// as "7.2.5-200.fc44.x86_64") is one whose classic tracepoint programs count
// their skipped runs. It goes by the upstream version: a distribution kernel
// that backported the counting to an older release is taken for one that
// does not count, which only costs the evidence, and a release that cannot be
// parsed is taken the same way.
func kernelCountsSkippedRuns(release string) bool {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	minorDigits := parts[1]
	if end := strings.IndexFunc(minorDigits, func(r rune) bool { return r < '0' || r > '9' }); end >= 0 {
		minorDigits = minorDigits[:end]
	}
	minor, err := strconv.Atoi(minorDigits)
	if err != nil {
		return false
	}
	if major != skippedRunsCountedSince[0] {
		return major > skippedRunsCountedSince[0]
	}
	return minor >= skippedRunsCountedSince[1]
}

// runningKernelRelease returns uname's release string, "" when uname fails.
func runningKernelRelease() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return unix.ByteSliceToString(uts.Release[:])
}
