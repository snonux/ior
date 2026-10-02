package internal

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// The boot clock, in the domain of the BPF record timestamps (task y13).
//
// The BPF programs stamp every record with bpf_ktime_get_boot_ns, the host's
// CLOCK_BOOTTIME. The loop compares those stamps with boot-clock readings of
// its own in four places: the comm recheck (provisionalSeedNeedsRecheck), the
// close row's procfs rule (fdTracker.cacheReadBefore), the restart fold's
// drop watch (restartDropWatch) and its probe-change stamp (noteProbeChange).
// All of them read the clock through bootClockNs.
//
// Inside a time namespace (unshare -T --boottime N) the two clocks differ:
// clock_gettime(CLOCK_BOOTTIME) returns the host's value plus the namespace's
// boottime offset, the BPF helper is not namespaced. Measured on Linux 7.2
// with --boottime 1000: /proc/uptime read 127791.96 while a BPF program's
// bpf_ktime_get_boot_ns read 126791.75 s. Uncorrected, a positive offset put
// every reading in the records' future (no procfs answer ever counted as read
// before a close, so those close rows lost their name; a TUI run refused
// every restart fold for the length of the offset after a probe change), and
// a negative one put it in their past (a close row took the name of the file
// that reused its number; a comm recheck that was needed was skipped; a
// restart fold that lost records or a probe change should have refused was
// made - restartDropWatch, noteProbeChange).
//
// So bootClockNs subtracts the offset, read once from /proc/self/
// timens_offsets. Reading it once is sound: the kernel refuses to change the
// offsets of a namespace a task has entered (EACCES), and ior never changes
// its namespace. The offsets in that file are relative to the host's clocks
// whatever the nesting (a namespace created inside one with offset 1000 and
// given 500 reads host + 500), so one subtraction reaches the BPF domain.
//
// The file describes the namespace the process's *children* are placed in
// (time_for_children), which is not always the one its own clock runs in:
// unshare(CLONE_NEWTIME) leaves the caller where it is, and only an exec (on
// kernels that switch there; older ones do not) or a fork moves a task. A
// process that unshared and wrote "boottime -2 500000000" kept the host's
// clock while its timens_offsets showed the new offset. ior never unshares,
// so on a current kernel the two are the same namespace, but started as
// "unshare -T --boottime N ior" on a kernel that does not switch on exec it
// would stay in the old namespace next to a file that says N. The offset is
// therefore used only when /proc/self/ns/time and time_for_children name the
// same namespace; otherwise it is unknown, taken as 0 and warned about once
// (warnUnknownBootClock), as it is when the file cannot be read or parsed.
// A kernel without time namespaces (no CONFIG_TIME_NS, or before 5.6) has
// neither the file nor the ns/time link: the offset is 0, without a warning.
// A missing file is read that way only then. If the link exists, or /proc/self
// itself does not (/proc not mounted, or mounted from another PID namespace),
// the offset is unknown as well (kernelHasNoTimeNamespaces).

const (
	// procSelfDir is where the running process's time namespace is described.
	procSelfDir = "/proc/self"
	// timensBoottimeName and timensBoottimeID are the two spellings of the
	// boottime line's first field in timens_offsets: the name, which is what
	// Linux 7.2 prints, and the clock id CLOCK_BOOTTIME (7), which the kernel
	// accepts on write ("7 3 250000000" read back as a boottime line) and is
	// accepted here too in case a kernel prints it.
	timensBoottimeName = "boottime"
	timensBoottimeID   = "7"
	// maxTimensOffsetSec bounds the seconds of an offset so that the offset
	// in nanoseconds, sub-second part included, fits an int64. The kernel
	// stays below it: it took "boottime 4000000000 0" and refused
	// "boottime 9223372036 0" with ERANGE.
	maxTimensOffsetSec = math.MaxInt64/nsPerSec - 1
	nsPerSec           = 1_000_000_000
)

// bootClockDomain is what ior learned about the clock its own CLOCK_BOOTTIME
// readings are on, relative to the host's (the BPF stamps').
type bootClockDomain struct {
	// offsetNs is this process's CLOCK_BOOTTIME minus the host's.
	offsetNs int64
	// warning is non-empty when the offset could not be determined and 0 is
	// assumed.
	warning string
}

// ownBootClockDomain resolves the domain on first use and keeps it for the
// run. First use rather than an explicit startup step, so that no reading can
// be taken before the offset is known, whatever the order of setup.
var ownBootClockDomain = sync.OnceValue(func() bootClockDomain {
	return resolveBootClockDomain(procSelfDir)
})

// warnUnknownBootClock reports, through warn, that the boottime offset of
// ior's time namespace could not be determined; it says nothing when the
// offset is known. Trace setup calls it once per trace session, before the
// collected warnings are handed to the event loop: a headless run warns once,
// a TUI run once for each trace it starts (a restart of the trace runs the
// setup again, and its warning rows start empty).
func warnUnknownBootClock(warn func(...any)) {
	ownBootClockDomain().report(warn)
}

// report hands the domain's warning, if it has one, to warn.
func (d bootClockDomain) report(warn func(...any)) {
	if d.warning != "" {
		warn(d.warning)
	}
}

// bootClockNs reads CLOCK_BOOTTIME and converts it to the host's boot clock,
// the one bpf_ktime_get_boot_ns stamps the ring-buffer records with, so its
// readings order against record times also when ior runs inside a time
// namespace (see the file comment). A failed read (not expected on Linux),
// like a reading the offset turns into no time at all (hostBootNs), returns
// the maximum value, which is the refusing side of all four comparisons:
//   - comm recheck: every seed counts as possibly predating a lost record and
//     keeps its /proc read, until the next drop is stamped
//     (provisionalSeedNeedsRecheck);
//   - close row: a procfs answer stamped with it was read before no close, so
//     the row stays unnamed rather than take a reuser's name;
//   - drop watch: a total first seen at it is older than no interruption, so
//     folds are refused until the total next changes and gets a real stamp;
//   - probe stamp: every row was interrupted before it, so folds are refused
//     for the rest of the run (a later change's stamp is never smaller).
//
// With an offset that was read from a namespace ior really runs in (matching
// ns links) the subtraction cannot produce such a value: the reading is the
// host's clock plus that offset.
func bootClockNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return math.MaxUint64
	}
	return hostBootNs(ts.Nano(), ownBootClockDomain().offsetNs)
}

// hostBootNs takes the namespace's offset out of a CLOCK_BOOTTIME reading. A
// reading or a result that is not a time (negative, or past the int64 range)
// cannot come from a real reading and its real offset; it is answered like a
// failed clock read.
func hostBootNs(readingNs, offsetNs int64) uint64 {
	if readingNs < 0 {
		return math.MaxUint64
	}
	// With a reading of at least 0 the difference leaves the int64 range only
	// upwards (a negative offset), and then wraps to a negative value: the
	// one check below covers both an offset past the reading and that.
	hostNs := readingNs - offsetNs
	if hostNs < 0 {
		return math.MaxUint64
	}
	return uint64(hostNs)
}

// resolveBootClockDomain reads the boottime offset of the time namespace the
// process described by procDir runs in (procDir is /proc/self outside tests).
func resolveBootClockDomain(procDir string) bootClockDomain {
	content, err := os.ReadFile(filepath.Join(procDir, "timens_offsets"))
	if errors.Is(err, fs.ErrNotExist) && kernelHasNoTimeNamespaces(procDir) {
		return bootClockDomain{} // the clocks are the host's
	}
	if err != nil {
		return unknownBootClockDomain(err)
	}
	offsetNs, err := parseTimensBoottimeOffset(string(content))
	if err != nil {
		return unknownBootClockDomain(err)
	}
	if err := ownTimeNamespaceIsChildrens(procDir); err != nil {
		return unknownBootClockDomain(err)
	}
	return bootClockDomain{offsetNs: offsetNs}
}

// kernelHasNoTimeNamespaces tells the one harmless reason for a missing
// timens_offsets from the others. A kernel without time namespaces (no
// CONFIG_TIME_NS, or older than 5.6) has no ns/time link either, in a
// /proc/self that is otherwise there. The file is also missing when procDir
// is not this process's entry at all - /proc not mounted, or the /proc of
// another PID namespace, where /proc/self does not resolve - and ior may well
// run in a time namespace then; and a kernel that has the link always has the
// file. Both of those are an unknown offset, not "none".
func kernelHasNoTimeNamespaces(procDir string) bool {
	if _, err := os.Stat(procDir); err != nil {
		return false
	}
	_, err := os.Lstat(filepath.Join(procDir, "ns", "time"))
	return errors.Is(err, fs.ErrNotExist)
}

// unknownBootClockDomain is the domain when the offset could not be
// determined: no correction, and the warning that says what may go wrong.
func unknownBootClockDomain(cause error) bootClockDomain {
	return bootClockDomain{warning: fmt.Sprintf(
		"Could not determine the boottime offset of ior's time namespace (%v); "+
			"assuming none. If ior runs inside a time namespace with such an "+
			"offset, close rows of descriptors opened before the trace may be "+
			"unnamed or misnamed, and interrupted calls may stay unfolded or be "+
			"folded with a later call.", cause)}
}

// ownTimeNamespaceIsChildrens checks that timens_offsets, which describes the
// namespace of the process's future children, also describes the process's
// own: both ns links must name the same namespace.
func ownTimeNamespaceIsChildrens(procDir string) error {
	own, err := os.Readlink(filepath.Join(procDir, "ns", "time"))
	if err != nil {
		return err
	}
	children, err := os.Readlink(filepath.Join(procDir, "ns", "time_for_children"))
	if err != nil {
		return err
	}
	if own != children {
		return fmt.Errorf("ior runs in %s but timens_offsets describes %s", own, children)
	}
	return nil
}

// parseTimensBoottimeOffset returns the boottime offset, in nanoseconds, from
// the content of a timens_offsets file:
//
//	monotonic           0         0
//	boottime        -1000         0
//
// Each line is a clock, seconds and nanoseconds. The kernel keeps the offset
// as a normalised timespec, so the nanoseconds are never negative and a
// negative offset is a negative second count plus nanoseconds: "-2 500000000"
// is -1.5 s (a child of that namespace read its clock 1.49 s behind the
// host's). Anything else is an error, including a missing boottime line.
func parseTimensBoottimeOffset(content string) (int64, error) {
	for line := range strings.Lines(content) {
		fields := strings.Fields(line)
		if len(fields) == 0 || (fields[0] != timensBoottimeName && fields[0] != timensBoottimeID) {
			continue
		}
		if len(fields) != 3 {
			return 0, fmt.Errorf("timens_offsets: malformed boottime line %q", strings.TrimSpace(line))
		}
		return timensOffsetNs(fields[1], fields[2])
	}
	return 0, errors.New("timens_offsets: no boottime line")
}

// timensOffsetNs converts the seconds and nanoseconds fields of one
// timens_offsets line into nanoseconds, refusing values the kernel never
// prints (nanoseconds outside [0, 1 s), seconds past maxTimensOffsetSec).
func timensOffsetNs(secField, nsecField string) (int64, error) {
	sec, err := strconv.ParseInt(secField, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("timens_offsets: boottime seconds: %w", err)
	}
	nsec, err := strconv.ParseInt(nsecField, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("timens_offsets: boottime nanoseconds: %w", err)
	}
	if nsec < 0 || nsec >= nsPerSec {
		return 0, fmt.Errorf("timens_offsets: boottime nanoseconds %d out of range", nsec)
	}
	if sec > maxTimensOffsetSec || sec < -maxTimensOffsetSec {
		return 0, fmt.Errorf("timens_offsets: boottime seconds %d out of range", sec)
	}
	return sec*nsPerSec + nsec, nil
}
