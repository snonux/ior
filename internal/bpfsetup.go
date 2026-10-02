package internal

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"

	"ior/internal/flags"

	bpf "github.com/aquasecurity/libbpfgo"
)

// setBPFGlobals writes the user-visible filters into the opened (not yet
// loaded) BPF object. warn receives non-fatal degradations (see
// setTidFilterTgid); it must not be nil.
func setBPFGlobals(cfg flags.Config, bpfModule *bpf.Module, warn func(args ...any)) error {
	// Ignore `ior` process itself from the filter.
	if err := bpfModule.InitGlobalVariable("IOR_PID_FILTER", uint32(os.Getpid())); err != nil {
		return fmt.Errorf("unable set IOR_PID_FILTER: %w", err)
	}
	if err := bpfModule.InitGlobalVariable("PID_FILTER", uint32(cfg.PidFilter)); err != nil {
		return fmt.Errorf("unable to set up PID_FILTER global variable: %w", err)
	}
	if err := bpfModule.InitGlobalVariable("TID_FILTER", uint32(cfg.TidFilter)); err != nil {
		return fmt.Errorf("unable to set up TID_FILTER global variable: %w", err)
	}
	return setTidFilterTgid(cfg, bpfModule.InitGlobalVariable, warn)
}

// errSymbolNotFound is the text libbpfgo's InitGlobalVariable returns for a
// global the object does not define. libbpfgo exposes no sentinel for it (it
// is a bare errors.New), so the message is matched. Two tests guard the text:
// TestLibbpfgoReportsAMissingGlobalAsSymbolNotFound opens a real object
// without privileges (SkipMemlockBump) and fails on a libbpfgo upgrade that
// rewords it, and the injected-setter tests pin that any other error stays
// fatal, so a reword can only ever fail closed (setup error), never swallow
// real breakage.
const errSymbolNotFound = "symbol not found"

// isMissingSymbol reports whether err is libbpfgo's "the object does not
// define this global" answer, the one InitGlobalVariable failure setup
// tolerates for an optional global.
func isMissingSymbol(err error) bool {
	return err != nil && err.Error() == errSymbolNotFound
}

// setTidFilterTgid sets the TID_FILTER_TGID global through setGlobal (the
// module's InitGlobalVariable; injected so a test can return errors a real
// object cannot provoke). The global only exists in objects built from
// 34b016d on, and an IOR_BPF_OBJECT override older than that has no symbol to
// write, so a missing symbol is skipped, not fatal: without -tid the unset
// value noTgid is what every run writes anyway. Only -tid makes the scoping
// matter: such an object cannot restrict the group-dead exit forwarding to the
// -tid target's process, so depending on its age it forwards every group-dead
// exit or none, and the warning says so without claiming which. Any other
// setGlobal failure is still an error.
func setTidFilterTgid(cfg flags.Config, setGlobal func(name string, value any) error, warn func(args ...any)) error {
	err := setGlobal("TID_FILTER_TGID", tidFilterTgid(cfg, procTgid))
	if err == nil {
		return nil
	}
	if !isMissingSymbol(err) {
		return fmt.Errorf("unable to set up TID_FILTER_TGID global variable: %w", err)
	}
	if cfg.TidFilter > 0 {
		warn("BPF object has no TID_FILTER_TGID global (built before it existed): " +
			"it cannot scope the process-exit forwarding to the -tid target")
	}
	return nil
}

// fileIdentEnv switches the BPF file-identity capture off for a run when set
// to 0, no, false or off (task 603; internal/c/fileident.c). The capture is
// on by default and costs a few dozen instructions per single-descriptor
// syscall; the switch is the way out should its kernel-side walk ever be
// refused by a verifier this tree was not loaded on (it is compiled out of
// the programs when the global is 0), or cost too much for a workload.
const fileIdentEnv = "IOR_FILE_IDENT"

// fileIdentWanted parses the fileIdentEnv value: unset or empty means on, as
// do 1, yes, true and on; 0, no, false and off switch the capture off. Any
// other value is reported through warn and leaves the capture on, so a typo
// cannot silently change what the rows mean.
func fileIdentWanted(value string, warn func(args ...any)) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "1", "yes", "true", "on":
		return true
	case "0", "no", "false", "off":
		return false
	}
	warn(fmt.Sprintf("%s=%q is not understood (use 0 or 1): file identity capture stays on", fileIdentEnv, value))
	return true
}

// fileIdentCaptureWanted decides whether this run switches the capture on:
// the environment does not say no (envValue, fileIdentWanted) and the running
// kernel can capture at all (kernelCan, kernelHasFileIdentKfunc). The
// environment is read first, so its typo warning does not depend on the
// kernel.
//
// The kernel half exists because "the object has the global" is not "the
// kernel fills the word": without the bpf_rdonly_cast kfunc the walk compiles
// to a constant 0 (internal/c/fileident.c), and user space would still
// compare - which is harmless for the rows, 0 contradicts nothing, but makes
// every procfs resolution pay a second readlink for an identity nobody can
// match. Switching the global off as well also keeps the walk out of the
// programs on exactly the kernels it was never loaded on.
func fileIdentCaptureWanted(envValue string, kernelCan func() bool, warn func(args ...any)) bool {
	return fileIdentWanted(envValue, warn) && kernelCan()
}

// setFileIdentGlobal writes the IOR_FILE_IDENT global through setGlobal (the
// module's InitGlobalVariable) and reports whether the object will write the
// file identity words of its records: it has the global and want switched it
// on. An object built before the capture has no such symbol - a missing
// symbol is therefore not an error, it is the answer "no": such an object
// leaves stale padding where the identity would be, and the event loop must
// not read it (eventLoop.trustFileIdents). Any other failure is an error.
func setFileIdentGlobal(want bool, setGlobal func(name string, value any) error) (bool, error) {
	value := uint32(0)
	if want {
		value = 1
	}
	err := setGlobal("IOR_FILE_IDENT", value)
	if err == nil {
		return want, nil
	}
	if isMissingSymbol(err) {
		return false, nil
	}
	return false, fmt.Errorf("unable to set up IOR_FILE_IDENT global variable: %w", err)
}

// noTgid is the BPF-side "unset" value of TID_FILTER_TGID, matching the -1
// convention of PID_FILTER and TID_FILTER.
const noTgid = ^uint32(0)

// tidFilterTgid returns the thread group the -tid thread belongs to, for the
// BPF global TID_FILTER_TGID. Under -tid, sched_process_exit's group-dead
// record usually comes from another thread of the traced process, so it must
// bypass the tid filter (ior_process_exit_in_scope in internal/c/exec.c) -
// but only for that process: an unscoped bypass under -tid without -pid would
// emit a record for every process death on the system.
//
// With -pid given the pid filter already is that scope. Otherwise the tgid is
// read from procfs once at setup; cfg.PidFilter is deliberately left alone,
// because it also scopes the aggregate drainer. If the thread cannot be
// resolved (it is already gone, or procfs is unreadable) the result is noTgid
// and no group-dead record bypasses the tid filter: the process's fd entries
// then age out through the LRU cap, which is harmless for a thread that no
// longer produces syscalls anyway.
func tidFilterTgid(cfg flags.Config, readTgid func(tid int) (int, error)) uint32 {
	if cfg.TidFilter <= 0 {
		return noTgid
	}
	if cfg.PidFilter > 0 {
		return uint32(cfg.PidFilter)
	}
	tgid, err := readTgid(cfg.TidFilter)
	if err != nil || tgid <= 0 {
		return noTgid
	}
	return uint32(tgid)
}

// procTgid reads the thread group id of tid from /proc/<tid>/status. Thread
// ids are addressable directly under /proc even though only tgids are listed.
func procTgid(tid int) (int, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return 0, fmt.Errorf("open status of tid %d: %w", tid, err)
	}
	// Read-only file: a close error cannot lose data, so it is discarded.
	defer func() { _ = f.Close() }()
	return parseStatusTgid(f)
}

// parseStatusTgid extracts the "Tgid:" field of a /proc/<id>/status file.
func parseStatusTgid(r io.Reader) (int, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		value, ok := strings.CutPrefix(scanner.Text(), "Tgid:")
		if !ok {
			continue
		}
		tgid, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return 0, fmt.Errorf("parse Tgid %q: %w", value, err)
		}
		return tgid, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read status: %w", err)
	}
	return 0, fmt.Errorf("no Tgid field in status")
}

// resizeBPFMaps applies the user-visible size knobs to the loaded-but-not-yet-
// attached BPF object. Only event_map is resizable: it is a ring buffer, so
// its size is in bytes (not entries) and libbpf rounds the request up to a
// power-of-two multiple of the page size (see ringbufMapSize).
func resizeBPFMaps(cfg flags.Config, bpfModule *bpf.Module) error {
	requested := uint32(cfg.EventMapSize)
	want, err := ringbufMapSize(requested, uint32(os.Getpagesize()))
	if err != nil {
		return fmt.Errorf("resize map event_map to %d: %w", requested, err)
	}
	// resizeBPFMap already includes the map name in any error it returns,
	// so no additional wrapping is needed here.
	return resizeBPFMap(bpfModule, "event_map", requested, want)
}

// ringbufMapSize mirrors libbpf's adjust_ringbuf_sz(): the kernel requires a
// BPF_MAP_TYPE_RINGBUF's max_entries to be a power-of-two multiple of the page
// size, so bpf_map__set_max_entries() silently replaces any other value with
// the smallest page_size*2^n strictly greater than the request. Exact
// matches pass through unchanged. It returns the size the map will really
// have, so the post-resize sanity check compares against that rather than
// rejecting every -mapSize that is not already a valid ring-buffer size. A
// request too large to round up inside uint32 is an error: libbpf's own
// adjust_ringbuf_sz() gives up there and returns the original size unchanged
// (leaving the kernel to reject it with EINVAL at load time), so failing early
// here gives the user a clear message instead of an opaque load error.
func ringbufMapSize(requested, pageSize uint32) (uint32, error) {
	if requested == 0 || pageSize == 0 {
		return 0, fmt.Errorf("invalid ring buffer size %d (page size %d)", requested, pageSize)
	}
	if requested%pageSize == 0 && isPowerOfTwo(requested/pageSize) {
		return requested, nil
	}
	for mul := uint32(1); mul <= math.MaxUint32/pageSize; mul <<= 1 {
		if mul*pageSize > requested {
			return mul * pageSize, nil
		}
	}
	return 0, fmt.Errorf("ring buffer size %d is too large to round up to a power-of-two multiple of the %d byte page size", requested, pageSize)
}

func isPowerOfTwo(n uint32) bool {
	return n != 0 && n&(n-1) == 0
}

// resizeBPFMap sets the map's max_entries to requested and verifies libbpf
// took it as want. want equals requested for plain maps; for a ring buffer it
// is the page-rounded size (see ringbufMapSize).
func resizeBPFMap(module *bpf.Module, name string, requested, want uint32) error {
	m, err := module.GetMap(name)
	if err != nil {
		// Wrap with map name so callers know which map lookup failed.
		return fmt.Errorf("resize map %s: get map: %w", name, err)
	}
	if err = m.SetMaxEntries(requested); err != nil {
		// Wrap with map name and target size so callers know which map failed
		// and what size was requested.
		return fmt.Errorf("resize map %s to %d: %w", name, requested, err)
	}
	if actual := m.MaxEntries(); actual != want {
		return fmt.Errorf("resize map %s to %d failed: actual size is %d, expected %d", name, requested, actual, want)
	}
	return nil
}
