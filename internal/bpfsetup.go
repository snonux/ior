package internal

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"ior/internal/flags"

	bpf "github.com/aquasecurity/libbpfgo"
)

func setBPFGlobals(cfg flags.Config, bpfModule *bpf.Module) error {
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
	tgid := tidFilterTgid(cfg, procTgid)
	if err := bpfModule.InitGlobalVariable("TID_FILTER_TGID", tgid); err != nil {
		return fmt.Errorf("unable to set up TID_FILTER_TGID global variable: %w", err)
	}
	return nil
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

func resizeBPFMaps(cfg flags.Config, bpfModule *bpf.Module) error {
	// resizeBPFMap already includes the map name in any error it returns,
	// so no additional wrapping is needed here.
	return resizeBPFMap(bpfModule, "event_map", uint32(cfg.EventMapSize))
}

func resizeBPFMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap(name)
	if err != nil {
		// Wrap with map name so callers know which map lookup failed.
		return fmt.Errorf("resize map %s: get map: %w", name, err)
	}
	if err = m.SetMaxEntries(size); err != nil {
		// Wrap with map name and target size so callers know which map failed
		// and what size was requested.
		return fmt.Errorf("resize map %s to %d: %w", name, size, err)
	}
	if actual := m.MaxEntries(); actual != size {
		return fmt.Errorf("resize map %s to %d failed: actual size is %d", name, size, actual)
	}
	return nil
}
