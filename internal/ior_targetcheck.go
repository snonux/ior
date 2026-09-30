package internal

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"ior/internal/flags"
)

// procRoot is the procfs mount checkTraceTarget inspects. Tests point it at a
// temporary directory laid out like /proc.
const procRoot = "/proc"

// checkTraceTarget reports why a -pid/-tid scope can never match anything,
// or nil when the scope is plausible. A filter on a process or thread that
// does not exist (a typo, a stale pid, a -tid that belongs to another
// process than -pid) used to start normally and then run the whole -duration
// with zero rows and exit 0, which is indistinguishable from "the target did
// nothing". The kernel-side filters compare plain numbers, so nothing else
// would ever notice.
//
// Only a definite "does not exist" answer counts. Any other stat failure
// (for example EACCES under hidepid) says nothing about the target, so it is
// treated as plausible rather than refusing a trace that might work. The
// check is inherently a snapshot - the target can still exit right after -
// but that later case is the event loop's job (eventLoop.endTraceOnTargetExit).
//
// root is the procfs mount (procRoot in production).
func checkTraceTarget(root string, cfg flags.Config) error {
	pid, tid := cfg.PidFilter, cfg.TidFilter
	if pid > 0 && !procEntryExists(filepath.Join(root, strconv.Itoa(pid))) {
		return fmt.Errorf("-pid %d: no such process", pid)
	}
	if tid <= 0 {
		return nil
	}
	if pid > 0 {
		// A thread is listed under its process; /proc/<tid> resolves for any
		// thread, so only the per-process task directory proves membership.
		if !procEntryExists(filepath.Join(root, strconv.Itoa(pid), "task", strconv.Itoa(tid))) {
			return fmt.Errorf("-tid %d: not a thread of -pid %d (the pid and tid filters are ANDed, so nothing could ever match)", tid, pid)
		}
		return nil
	}
	if !procEntryExists(filepath.Join(root, strconv.Itoa(tid))) {
		return fmt.Errorf("-tid %d: no such thread", tid)
	}
	return nil
}

// procEntryExists is false only when stat says path does not exist; every
// other outcome, including stat failures such as EACCES, counts as existing
// (see checkTraceTarget for why).
func procEntryExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !errors.Is(err, fs.ErrNotExist)
}

// reportTraceTarget applies checkTraceTarget to the session. A headless run
// (probes == nil) has nobody who could correct the scope later, so an
// impossible one is a startup error with a non-zero exit. The TUI keeps the
// session alive and lets the user pick another target in the pid picker or
// filter, and its picker sources pids from a live scan that can lose a race
// with the process exiting, so there it is a warning row instead.
func reportTraceTarget(cfg flags.Config, headless bool, warn func(args ...any)) error {
	err := checkTraceTarget(procRoot, cfg)
	if err == nil {
		return nil
	}
	if headless {
		return err
	}
	warn("ior: " + err.Error() + ": the trace will stay empty")
	return nil
}
