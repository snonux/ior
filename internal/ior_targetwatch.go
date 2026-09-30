package internal

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ior/internal/flags"

	"golang.org/x/sys/unix"
)

// targetWatch answers "is the -pid target still the process ior was started
// for?" without the ring buffer (task vr2). It is opened before the probes are
// attached, because that is what makes it immune to pid reuse: a target that
// dies and whose pid is recycled while ior is still attaching must count as
// gone, which only a snapshot taken at startup can tell.
//
// Two mechanisms, strongest first:
//
//   - a pidfd (pidfd_open, Linux 5.3+) refers to that one process for good;
//     it becomes readable when the process exits, and a recycled pid cannot
//     fool it.
//   - the start time (field 22 of /proc/<pid>/stat, in clock ticks since
//     boot) captured at open: a different value later means the pid belongs to
//     another process now, and a missing /proc entry means it is gone. This
//     backs the pidfd (kernel too old, EPERM) and is the only mechanism when
//     pidfd_open fails.
//
// A zombie with no other live thread counts as gone too: it has exited and
// only its parent has not reaped it, and the group-dead record was emitted
// when it did.
type targetWatch struct {
	pid       int
	root      string // procfs mount (procRoot in production)
	pidfd     int    // -1 when pidfd_open failed
	startTime string // field 22 of /proc/<pid>/stat at open; "" when unknown
}

// openTargetWatch starts watching pid, which must be the -pid filter (> 0).
// It never fails: a target that is unreadable now leaves the watch with only
// the mechanisms that still work (an absent /proc entry still means gone).
// root is the procfs mount (procRoot in production). Close releases the pidfd.
func openTargetWatch(root string, pid int) *targetWatch {
	w := &targetWatch{pid: pid, root: root, pidfd: -1}
	if fd, err := unix.PidfdOpen(pid, 0); err == nil {
		w.pidfd = fd
	}
	fields, _ := w.statFields()
	w.startTime = startTimeOf(fields)
	return w
}

// Close releases the pidfd. Safe on nil and more than once.
func (w *targetWatch) Close() {
	if w == nil || w.pidfd < 0 {
		return
	}
	_ = unix.Close(w.pidfd)
	w.pidfd = -1
}

// gone reports whether the watched process has exited or its pid now belongs
// to another process. Anything it cannot determine (a stat error other than
// "no such file") counts as alive: ending a trace on a guess would lose data,
// while a missed death only costs the fallback's latency (the record path, and
// -duration, still apply).
func (w *targetWatch) gone() bool {
	if w.pidfd >= 0 {
		fds := []unix.PollFd{{Fd: int32(w.pidfd), Events: unix.POLLIN}}
		if n, err := unix.Poll(fds, 0); err == nil && n > 0 && fds[0].Revents&unix.POLLIN != 0 {
			return true
		}
	}
	fields, err := w.statFields()
	if os.IsNotExist(err) {
		return true
	}
	if err != nil {
		return false
	}
	if pidRecycled(w.startTime, startTimeOf(fields)) {
		return true
	}
	return len(fields) > 0 && fields[0] == "Z" && w.leaderIsLastTask()
}

// pidRecycled reports whether the start time now differs from the one captured
// at open. An unknown start time at open ("") cannot be compared.
func pidRecycled(captured, now string) bool {
	return captured != "" && now != captured
}

// statFields reads /proc/<pid>/stat and returns the fields after the command
// name, i.e. from field 3 (state) on. The command is parenthesised and may
// contain spaces and parentheses, so the split is at the LAST ')'.
func (w *targetWatch) statFields() ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(w.root, strconv.Itoa(w.pid), "stat"))
	if err != nil {
		return nil, err
	}
	return parseStatFields(string(raw)), nil
}

// parseStatFields returns the fields after the ")" that closes the command
// name in a /proc/<pid>/stat line; nil if the line is malformed.
func parseStatFields(line string) []string {
	i := strings.LastIndexByte(line, ')')
	if i < 0 {
		return nil
	}
	return strings.Fields(line[i+1:])
}

// startTimeOf is field 22 of /proc/<pid>/stat, index 19 of the fields after
// the command name (which start at field 3); "" if the line was too short.
func startTimeOf(fields []string) string {
	const startTimeIndex = 22 - 3
	if len(fields) <= startTimeIndex {
		return ""
	}
	return fields[startTimeIndex]
}

// leaderIsLastTask reports that /proc/<pid>/task lists no thread but the
// leader. For a zombie leader that means the process has exited; a zombie
// leader whose other threads still run is not gone (its state stays Z until
// the last thread is, yet the threads keep executing).
func (w *targetWatch) leaderIsLastTask() bool {
	tasks, err := os.ReadDir(filepath.Join(w.root, strconv.Itoa(w.pid), "task"))
	if err != nil {
		return true
	}
	for _, task := range tasks {
		if task.Name() != strconv.Itoa(w.pid) {
			return false
		}
	}
	return true
}

// openHeadlessTargetWatch is the liveness watch of a headless -pid run, nil
// for the TUI (which keeps its session open after the target died) and for a
// run without -pid.
func openHeadlessTargetWatch(cfg flags.Config, headless bool) *targetWatch {
	if !headless || cfg.PidFilter <= 0 {
		return nil
	}
	return openTargetWatch(procRoot, cfg.PidFilter)
}

// attachTo hands the watch to the run's trace loop (traceInfra.targetGone).
// Safe on a nil watch, which leaves the run without a liveness fallback.
func (w *targetWatch) attachTo(infra *traceInfra) {
	if w != nil {
		infra.targetGone = w.gone
	}
}

// disableTargetExitRecordEnv is a test hook: when set to exactly "1" (any
// other value, including the empty string, leaves the trigger on) the
// group-dead-record trigger (endTraceOnTargetExit) is disabled, so an
// integration test can prove the liveness watcher alone ends a run, which a
// real lost record or a death during the attach would otherwise be needed for
// and cannot be forced. It is not documented for users.
const disableTargetExitRecordEnv = "IOR_TEST_DISABLE_TARGET_EXIT_RECORD"

// targetExitRecordDisabled reports the test hook above.
func targetExitRecordDisabled() bool {
	return os.Getenv(disableTargetExitRecordEnv) == "1"
}
