package internal

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ior/internal/flags"

	"golang.org/x/sys/unix"
)

// pidfdThread is PIDFD_THREAD (Linux 6.9, defined as O_EXCL; x/sys has no
// name for it): pidfd_open then refers to one thread instead of a thread
// group leader, which a plain pidfd_open refuses for a non-leader tid.
const pidfdThread = unix.O_EXCL

// targetWatch answers "is the target still the process (-pid) or thread
// (-tid) ior was started for?" without the ring buffer (tasks vr2, os2). It is
// opened before the probes are attached, because that is what makes it immune
// to id reuse: a target that dies and whose pid or tid is recycled while ior
// is still attaching must count as gone, which only a snapshot taken at
// startup can tell.
//
// Two mechanisms, strongest first:
//
//   - a pidfd (pidfd_open, Linux 5.3+; PIDFD_THREAD, 6.9+, for a -tid thread)
//     refers to that one process or thread for good, and a recycled id cannot
//     fool it. A process pidfd becomes readable when the whole process has
//     exited (its leader is a zombie with no thread left); a PIDFD_THREAD
//     pidfd as soon as that thread has exited (exit_state set: a zombie
//     counts, it need not be reaped), which for a leader whose siblings run
//     on is long before the process ends. A kernel without PIDFD_THREAD
//     answers EINVAL and leaves a -tid watch with the procfs mechanism alone.
//   - the start time (field 22 of /proc/<id>/stat, in clock ticks since
//     boot) captured at open: a different value later means the id belongs to
//     another task now, and a missing /proc entry means it is gone. This
//     backs the pidfd (kernel too old, EPERM) and is the only mechanism when
//     pidfd_open fails. /proc/<tid>/stat answers for any thread, though only
//     thread-group leaders are listed in /proc.
//
// A zombie counts as gone too: it has exited and only its parent has not
// reaped it. For a process that needs its leader to be the last task (a zombie
// leader whose threads still run is alive); for a -tid target the zombie task
// itself is what ended, whatever its siblings do.
//
// A -tid target's exit (readable pidfd, zombie state) is only trusted once two
// consecutive polls saw it, unless its /proc entry is gone or its start time
// changed (those are final at once). Reason: when a non-leader thread calls
// execve, de_thread() lets the old leader die and become a zombie, then hands
// its tid and start time to the exec'ing thread, which runs on as the new
// program under the same tid (task os2). For those microseconds a -tid
// <leader> watch sees an exited leader, though the tid it traces lives on;
// the next poll sees the live program. A leader that really exited stays a
// zombie, so it is confirmed one interval (targetWatchInterval) later, and a
// non-leader is reaped at once, which the missing /proc entry reports.
type targetWatch struct {
	target    traceTarget
	root      string // procfs mount (procRoot in production)
	pidfd     int    // -1 when pidfd_open failed
	startTime string // field 22 of /proc/<id>/stat at open; "" when unknown
	// exitSeen is set when the previous gone() poll of a -tid target saw an
	// unconfirmed exit (see above). Only the watcher goroutine calls gone().
	exitSeen bool
}

// openTargetWatch starts watching target. It never fails: a target that is
// unreadable now leaves the watch with only the mechanisms that still work (an
// absent /proc entry still means gone). root is the procfs mount (procRoot in
// production). Close releases the pidfd.
func openTargetWatch(root string, target traceTarget) *targetWatch {
	w := &targetWatch{target: target, root: root, pidfd: -1}
	flags := 0
	if target.thread {
		flags = pidfdThread
	}
	if fd, err := unix.PidfdOpen(target.id, flags); err == nil {
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

// gone reports whether the watched process or thread has exited or its id now
// belongs to another task. Anything it cannot determine (a stat error other than
// "no such file") counts as alive unless the pidfd says otherwise: ending a
// trace on a guess would lose data, while a missed death only costs the
// fallback's latency (the record path, and -duration, still apply). A -tid
// target's exit must be seen by two consecutive calls (see targetWatch).
func (w *targetWatch) gone() bool {
	exited := w.pidfdReadable()
	fields, err := w.statFields()
	if os.IsNotExist(err) {
		return true
	}
	if err == nil {
		if pidRecycled(w.startTime, startTimeOf(fields)) {
			return true
		}
		exited = exited || w.exitedZombie(fields)
	}
	return w.confirmExit(exited)
}

// pidfdReadable reports whether the pidfd signals the target's exit (see
// targetWatch for when each kind of pidfd becomes readable).
func (w *targetWatch) pidfdReadable() bool {
	if w.pidfd < 0 {
		return false
	}
	fds := []unix.PollFd{{Fd: int32(w.pidfd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, 0)
	return err == nil && n > 0 && fds[0].Revents&unix.POLLIN != 0
}

// confirmExit turns this poll's exit observation into the answer of gone: a
// process target's exit counts at once; a thread target's only when the
// previous poll saw it too, so the brief zombie of a leader whose tid an
// exec'ing sibling inherits is not mistaken for the traced tid's end.
func (w *targetWatch) confirmExit(exited bool) bool {
	if !exited || !w.target.thread {
		w.exitSeen = false
		return exited
	}
	if w.exitSeen {
		return true
	}
	w.exitSeen = true
	return false
}

// exitedZombie reports whether the stat fields describe a task that has
// exited but is not reaped yet: state Z (or X, the dead state some kernels
// show). A zombie process leader only counts once no other thread is left
// (leaderIsLastTask); a -tid target counts at once.
func (w *targetWatch) exitedZombie(fields []string) bool {
	if len(fields) == 0 || (fields[0] != "Z" && fields[0] != "X") {
		return false
	}
	return w.target.thread || w.leaderIsLastTask()
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
	raw, err := os.ReadFile(filepath.Join(w.root, strconv.Itoa(w.target.id), "stat"))
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
	pid := strconv.Itoa(w.target.id)
	tasks, err := os.ReadDir(filepath.Join(w.root, pid, "task"))
	if err != nil {
		return true
	}
	for _, task := range tasks {
		if task.Name() != pid {
			return false
		}
	}
	return true
}

// openHeadlessTargetWatch is the liveness watch of a headless -pid / -tid run
// (the -tid thread when given, else the -pid process: newTraceTarget), nil for
// the TUI (which keeps its session open after the target died) and for a run
// with neither filter.
func openHeadlessTargetWatch(cfg flags.Config, headless bool) *targetWatch {
	target, ok := newTraceTarget(cfg.PidFilter, cfg.TidFilter)
	if !headless || !ok {
		return nil
	}
	return openTargetWatch(procRoot, target)
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

// disableTargetWatchEnv is the opposite test hook: exactly "1" keeps the
// liveness watcher (startTargetLivenessWatcher) from starting, so an
// integration test can prove the exit-record trigger alone ends a run. Both
// triggers print the same status line, and the watcher polls every 500 ms, so
// without this a broken record trigger would go unnoticed at integration
// level. Not documented for users either.
const disableTargetWatchEnv = "IOR_TEST_DISABLE_TARGET_WATCH"

// targetWatchDisabled reports the test hook above.
func targetWatchDisabled() bool {
	return os.Getenv(disableTargetWatchEnv) == "1"
}
