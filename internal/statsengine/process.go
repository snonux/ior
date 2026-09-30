package statsengine

import (
	"cmp"
	"slices"
	"time"

	"ior/internal/event"
)

const processRankTopNDefault = 20

// processAccumulator folds syscall pairs into one row per process lifetime.
//
// A lifetime is live while its PID is in byPID. RetireProcess ends it when the
// whole process exits: the row moves to retired, still reported by Snapshot,
// and the next pair for that PID opens a fresh row. That keeps the Processes
// table cumulative for the session while a recycled PID no longer merges two
// processes into one row labelled with the newer one's comm.
type processAccumulator struct {
	topN    int
	maxSeen int
	byPID   map[uint32]*processStats
	// retired holds the rows of processes that exited, in retirement order.
	// It counts against maxSeen together with byPID, so compaction bounds it
	// the same way it bounds the live rows.
	retired []*processStats
	// nextLifetime is the lifetime ordinal the next row of a PID gets, set
	// only for PIDs whose last lifetime retired with no new one started yet.
	// Ordinals keep the rows of one PID distinguishable (ProcessSnapshot.
	// Lifetime), which the TUI uses as part of its selection key.
	nextLifetime map[uint32]uint32
}

type processStats struct {
	pid uint32
	// lifetime is 0 for the first process seen with this PID in the session
	// and counts up with every retired predecessor (see nextLifetime).
	lifetime uint32
	// leaderComm is the comm last seen on the thread-group leader (tid ==
	// pid), i.e. the process name ps shows. It is the preferred label.
	leaderComm string
	// firstComm is the first non-empty comm seen on any thread. It is the
	// label only while the leader has not been seen, and it never changes
	// once set so that fallback label stays stable too.
	firstComm    string
	count        uint64
	totalBytes   uint64
	totalLatency uint64
}

type processSnapshotInput struct {
	pid          uint32
	lifetime     uint32
	comm         string
	count        uint64
	totalBytes   uint64
	totalLatency uint64
}

func newProcessAccumulator() *processAccumulator {
	return newProcessAccumulatorWithConfig(processRankTopNDefault)
}

func newProcessAccumulatorWithConfig(topN int) *processAccumulator {
	if topN <= 0 {
		topN = processRankTopNDefault
	}
	return newProcessAccumulatorWithLimits(topN, topN*32)
}

func newProcessAccumulatorWithLimits(topN int, maxSeen int) *processAccumulator {
	if topN <= 0 {
		topN = processRankTopNDefault
	}
	if maxSeen < topN {
		maxSeen = topN
	}
	return &processAccumulator{
		topN:         topN,
		maxSeen:      maxSeen,
		byPID:        make(map[uint32]*processStats),
		nextLifetime: make(map[uint32]uint32),
	}
}

// Add folds one syscall pair into the stats of its process (tgid).
//
// A comm change for a known PID never resets the counters. pair.Comm is the
// per-*thread* name (bpf_get_current_comm / the tid-keyed comm resolver), so
// the threads of a single process routinely disagree (pthread_setname_np:
// Java "GC Thread#0", browsers, thread pools), and exec() renames the process
// without starting a new lifetime. Treating a differing comm as PID reuse -
// what this method used to do - reset the row on every alternation between
// two threads and made the Processes tab undercount multithreaded apps
// drastically (200 interleaved syscalls reported as 1).
//
// PID reuse is detected from the process-exit signal instead: the event loop
// forwards the sched_process_exit record that ends the whole thread group
// (ProcessExitEvent.IsGroupDead) to RetireProcess, and the next pair for the
// PID opens a new row. The kernel recycles PIDs quickly on a box churning
// short-lived processes (pid_max defaults to 32768, or 1024 per CPU), and
// without that signal the new process's counts merged into the dead one's row
// under the new comm. A lost group-dead record (ring-buffer backpressure)
// falls back to that merge for the one PID.
//
// The comm is only a label, see processStats.label.
func (a *processAccumulator) Add(pair *event.Pair) {
	if a == nil || pair == nil || pair.EnterEv == nil {
		return
	}

	pid := pair.EnterEv.GetPid()
	stats := a.byPID[pid]
	if stats == nil {
		stats = a.startLifetime(pid)
	}

	stats.count++
	stats.totalBytes += pair.Bytes
	stats.totalLatency += pair.Duration
	stats.observeComm(pair.EnterEv.GetTid(), pair.Comm)
	a.compactIfNeeded()
}

// RetireProcess ends the current lifetime of pid: its row keeps its counts
// and label but stops receiving pairs, so a later process handed the same PID
// starts a row of its own. Call it only for the exit that ends the whole
// thread group; a single thread exiting does not end the process. A PID
// without a live row (never traced, already retired, or compacted away) is a
// no-op, so duplicate or unscoped exit records are harmless.
func (a *processAccumulator) RetireProcess(pid uint32) {
	if a == nil {
		return
	}
	stats := a.byPID[pid]
	if stats == nil {
		return
	}
	delete(a.byPID, pid)
	a.retired = append(a.retired, stats)
	a.nextLifetime[pid] = stats.lifetime + 1
}

// Snapshot returns a slice of ProcessSnapshots for all tracked processes.
// It panics on build error, which should never happen for a valid accumulator.
func (a *processAccumulator) Snapshot(elapsed time.Duration) []ProcessSnapshot {
	if a == nil {
		return nil
	}

	snap, err := buildProcessSnapshots(a.snapshotInputs(), elapsed)
	if err != nil {
		panic("buildProcessSnapshots: " + err.Error())
	}
	return snap
}

// startLifetime opens and registers the live row of a new process with pid,
// numbered after any retired predecessor with the same PID.
func (a *processAccumulator) startLifetime(pid uint32) *processStats {
	stats := &processStats{pid: pid, lifetime: a.nextLifetime[pid]}
	delete(a.nextLifetime, pid)
	a.byPID[pid] = stats
	return stats
}

func (a *processAccumulator) snapshotInputs() []processSnapshotInput {
	if a == nil {
		return nil
	}

	inputs := make([]processSnapshotInput, 0, len(a.byPID)+len(a.retired))
	for _, stats := range a.byPID {
		inputs = append(inputs, stats.snapshotInput())
	}
	for _, stats := range a.retired {
		inputs = append(inputs, stats.snapshotInput())
	}
	return inputs
}

// buildProcessSnapshots converts raw process accumulator inputs into sorted
// ProcessSnapshot slices. The error return is reserved for future validation;
// currently this function always succeeds.
func buildProcessSnapshots(inputs []processSnapshotInput, elapsed time.Duration) ([]ProcessSnapshot, error) {
	rateDiv := elapsed.Seconds()
	result := make([]ProcessSnapshot, 0, len(inputs))
	for _, in := range inputs {
		result = append(result, in.toSnapshot(rateDiv))
	}
	slices.SortFunc(result, func(a, b ProcessSnapshot) int {
		if a.Syscalls != b.Syscalls {
			return cmp.Compare(b.Syscalls, a.Syscalls)
		}
		if a.Bytes != b.Bytes {
			return cmp.Compare(b.Bytes, a.Bytes)
		}
		if a.PID != b.PID {
			return cmp.Compare(a.PID, b.PID)
		}
		return cmp.Compare(a.Lifetime, b.Lifetime)
	})
	return result, nil
}

// compactIfNeeded bounds memory on high-cardinality traces: once live and
// retired rows together exceed maxSeen, only the topN best-ranked rows of
// either kind survive. Retired rows compete on the same terms as live ones,
// so a busy process that exited stays listed while idle short-lived ones are
// dropped.
func (a *processAccumulator) compactIfNeeded() {
	if len(a.byPID)+len(a.retired) <= a.maxSeen {
		return
	}

	ordered := make([]*processStats, 0, len(a.byPID)+len(a.retired))
	for _, stats := range a.byPID {
		ordered = append(ordered, stats)
	}
	ordered = append(ordered, a.retired...)
	slices.SortFunc(ordered, func(a, b *processStats) int {
		if betterProcessRank(a, b) {
			return -1
		}
		if betterProcessRank(b, a) {
			return 1
		}
		return 0
	})
	if len(ordered) > a.topN {
		ordered = ordered[:a.topN]
	}
	a.keepOnly(ordered)
}

// keepOnly rebuilds the live and retired rows from the compaction survivors.
// A row is live exactly when byPID still points at it. nextLifetime is pruned
// to the PIDs with a surviving retired row: once every earlier row of a PID is
// gone, restarting its ordinals at 0 cannot collide with a listed row.
func (a *processAccumulator) keepOnly(survivors []*processStats) {
	kept := make(map[uint32]*processStats, len(survivors))
	var retired []*processStats
	for _, stats := range survivors {
		if a.byPID[stats.pid] == stats {
			kept[stats.pid] = stats
			continue
		}
		retired = append(retired, stats)
	}
	nextLifetime := make(map[uint32]uint32)
	for _, stats := range retired {
		if next, ok := a.nextLifetime[stats.pid]; ok {
			nextLifetime[stats.pid] = next
		}
	}
	a.byPID = kept
	a.retired = retired
	a.nextLifetime = nextLifetime
}

func betterProcessRank(a, b *processStats) bool {
	if a.count != b.count {
		return a.count > b.count
	}
	if a.totalBytes != b.totalBytes {
		return a.totalBytes > b.totalBytes
	}
	if a.pid != b.pid {
		return a.pid < b.pid
	}
	return a.lifetime < b.lifetime
}

func (s *processStats) snapshotInput() processSnapshotInput {
	return processSnapshotInput{
		pid:          s.pid,
		lifetime:     s.lifetime,
		comm:         s.label(),
		count:        s.count,
		totalBytes:   s.totalBytes,
		totalLatency: s.totalLatency,
	}
}

// observeComm records the comm of the thread tid of this process. Empty comms
// are ignored so an unresolved name never blanks a known label.
func (s *processStats) observeComm(tid uint32, comm string) {
	if comm == "" {
		return
	}
	if s.firstComm == "" {
		s.firstComm = comm
	}
	if tid == s.pid {
		s.leaderComm = comm
	}
}

// label returns the process name shown for this PID: the thread-group
// leader's comm when the leader has been seen, else the first thread comm
// seen for the PID.
//
// The label must not change between snapshots for a multithreaded process: a
// plain "latest thread wins" label flipped between thread names, which
// reordered Sort-by-Comm (moving the index-based selection to another PID),
// rebuilt the Comm column filter from an arbitrary thread name and made
// treemap/bubble labels flicker. Preferring the leader fixes that when the
// leader makes syscalls; the fallback is "first seen" rather than "latest"
// because the leader often never completes a traced syscall at all (a Java
// launcher or worker-pool server whose main thread is parked in
// pthread_join/futex for the whole run), and a latest-wins fallback would
// flicker for exactly those processes. The first name may be a worker thread
// name rather than the program name; stability matters more here, and the
// event loop does not hand the leader's comm to non-leader pairs.
//
// exec() still relabels the row: the kernel makes the exec'ing thread the
// leader (tid == pid) and updates its comm, so the post-exec syscalls come
// from tid == pid and set leaderComm to the new name.
func (s *processStats) label() string {
	if s.leaderComm != "" {
		return s.leaderComm
	}
	return s.firstComm
}

func (s processSnapshotInput) toSnapshot(rateDiv float64) ProcessSnapshot {
	avg := 0.0
	if s.count > 0 {
		avg = float64(s.totalLatency) / float64(s.count)
	}

	return ProcessSnapshot{
		PID:            s.pid,
		Lifetime:       s.lifetime,
		Comm:           s.comm,
		Syscalls:       s.count,
		RatePerSec:     safeRate(s.count, rateDiv),
		Bytes:          s.totalBytes,
		AvgLatencyNs:   avg,
		TotalLatencyNs: s.totalLatency,
	}
}
