package statsengine

import (
	"cmp"
	"slices"
	"time"

	"ior/internal/event"
)

const processRankTopNDefault = 20

type processAccumulator struct {
	topN    int
	maxSeen int
	byPID   map[uint32]*processStats
}

type processStats struct {
	pid uint32
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
		topN:    topN,
		maxSeen: maxSeen,
		byPID:   make(map[uint32]*processStats),
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
// The trade-off is that real PID reuse is not detected: when the kernel hands
// a dead process's PID to a new one within the same trace, both lifetimes are
// merged into one row, and the new process's comm then labels counts that
// largely belong to the old one - misattribution, not merely a bounded
// overcount. That is not a corner case: the kernel default pid_max is 32768
// (or 1024 per CPU), and on a box churning short-lived processes PIDs wrap
// quickly. The accumulator cannot fix it alone, because it only sees pairs;
// the sched_process_exit records that end a lifetime are consumed inside the
// event loop (handleProcessExitEvent). They fire per task, but carry a
// group_dead flag (ProcessExitEvent.IsGroupDead) marking the exit that ends
// the whole process. A real fix needs that process-exit signal (or a
// pid+start-time key) forwarded to the stats engine; until then merging is
// preferred over the old heuristic, which was wrong for every multithreaded
// process rather than only on reuse.
//
// The comm is only a label, see processStats.label.
func (a *processAccumulator) Add(pair *event.Pair) {
	if a == nil || pair == nil || pair.EnterEv == nil {
		return
	}

	pid := pair.EnterEv.GetPid()
	stats := a.byPID[pid]
	if stats == nil {
		stats = &processStats{pid: pid}
		a.byPID[pid] = stats
	}

	stats.count++
	stats.totalBytes += pair.Bytes
	stats.totalLatency += pair.Duration
	stats.observeComm(pair.EnterEv.GetTid(), pair.Comm)
	a.compactIfNeeded()
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

func (a *processAccumulator) snapshotInputs() []processSnapshotInput {
	if a == nil {
		return nil
	}

	inputs := make([]processSnapshotInput, 0, len(a.byPID))
	for _, stats := range a.byPID {
		inputs = append(inputs, processSnapshotInput{
			pid:          stats.pid,
			comm:         stats.label(),
			count:        stats.count,
			totalBytes:   stats.totalBytes,
			totalLatency: stats.totalLatency,
		})
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
		return cmp.Compare(a.PID, b.PID)
	})
	return result, nil
}

func (a *processAccumulator) compactIfNeeded() {
	if len(a.byPID) <= a.maxSeen {
		return
	}

	ordered := make([]*processStats, 0, len(a.byPID))
	for _, stats := range a.byPID {
		ordered = append(ordered, stats)
	}
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

	kept := make(map[uint32]*processStats, len(ordered))
	for _, stats := range ordered {
		kept[stats.pid] = stats
	}
	a.byPID = kept
}

func betterProcessRank(a, b *processStats) bool {
	if a.count != b.count {
		return a.count > b.count
	}
	if a.totalBytes != b.totalBytes {
		return a.totalBytes > b.totalBytes
	}
	return a.pid < b.pid
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
		Comm:           s.comm,
		Syscalls:       s.count,
		RatePerSec:     safeRate(s.count, rateDiv),
		Bytes:          s.totalBytes,
		AvgLatencyNs:   avg,
		TotalLatencyNs: s.totalLatency,
	}
}
