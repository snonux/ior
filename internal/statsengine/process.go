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
	pid          uint32
	comm         string
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
// Real PID reuse is not detected here on purpose. The accumulator only sees
// pairs; the sched_process_exit records that could mark the end of a lifetime
// are consumed inside the event loop (handleProcessExitEvent) and fire per
// task, not per process, and evicting on exit would also erase finished
// processes from what is a cumulative per-session table. With pid_max in the
// millions on modern kernels a PID is rarely recycled within one trace, and
// when it is, merging the two lifetimes into one row is a small, bounded
// overcount - far better than the systematic undercount of the old heuristic.
//
// The comm is therefore only a label: the most recent non-empty thread name
// seen for the PID. For a multithreaded process it may switch between thread
// names from one snapshot to the next; that is cosmetic, whereas tracking a
// most-frequent name would need a per-PID map of every thread name.
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
	if pair.Comm != "" {
		stats.comm = pair.Comm
	}
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
			comm:         stats.comm,
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
