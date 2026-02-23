package statsengine

import (
	"ior/internal/event"
	"sort"
	"time"
)

type processAccumulator struct {
	byPID map[uint32]*processStats
}

type processStats struct {
	pid          uint32
	comm         string
	count        uint64
	totalBytes   uint64
	totalLatency uint64
}

func newProcessAccumulator() *processAccumulator {
	return &processAccumulator{byPID: make(map[uint32]*processStats)}
}

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
	if pair.Comm != "" && stats.comm != "" && stats.comm != pair.Comm {
		// Best-effort PID reuse handling: when command name changes for an
		// existing PID, treat it as a new process lifetime and reset counters.
		stats = &processStats{pid: pid}
		a.byPID[pid] = stats
	}

	stats.count++
	stats.totalBytes += pair.Bytes
	stats.totalLatency += pair.Duration
	if pair.Comm != "" {
		stats.comm = pair.Comm
	}
}

func (a *processAccumulator) Snapshot(elapsed time.Duration) []ProcessSnapshot {
	if a == nil {
		return nil
	}

	rateDiv := elapsed.Seconds()
	result := make([]ProcessSnapshot, 0, len(a.byPID))
	for _, stats := range a.byPID {
		result = append(result, stats.toSnapshot(rateDiv))
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Syscalls != result[j].Syscalls {
			return result[i].Syscalls > result[j].Syscalls
		}
		if result[i].Bytes != result[j].Bytes {
			return result[i].Bytes > result[j].Bytes
		}
		return result[i].PID < result[j].PID
	})

	return result
}

func (s *processStats) toSnapshot(rateDiv float64) ProcessSnapshot {
	avg := 0.0
	if s.count > 0 {
		avg = float64(s.totalLatency) / float64(s.count)
	}

	return ProcessSnapshot{
		PID:          s.pid,
		Comm:         s.comm,
		Syscalls:     s.count,
		RatePerSec:   safeRate(s.count, rateDiv),
		Bytes:        s.totalBytes,
		AvgLatencyNs: avg,
	}
}
