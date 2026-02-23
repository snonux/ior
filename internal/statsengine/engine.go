package statsengine

import (
	"ior/internal/event"
	"ior/internal/types"
	"math"
	"sync"
	"time"
)

const trendWindowSlots = 20

// Engine aggregates streaming syscall data into immutable snapshots.
type Engine struct {
	mu sync.Mutex

	now       func() time.Time
	startedAt time.Time

	totalSyscalls   uint64
	totalErrors     uint64
	totalBytes      uint64
	totalReadBytes  uint64
	totalWriteBytes uint64
	totalLatency    uint64
	totalGap        uint64

	syscalls         *syscallAccumulator
	files            *fileRanker
	processes        *processAccumulator
	latencyHist      *histogram
	gapHist          *histogram
	latencySeries    *ringTimeSeries
	gapSeries        *ringTimeSeries
	throughputSeries *ringTimeSeries
}

// NewEngine creates a new stats engine.
func NewEngine(topN int) *Engine {
	return newEngineWithClock(topN, time.Now)
}

func newEngineWithClock(topN int, now func() time.Time) *Engine {
	if now == nil {
		now = time.Now
	}

	return &Engine{
		now:              now,
		startedAt:        now(),
		syscalls:         newSyscallAccumulator(),
		files:            newFileRankerWithConfig(topN),
		processes:        newProcessAccumulator(),
		latencyHist:      newHistogram(),
		gapHist:          newHistogram(),
		latencySeries:    newRingTimeSeries(),
		gapSeries:        newRingTimeSeries(),
		throughputSeries: newRingTimeSeries(),
	}
}

// Ingest updates all aggregates for one event pair.
func (e *Engine) Ingest(pair *event.Pair) {
	if e == nil || pair == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.now()
	e.totalSyscalls++
	e.totalBytes += pair.Bytes
	e.totalLatency += pair.Duration
	e.totalGap += pair.DurationToPrev

	e.updateErrorAndByteClasses(pair)
	e.syscalls.Add(pair)
	e.files.Add(pair)
	e.processes.Add(pair)
	e.latencyHist.Increment(pair.Duration)
	e.gapHist.Increment(pair.DurationToPrev)
	e.latencySeries.Add(float64(pair.Duration), now)
	e.gapSeries.Add(float64(pair.DurationToPrev), now)
	e.throughputSeries.Add(float64(pair.Bytes), now)
}

func (e *Engine) updateErrorAndByteClasses(pair *event.Pair) {
	retEv, ok := pair.ExitEv.(*types.RetEvent)
	if !ok {
		return
	}
	if retEv.Ret < 0 {
		e.totalErrors++
	}

	switch retEv.RetType {
	case types.READ_CLASSIFIED:
		e.totalReadBytes += pair.Bytes
	case types.WRITE_CLASSIFIED:
		e.totalWriteBytes += pair.Bytes
	case types.TRANSFER_CLASSIFIED:
		e.totalReadBytes += pair.Bytes
		e.totalWriteBytes += pair.Bytes
	}
}

// Snapshot returns an immutable point-in-time view of all stats.
func (e *Engine) Snapshot() *Snapshot {
	if e == nil {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.now()
	elapsed := nonNegativeDuration(now.Sub(e.startedAt))
	rateDiv := elapsed.Seconds()

	latencySeries := e.latencySeries.Values()
	gapSeries := e.gapSeries.Values()
	throughputSeries := e.throughputSeries.Values()

	snapshot := NewSnapshot(
		latencySeries,
		gapSeries,
		throughputSeries,
		e.syscalls.Snapshot(elapsed),
		e.files.Snapshot(),
		e.processes.Snapshot(elapsed),
		e.latencyHist.Snapshot(),
		e.gapHist.Snapshot(),
	)

	snapshot.GeneratedAt = now
	snapshot.Elapsed = elapsed
	snapshot.TotalSyscalls = e.totalSyscalls
	snapshot.TotalErrors = e.totalErrors
	snapshot.TotalBytes = e.totalBytes
	snapshot.SyscallRatePerSec = safeRate(e.totalSyscalls, rateDiv)
	snapshot.ErrorRatePerSec = safeRate(e.totalErrors, rateDiv)
	snapshot.ReadBytesPerSec = safeRate(e.totalReadBytes, rateDiv)
	snapshot.WriteBytesPerSec = safeRate(e.totalWriteBytes, rateDiv)
	snapshot.LatencyMeanNs = safeMean(e.totalLatency, e.totalSyscalls)
	snapshot.GapMeanNs = safeMean(e.totalGap, e.totalSyscalls)
	snapshot.LatencyTrend = detectTrend(latencySeries)
	snapshot.GapTrend = detectTrend(gapSeries)
	snapshot.ThroughputTrend = detectTrend(throughputSeries)

	return &snapshot
}

func safeMean(total uint64, count uint64) float64 {
	if count == 0 {
		return 0
	}
	return float64(total) / float64(count)
}

func nonNegativeDuration(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	return d
}

func detectTrend(series []float64) Trend {
	if len(series) < trendWindowSlots*2 {
		return Trend{Direction: TrendStable}
	}

	prev := average(series[len(series)-trendWindowSlots*2 : len(series)-trendWindowSlots])
	recent := average(series[len(series)-trendWindowSlots:])
	delta := recent - prev

	if prev == 0 {
		if recent == 0 {
			return Trend{Direction: TrendStable}
		}
		return Trend{Direction: TrendRising, DeltaPercent: 100}
	}

	deltaPercent := delta / math.Abs(prev) * 100
	if math.Abs(deltaPercent) < 5 {
		return Trend{Direction: TrendStable, DeltaPercent: deltaPercent}
	}
	if deltaPercent > 0 {
		return Trend{Direction: TrendRising, DeltaPercent: deltaPercent}
	}
	return Trend{Direction: TrendFalling, DeltaPercent: deltaPercent}
}

func average(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}
