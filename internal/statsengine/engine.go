package statsengine

import (
	"math"
	"sync"
	"time"

	"ior/internal/event"
	"ior/internal/types"
)

const (
	// trendWindowSlots is the number of slots used for trend detection in ring
	// time series. Two consecutive windows of this size are compared to detect
	// rising, falling, or stable throughput/latency trends.
	trendWindowSlots = 20

	// DefaultTopN is the default maximum number of top entries tracked per
	// category (files, processes). It is exported so callers can use it as the
	// standard capacity when constructing a new Engine via NewEngine.
	DefaultTopN = 64
)

// Engine aggregates streaming syscall data into immutable snapshots.
type Engine struct {
	mu sync.Mutex

	now       func() time.Time
	startedAt time.Time
	topN      int

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

type snapshotInputs struct {
	now       time.Time
	startedAt time.Time

	totalSyscalls   uint64
	totalErrors     uint64
	totalBytes      uint64
	totalReadBytes  uint64
	totalWriteBytes uint64
	totalLatency    uint64
	totalGap        uint64

	latencySeries    []float64
	gapSeries        []float64
	throughputSeries []float64

	syscalls  []syscallSnapshotInput
	files     []fileSnapshotInput
	processes []processSnapshotInput

	latencyHist histogramSnapshotInput
	gapHist     histogramSnapshotInput
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
		topN:             topN,
		syscalls:         newSyscallAccumulator(),
		files:            newFileRankerWithConfig(topN),
		processes:        newProcessAccumulatorWithConfig(topN),
		latencyHist:      newHistogram(),
		gapHist:          newHistogram(),
		latencySeries:    newRingTimeSeries(),
		gapSeries:        newRingTimeSeries(),
		throughputSeries: newRingTimeSeries(),
	}
}

// Reset clears all accumulated stats and restarts series baselines.
func (e *Engine) Reset() {
	if e == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.startedAt = e.now()
	e.totalSyscalls = 0
	e.totalErrors = 0
	e.totalBytes = 0
	e.totalReadBytes = 0
	e.totalWriteBytes = 0
	e.totalLatency = 0
	e.totalGap = 0
	e.syscalls = newSyscallAccumulator()
	e.files = newFileRankerWithConfig(e.topN)
	e.processes = newProcessAccumulatorWithConfig(e.topN)
	e.latencyHist = newHistogram()
	e.gapHist = newHistogram()
	e.latencySeries = newRingTimeSeries()
	e.gapSeries = newRingTimeSeries()
	e.throughputSeries = newRingTimeSeries()
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

// subSnapshots holds the concurrently built per-category snapshot slices.
type subSnapshots struct {
	syscalls    []SyscallSnapshot
	files       []FileSnapshot
	processes   []ProcessSnapshot
	latencyHist HistogramSnapshot
	gapHist     HistogramSnapshot
}

// captureSnapshotInputs copies all engine state under the lock so that the
// subsequent (lock-free) computation does not block ingestion.
func (e *Engine) captureSnapshotInputs() snapshotInputs {
	e.mu.Lock()
	defer e.mu.Unlock()

	return snapshotInputs{
		now:              e.now(),
		startedAt:        e.startedAt,
		totalSyscalls:    e.totalSyscalls,
		totalErrors:      e.totalErrors,
		totalBytes:       e.totalBytes,
		totalReadBytes:   e.totalReadBytes,
		totalWriteBytes:  e.totalWriteBytes,
		totalLatency:     e.totalLatency,
		totalGap:         e.totalGap,
		latencySeries:    e.latencySeries.Values(),
		gapSeries:        e.gapSeries.Values(),
		throughputSeries: e.throughputSeries.Values(),
		syscalls:         e.syscalls.snapshotInputs(),
		files:            e.files.snapshotInputs(),
		processes:        e.processes.snapshotInputs(),
		latencyHist:      e.latencyHist.snapshotInputs(),
		gapHist:          e.gapHist.snapshotInputs(),
	}
}

// buildSubSnapshots runs all five per-category snapshot builders concurrently
// and returns their results bundled together.
func buildSubSnapshots(in snapshotInputs, elapsed time.Duration) subSnapshots {
	var (
		ss subSnapshots
		wg sync.WaitGroup
	)

	wg.Add(5)
	go func() { defer wg.Done(); ss.syscalls = buildSyscallSnapshots(in.syscalls, elapsed) }()
	go func() { defer wg.Done(); ss.files = buildFileSnapshots(in.files) }()
	go func() { defer wg.Done(); ss.processes = buildProcessSnapshots(in.processes, elapsed) }()
	go func() { defer wg.Done(); ss.latencyHist = buildHistogramSnapshot(in.latencyHist) }()
	go func() { defer wg.Done(); ss.gapHist = buildHistogramSnapshot(in.gapHist) }()
	wg.Wait()

	return ss
}

// populateSnapshotFields fills in the scalar fields of the snapshot from the
// captured inputs and pre-computed elapsed/rateDiv values.
func populateSnapshotFields(snap *Snapshot, in snapshotInputs, elapsed time.Duration) {
	rateDiv := elapsed.Seconds()

	snap.GeneratedAt = in.now
	snap.Elapsed = elapsed
	snap.TotalSyscalls = in.totalSyscalls
	snap.TotalErrors = in.totalErrors
	snap.TotalBytes = in.totalBytes
	snap.SyscallRatePerSec = safeRate(in.totalSyscalls, rateDiv)
	snap.ErrorRatePerSec = safeRate(in.totalErrors, rateDiv)
	snap.ReadBytesPerSec = safeRate(in.totalReadBytes, rateDiv)
	snap.WriteBytesPerSec = safeRate(in.totalWriteBytes, rateDiv)
	snap.LatencyMeanNs = safeMean(in.totalLatency, in.totalSyscalls)
	snap.GapMeanNs = safeMean(in.totalGap, in.totalSyscalls)
	snap.LatencyTrend = detectTrend(in.latencySeries)
	snap.GapTrend = detectTrend(in.gapSeries)
	snap.ThroughputTrend = detectTrend(in.throughputSeries)
}

// Snapshot returns an immutable point-in-time view of all stats.
// It captures engine state under the lock, then builds sub-snapshots
// concurrently, and finally assembles the result without holding the lock.
func (e *Engine) Snapshot() *Snapshot {
	if e == nil {
		return nil
	}

	in := e.captureSnapshotInputs()
	elapsed := nonNegativeDuration(in.now.Sub(in.startedAt))
	ss := buildSubSnapshots(in, elapsed)

	snap := NewSnapshot(
		in.latencySeries, in.gapSeries, in.throughputSeries,
		ss.syscalls, ss.files, ss.processes,
		ss.latencyHist, ss.gapHist,
	)
	populateSnapshotFields(&snap, in, elapsed)

	return &snap
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
