package statsengine

import (
	"math"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

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

// Accumulator is the event-ingestion side of the stats engine.
// It accepts incoming event pairs (Ingest) and supports resetting all
// accumulated state back to zero (Reset). Snapshot building is a separate
// responsibility expressed by runtime.SnapshotSource; separating the two
// satisfies SRP — callers that only push events hold an Accumulator, while
// callers that only read statistics hold a SnapshotSource.
type Accumulator interface {
	// Ingest records one event pair into the in-memory aggregates.
	Ingest(pair *event.Pair)
	// Reset clears all accumulated stats and restarts series baselines.
	Reset()
}

// ProcessRetirer is the process-exit side of the stats engine: the event loop
// reports each whole-process exit so that a recycled PID starts a new row in
// the Processes table instead of merging into the dead process's one.
type ProcessRetirer interface {
	// RetireProcess ends the current lifetime of pid (a tgid). Only the
	// exit that ends the whole thread group may be reported.
	RetireProcess(pid uint32)
}

// compile-time assertions: *Engine must satisfy Accumulator and ProcessRetirer.
var (
	_ Accumulator    = (*Engine)(nil)
	_ ProcessRetirer = (*Engine)(nil)
)

// Engine aggregates streaming syscall data into immutable snapshots.
type Engine struct {
	mu sync.Mutex

	now       func() time.Time
	startedAt time.Time
	topN      int

	totalSyscalls          uint64
	totalUntimed           uint64 // part of totalSyscalls without a latency
	totalErrors            uint64
	totalBytes             uint64
	totalAddressSpaceBytes uint64
	totalReadBytes         uint64
	totalWriteBytes        uint64
	totalLatency           uint64
	totalGap               uint64
	gapSamples             uint64 // pairs behind totalGap (see ingestGap)

	// lastAggregateAt is when the previous kernel aggregate batch was
	// ingested; the next batch is spread over the time since then (see
	// aggregateSpanStart). Zero until the first batch.
	lastAggregateAt time.Time
	// aggregateSpan is the kernel aggregate drain period, the longest
	// interval one batch is spread over (see SetAggregateDrainPeriod). It is
	// configuration, so Reset keeps it.
	aggregateSpan time.Duration

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

	totalSyscalls          uint64
	totalUntimed           uint64 // part of totalSyscalls without a latency
	totalErrors            uint64
	totalBytes             uint64
	totalAddressSpaceBytes uint64
	totalReadBytes         uint64
	totalWriteBytes        uint64
	totalLatency           uint64
	totalGap               uint64
	gapSamples             uint64 // pairs behind totalGap (see ingestGap)

	latencySeries    []float64
	gapSeries        []float64
	throughputSeries []float64

	syscalls  syscallCapture
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
		aggregateSpan:    defaultAggregateDrainPeriod,
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
	e.totalUntimed = 0
	e.totalErrors = 0
	e.totalBytes = 0
	e.totalAddressSpaceBytes = 0
	e.totalReadBytes = 0
	e.totalWriteBytes = 0
	e.totalLatency = 0
	e.totalGap = 0
	e.gapSamples = 0
	e.lastAggregateAt = time.Time{}
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
	e.totalAddressSpaceBytes += pair.AddressSpaceBytes
	e.totalLatency += pair.Duration

	e.updateErrorAndByteClasses(pair)
	e.ingestGap(pair, now)
	e.syscalls.Add(pair)
	e.files.Add(pair)
	e.processes.Add(pair)
	e.latencyHist.Increment(pair.Duration)
	e.latencySeries.Add(float64(pair.Duration), now)
	e.throughputSeries.Add(float64(pair.Bytes), now)
}

// RetireProcess ends the current lifetime of pid in the per-process stats:
// its row stays in the snapshot with its counts and label, and the next pair
// for pid opens a new row. It must be called in stream order with Ingest (the
// event loop does both from its own goroutine), so the dying process's last
// pairs land before the retirement and the successor's first ones after it.
// Reset discards retired rows along with everything else.
func (e *Engine) RetireProcess(pid uint32) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.processes.RetireProcess(pid)
}

// ingestGap records pair's inter-syscall gap. A TID's first pair has no
// previous pair, so its DurationToPrev of 0 is no measurement: it is kept out
// of the gap total, sample count, histogram and series, where it would pull
// the distribution toward zero (one such pair per thread, so many
// short-lived threads would dominate).
func (e *Engine) ingestGap(pair *event.Pair, now time.Time) {
	if pair.FirstOnTID {
		return
	}
	e.totalGap += pair.DurationToPrev
	e.gapSamples++
	e.gapHist.Increment(pair.DurationToPrev)
	e.gapSeries.Add(float64(pair.DurationToPrev), now)
}

func (e *Engine) updateErrorAndByteClasses(pair *event.Pair) {
	// Error counting keys off any ret-carrying exit event so failing
	// accept/pipe/socketpair/eventfd calls are counted too; the read/write byte
	// classification is a *types.RetEvent-only field (RetType).
	if retCarrier, ok := pair.ExitEv.(event.RetCarrier); ok && event.IsErrnoRet(retCarrier.GetRet()) {
		e.totalErrors++
	}

	retEv, ok := pair.ExitEv.(*types.RetEvent)
	if !ok {
		return
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
	syscallJobs []percentileJob // resolved, to be cached by storeSyscallPercentiles
	files       []FileSnapshot
	processes   []ProcessSnapshot
	latencyHist HistogramSnapshot
	gapHist     HistogramSnapshot
}

// captureSnapshotInputs copies all engine state under the lock so that the
// subsequent (lock-free) computation does not block ingestion. Syscall latency
// reservoirs are only copied here, into each syscall's reusable scratch
// buffer; computing their percentiles is deferred to buildSubSnapshots because
// it dominated the lock hold time (~25ms per refresh with 60 full reservoirs),
// stalling Ingest on the event-loop goroutine.
func (e *Engine) captureSnapshotInputs() snapshotInputs {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()

	return snapshotInputs{
		now:                    now,
		startedAt:              e.startedAt,
		totalSyscalls:          e.totalSyscalls,
		totalUntimed:           e.totalUntimed,
		totalErrors:            e.totalErrors,
		totalBytes:             e.totalBytes,
		totalAddressSpaceBytes: e.totalAddressSpaceBytes,
		totalReadBytes:         e.totalReadBytes,
		totalWriteBytes:        e.totalWriteBytes,
		totalLatency:           e.totalLatency,
		totalGap:               e.totalGap,
		gapSamples:             e.gapSamples,
		latencySeries:          e.latencySeries.ValuesAt(now),
		gapSeries:              e.gapSeries.ValuesAt(now),
		throughputSeries:       e.throughputSeries.ValuesAt(now),
		syscalls:               e.syscalls.captureInputs(),
		files:                  e.files.snapshotInputs(),
		processes:              e.processes.snapshotInputs(),
		latencyHist:            e.latencyHist.snapshotInputs(),
		gapHist:                e.gapHist.snapshotInputs(),
	}
}

// buildSubSnapshots runs all per-category snapshot builders concurrently
// using errgroup so that any error from a sub-builder is captured and returned
// to the caller instead of being silently dropped. It runs without the engine
// lock and also resolves the stale syscall percentiles, returning the resolved
// jobs in subSnapshots.syscallJobs for the caller to cache.
func buildSubSnapshots(in snapshotInputs, elapsed time.Duration) (subSnapshots, error) {
	var (
		ss subSnapshots
		eg errgroup.Group
	)

	eg.Go(func() error {
		var err error
		capture := in.syscalls
		capture.resolvePercentiles()
		ss.syscallJobs = capture.jobs
		ss.syscalls, err = buildSyscallSnapshots(capture.inputs, elapsed)
		return err
	})
	eg.Go(func() error {
		var err error
		ss.files, err = buildFileSnapshots(in.files)
		return err
	})
	eg.Go(func() error {
		var err error
		ss.processes, err = buildProcessSnapshots(in.processes, elapsed)
		return err
	})
	eg.Go(func() error {
		var err error
		ss.latencyHist, err = buildHistogramSnapshot(in.latencyHist)
		return err
	})
	eg.Go(func() error {
		var err error
		ss.gapHist, err = buildHistogramSnapshot(in.gapHist)
		return err
	})

	if err := eg.Wait(); err != nil {
		return subSnapshots{}, err
	}

	return ss, nil
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
	snap.TotalAddressSpaceBytes = in.totalAddressSpaceBytes
	snap.SyscallRatePerSec = safeRate(in.totalSyscalls, rateDiv)
	snap.ErrorRatePerSec = safeRate(in.totalErrors, rateDiv)
	snap.AddressSpaceBytesPerSec = safeRate(in.totalAddressSpaceBytes, rateDiv)
	snap.ReadBytesPerSec = safeRate(in.totalReadBytes, rateDiv)
	snap.WriteBytesPerSec = safeRate(in.totalWriteBytes, rateDiv)
	snap.LatencyMeanNs = safeMean(in.totalLatency, timedCount(in.totalSyscalls, in.totalUntimed))
	snap.GapMeanNs = tracedGapMean(in)
	snap.LatencyTrend = detectTrend(in.latencySeries)
	snap.GapTrend = detectTrend(in.gapSeries)
	snap.ThroughputTrend = detectTrend(in.throughputSeries)
}

// storeSyscallPercentiles briefly re-takes the lock to cache the percentiles
// resolved outside it, so the next snapshot does not recompute the same
// reservoirs, and to hand the job buffers back as the syscalls' scratch
// buffers. After a concurrent Reset the jobs point at the discarded
// accumulator's stats; writing to those is harmless.
func (e *Engine) storeSyscallPercentiles(jobs []percentileJob) {
	if len(jobs) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	storePercentileJobs(jobs)
}

// Snapshot returns an immutable point-in-time view of all stats.
// It captures engine state under the lock, then builds sub-snapshots
// (including the syscall percentile selection) concurrently via errgroup
// without holding the lock, caches the fresh percentiles (and returns the
// scratch buffers) under a short second lock, and finally assembles the
// result. An error is returned if any sub-builder fails; the scratch buffers
// of that snapshot are then simply dropped and reallocated next time.
func (e *Engine) Snapshot() (*Snapshot, error) {
	if e == nil {
		return nil, nil
	}

	in := e.captureSnapshotInputs()
	elapsed := nonNegativeDuration(in.now.Sub(in.startedAt))

	ss, err := buildSubSnapshots(in, elapsed)
	if err != nil {
		return nil, err
	}
	e.storeSyscallPercentiles(ss.syscallJobs)

	snap := NewSnapshot(
		in.latencySeries, in.gapSeries, in.throughputSeries,
		ss.syscalls, ss.files, ss.processes,
		ss.latencyHist, ss.gapHist,
	)
	populateSnapshotFields(&snap, in, elapsed)

	return &snap, nil
}

// tracedGapMean is the mean gap between consecutive TRACED calls on a
// thread: totalGap over the pairs that have a previous pair, the same samples
// as the gap histogram and series. A pair's DurationToPrev runs from the
// previous EMITTED pair of its TID, so under syscall sampling or for
// syscalls the kernel only counts in aggregate rows (futex and clock_gettime
// by default) it spans the untraced calls in between; it is then not a
// per-call gap.
// No formula over the aggregate rows recovers one either: those rows carry
// no gap and no thread, and threads that make only untraced calls (such as
// parked futex waiters) would add calls to a per-call denominator without
// any gap to share, diluting it toward zero.
func tracedGapMean(in snapshotInputs) float64 {
	return safeMean(in.totalGap, in.gapSamples)
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
