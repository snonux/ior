package statsengine

import (
	"math"
	"testing"
	"time"

	"ior/internal/event"
	"ior/internal/types"
)

func TestIngestSyscallAggregatesUpdatesSnapshot(t *testing.T) {
	engine := NewEngine(DefaultTopN)
	engine.IngestSyscallAggregates([]SyscallAggregate{
		{
			TraceID:        types.SYS_ENTER_FUTEX,
			Count:          3,
			Errors:         1,
			TotalLatencyNs: 90,
			MinLatencyNs:   10,
			MaxLatencyNs:   50,
			LatencyHistogramNs: [8]uint64{
				1, 1, 1, 0, 0, 0, 0, 0,
			},
		},
	})

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	if snap.TotalSyscalls != 3 {
		t.Fatalf("TotalSyscalls = %d, want 3", snap.TotalSyscalls)
	}
	if snap.TotalErrors != 1 {
		t.Fatalf("TotalErrors = %d, want 1", snap.TotalErrors)
	}
	if snap.LatencyHistogram.Total != 3 {
		t.Fatalf("LatencyHistogram.Total = %d, want 3", snap.LatencyHistogram.Total)
	}

	syscalls := snap.Syscalls()
	var futexRow *SyscallSnapshot
	for i := range syscalls {
		row := &syscalls[i]
		if row.TraceID == types.SYS_ENTER_FUTEX {
			futexRow = row
			break
		}
	}
	if futexRow == nil {
		t.Fatal("expected futex syscall row")
	}
	if futexRow.Count != 3 || futexRow.Errors != 1 {
		t.Fatalf("futex row = %+v, want count=3 errors=1", *futexRow)
	}
	if futexRow.LatencyMinNs != 10 || futexRow.LatencyMaxNs != 50 {
		t.Fatalf("futex min/max = %d/%d, want 10/50", futexRow.LatencyMinNs, futexRow.LatencyMaxNs)
	}
}

// firstPair returns a pair that is its TID's first, so it has no gap.
func firstPair(duration uint64) *event.Pair {
	pair := newEnginePair(types.SYS_ENTER_READ, 0, types.UNCLASSIFIED, "p", 1, "", 0, 0, duration, 0)
	pair.FirstOnTID = true
	return pair
}

// Under 1-in-N sampling a traced pair's gap runs from the previous traced
// pair of its thread, so it spans the N-1 untraced calls (counted only in
// aggregate rows) in between. GapMeanNs is documented as the mean gap
// between traced calls, so with per-call gap G=100, latency L=20 and N=10 it
// reports each traced gap N*G + (N-1)*L = 1180, the same samples as the gap
// histogram; the untraced calls do not enter its denominator. The TID's
// first pair has no gap and is left out.
func TestGapMeanIsPerTracedPairUnderSampling(t *testing.T) {
	const (
		n        = 10
		gap      = 100
		latency  = 20
		sampled  = 4
		spanning = n*gap + (n-1)*latency
	)
	engine := NewEngine(DefaultTopN)
	engine.Ingest(firstPair(latency))
	for range sampled {
		engine.Ingest(newEnginePair(types.SYS_ENTER_READ, 0, types.UNCLASSIFIED, "p", 1, "", 0, 0, latency, spanning))
	}
	engine.IngestSyscallAggregates([]SyscallAggregate{
		{TraceID: types.SYS_ENTER_READ, Count: sampled * (n - 1), TotalLatencyNs: sampled * (n - 1) * latency},
	})

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	if snap.TotalSyscalls != 1+sampled*n {
		t.Fatalf("TotalSyscalls = %d, want %d", snap.TotalSyscalls, 1+sampled*n)
	}
	if snap.GapMeanNs != spanning {
		t.Fatalf("GapMeanNs = %v, want traced-pair mean %d", snap.GapMeanNs, spanning)
	}
	if snap.GapHistogram.Total != sampled {
		t.Fatalf("GapHistogram.Total = %d, want %d", snap.GapHistogram.Total, sampled)
	}
}

// Aggregate-only syscalls (futex and clock_gettime by default) of threads
// that make no traced calls at all, such as parked futex waiters, must not
// dilute the gap mean: 100 reads 1ms apart next to a million aggregated
// futex calls still have a 1ms gap mean, not ~0.1us.
func TestGapMeanNotDilutedByAggregateOnlyThreads(t *testing.T) {
	const gap = 1_000_000
	engine := NewEngine(DefaultTopN)
	for range 100 {
		engine.Ingest(newEnginePair(types.SYS_ENTER_READ, 0, types.UNCLASSIFIED, "reader", 1, "", 0, 0, 10, gap))
	}
	engine.IngestSyscallAggregates([]SyscallAggregate{
		{TraceID: types.SYS_ENTER_FUTEX, Count: 1_000_000, TotalLatencyNs: 1_000_000},
	})

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	if snap.TotalSyscalls != 1_000_100 || snap.GapMeanNs != gap {
		t.Fatalf("total/gap mean = %d/%v, want 1000100/%d", snap.TotalSyscalls, snap.GapMeanNs, gap)
	}
}

// A TID's first pair has no gap: it must not add a 0 to the gap histogram
// or series, nor count in the gap mean. Pairs with gaps 30 and 90 plus one
// first pair average 60, not 40.
func TestFirstPairOnTIDIsNotAGapSample(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	engine := newEngineWithClock(DefaultTopN, func() time.Time { return now })
	engine.Ingest(firstPair(10))
	engine.Ingest(newEnginePair(types.SYS_ENTER_READ, 0, types.UNCLASSIFIED, "p", 1, "", 0, 0, 10, 30))
	engine.Ingest(newEnginePair(types.SYS_ENTER_READ, 0, types.UNCLASSIFIED, "p", 1, "", 0, 0, 10, 90))

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	if snap.TotalSyscalls != 3 || snap.GapMeanNs != 60 {
		t.Fatalf("total/gap mean = %d/%v, want 3/60", snap.TotalSyscalls, snap.GapMeanNs)
	}
	if snap.GapHistogram.Total != 2 {
		t.Fatalf("GapHistogram.Total = %d, want 2", snap.GapHistogram.Total)
	}
	if series := snap.GapSeriesNs(); series[len(series)-1] != 60 {
		t.Fatalf("gap series = %v, want last point 60", series)
	}
}

// With only aggregate rows (or only first pairs) there is no gap at all: the
// mean is 0, not a division by zero.
func TestGapMeanWithoutGapSamplesIsZero(t *testing.T) {
	engine := NewEngine(DefaultTopN)
	engine.IngestSyscallAggregates([]SyscallAggregate{
		{TraceID: types.SYS_ENTER_FUTEX, Count: 5, TotalLatencyNs: 50},
	})
	engine.Ingest(firstPair(10))

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	if snap.GapMeanNs != 0 || snap.GapHistogram.Total != 0 {
		t.Fatalf("gap mean/hist total = %v/%d, want 0/0", snap.GapMeanNs, snap.GapHistogram.Total)
	}
}

// Reset must forget the gap samples, or the next session's gap mean divides
// by pairs of the previous one.
func TestResetClearsGapSamples(t *testing.T) {
	engine := NewEngine(DefaultTopN)
	engine.Ingest(newEnginePair(types.SYS_ENTER_READ, 0, types.UNCLASSIFIED, "p", 1, "", 0, 0, 10, 100))
	engine.Ingest(newEnginePair(types.SYS_ENTER_READ, 0, types.UNCLASSIFIED, "p", 1, "", 0, 0, 10, 100))
	engine.Reset()
	engine.Ingest(newEnginePair(types.SYS_ENTER_READ, 0, types.UNCLASSIFIED, "p", 1, "", 0, 0, 10, 30))

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	if snap.GapMeanNs != 30 {
		t.Fatalf("GapMeanNs after reset = %v, want 30", snap.GapMeanNs)
	}
}

// An aggregate batch weighs its timed invocations in the latency series slot:
// one 1000ns pair next to a drain of 99 calls averaging 10ns gives a slot
// mean of (1000+990)/100 = 19.9, not the unweighted (1000+10)/2 = 505.
func TestLatencySeriesWeighsAggregateBatchByTimedCount(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	engine := newEngineWithClock(DefaultTopN, func() time.Time { return now })
	engine.Ingest(newEnginePair(types.SYS_ENTER_READ, 0, types.UNCLASSIFIED, "p", 1, "", 0, 0, 1000, 1))
	engine.IngestSyscallAggregates([]SyscallAggregate{
		// 100 counted, 1 untimed: the 99 timed calls sum to 990ns.
		{TraceID: types.SYS_ENTER_FUTEX, Count: 100, UntimedCount: 1, TotalLatencyNs: 990},
	})

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	series := snap.LatencySeriesNs()
	if len(series) == 0 || math.Abs(series[len(series)-1]-19.9) > 1e-9 {
		t.Fatalf("latency series = %v, want last point 19.9", series)
	}
}

// Drains arrive every second but series slots are 500ms wide. Interleaving
// them with one 1000ns pair per slot must give every slot the same mean,
// (500*10 + 1000) / 501: each drain is spread over both slots it covers.
// Recording a drain in one slot made a comb (~11 next to 1000) that
// detectTrend read as a trend depending on ticker phase.
func TestLatencySeriesSpreadsDrainsAcrossSlots(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	engine := newEngineWithClock(DefaultTopN, clock.Now)
	const seconds = trendWindowSlots + 1
	for range seconds {
		clock.Advance(250 * time.Millisecond)
		engine.Ingest(newEnginePair(types.SYS_ENTER_READ, 0, types.UNCLASSIFIED, "p", 1, "", 0, 0, 1000, 1))
		clock.Advance(500 * time.Millisecond)
		engine.Ingest(newEnginePair(types.SYS_ENTER_READ, 0, types.UNCLASSIFIED, "p", 1, "", 0, 0, 1000, 1))
		clock.Advance(250 * time.Millisecond)
		engine.IngestSyscallAggregates([]SyscallAggregate{
			{TraceID: types.SYS_ENTER_FUTEX, Count: 1000, TotalLatencyNs: 10_000},
		})
	}
	clock.Advance(-time.Millisecond) // end the window at the last filled slot

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	series := snap.LatencySeriesNs()
	want := (500*10 + 1000) / 501.0
	for _, v := range series[len(series)-2*seconds:] {
		if math.Abs(v-want) > 1e-9 {
			t.Fatalf("latency series = %v, want every covered slot %v", series[len(series)-2*seconds:], want)
		}
	}
	if snap.LatencyTrend.Direction != TrendStable {
		t.Fatalf("LatencyTrend = %+v, want stable", snap.LatencyTrend)
	}
}

// A drain after an idle stretch (the drainer forwards no empty batches) is
// spread over one drain period only, not back to the previous batch: the
// slots in between stay empty.
func TestAggregateSpanCappedAtDrainPeriod(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	engine := newEngineWithClock(DefaultTopN, clock.Now)
	clock.Advance(time.Second)
	engine.IngestSyscallAggregates([]SyscallAggregate{{TraceID: types.SYS_ENTER_FUTEX, Count: 2, TotalLatencyNs: 20}})
	clock.Advance(10 * time.Second)
	engine.IngestSyscallAggregates([]SyscallAggregate{{TraceID: types.SYS_ENTER_FUTEX, Count: 2, TotalLatencyNs: 20}})
	clock.Advance(-time.Millisecond)

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	series := snap.LatencySeriesNs()
	tail := series[len(series)-22:]
	want := []float64{10, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 10}
	for i := range want {
		if tail[i] != want[i] {
			t.Fatalf("latency series tail = %v, want %v", tail, want)
		}
	}
}

// The drain period set by the event loop bounds the spread: with a 5s
// period, a drain after 10s of idleness fills the last 10 half-second slots
// and leaves the ones before empty. A non-positive period restores the 1s
// default, and Reset keeps the configured period.
func TestSetAggregateDrainPeriodBoundsSpread(t *testing.T) {
	tests := []struct {
		name   string
		period time.Duration
		reset  bool
		filled int
	}{
		{name: "configured 5s", period: 5 * time.Second, filled: 10},
		{name: "kept across reset", period: 5 * time.Second, reset: true, filled: 10},
		{name: "zero restores default", period: 0, filled: 2},
		{name: "negative restores default", period: -time.Second, filled: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
			engine := newEngineWithClock(DefaultTopN, clock.Now)
			engine.SetAggregateDrainPeriod(3 * time.Second) // overwritten below
			engine.SetAggregateDrainPeriod(tt.period)
			if tt.reset {
				engine.Reset()
			}
			clock.Advance(10 * time.Second)
			engine.IngestSyscallAggregates([]SyscallAggregate{{TraceID: types.SYS_ENTER_FUTEX, Count: 2, TotalLatencyNs: 20}})
			clock.Advance(-time.Millisecond)

			snap, err := engine.Snapshot()
			if err != nil {
				t.Fatalf("snapshot error: %v", err)
			}
			series := snap.LatencySeriesNs()
			tail := series[len(series)-tt.filled-1:]
			if tail[0] != 0 {
				t.Fatalf("series tail = %v, want slot before the spread empty", tail)
			}
			for _, v := range tail[1:] {
				if math.Abs(v-10) > 1e-9 {
					t.Fatalf("series tail = %v, want %d slots of 10", tail, tt.filled)
				}
			}
		})
	}
}

func TestSetAggregateDrainPeriodNilEngine(t *testing.T) {
	var engine *Engine
	engine.SetAggregateDrainPeriod(time.Second) // must not panic
}

// A forward wall-clock step between two drains must not stretch the next
// batch over the whole series window: the span stays capped at one drain
// period, so a batch after a 1h step fills at most aggregateSpan/slotSize
// (here 2) slots. fakeClock readings carry no monotonic part, so this pins
// the wall-clock cap; aggregateSpanStart strips time.Now's monotonic
// readings to get the same behaviour for real clocks.
func TestAggregateSpanCappedAfterForwardWallClockStep(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	engine := newEngineWithClock(DefaultTopN, clock.Now)
	clock.Advance(time.Second)
	engine.IngestSyscallAggregates([]SyscallAggregate{{TraceID: types.SYS_ENTER_FUTEX, Count: 2, TotalLatencyNs: 20}})
	clock.Advance(time.Hour)
	engine.IngestSyscallAggregates([]SyscallAggregate{{TraceID: types.SYS_ENTER_FUTEX, Count: 2, TotalLatencyNs: 20}})
	clock.Advance(-time.Millisecond)

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	maxSlots := int(defaultAggregateDrainPeriod / timeSeriesSlotWidthDefault)
	filled := 0
	for _, v := range snap.LatencySeriesNs() {
		if v != 0 {
			filled++
		}
	}
	if filled == 0 || filled > maxSlots {
		t.Fatalf("filled slots = %d, want 1..%d", filled, maxSlots)
	}
}
