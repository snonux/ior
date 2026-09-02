package internal

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"
)

// ringbufDropSourceStub returns a scripted sequence of cumulative counter
// readings (the last one repeats), or an error.
type ringbufDropSourceStub struct {
	mu      sync.Mutex
	totals  []uint64
	err     error
	callCnt int
}

func (s *ringbufDropSourceStub) Total() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.callCnt++
	if s.err != nil {
		return 0, s.err
	}
	if len(s.totals) == 0 {
		return 0, nil
	}
	next := s.totals[0]
	if len(s.totals) > 1 {
		s.totals = s.totals[1:]
	}
	return next, nil
}

// perCPUMapStub serves a raw per-CPU map value, mimicking libbpfgo's
// BPFMap.GetValue for a PERCPU_ARRAY (one 8-byte element per possible CPU).
type perCPUMapStub struct {
	raw []byte
	err error
}

func (m perCPUMapStub) GetValue(unsafe.Pointer) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.raw, nil
}

func perCPUCounterBytes(values ...uint64) []byte {
	raw := make([]byte, 0, len(values)*ringbufDropValueStride)
	for _, v := range values {
		var buf [ringbufDropValueStride]byte
		binary.LittleEndian.PutUint64(buf[:], v)
		raw = append(raw, buf[:]...)
	}
	return raw
}

func TestSumPerCPUCountersAddsEveryCPUSlot(t *testing.T) {
	got, err := sumPerCPUCounters(perCPUCounterBytes(3, 0, 11, 1))
	if err != nil {
		t.Fatalf("sumPerCPUCounters: %v", err)
	}
	if got != 15 {
		t.Fatalf("total = %d, want 15", got)
	}
}

func TestSumPerCPUCountersRejectsMalformedValue(t *testing.T) {
	for name, raw := range map[string][]byte{
		"empty":     {},
		"truncated": make([]byte, 12),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := sumPerCPUCounters(raw); err == nil {
				t.Fatal("want an error for a malformed per-cpu value")
			}
		})
	}
}

func TestRingbufDropCounterTotalSumsMapValue(t *testing.T) {
	counter := &ringbufDropCounter{dropMap: perCPUMapStub{raw: perCPUCounterBytes(7, 5)}}
	got, err := counter.Total()
	if err != nil {
		t.Fatalf("Total: %v", err)
	}
	if got != 12 {
		t.Fatalf("Total = %d, want 12", got)
	}
}

func TestRingbufDropCounterTotalWrapsMapError(t *testing.T) {
	counter := &ringbufDropCounter{dropMap: perCPUMapStub{err: errors.New("boom")}}
	if _, err := counter.Total(); err == nil || !strings.Contains(err.Error(), ringbufDropMapName) {
		t.Fatalf("err = %v, want it to name %s", err, ringbufDropMapName)
	}
}

func TestRingbufDropCounterTotalIsZeroWithoutMap(t *testing.T) {
	var counter *ringbufDropCounter
	got, err := counter.Total()
	if err != nil || got != 0 {
		t.Fatalf("Total = (%d, %v), want (0, nil)", got, err)
	}
}

func TestRingbufDropMonitorReportsDeltaPerTick(t *testing.T) {
	monitor := newRingbufDropMonitor(&ringbufDropSourceStub{totals: []uint64{0, 4, 4, 9}})

	want := []ringbufDropResult{
		{total: 0, delta: 0},
		{total: 4, delta: 4},
		{total: 4, delta: 0},
		{total: 9, delta: 5},
	}
	for i, expected := range want {
		if got := monitor.Tick(); got != expected {
			t.Fatalf("tick %d = %+v, want %+v", i, got, expected)
		}
	}
}

func TestRingbufDropMonitorTickReportsReadFailure(t *testing.T) {
	monitor := newRingbufDropMonitor(&ringbufDropSourceStub{err: errors.New("boom")})
	got := monitor.Tick()
	if got.warning == "" || !strings.Contains(got.warning, "boom") {
		t.Fatalf("warning = %q, want the read failure", got.warning)
	}
	if got.total != 0 || got.delta != 0 {
		t.Fatalf("counters = %+v, want zero on failure", got)
	}
}

func TestRingbufDropMonitorFinalTickOnStop(t *testing.T) {
	src := &ringbufDropSourceStub{totals: []uint64{12}}
	monitor := newRingbufDropMonitor(src)

	var mu sync.Mutex
	var results []ringbufDropResult
	ctx, cancel := context.WithCancel(context.Background())
	stop := monitor.Start(ctx, time.Hour, func(r ringbufDropResult) {
		mu.Lock()
		defer mu.Unlock()
		results = append(results, r)
	})
	cancel()
	stop()

	mu.Lock()
	defer mu.Unlock()
	if len(results) != 1 {
		t.Fatalf("results = %+v, want exactly the final tick", results)
	}
	if results[0].total != 12 || results[0].delta != 12 {
		t.Fatalf("final tick = %+v, want total/delta 12", results[0])
	}
}

func TestEventLoopDropMonitorWarnsAndRecordsTotal(t *testing.T) {
	el := &eventLoop{
		cfg:     eventLoopConfig{aggregateDrainEvery: time.Hour},
		dropSrc: &ringbufDropSourceStub{totals: []uint64{6}},
		done:    make(chan struct{}),
	}
	var mu sync.Mutex
	var warnings []string
	el.warningCb = func(message string) {
		mu.Lock()
		defer mu.Unlock()
		warnings = append(warnings, message)
	}

	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startRingbufDropMonitor(ctx)
	cancel()
	stop()

	if got := el.numRingbufDrops.Load(); got != 6 {
		t.Fatalf("numRingbufDrops = %d, want 6", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(warnings) != 1 || !strings.Contains(warnings[0], "6 events dropped kernel-side") {
		t.Fatalf("warnings = %q, want one drop warning", warnings)
	}
}

func TestEventLoopDropMonitorStaysQuietWithoutDrops(t *testing.T) {
	el := &eventLoop{
		cfg:     eventLoopConfig{aggregateDrainEvery: time.Hour},
		dropSrc: &ringbufDropSourceStub{totals: []uint64{0}},
		done:    make(chan struct{}),
	}
	var warned bool
	el.warningCb = func(string) { warned = true }

	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startRingbufDropMonitor(ctx)
	cancel()
	stop()

	if warned {
		t.Fatal("a run without drops must not warn")
	}
	if got := el.numRingbufDrops.Load(); got != 0 {
		t.Fatalf("numRingbufDrops = %d, want 0", got)
	}
}

func TestEventLoopDropMonitorForwardsReadFailure(t *testing.T) {
	el := &eventLoop{
		cfg:     eventLoopConfig{aggregateDrainEvery: time.Hour},
		dropSrc: &ringbufDropSourceStub{err: errors.New("boom")},
		done:    make(chan struct{}),
	}
	var warnings []string
	el.warningCb = func(message string) { warnings = append(warnings, message) }

	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startRingbufDropMonitor(ctx)
	cancel()
	stop()

	if len(warnings) != 1 || !strings.Contains(warnings[0], "drop counter read failed") {
		t.Fatalf("warnings = %q, want the read failure surfaced", warnings)
	}
}

func TestEventLoopWithoutDropSourceStartsNoMonitor(t *testing.T) {
	el := &eventLoop{cfg: eventLoopConfig{aggregateDrainEvery: time.Hour}, done: make(chan struct{})}
	el.warningCb = func(string) { t.Fatal("no drop source must produce no warnings") }

	stop := el.startRingbufDropMonitor(context.Background())
	stop()
}

// TestStatsReportsRingbufDrops locks in the stats() surfacing of the counter:
// the line is always present (an explicit "no loss" statement) and carries the
// count, the rate and the share of events lost.
func TestStatsReportsRingbufDrops(t *testing.T) {
	el := &eventLoop{done: make(chan struct{})}
	el.startTime = time.Now().Add(-2 * time.Second)
	el.numTracepoints = 98
	el.numRingbufDrops.Store(2)
	close(el.done)

	stats := el.stats()
	if !strings.Contains(stats, "ring buffer drops: 2 (") {
		t.Fatalf("stats missing the drop count:\n%s", stats)
	}
	if !strings.Contains(stats, "2.00% of events") {
		t.Fatalf("stats missing the drop share:\n%s", stats)
	}
}

func TestStatsReportsZeroRingbufDrops(t *testing.T) {
	el := &eventLoop{done: make(chan struct{})}
	el.startTime = time.Now().Add(-time.Second)
	el.numTracepoints = 10
	close(el.done)

	if stats := el.stats(); !strings.Contains(stats, "ring buffer drops: 0 (0.00/s, 0.00% of events)") {
		t.Fatalf("stats missing the zero-drop line:\n%s", stats)
	}
}

// TestRingbufDropCounterConcurrentWithStatsRead exercises the actual data race
// the atomic counter exists for: the monitor goroutine stores new totals while
// the shutdown path reads them for the statistics summary. Meaningful under
// -race.
func TestRingbufDropCounterConcurrentWithStatsRead(t *testing.T) {
	el := &eventLoop{
		cfg:     eventLoopConfig{aggregateDrainEvery: time.Millisecond},
		dropSrc: &ringbufDropSourceStub{totals: []uint64{1, 2, 3, 4, 5}},
		done:    make(chan struct{}),
	}
	el.warningCb = func(string) {}
	el.startTime = time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startRingbufDropMonitor(ctx)

	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for i := 0; i < 200; i++ {
			_ = el.numRingbufDrops.Load()
		}
	}()

	<-readerDone
	cancel()
	stop()

	close(el.done)
	// The number of ticks that fit into the reader loop is timing-dependent,
	// so assert stats() reports exactly what the counter holds after the
	// final tick rather than a fixed total.
	want := fmt.Sprintf("ring buffer drops: %d (", el.numRingbufDrops.Load())
	if stats := el.stats(); !strings.Contains(stats, want) {
		t.Fatalf("stats should report %q:\n%s", want, stats)
	}
}

// TestEventLoopDropMonitorWithoutWarningSinkDoesNotPanic covers the -plain /
// headless fallback path, where drops are logged to stderr because no warning
// callback is wired.
func TestEventLoopDropMonitorWithoutWarningSinkDoesNotPanic(t *testing.T) {
	el := &eventLoop{
		cfg:     eventLoopConfig{aggregateDrainEvery: time.Hour},
		dropSrc: &ringbufDropSourceStub{totals: []uint64{3}},
		done:    make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startRingbufDropMonitor(ctx)
	cancel()
	stop()

	if got := el.numRingbufDrops.Load(); got != 3 {
		t.Fatalf("numRingbufDrops = %d, want 3", got)
	}
}
