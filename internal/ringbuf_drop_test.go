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
	el := &eventLoop{done: make(chan struct{}), dropSrc: &ringbufDropSourceStub{}}
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
	// A drop source is required for a zero to mean anything: without one the
	// line reports unknown, because nothing was measured.
	el := &eventLoop{done: make(chan struct{}), dropSrc: &ringbufDropSourceStub{}}
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

// ringbufDropSourceFunc adapts a plain function to ringbufDropSource so a test
// can script a sequence that mixes read failures with successful readings -
// something the slice/error stub above cannot express.
type ringbufDropSourceFunc func() (uint64, error)

func (f ringbufDropSourceFunc) Total() (uint64, error) { return f() }

// startAndStopDropMonitor runs one full monitor lifecycle (start, cancel, stop),
// which yields exactly one final tick, and returns whatever it wrote to stderr.
func startAndStopDropMonitor(t *testing.T, el *eventLoop) string {
	t.Helper()
	return captureStderr(t, func() {
		ctx, cancel := context.WithCancel(context.Background())
		stop := el.startRingbufDropMonitor(ctx)
		cancel()
		stop()
	})
}

// TestEventLoopDropMonitorReadFailureReachesStderrWithoutWarningSink is the
// headless half of the drop-observability contract. -plain, -flamegraph and
// headless -parquet wire no warning callback (only makeTUIEventLoopConfigurer
// does), so the read-failure branch's plain notifyWarning discarded the message
// outright: a run whose drop counter could not be read said nothing at all,
// while the drop-delta branch right below it had had a stderr fallback all
// along. The failure must reach the user in every mode.
// TestEventLoopDropMonitorDeltaReachesStderrWithoutWarningSink pins the
// fallback the read-failure branch was originally copied from.
//
// It predates this file's fix and was never covered: reverting the delta
// branch to plain notifyWarning left every test passing, which is how the
// sibling branch came to lack the fallback in the first place. Now that both
// branches share notifyWarningOrLog, one untested call site is enough to lose
// the behaviour for both.
//
// Actual loss is the loudest thing this counter has to say, and a headless run
// would otherwise only learn of it from the end-of-run statistics, which can
// be hours away.
func TestEventLoopDropMonitorDeltaReachesStderrWithoutWarningSink(t *testing.T) {
	el := &eventLoop{
		cfg:     eventLoopConfig{aggregateDrainEvery: time.Hour},
		dropSrc: &ringbufDropSourceStub{totals: []uint64{7}},
		done:    make(chan struct{}),
	}
	// No warningCb is wired: exactly the headless configuration.

	logged := startAndStopDropMonitor(t, el)

	if !strings.Contains(logged, "7") {
		t.Fatalf("stderr = %q, want the kernel-side drop count", logged)
	}
	if el.numRingbufDrops.Load() != 7 {
		t.Errorf("numRingbufDrops = %d, want 7", el.numRingbufDrops.Load())
	}
}

func TestEventLoopDropMonitorReadFailureReachesStderrWithoutWarningSink(t *testing.T) {
	el := &eventLoop{
		cfg:     eventLoopConfig{aggregateDrainEvery: time.Hour},
		dropSrc: &ringbufDropSourceStub{err: errors.New("boom")},
		done:    make(chan struct{}),
	}
	// No warningCb is wired: exactly the headless configuration.

	logged := startAndStopDropMonitor(t, el)

	if !strings.Contains(logged, "drop counter read failed") || !strings.Contains(logged, "boom") {
		t.Fatalf("stderr = %q, want the drop-counter read failure", logged)
	}
}

// TestStatsReportsUnknownRingbufDropsWhenTheCounterCannotBeRead is the other
// half: a failed read leaves numRingbufDrops at its last value (0 here, since
// the very first read failed), and the statistics block documents a zero as an
// explicit "no loss" statement. Printing it would assert as fact a figure
// nobody measured.
func TestStatsReportsUnknownRingbufDropsWhenTheCounterCannotBeRead(t *testing.T) {
	el := &eventLoop{
		cfg:     eventLoopConfig{aggregateDrainEvery: time.Hour},
		dropSrc: &ringbufDropSourceStub{err: errors.New("boom")},
		done:    make(chan struct{}),
	}
	el.startTime = time.Now().Add(-time.Second)
	el.numTracepoints = 10

	_ = startAndStopDropMonitor(t, el)
	close(el.done)

	stats := el.stats()
	if strings.Contains(stats, "ring buffer drops: 0") {
		t.Fatalf("an unreadable counter must not be reported as zero drops:\n%s", stats)
	}
	// The specific cause, not just "unknown": a counter that is present but
	// unreadable is a different problem from one that was never there, and
	// they want different remedies.
	if !strings.Contains(stats, "ring buffer drops: unknown (drop counter unreadable)") {
		t.Fatalf("stats should report the drop total as unknown because the counter could not be read:\n%s", stats)
	}
}

// TestStatsReportsUnknownRingbufDropsWithoutADropCounter covers the purest
// form of the same problem: a BPF object with no ringbuf_drop_map leaves
// dropSrc nil, the monitor never runs, and nothing is ever measured. The line
// used to print a confident 0 for that - a "no loss" claim backed by no
// reading at all. attachRingbufDropCounter does warn on stderr at startup, but
// a long run's summary is read hours later and on its own.
func TestStatsReportsUnknownRingbufDropsWithoutADropCounter(t *testing.T) {
	el := &eventLoop{done: make(chan struct{})}
	el.startTime = time.Now().Add(-time.Second)
	el.numTracepoints = 10
	close(el.done)

	stats := el.stats()
	if strings.Contains(stats, "ring buffer drops: 0") {
		t.Fatalf("a run with no drop counter must not be reported as zero drops:\n%s", stats)
	}
	if !strings.Contains(stats, "ring buffer drops: unknown (drop counter unavailable)") {
		t.Fatalf("stats should report the drop total as unknown because there was no counter:\n%s", stats)
	}
}

// TestStatsKeepsTheLastKnownCountWhenTheCounterStopsBeingReadable covers a run
// that lost events and then lost the counter: the total is unknown from there
// on, but what was already counted is still worth reporting - and must not be
// mistaken for the run total.
func TestStatsKeepsTheLastKnownCountWhenTheCounterStopsBeingReadable(t *testing.T) {
	el := &eventLoop{done: make(chan struct{}), dropSrc: &ringbufDropSourceStub{}}
	el.startTime = time.Now().Add(-time.Second)
	el.numTracepoints = 10

	failing := errors.New("boom")
	calls := 0
	monitor := newRingbufDropMonitor(ringbufDropSourceFunc(func() (uint64, error) {
		calls++
		if calls == 1 {
			return 6, nil
		}
		return 0, failing
	}))
	logged := captureStderr(t, func() {
		el.handleRingbufDropResult(monitor.Tick())
		el.handleRingbufDropResult(monitor.Tick())
	})
	if !strings.Contains(logged, "6 events dropped kernel-side") {
		t.Fatalf("stderr = %q, want the drop burst reported", logged)
	}

	close(el.done)
	stats := el.stats()
	if strings.Contains(stats, "ring buffer drops: 6 (") {
		t.Fatalf("a stale count must not be reported as the run total:\n%s", stats)
	}
	if !strings.Contains(stats, "ring buffer drops: unknown (drop counter unreadable; 6 counted before the failure)") {
		t.Fatalf("stats should report an unknown total with what was counted:\n%s", stats)
	}
}

// TestStatsReportsTheTotalAgainAfterTheCounterRecovers pins the other
// direction: the kernel counter is cumulative, so one successful read after a
// failure recovers the full total and the figure is a fact again.
func TestStatsReportsTheTotalAgainAfterTheCounterRecovers(t *testing.T) {
	el := &eventLoop{done: make(chan struct{}), dropSrc: &ringbufDropSourceStub{}}
	el.startTime = time.Now().Add(-time.Second)
	el.numTracepoints = 96

	calls := 0
	monitor := newRingbufDropMonitor(ringbufDropSourceFunc(func() (uint64, error) {
		calls++
		if calls == 1 {
			return 0, errors.New("boom")
		}
		return 4, nil
	}))
	_ = captureStderr(t, func() {
		el.handleRingbufDropResult(monitor.Tick())
		el.handleRingbufDropResult(monitor.Tick())
	})

	close(el.done)
	stats := el.stats()
	if strings.Contains(stats, "unknown") {
		t.Fatalf("a recovered counter must report its total, not unknown:\n%s", stats)
	}
	if !strings.Contains(stats, "ring buffer drops: 4 (") || !strings.Contains(stats, "4.00% of events") {
		t.Fatalf("stats should report the recovered total:\n%s", stats)
	}
}

// TestAggregateDrainFailureReachesStderrWithoutWarningSink guards the sibling
// swallow. The aggregate drain loop only runs with an aggregate sink wired,
// which today means TUI mode only - where a warning callback always exists - so
// this path is not reachable in production. It shares the fallback anyway, so
// that a future headless aggregate consumer cannot silently reintroduce the
// defect this file fixes.
func TestAggregateDrainFailureReachesStderrWithoutWarningSink(t *testing.T) {
	el := &eventLoop{done: make(chan struct{})}

	logged := captureStderr(t, func() {
		el.handleAggregateDrainResult(aggregateDrainResult{warning: "drain syscall_aggregate_map: boom"})
	})

	if !strings.Contains(logged, "drain syscall_aggregate_map: boom") {
		t.Fatalf("stderr = %q, want the aggregate drain failure", logged)
	}
}

// TestStatsGatesTheDropTotalOnTheFailureFlagNotOnTheTotal pins the half of
// the publication order that is deterministically observable.
//
// handleRingbufDropResult stores the total first and clears the failure flag
// second, and stats() reads them in the opposite order, so a reader that sees
// a cleared flag is guaranteed to see the total that cleared it. The window
// between two adjacent atomic stores is far too narrow to hit from a test - a
// racing version of this passed against both orderings inverted, so it was not
// worth keeping - but the intermediate state it protects is not: with the
// total already published and the flag not yet cleared, stats() must still
// report unknown. That is what says the claim is gated on evidence of a
// successful read rather than on the total merely being non-zero.
func TestStatsGatesTheDropTotalOnTheFailureFlagNotOnTheTotal(t *testing.T) {
	el := &eventLoop{dropSrc: &ringbufDropSourceStub{}}
	el.ringbufDropReadFailed.Store(true)
	el.numRingbufDrops.Store(4242)

	line := el.ringbufDropStatLine(func(uint64) float64 { return 0 })
	if !strings.Contains(line, "unknown") {
		t.Errorf("stats line = %q, want unknown: a total published while the last read is still marked failed says nothing about the run", strings.TrimSpace(line))
	}
	if !strings.Contains(line, "4242 counted before the failure") {
		t.Errorf("stats line = %q, want the last known count reported as counted-before-the-failure rather than as the run total", strings.TrimSpace(line))
	}

	// Clearing the flag - what handleRingbufDropResult does second - is what
	// turns the same total into a statement of fact.
	el.ringbufDropReadFailed.Store(false)
	line = el.ringbufDropStatLine(func(uint64) float64 { return 0 })
	if strings.Contains(line, "unknown") {
		t.Errorf("stats line = %q, want the total reported as fact once a read has succeeded", strings.TrimSpace(line))
	}
	if !strings.Contains(line, "4242") {
		t.Errorf("stats line = %q, want the counted total", strings.TrimSpace(line))
	}
}
