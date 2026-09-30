package internal

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ior/internal/event"
	"ior/internal/flags"
	"ior/internal/flamegraph"
	"ior/internal/globalfilter"
	"ior/internal/statsengine"
	"ior/internal/types"
)

func mustParseArgs(t *testing.T, args ...string) flags.Config {
	t.Helper()
	cfg, err := flags.ParseArgs(args)
	if err != nil {
		t.Fatalf("ParseArgs(%v) error = %v", args, err)
	}
	return cfg
}

// Only an explicit rate makes a raw-mode run sampled: the built-in
// aggregate-only defaults are promoted to 1 there, so a plain run neither needs
// the kernel counters nor carries a marker.
func TestRawModeSamplingRates(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want map[types.TraceId]uint32
	}{
		{"plain without explicit rates samples nothing", []string{"-plain"}, nil},
		{"parquet without explicit rates samples nothing", []string{"-parquet", "x.parquet"}, nil},
		{"flamegraph without explicit rates samples nothing", []string{"-flamegraph"}, nil},
		{"plain read=10", []string{"-plain", "-syscall-sampling-syscalls", "read=10"},
			map[types.TraceId]uint32{types.SYS_ENTER_READ: 10}},
		{"parquet read=10", []string{"-parquet", "x.parquet", "-syscall-sampling-syscalls", "read=10"},
			map[types.TraceId]uint32{types.SYS_ENTER_READ: 10}},
		{"explicit zero stays aggregate-only", []string{"-flamegraph", "-syscall-sampling-syscalls", "read=0"},
			map[types.TraceId]uint32{types.SYS_ENTER_READ: 0}},
		{"explicit rate 1 is not sampling", []string{"-plain", "-syscall-sampling-syscalls", "read=1"}, nil},
		{"the TUI keeps its own aggregate sink", []string{"-syscall-sampling-syscalls", "read=10"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := rawModeSamplingRates(mustParseArgs(t, tc.args...))
			if len(got) != len(tc.want) {
				t.Fatalf("rates = %v, want %v", got, tc.want)
			}
			for id, rate := range tc.want {
				if got[id] != rate {
					t.Fatalf("rates = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// A family rate reaches every syscall of the family, and the rate is the
// effective one (an explicit per-syscall rate wins over it).
func TestRawModeSamplingRatesFollowPrecedence(t *testing.T) {
	cfg := mustParseArgs(t, "-plain", "-syscall-sampling-families", "IPC=4", "-syscall-sampling-syscalls", "futex=7")
	got := rawModeSamplingRates(cfg)
	if got[types.SYS_ENTER_FUTEX] != 7 {
		t.Fatalf("futex rate = %d, want the explicit 7", got[types.SYS_ENTER_FUTEX])
	}
	if got[types.SYS_ENTER_FUTEX_WAIT] != 4 {
		t.Fatalf("futex_wait rate = %d, want the family's 4", got[types.SYS_ENTER_FUTEX_WAIT])
	}
}

func sampledLoop(t *testing.T, args ...string) *eventLoop {
	t.Helper()
	cfg := mustParseArgs(t, args...)
	el := mustNewEventLoop(t, newEventLoopConfig(cfg))
	el.SetPrintCallback(func(ep *event.Pair) { ep.Recycle() })
	return el
}

func TestNewEventLoopWiresTheTallyOnlyForASampledRawRun(t *testing.T) {
	sampled := sampledLoop(t, "-plain", "-syscall-sampling-syscalls", "read=10")
	if sampled.samplingTally == nil {
		t.Fatal("no tally for a sampled raw-mode run")
	}
	if sampled.aggregateSink != syscallAggregateSink(sampled.samplingTally) {
		t.Fatal("the tally is not the aggregate sink, so the drain loop would not run")
	}
	for _, args := range [][]string{{"-plain"}, {"-syscall-sampling-syscalls", "read=10"}} {
		el := sampledLoop(t, args...)
		if el.samplingTally != nil || el.aggregateSink != nil {
			t.Fatalf("args %v: tally=%v sink=%v, want neither", args, el.samplingTally, el.aggregateSink)
		}
		if got := el.samplingResult(); got.Active() {
			t.Fatalf("args %v: sampling result %+v, want none", args, got)
		}
	}
}

// emitPair hands one completed pair of traceID through the loop's emission path.
func emitPair(el *eventLoop, traceID types.TraceId) {
	ch := make(chan *event.Pair, 1)
	ch <- &event.Pair{
		EnterEv: &types.RetEvent{TraceId: traceID, Pid: 1},
		ExitEv:  &types.RetEvent{TraceId: traceID + 1, Pid: 1},
	}
	el.drainPairs(ch)
}

// The exact population of a sampled syscall is the rows written plus the
// invocations only the kernel counted; a syscall traced in full adds nothing.
func TestSampledRunReportsTheExactPopulation(t *testing.T) {
	el := sampledLoop(t, "-plain", "-syscall-sampling-syscalls", "read=10")
	src := &aggregateSourceStub{rows: [][]statsengine.SyscallAggregate{
		{{TraceID: types.SYS_ENTER_READ, Count: 500}},
		{{TraceID: types.SYS_ENTER_READ, Count: 390}},
	}}
	el.aggregateSrc = src
	el.cfg.aggregateDrainEvery = time.Millisecond

	for range 110 {
		emitPair(el, types.SYS_ENTER_READ)
	}
	emitPair(el, types.SYS_ENTER_WRITE) // traced in full: not part of the tally

	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startAggregateDrainLoop(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for {
		src.mu.Lock()
		drained := len(src.rows) == 0
		src.mu.Unlock()
		if drained || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	stop()

	got := el.samplingResult()
	if !got.TotalsKnown() || len(got.Entries) != 1 {
		t.Fatalf("result = %+v, want known totals for one syscall", got)
	}
	read := got.Entries[0]
	if read.Syscall != "read" || read.Rate != 10 || read.Traced != 110 || read.Counted != 890 || read.Total() != 1000 {
		t.Fatalf("read entry = %+v, want rate 10, 110 traced + 890 counted = 1000", read)
	}
}

func TestSamplingStatLinesStateTheTrueTotals(t *testing.T) {
	el := sampledLoop(t, "-plain", "-syscall-sampling-syscalls", "read=10")
	el.aggregateSrc = &aggregateSourceStub{rows: [][]statsengine.SyscallAggregate{{{TraceID: types.SYS_ENTER_READ, Count: 90}}}}
	for range 10 {
		emitPair(el, types.SYS_ENTER_READ)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startAggregateDrainLoop(ctx)
	cancel()
	stop() // the final drain merges the kernel counts

	lines := el.samplingStatLines()
	for _, want := range []string{"read: 100 calls (1-in-10: 10 traced, 90 counted only)", "syscalls including kernel-counted only: 100"} {
		if !strings.Contains(lines, want) {
			t.Fatalf("stat lines = %q, want %q", lines, want)
		}
	}
}

func TestUnsampledRunHasNoSamplingStatLines(t *testing.T) {
	el := sampledLoop(t, "-plain")
	if got := el.samplingStatLines(); got != "" {
		t.Fatalf("stat lines = %q, want none", got)
	}
}

// The kernel counters are keyed by syscall only, so a filter on anything else
// cannot be applied to them: the totals must then be withheld, not reported
// as a count that ignores the filter.
func TestSamplingTotalsAreUnavailableUnderAnUnsupportedFilter(t *testing.T) {
	el := sampledLoop(t, "-plain", "-syscall-sampling-syscalls", "read=10")
	el.SetFilter(globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "bash"}})
	for range 10 {
		emitPair(el, types.SYS_ENTER_READ)
	}
	got := el.samplingResult()
	if !got.Active() || got.TotalsKnown() {
		t.Fatalf("result = %+v, want a sampled run with unavailable totals", got)
	}
	if lines := el.samplingStatLines(); !strings.Contains(lines, "unavailable") || strings.Contains(lines, "10 traced") {
		t.Fatalf("stat lines = %q, want an unavailable note without counts", lines)
	}
}

// A drain that failed last leaves the counts short: no totals rather than
// wrong ones. A later good drain recovers, because the kernel map is cumulative.
func TestSamplingTotalsAreUnavailableAfterAFailedDrain(t *testing.T) {
	el := sampledLoop(t, "-plain", "-syscall-sampling-syscalls", "read=10")
	el.handleAggregateDrainResult(aggregateDrainResult{warning: "syscall aggregate drain failed: boom"})
	if got := el.samplingResult(); got.TotalsKnown() {
		t.Fatalf("result = %+v after a failed drain, want unavailable totals", got)
	}
	el.handleAggregateDrainResult(aggregateDrainResult{rows: []statsengine.SyscallAggregate{{TraceID: types.SYS_ENTER_READ, Count: 5}}})
	got := el.samplingResult()
	if !got.TotalsKnown() || got.Entries[0].Counted != 5 {
		t.Fatalf("result = %+v after a good drain, want counted 5", got)
	}
}

func TestAnnounceSamplingNamesTheRatesOnlyWhenSampling(t *testing.T) {
	var lines []string
	el := sampledLoop(t, "-plain", "-syscall-sampling-syscalls", "read=10,write=0")
	el.SetStatusCallback(func(args ...any) { lines = append(lines, args[0].(string)) })
	el.announceSampling()
	if len(lines) != 1 || !strings.Contains(lines[0], "read=10,write=0") || !strings.Contains(lines[0], "sample") {
		t.Fatalf("announcement = %q, want one line naming the rates", lines)
	}

	quiet := sampledLoop(t, "-plain")
	quiet.SetStatusCallback(func(args ...any) { t.Errorf("unsampled run announced %v", args) })
	quiet.announceSampling()
}

func TestTallyIgnoresSyscallsItDoesNotSample(t *testing.T) {
	tally := newSamplingTally(map[types.TraceId]uint32{types.SYS_ENTER_READ: 4}, nil)
	tally.countTraced(types.SYS_ENTER_WRITE)
	tally.IngestSyscallAggregates([]statsengine.SyscallAggregate{{TraceID: types.SYS_ENTER_WRITE, Count: 9}})
	got := tally.summary("")
	if len(got.Entries) != 1 || got.Entries[0].Traced != 0 || got.Entries[0].Counted != 0 {
		t.Fatalf("summary = %+v, want only read, untouched", got)
	}
}

// A failing aggregate source must not stop the run or go unreported.
func TestSampledRunSurvivesAFailingAggregateSource(t *testing.T) {
	el := sampledLoop(t, "-plain", "-syscall-sampling-syscalls", "read=10")
	el.aggregateSrc = &aggregateSourceStub{err: errors.New("map gone")}
	var warnings []string
	el.SetWarningCallback(func(m string) { warnings = append(warnings, m) })
	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startAggregateDrainLoop(ctx)
	cancel()
	stop()
	if len(warnings) == 0 || !strings.Contains(warnings[0], "map gone") {
		t.Fatalf("warnings = %q, want the drain failure", warnings)
	}
	if el.samplingResult().TotalsKnown() {
		t.Fatal("totals claimed known although the final drain failed")
	}
}

// A sampled -flamegraph run keeps its sample marker and exact totals in the
// recording header; the same run without sampling writes no marker.
func TestFinaliseTraceStoresTheSamplingInTheRecording(t *testing.T) {
	t.Chdir(t.TempDir())
	el := sampledLoop(t, "-flamegraph", "-syscall-sampling-syscalls", "read=10")
	el.aggregateSrc = &aggregateSourceStub{rows: [][]statsengine.SyscallAggregate{{{TraceID: types.SYS_ENTER_READ, Count: 90}}}}
	for range 10 {
		emitPair(el, types.SYS_ENTER_READ)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startAggregateDrainLoop(ctx)
	cancel()
	stop()

	recorder := flamegraph.NewRecorder("qq2")
	if err := finaliseTrace(recorder, el.samplingResult(), time.Second, func(...any) {}); err != nil {
		t.Fatalf("finaliseTrace: %v", err)
	}
	matches, err := filepath.Glob("*qq2*.ior.zst")
	if err != nil || len(matches) != 1 {
		t.Fatalf("recordings = %v, %v; want exactly one", matches, err)
	}
	_, got, err := flamegraph.LoadRecording(matches[0])
	if err != nil {
		t.Fatalf("LoadRecording: %v", err)
	}
	if !got.TotalsKnown() || len(got.Entries) != 1 || got.Entries[0].Total() != 100 || got.Entries[0].Rate != 10 {
		t.Fatalf("recording sampling = %+v, want read at 1-in-10 with a total of 100", got)
	}
}

// finalDrain runs the aggregate drain loop once, as the end of a run does: the
// stop takes a last drain, which merges the kernel counts of the source.
func finalDrain(el *eventLoop) {
	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startAggregateDrainLoop(ctx)
	cancel()
	stop()
}

// A dropped ring-buffer event is a row that was emitted and never reached the
// loop: it is in neither the traced count nor the kernel aggregate (which only
// counts invocations that were not emitted), so the sum falls short. Reporting
// it as "exact kernel totals" was false; the counts must be labelled a lower
// bound instead - in the statistics and in the summary that feeds the footer
// and the header.
func TestSamplingTotalsAreALowerBoundUnderRingbufDrops(t *testing.T) {
	tests := []struct {
		name  string
		drops func(*eventLoop)
	}{
		{"events were dropped", func(el *eventLoop) { el.numRingbufDrops.Store(211176) }},
		{"the drop counter could not be read", func(el *eventLoop) { el.ringbufDropReadFailed.Store(true) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			el := sampledLoop(t, "-plain", "-syscall-sampling-syscalls", "read=10")
			el.aggregateSrc = &aggregateSourceStub{rows: [][]statsengine.SyscallAggregate{{{TraceID: types.SYS_ENTER_READ, Count: 90}}}}
			for range 10 {
				emitPair(el, types.SYS_ENTER_READ)
			}
			finalDrain(el)
			tc.drops(el)

			got := el.samplingResult()
			if !got.TotalsKnown() || !got.LowerBound {
				t.Fatalf("result = %+v, want known totals marked as a lower bound", got)
			}
			if !strings.Contains(got.Totals(), `"lower_bound":true`) || !strings.Contains(got.Totals(), `"total":100`) {
				t.Fatalf("Totals() = %s, want the numbers kept and lower_bound set", got.Totals())
			}
			lines := el.samplingStatLines()
			for _, want := range []string{"lower bounds", "read: at least 100 calls", "kernel-counted only: at least 100"} {
				if !strings.Contains(lines, want) {
					t.Fatalf("stat lines = %q, want %q", lines, want)
				}
			}
			if strings.Contains(lines, "exact kernel totals") {
				t.Fatalf("stat lines = %q claim exactness although events were lost", lines)
			}
		})
	}
}

// Without drops the totals stay exact and carry no lower-bound mark.
func TestSamplingTotalsStayExactWithoutRingbufDrops(t *testing.T) {
	el := sampledLoop(t, "-plain", "-syscall-sampling-syscalls", "read=10")
	el.aggregateSrc = &aggregateSourceStub{rows: [][]statsengine.SyscallAggregate{{{TraceID: types.SYS_ENTER_READ, Count: 90}}}}
	for range 10 {
		emitPair(el, types.SYS_ENTER_READ)
	}
	finalDrain(el)
	got := el.samplingResult()
	if !got.TotalsKnown() || got.LowerBound {
		t.Fatalf("result = %+v, want exact totals", got)
	}
	if !strings.Contains(el.samplingStatLines(), "exact kernel totals") {
		t.Fatalf("stat lines = %q, want the exactness statement", el.samplingStatLines())
	}
}

// A syscall named in -syscall-sampling-syscalls whose probe was never attached
// (here: only read and openat are traced) has no measured count, so it gets no
// "0 calls" line and no entry in the startup line, footer or header.
func TestSamplingReportsOnlySyscallsThatAttached(t *testing.T) {
	el := sampledLoop(t, "-plain", "-trace-syscalls", "read,openat",
		"-syscall-sampling-syscalls", "read=10,write=10,futex=0")
	attached := map[string]bool{"read": true, "openat": true}
	el.restrictSamplingToActive(func(name string) bool { return attached[name] })

	plan := el.samplingPlan()
	if got := plan.Rates(); got != "read=10" {
		t.Fatalf("plan rates = %q, want only the attached read=10", got)
	}
	el.aggregateSrc = &aggregateSourceStub{rows: [][]statsengine.SyscallAggregate{{
		{TraceID: types.SYS_ENTER_READ, Count: 90},
		{TraceID: types.SYS_ENTER_WRITE, Count: 5}, // never attached: must be ignored
	}}}
	finalDrain(el)
	result := el.samplingResult()
	if len(result.Entries) != 1 || result.Entries[0].Syscall != "read" || result.Entries[0].Counted != 90 {
		t.Fatalf("result entries = %+v, want only read with 90 counted", result.Entries)
	}
	lines := el.samplingStatLines()
	for _, bad := range []string{"futex", "write"} {
		if strings.Contains(lines, bad) || strings.Contains(result.Totals(), bad) {
			t.Fatalf("never-attached %s is reported: %q %s", bad, lines, result.Totals())
		}
	}
}

// If none of the sampled syscalls attached, nothing was sampled and the run
// carries no marker at all.
func TestSamplingOfNothingAttachedIsNotReported(t *testing.T) {
	el := sampledLoop(t, "-plain", "-syscall-sampling-syscalls", "futex=0")
	el.restrictSamplingToActive(func(string) bool { return false })
	if got := el.samplingResult(); got.Active() {
		t.Fatalf("result = %+v, want none", got)
	}
	if lines := el.samplingStatLines(); lines != "" {
		t.Fatalf("stat lines = %q, want none", lines)
	}
	el.SetStatusCallback(func(args ...any) { t.Errorf("announced %v", args) })
	el.announceSampling()
}

// A family rate is one item in the startup line, the statistics and the
// summary, however many syscalls the family has; per-syscall lines appear
// only for syscalls that were invoked, and an explicit per-syscall rate still
// shows next to the family.
func TestFamilyRateDoesNotFloodTheReport(t *testing.T) {
	el := sampledLoop(t, "-plain", "-syscall-sampling-families", "FS=10", "-syscall-sampling-syscalls", "sync=5")
	if n := len(el.samplingTally.rates); n < 50 {
		t.Fatalf("the family covers %d syscalls, the test needs a big family", n)
	}
	var announced string
	el.SetStatusCallback(func(args ...any) { announced = args[0].(string) })
	el.announceSampling()
	if !strings.Contains(announced, "(FS=10,sync=5)") || len(announced) > 250 {
		t.Fatalf("startup line (%d bytes) = %q, want FS=10 once plus the explicit sync=5", len(announced), announced)
	}

	el.aggregateSrc = &aggregateSourceStub{rows: [][]statsengine.SyscallAggregate{{{TraceID: types.SYS_ENTER_READ, Count: 90}}}}
	for range 10 {
		emitPair(el, types.SYS_ENTER_READ)
	}
	finalDrain(el)
	result := el.samplingResult()
	if got := result.Rates(); got != "FS=10,sync=5" {
		t.Fatalf("Rates() = %q, want FS=10,sync=5", got)
	}
	// read (invoked) and sync (explicit, silent): two entries, not the whole family.
	if len(result.Entries) != 2 {
		t.Fatalf("entries = %+v, want read and the explicit sync only", result.Entries)
	}
	lines := strings.Split(strings.TrimSpace(el.samplingStatLines()), "\n")
	if len(lines) != 3 { // headline, read, "syscalls including ..."
		t.Fatalf("stat lines = %q, want a headline, the read line and the sum", lines)
	}
	if !strings.Contains(lines[1], "read: 100 calls (1-in-10: 10 traced, 90 counted only)") {
		t.Fatalf("read line = %q", lines[1])
	}
}

// The family rates follow the same promotion as the per-syscall ones: an
// explicit family 0 is promoted to 1 in raw modes (nothing sampled), and
// outside raw modes there is no tally at all.
func TestRawModeSamplingFamilyRates(t *testing.T) {
	if got := rawModeSamplingFamilyRates(mustParseArgs(t, "-plain", "-syscall-sampling-families", "FS=10,IPC=0")); len(got) != 1 || got[types.FamilyFS] != 10 {
		t.Fatalf("family rates = %v, want FS=10 only (IPC=0 is promoted to 1)", got)
	}
	if got := rawModeSamplingFamilyRates(mustParseArgs(t, "-syscall-sampling-families", "FS=10")); got != nil {
		t.Fatalf("family rates = %v in the TUI, want none", got)
	}
}
