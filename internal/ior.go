package internal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ior/internal/event"
	"ior/internal/flags"
	"ior/internal/flamegraph"
	"ior/internal/globalfilter"
	"ior/internal/probemanager"
	"ior/internal/runtime"
	"ior/internal/sampling"
	"ior/internal/statsengine"
	"ior/internal/streamrow"
	"ior/internal/tracepoints"

	bpf "github.com/aquasecurity/libbpfgo"
)

// TUIRunFunc is the function type for launching the TUI with a given config
// and trace starter. Concrete implementations live in the tui layer; the cmd
// layer passes them to Run so that the core package (internal) never imports
// the TUI layer.
type TUIRunFunc func(flags.Config, runtime.TraceStarter) error

// TUIRunners bundles the TUI launchers the cmd layer injects into Run. Every
// field must be set; Run rejects a value with any nil field.
type TUIRunners struct {
	// Trace launches the interactive TUI backed by a live BPF trace.
	Trace TUIRunFunc
	// TestFlames launches the TUI seeded with static synthetic flame data.
	TestFlames TUIRunFunc
	// TestLiveFlames launches the TUI fed by live synthetic flame data.
	TestLiveFlames TUIRunFunc
}

// traceEventLoopFactory builds the mode-specific event loop after the shared
// BPF, channel, context, and profiling setup has succeeded. Its logger
// argument is the setup-warning sink for non-fatal degradations.
type traceEventLoopFactory func(flags.Config, *bpf.Module, func(...any)) (*eventLoop, error)

var errRootPrivilegesRequired = errors.New("tracing requires root privileges (run with sudo)")

// Run is the main entry point for the ior binary.
// cfg must be provided by the caller; it should not be fetched from the global
// singleton here. The mode registry is built per call from the injected TUI
// runners, so no package-level state is mutated.
func Run(cfg flags.Config, tui TUIRunners) error {
	deps, err := productionRunnerDeps(tui)
	if err != nil {
		return err
	}
	// Before the first write of any kind: the banner itself already hits a
	// closed stdout when the launcher exited right away (`ior ... | head -1`).
	guardBrokenPipe(cfg)
	printStartupBanner(cfg)
	return newModeRegistry(deps).dispatch(cfg)
}

// printStartupBanner prints the ASCII startup banner. In -plain mode stdout
// carries only CSV rows, so the banner (and all other human-facing output)
// goes to stderr instead.
func printStartupBanner(cfg flags.Config) {
	if cfg.PlainMode {
		flags.PrintVersionTo(os.Stderr)
		return
	}
	flags.PrintVersion()
}

// dispatchRunWithDeps constructs an isolated registry from the given deps and
// dispatches cfg through it. Used by tests to inject stub functions.
func dispatchRunWithDeps(cfg flags.Config, deps runnerDeps) error {
	return newModeRegistry(deps).dispatch(cfg)
}

// validateRunConfig runs all mode-combination checks without running any
// mode. Validation never calls a runner, so the registry needs no deps.
func validateRunConfig(cfg flags.Config) error {
	return newModeRegistry(runnerDeps{}).validate(cfg)
}

// tuiTestFlamesStarter returns a TraceStarter that seeds static test flame data
// into the runtime bindings without starting BPF tracing.
func tuiTestFlamesStarter(cfg flags.Config) runtime.TraceStarter {
	return func(_ context.Context, req runtime.TraceRequest) error {
		engine, streamBuf, liveTrie := buildTestFlamesRuntime(cfg)
		publishTestFlamesRuntime(req.Bindings, engine, streamBuf, liveTrie)
		return nil
	}
}

// tuiTestLiveFlamesStarter returns a TraceStarter that seeds a continuously
// updating synthetic flame data source into the runtime bindings.
func tuiTestLiveFlamesStarter(cfg flags.Config) runtime.TraceStarter {
	return func(ctx context.Context, req runtime.TraceRequest) error {
		engine, streamBuf, liveTrie := buildTestLiveFlamesRuntime(ctx, cfg)
		publishTestFlamesRuntime(req.Bindings, engine, streamBuf, liveTrie)
		return nil
	}
}

// publishTestFlamesRuntime hands the synthetic test-flames components to the
// TUI. Only setter methods are needed, so it takes the narrower publisher
// side of the bindings; a nil publisher (no TUI attached) publishes nothing.
func publishTestFlamesRuntime(
	publisher runtime.RuntimePublisher,
	engine *statsengine.Engine,
	streamBuf *streamrow.RingBuffer,
	liveTrie *flamegraph.LiveTrie,
) {
	if publisher == nil {
		return
	}
	publisher.SetDashboardSnapshotSource(engine)
	publisher.SetEventStreamSource(streamBuf)
	publisher.SetLiveTrie(liveTrie)
}

// buildTestFlamesRuntime allocates a stats engine, stream buffer, and seeded
// live trie for static test-flames mode. Component allocation is delegated to
// RuntimeBuilder so this function focuses on the seed step only.
func buildTestFlamesRuntime(cfg flags.Config) (*statsengine.Engine, *streamrow.RingBuffer, *flamegraph.LiveTrie) {
	components := newRuntimeBuilder(cfg).Build()
	flamegraph.SeedTestFlameData(components.liveTrie)
	statsengine.SeedTestStatsData(components.engine)
	streamrow.SeedTestStreamData(components.streamBuf)
	return components.engine, components.streamBuf, components.liveTrie
}

// buildTestLiveFlamesRuntime allocates a stats engine, stream buffer, and live
// trie for live test-flames mode, then launches a goroutine to update the trie.
// Component allocation is delegated to RuntimeBuilder; this function handles
// only the seed step and the background updater goroutine.
func buildTestLiveFlamesRuntime(ctx context.Context, cfg flags.Config) (*statsengine.Engine, *streamrow.RingBuffer, *flamegraph.LiveTrie) {
	components := newRuntimeBuilder(cfg).Build()
	flamegraph.SeedTestLiveFlameData(components.liveTrie, 0)
	statsengine.SeedTestStatsData(components.engine)
	streamrow.SeedTestStreamData(components.streamBuf)

	interval := cfg.LiveInterval
	if interval <= 0 {
		interval = 200 * time.Millisecond
	}
	go runSyntheticLiveFlames(ctx, components.liveTrie, interval)
	return components.engine, components.streamBuf, components.liveTrie
}

func runSyntheticLiveFlames(ctx context.Context, liveTrie *flamegraph.LiveTrie, interval time.Duration) {
	if liveTrie == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	tick := uint64(1)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Keep a moving synthetic workload profile so the live test flamegraph
			// visibly changes shape over time instead of only increasing totals.
			liveTrie.Reset()
			flamegraph.SeedTestLiveFlameData(liveTrie, tick)
			tick++
		}
	}
}

// tuiRuntime holds all the per-restart state that the TUI trace starter
// allocates and wires into the runtime bindings before each trace goroutine.
//
// The stats engine is split into two narrower interfaces to honour SRP:
//   - accumulator accepts incoming event pairs (statsengine.Accumulator)
//   - snapSource serves dashboard snapshot queries and baseline resets
//     (runtime.ResettableSnapshotSource)
//
// Both are satisfied by the same *statsengine.Engine instance, but holding
// them separately makes each consumer's dependency explicit and prevents
// callers from accidentally calling Ingest from snapshot-only paths or vice
// versa.
type tuiRuntime struct {
	accumulator statsengine.Accumulator
	snapSource  runtime.ResettableSnapshotSource
	streamBuf   runtime.EventSink
	streamSrc   runtime.StreamSource
	streamSeq   runtime.Sequencer
	liveTrie    *flamegraph.LiveTrie
	// recorder stays behind the narrow runtime.RowRecorder seam: the core
	// only records rows and claims failures to report, so parquet's wider
	// surface (start/stop/status, the TUI's concern) cannot ripple into this
	// wiring. It is set only when there is no emitter: the emitter reads the
	// recorder from the live bindings itself, so the plain fallback is the
	// sole reader of this field.
	recorder runtime.RowRecorder
	// emitter, when non-nil, is the session's single-gate event output (push,
	// record and recorder warning behind one session gate); the TUI's session
	// view provides it. Nil (headless modes, fakes) leaves the print callback on
	// the separate streamBuf.Push and recordRow calls (see rowEmitter).
	emitter runtime.RowEmitter
	// filterEpochFn reads the live filter epoch from the TUI-owned runtime
	// bindings at row-stamp time, so in-place filter swaps advance the epoch
	// recorded in parquet rows without a trace restart. Like recorder, it is
	// set only for the plain fallback (an emitter reads the epoch from the
	// live bindings). Nil (headless modes without TUI bindings) stamps epoch 0.
	filterEpochFn func() uint64
}

// currentFilterEpoch returns the live filter epoch for parquet row stamping.
// A nil provider (headless modes without TUI bindings, or wiring that never
// captured one) reports epoch 0, matching the pre-provider behavior.
func (rt *tuiRuntime) currentFilterEpoch() uint64 {
	if rt.filterEpochFn == nil {
		return 0
	}
	return rt.filterEpochFn()
}

// buildTUIRuntime constructs fresh trace-session components via RuntimeBuilder
// and then wires them into the persistent runtime bindings, when a TUI
// supplied them (nil bindings leave the fresh components unwired).
// Construction (allocating engine, buffer, sequencer, trie) is handled by
// RuntimeBuilder; this function focuses on the wiring: reusing the persistent
// stream buffer and sequencer from the TUI, reading the recorder and filter
// epoch, and publishing the new components back to the runtime bindings.
func buildTUIRuntime(cfg flags.Config, bindings runtime.TraceRuntimeBindings) (*tuiRuntime, error) {
	components := newRuntimeBuilder(cfg).Build()
	rt := &tuiRuntime{
		// Wire the same engine instance into both roles: accumulator for
		// event ingestion, snapSource for dashboard snapshot queries.
		accumulator: components.engine,
		snapSource:  components.engine,
		streamBuf:   components.streamBuf,
		streamSrc:   components.streamBuf,
		streamSeq:   components.streamSeq,
		liveTrie:    components.liveTrie,
	}

	if bindings != nil {
		if err := wireRuntimeBindings(rt, bindings); err != nil {
			return nil, err
		}
	}
	return rt, nil
}

// wireRuntimeBindings reuses persistent TUI-owned state (stream buffer,
// sequencer, recorder, filter epoch) from bindings and publishes the freshly
// built components back to the TUI so the new trace session is visible.
// It is called only when the trace request carries TraceRuntimeBindings.
func wireRuntimeBindings(rt *tuiRuntime, bindings runtime.TraceRuntimeBindings) error {
	// StreamBuffer returns the EventSink the core needs directly - the old
	// read-only StreamSource return forced a downcast here, which turned a
	// compile-time contract into a runtime failure path. In the TUI it is the
	// session's gated sink, which is also what gets published as the stream
	// source below; it keeps the ring buffer's AppendSnapshot fast path, so
	// the stream tab's refresh stays allocation-free.
	if persistent := bindings.StreamBuffer(); persistent != nil {
		rt.streamSrc = persistent
		rt.streamBuf = persistent
		// The single-gate emitter pushes into the bindings' own buffer, so it
		// is only valid next to that buffer: without one the rows stay on the
		// fresh local buffer through the plain fallback.
		if source, ok := bindings.(runtime.RowEmitterSource); ok {
			rt.emitter = source.RowEmitter()
		}
	}
	if persistentSeq := bindings.StreamSequencer(); persistentSeq != nil {
		rt.streamSeq = persistentSeq
	}
	// Two owners of the row output, never both: with an emitter, the session
	// gate reads the recorder and the filter epoch from the live bindings on
	// every event, so those bindings are the single source of truth and the
	// runtime keeps no copy. Only the plain fallback (plainRowEmitter) has no
	// gate to read them through and uses the runtime's own recorder and epoch
	// provider, captured here.
	if rt.emitter == nil {
		rt.recorder = bindings.Recorder()
		// Capture the epoch provider, not the value: the TUI advances the
		// epoch on every filter change (including in-place swaps that never
		// re-wire the runtime), and recorded rows must stamp the epoch
		// current at record time.
		rt.filterEpochFn = bindings.FilterEpoch
	}
	// Expose the snapshot-read side to the dashboard; the accumulator (write
	// side) is used only by the event-loop callback below.
	bindings.SetDashboardSnapshotSource(rt.snapSource)
	bindings.SetEventStreamSource(rt.streamSrc)
	bindings.SetLiveTrie(rt.liveTrie)
	return nil
}

// warnRecorderResult reports one recorder.Record result as a stream warning
// when it is news (see runtime.RecorderWarningText). It is the fallback for a
// recorder without a session gate; the gap between the claim inside
// runtime.RecorderWarningText and this delivery is harmless there because
// nothing can retire the session in between (see runtime.WarningRecorder).
func warnRecorderResult(el *eventLoop, rec runtime.RowRecorder, err error) {
	el.notifyWarning(runtime.RecorderWarningText(rec, err))
}

// recordRow records one stream row and reports the result when it is news.
// A session-gated recorder (runtime.WarningRecorder) records, claims a failure
// and publishes its warning in one atomic step, so a session retired in the
// middle can neither drop the warning of a failure it already claimed nor
// consume one it can no longer show; the failure then stays with the recorder
// for the next session or the record modal. Other recorders use the plain
// three-step form.
func recordRow(el *eventLoop, rec runtime.RowRecorder, row streamrow.Row, filterEpoch uint64) {
	if gated, ok := rec.(runtime.WarningRecorder); ok {
		gated.RecordWarning(row, filterEpoch, runtime.RecorderWarningText)
		return
	}
	warnRecorderResult(el, rec, rec.Record(row, filterEpoch))
}

// rowEmitter returns the output the print callback delivers each row to: the
// session's single-gate emitter when the bindings provided one, otherwise the
// plain push-then-record fallback bound to el's warning sink. It is resolved
// once per event loop, not per event.
func (rt *tuiRuntime) rowEmitter(el *eventLoop) runtime.RowEmitter {
	if rt.emitter != nil {
		return rt.emitter
	}
	return plainRowEmitter{rt: rt, el: el}
}

// plainRowEmitter is the ungated RowEmitter: the stream push followed by
// recordRow, for runtimes whose bindings have no session gate to share
// (headless modes, test fakes). It reads rt's fields on every call, like the
// print callback did before the emitter existed, so a recorder or buffer
// swapped in after wiring is honoured.
type plainRowEmitter struct {
	rt *tuiRuntime
	el *eventLoop
}

// EmitRow pushes row to the stream and records it when a recorder is wired.
func (p plainRowEmitter) EmitRow(row streamrow.Row) {
	p.rt.streamBuf.Push(row)
	if p.rt.recorder != nil {
		recordRow(p.el, p.rt.recorder, row, p.rt.currentFilterEpoch())
	}
}

// makeTUIEventLoopConfigurer returns the func(*eventLoop) callback that wires
// the event loop into the TUI runtime and an ownership-aware function that
// unregisters its live-filter setter. The callback sets the initial filter,
// installs the print callback that fans out to engine/stream/trie, and
// registers the setter with publisher so the TUI can swap filters without
// restarting BPF probes. A nil publisher (no TUI attached) registers nothing.
// In TUI mode publisher is the session's bindings view, so a session that a
// restart has already superseded registers nothing either: its setter would
// otherwise replace the newer session's (see tui.traceSessionBindings). The
// row emitter (or, without one, the stream buffer and recorder) in rt comes
// from that same view, which drops the rows and warnings a stopped session
// still pushes, so the callbacks below need no session check of their own.
func makeTUIEventLoopConfigurer(cfg flags.Config, rt *tuiRuntime, publisher runtime.RuntimePublisher) (func(*eventLoop), func()) {
	var unregisterLiveFilterSetter func()
	type aggregateSink interface {
		IngestSyscallAggregates([]statsengine.SyscallAggregate)
	}
	configure := func(el *eventLoop) {
		// Seed the event loop's filter from config so subsequent reads via
		// el.Filter() see the same filter the trace was started with.
		el.SetFilter(cfg.GlobalFilter)
		emitter := rt.rowEmitter(el)
		el.SetPrintCallback(func(ep *event.Pair) {
			if !shouldIngestTracePair(el.Filter(), ep) {
				ep.Recycle()
				return
			}
			row := streamrow.New(rt.streamSeq.Next(), ep)
			rt.accumulator.Ingest(ep)
			emitter.EmitRow(row)
			rt.liveTrie.Ingest(ep)
			// Both downstream consumers snapshot the pair synchronously, so
			// the pooled pair can be recycled immediately afterwards.
			ep.Recycle()
		})
		el.SetWarningCallback(func(message string) {
			rt.streamBuf.Push(streamrow.NewWarning(rt.streamSeq.Next(), message))
		})
		if sink, ok := rt.snapSource.(aggregateSink); ok {
			el.SetAggregateSink(sink)
		}
		if publisher != nil {
			unregisterLiveFilterSetter = publisher.SetLiveFilterSetter(el.SetFilter)
		}
	}
	unregister := func() {
		if unregisterLiveFilterSetter != nil {
			unregisterLiveFilterSetter()
		}
	}
	return configure, unregister
}

// tuiTraceStarterFromRunTrace returns a runtime.TraceStarter that drives a
// full BPF trace session from within the TUI lifecycle; each start request is
// handled by startTUITrace.
func tuiTraceStarterFromRunTrace(
	baseCfg flags.Config,
	startTrace traceRunFunc,
) runtime.TraceStarter {
	return func(ctx context.Context, req runtime.TraceRequest) error {
		return startTUITrace(ctx, req, baseCfg, startTrace)
	}
}

// startTUITrace starts one TUI trace session. It claims the request's
// shutdown reporter, derives the session config from the request's filter,
// allocates per-restart state via buildTUIRuntime, wires the event loop via
// makeTUIEventLoopConfigurer, and hands the request's bindings and shutdown
// reporter explicitly down to setup (traceSetupHooks). The trace itself runs
// in the background (tuiTraceLaunch.start); from then on that goroutine owns
// completing the shutdown reporter, while every earlier return completes it
// here.
func startTUITrace(
	ctx context.Context,
	req runtime.TraceRequest,
	baseCfg flags.Config,
	startTrace traceRunFunc,
) error {
	shutdownReporter := req.ShutdownReporter
	if shutdownReporter != nil && !shutdownReporter.Claim() {
		return context.Canceled
	}
	// libbpf's output must never reach stderr while the dashboard owns the
	// screen; its WARN lines are collected as setup warnings instead (see
	// libbpfLogger and setupTraceInfraBPF), the rest is dropped. This only
	// selects the mode: the previous session is cancelled without being
	// awaited, so it may still be loading, and its warning routing is not
	// this call's to reset.
	setLibbpfLogging(true)
	backgroundOwnsCompletion := false
	defer func() {
		if !backgroundOwnsCompletion {
			shutdownReporter.Complete()
		}
	}()

	cfg := traceConfigForRequest(baseCfg, req)
	rt, err := buildTUIRuntime(cfg, req.Bindings)
	if err != nil {
		return err
	}
	configureEl, unregisterLiveFilterSetter := makeTUIEventLoopConfigurer(cfg, rt, req.Bindings)
	launch := tuiTraceLaunch{
		cfg:                        cfg,
		rt:                         rt,
		configureEl:                configureEl,
		unregisterLiveFilterSetter: unregisterLiveFilterSetter,
		hooks:                      traceSetupHooks{probes: req.Bindings, shutdown: shutdownReporter},
		startTrace:                 startTrace,
	}
	backgroundOwnsCompletion = true
	return launch.start(ctx)
}

// tuiTraceLaunch bundles everything one background TUI trace run needs.
type tuiTraceLaunch struct {
	cfg                        flags.Config
	rt                         *tuiRuntime
	configureEl                func(*eventLoop)
	unregisterLiveFilterSetter func()
	hooks                      traceSetupHooks
	startTrace                 traceRunFunc
}

// start runs the trace in a goroutine and waits until the BPF probes are
// attached (startedCh), startup fails, or ctx is cancelled.
//
// A dedicated done channel is closed by a defer when start returns for any
// reason (ctx cancellation, successful start, or startup error). The trace
// goroutine selects on both errCh and done when delivering its result, so it
// can always exit regardless of which exit arm start took.
func (l tuiTraceLaunch) start(ctx context.Context) error {
	startedCh := make(chan struct{})
	// errCh carries at most one result from the trace goroutine to the select
	// below. done is closed on return so the goroutine can always exit even
	// when start already left via startedCh or ctx.Done() and nobody is
	// draining errCh.
	errCh := make(chan error)
	done := make(chan struct{})
	defer close(done)

	go l.run(ctx, startedCh, errCh, done)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-startedCh:
		return nil
	case err := <-errCh:
		// A stop that races the failure leaves both this arm and
		// ctx.Done() ready, and Go picks between them at random, so this
		// one has to apply the same rule: the user asked for the trace to
		// end. Returning the failure instead raises TracingErrorMsg
		// against the *next* session, clearing its attach spinner and
		// showing it an error the previous trace produced.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
}

// run is the trace goroutine body. It completes the shutdown reporter when it
// exits. A result that arrives after start has returned (the done arm) has no
// caller left to return it to, so it goes to reportLateTraceError instead of
// being dropped - unless the context was cancelled, which means the caller
// asked for the stop.
func (l tuiTraceLaunch) run(ctx context.Context, startedCh chan<- struct{}, errCh chan<- error, done <-chan struct{}) {
	defer l.hooks.shutdown.Complete()
	err := l.startTrace(ctx, l.cfg, startedCh, l.configureEl, l.hooks)
	l.unregisterLiveFilterSetter()
	// Deliver the result only if start is still selecting. done is closed
	// when start returns, so the goroutine will always proceed through this
	// select and never block.
	select {
	case errCh <- err:
	case <-done:
		reportLateTraceError(ctx, l.rt, err)
	}
}

// reportLateTraceError is the last resort for a trace result that has no
// caller left to receive it, because the starter already returned - on the
// started signal, or because its context was cancelled.
//
// In the current code it never fires in TUI mode, and that is worth stating
// rather than leaving as a puzzle. Nothing after signalTraceStarted can fail
// (runTraceWithContext's only remaining error source is finaliseTrace's
// recorder.Write, and the recorder is non-nil only for -flamegraph, which the
// mode registry makes mutually exclusive with the TUI), and the one thing that
// does reach here - a setup failure that raced a stop - is deliberately
// silenced, because the user asked for the trace to end. What this exists for
// is the case neither of those covers: a post-signal failure added later would
// otherwise be dropped on the floor exactly the way the original defect
// dropped setup failures.
//
// ctx is the starter's context and is what decides silence. Testing the error
// for context.Canceled instead would let a genuine setup failure that raced a
// restart print "Trace stopped: ..." into the *next* session's stream, since
// the TUI resets that buffer in place and hands the same object to every run.
func reportLateTraceError(ctx context.Context, rt *tuiRuntime, err error) {
	if err == nil || ctx.Err() != nil {
		return
	}
	if rt == nil || rt.streamBuf == nil || rt.streamSeq == nil {
		return
	}
	rt.streamBuf.Push(streamrow.NewWarning(rt.streamSeq.Next(), fmt.Sprintf("Trace stopped: %v", err)))
}

// shouldIngestTracePair is the TUI's second filtering stage, re-applying the
// filter after a live swap so a pair admitted under the previous filter cannot
// reach the dashboard under the new one.
//
// It uses the same MatchPair as the event-loop checkpoint; the either-name
// rule for rename-like kinds is part of that one method now (see
// Filter.MatchPair), so this stage cannot narrow the contract the checkpoint
// applied - previously it had to remember to pick the wide variant, and
// forgetting exactly that made `-path <oldname>` rows survive in -plain but
// vanish on the dashboard.
func shouldIngestTracePair(filter globalfilter.Filter, pair *event.Pair) bool {
	if !filter.IsActive() {
		return true
	}
	return filter.MatchPair(pair)
}

// traceConfigForRequest returns the config one TUI trace session runs with:
// baseCfg with the request's filter and probe selection applied. A nil filter
// keeps baseCfg's filter and PID/TID scope as configured; a non-nil one
// replaces the global filter with a clone (so the caller may keep mutating its
// own copy) and derives the scope from it. The probe selection is applied by
// applyProbeSelection.
func traceConfigForRequest(baseCfg flags.Config, req runtime.TraceRequest) flags.Config {
	cfg := baseCfg
	applyProbeSelection(&cfg, req.AttachSyscalls)
	if req.Filter == nil {
		return cfg
	}
	cfg.GlobalFilter = req.Filter.Clone()
	applyTraceScopeFromGlobalFilter(&cfg, cfg.GlobalFilter)
	return cfg
}

// applyProbeSelection replaces the configured tracepoint selector with one
// attaching exactly syscalls when the TUI carried a runtime probe selection
// into this session (non-nil, see runtime.TraceRequest.AttachSyscalls); nil
// keeps the startup -trace-* / -tps selection. Only attachment changes: the
// sampling rates are configured for every syscall at load time
// (buildSyscallSamplingRates walks all trace IDs, not just attached ones), so
// a syscall attached through the selection - or later at runtime from the
// probes modal - gets the same sampling / aggregate-only treatment as one
// attached through the startup flags.
func applyProbeSelection(cfg *flags.Config, syscalls []string) {
	if syscalls == nil {
		return
	}
	cfg.TracepointSelector = tracepoints.SelectorForSyscalls(syscalls)
}

func applyTraceScopeFromGlobalFilter(cfg *flags.Config, filter globalfilter.Filter) {
	if cfg == nil {
		return
	}
	// These values bypass flags.validateConfig because they do not come
	// from CLI input: EqValue only returns positive IDs and the PID/TID
	// picker sources them from a live /proc scan, so the trusted-source
	// invariant of validateProcessID (in [1, pid_max]) holds by
	// construction. If a future GlobalFilter ever carries user-typed
	// IDs, re-validate here.
	cfg.PidFilter = -1
	cfg.TidFilter = -1
	if pid, ok := filter.PID.EqValue(); ok {
		// EqValue returns int64; PID values are always within int range (Linux PID_MAX ≤ 4194304).
		cfg.PidFilter = int(pid)
	}
	if tid, ok := filter.TID.EqValue(); ok {
		// EqValue returns int64; TID values are always within int range (Linux PID_MAX ≤ 4194304).
		cfg.TidFilter = int(tid)
	}
}

func runTrace(cfg flags.Config) error {
	return runTraceWithContext(context.Background(), cfg, nil, nil, traceSetupHooks{})
}

func newEventLoopConfig(cfg flags.Config) eventLoopConfig {
	return eventLoopConfig{
		pidFilter:               cfg.PidFilter,
		tidFilter:               cfg.TidFilter,
		filter:                  traceFilterFromConfig(cfg),
		pprofEnable:             cfg.PprofEnable,
		plainMode:               cfg.PlainMode,
		escapeMode:              cfg.EscapeMode,
		aggregateIngestTraceIDs: buildAggregateIngestTraceIDs(cfg),
		samplingRates:           rawModeSamplingRates(cfg),
		samplingFamilyRates:     rawModeSamplingFamilyRates(cfg),
	}
}

// traceFilterFromConfig delegates to flags.BuildTraceFilter to resolve the
// active event filter from the CLI configuration fields.
func traceFilterFromConfig(cfg flags.Config) globalfilter.Filter {
	return flags.BuildTraceFilter(cfg)
}

// newLogger returns the human-facing status logger used by headless trace
// modes. verbose is true for every non-TUI mode (plain CSV, flamegraph,
// headless Parquet); messages go to stderr so stdout stays reserved for
// machine-readable output (CSV rows, or nothing for file-based modes). In TUI
// mode the logger is silent.
func newLogger(verbose bool) func(...any) {
	if !verbose {
		return func(...any) {}
	}
	return func(args ...any) { _, _ = fmt.Fprintln(os.Stderr, args...) }
}

func setupTraceContext(parentCtx context.Context, cfg flags.Config, logln func(...any)) (context.Context, context.CancelFunc, func()) {
	ctx := parentCtx
	cancel := func() {}
	if shouldAutoStopByDuration(cfg) {
		duration := time.Duration(cfg.Duration) * time.Second
		logln("Probing for", duration)
		ctx, cancel = context.WithTimeout(parentCtx, duration)
	} else {
		logln("Probing until stopped...")
		ctx, cancel = context.WithCancel(parentCtx)
	}

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, shutdownSignals(cfg)...)
	stopSignals := func() {
		signal.Stop(signalCh)
	}
	go func() {
		select {
		case <-signalCh:
			logln("Received signal, shutting down...")
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel, stopSignals
}

// shutdownSignals lists the signals that end a trace gracefully, so the
// recorder is finalised and the output published instead of the process
// dying with the recording unwritten. SIGINT/SIGTERM apply everywhere. SIGHUP
// (the controlling terminal or SSH session went away, e.g. a dropped
// connection or a closed terminal window) is added for the headless modes
// only: there it used to kill the process before -flamegraph/-parquet wrote
// anything. In TUI mode this handler is not what ends the program: the TUI
// owns terminal teardown and routes SIGTERM/SIGINT/SIGHUP through its own quit
// path (tui.watchTerminationSignals: first signal = the 'q' cleanup, a later
// one aborts a hung shutdown; task rr2) so an active 'R' recording is
// finalised, which is why SIGHUP is not added here.
//
// SIGHUP is claimed only when the process did not start with it ignored.
// signal.Notify installs a handler even over an inherited SIG_IGN, which would
// silently undo `nohup ior -flamegraph -duration 3600 &` (or a shell wrapper
// that traps HUP to nothing): the run would end at the first hangup instead of
// surviving it as the user asked. signal.Ignored reflects that inherited state as long as
// nothing has called Notify for SIGHUP yet, which holds here because this runs
// before the only Notify that can name it.
func shutdownSignals(cfg flags.Config) []os.Signal {
	return shutdownSignalsFor(cfg, signal.Ignored(syscall.SIGHUP))
}

// shutdownSignalsFor is shutdownSignals with the process's SIGHUP disposition
// passed in, so the decision is testable without touching process signal state.
func shutdownSignalsFor(cfg flags.Config, sighupIgnored bool) []os.Signal {
	sigs := []os.Signal{os.Interrupt, syscall.SIGTERM}
	if shouldAutoStopByDuration(cfg) && !sighupIgnored {
		sigs = append(sigs, syscall.SIGHUP)
	}
	return sigs
}

// guardBrokenPipe makes a write to a closed stdout/stderr return EPIPE instead
// of terminating the process, for the file-output headless modes
// (-flamegraph, -parquet). Go's default is to die from SIGPIPE on a broken
// fd 1 or 2, which happens as soon as the reader of `ior ... | head` or
// `ior ... 2>&1 | grep -m1 ...` exits - long before the recording is written,
// and again on the very last "Shutdown complete." line, which would turn a
// finished run into a death by signal. Every status write to those fds
// discards its error, so ignoring the signal loses nothing and lets the
// recording finish.
//
// It is installed once from Run and never undone: the process ends with Run,
// and the teardown logging after the trace (which outlives any per-trace
// signal registration) needs the guard too. -plain is deliberately excluded:
// its product IS the stream on stdout, and dying on a closed reader is the
// right Unix behaviour there. Notify without a reader is enough: the runtime
// drops what a full channel cannot take, and the mere registration is what
// switches off the die-on-SIGPIPE default.
func guardBrokenPipe(cfg flags.Config) {
	if cfg.PlainMode || !(cfg.FlamegraphOutput || isHeadlessParquetMode(cfg)) {
		return
	}
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
}

func configureEventLoopOutput(el *eventLoop, mgr *probemanager.Manager, configure func(*eventLoop)) {
	if configure != nil {
		configure(el)
	}
	// The active-probe filter sits in front of whatever callback is now
	// installed. It must wrap rather than replace via SetPrintCallback: when
	// configure left the default -plain sink in place, replacing would drop
	// the sink's flusher, and the buffered rows would then only leave in 64 KiB
	// chunks and never at shutdown. Modes whose configure installed their own
	// callback already dropped the flusher through SetPrintCallback.
	el.WrapPrintCallback(func(next func(*event.Pair)) func(*event.Pair) {
		return func(ep *event.Pair) {
			if !mgr.IsActive(ep.EnterEv.GetTraceId().Name()) {
				ep.Recycle()
				return
			}
			if next != nil {
				next(ep)
			}
		}
	})
}

// startTraceShutdownWatcher launches a goroutine that waits for ctx to be
// cancelled, then flushes stats and stops profiling. It returns a done channel
// that is closed once the goroutine has finished all cleanup. Callers must
// drain this channel before returning to avoid a goroutine leak when the
// context is cancelled but the caller exits before the goroutine runs.
func startTraceShutdownWatcher(ctx context.Context, verbose bool, el *eventLoop, profiling *profilingControl, logln func(...any)) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		if verbose {
			// el.stats() already ends with a newline; write to stderr so the
			// summary never mixes with machine-readable stdout data.
			_, _ = fmt.Fprint(os.Stderr, el.stats())
		}
		profiling.stop(logln)
	}()
	return done
}

// maybePrependFlamegraphConfigure wraps configure so that, when flamegraph
// output is requested, each event pair is also forwarded to the recorder.
// Returns the (possibly wrapped) configure func and the recorder (or nil).
func maybePrependFlamegraphConfigure(cfg flags.Config, configure func(*eventLoop)) (func(*eventLoop), *flamegraph.Recorder) {
	if !cfg.FlamegraphOutput {
		return configure, nil
	}
	recorder := flamegraph.NewRecorder(cfg.OutputName)
	recordOutput := func(el *eventLoop) {
		el.SetPrintCallback(func(ep *event.Pair) {
			recorder.AddPair(ep)
			ep.Recycle()
		})
	}
	return chainEventLoopConfigure(recordOutput, configure), recorder
}

// runTraceLoop drives one trace over infra - the part of a run that every
// headless mode and the TUI share once setup has succeeded. It wires the
// mode's output through configure (behind the probe manager's active-probe
// filter), runs the event loop until the trace context ends, and then waits
// for the shutdown watcher and for profiling to finish, so no goroutine of the
// run outlives it. It returns how long the event loop ran. Mode-specific
// finalisation (flushing a flamegraph or Parquet recorder) and infra.Close are
// the caller's.
func runTraceLoop(infra *traceInfra, verbose bool, configure func(*eventLoop), logln func(...any)) time.Duration {
	configureEventLoopOutput(infra.el, infra.mgr, configure)
	// A failed stdout write ends the trace instead of tracing on into the void.
	infra.el.stopTrace = infra.cancel
	// A failure during an already-cancelled trace is the shutdown flush
	// failing: the warning must not claim the trace is being stopped then.
	infra.el.traceEnding = func() bool { return infra.ctx.Err() != nil }
	// A headless -pid / -tid run ends with its target (strace -p semantics)
	// instead of idling to -duration and later tracing a recycled id; verbose
	// is true for exactly the headless modes. The TUI keeps its session open
	// (see eventLoop.endTraceOnTargetExit). Two triggers: the exit records
	// here (the -pid process's group-dead record, the -tid thread's own exit
	// record), and the liveness watcher started below for the records that
	// never arrive (dropped, or the target died during the probe attach).
	infra.el.stopOnTargetExit = verbose && !targetExitRecordDisabled()
	// The watcher's done channel is drained below: returning while it is
	// still running would leak it when ctx is cancelled but the goroutine has
	// not yet exited.
	watcherDone := startTraceShutdownWatcher(infra.ctx, verbose, infra.el, infra.profiling, logln)

	stopTargetWatch := startTargetLivenessWatcher(infra, verbose)
	startTime := time.Now()
	infra.el.run(infra.ctx, infra.ch)
	totalDuration := time.Since(startTime)
	<-watcherDone
	stopTargetWatch()
	<-infra.profiling.done
	return totalDuration
}

// startTargetLivenessWatcher starts the fallback trigger for a headless -pid
// or -tid run (watchTargetLiveness): it polls infra.targetGone, which
// runTraceWithContext set up before the probes attached, so a target whose
// exit record never reaches the loop (ring-buffer drop, death during the
// attach) still ends the run. Nothing starts for the TUI or without a
// liveness function, nor under the IOR_TEST_DISABLE_TARGET_WATCH test hook
// (targetWatchDisabled). The returned func stops the watcher and waits for
// it, so no goroutine outlives runTraceLoop; call it once the event loop
// returned.
func startTargetLivenessWatcher(infra *traceInfra, verbose bool) (stop func()) {
	if !verbose || infra.targetGone == nil || targetWatchDisabled() {
		return func() {}
	}
	ctx, cancel := context.WithCancel(infra.ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		infra.el.watchTargetLiveness(ctx, targetWatchInterval, infra.targetGone)
	}()
	return func() {
		cancel()
		<-done
	}
}

// finaliseTrace flushes the flamegraph recorder if one was created and logs
// the total run duration. It runs after runTraceLoop has returned, which is
// what makes samples final: the recording's header carries them, so a run that
// sampled says so and keeps the exact totals (a run that sampled nothing passes
// the zero Summary and writes the plain format).
func finaliseTrace(recorder *flamegraph.Recorder, samples sampling.Summary, totalDuration time.Duration, logln func(...any)) error {
	if recorder != nil {
		recorder.SetSampling(samples)
		if err := recorder.Write(); err != nil {
			return err
		}
	}
	logTraceStopped(totalDuration, logln)
	return nil
}

// logTraceStopped reports the end of a successfully finalised trace run.
func logTraceStopped(totalDuration time.Duration, logln func(...any)) {
	logln("Trace stopped after", totalDuration, "- cleaning up...")
}

// traceRunFunc is the shape of runTraceWithContext, the seam through which the
// TUI trace starter drives one trace run (and tests stub it).
type traceRunFunc func(
	parentCtx context.Context,
	cfg flags.Config,
	started chan<- struct{},
	configure func(*eventLoop),
	hooks traceSetupHooks,
) error

// probeManagerPublisher is the one publisher method trace setup needs: handing
// the attached probe manager to the TUI probes view (and clearing it on
// release). runtime.RuntimePublisher satisfies it. In TUI mode it is the
// session-scoped view of the TUI bindings, which drops the publish and the
// clear of a session a newer one has superseded, so trace setup can publish
// and clear unconditionally.
type probeManagerPublisher interface {
	SetProbeManager(manager runtime.ProbeManager)
}

// traceSetupHooks are the per-session collaborators a TUI trace hands setup
// explicitly, instead of setup fishing them out of the context. The zero
// value is a headless run: nothing is published and no shutdown progress is
// reported beyond the log.
type traceSetupHooks struct {
	// probes receives the probe manager once the syscall probes are attached,
	// and nil again when the BPF side is released. Nil: no TUI attached.
	probes probeManagerPublisher
	// shutdown receives this session's shutdown progress. Nil: nobody waits.
	shutdown *runtime.TraceShutdownReporter
}

// runTraceWithContext is the concrete BPF trace implementation. Root privilege
// is checked by the mode handler (via runnerDeps.getEUID) before calling this
// function; the handler is the authoritative place for the EUID gate.
// hooks carries the TUI collaborators setup reports to; headless modes pass
// the zero value.
func runTraceWithContext(parentCtx context.Context, cfg flags.Config, started chan<- struct{}, configure func(*eventLoop), hooks traceSetupHooks) error {
	verbose := started == nil
	logln := newLogger(verbose)
	configure, recorder := maybePrependFlamegraphConfigure(cfg, configure)
	// Before BPF setup and the trace itself: an output that cannot be written
	// (unwritable directory, name the filesystem rejects) must fail now, not
	// after -duration seconds of tracing with nothing saved. Nil (no
	// -flamegraph) is a no-op.
	if err := recorder.Prepare(); err != nil {
		return err
	}

	// Opened before the probes attach (about five seconds): a target that dies
	// in that window leaves no exit record, and only a snapshot of the process
	// taken now can tell a recycled pid from the original (targetWatch).
	watch := openHeadlessTargetWatch(cfg, verbose)
	defer watch.Close()

	infra, err := setupTraceInfra(parentCtx, cfg, started, hooks, logln)
	if err != nil {
		return err
	}
	defer infra.Close()
	watch.attachTo(infra)

	totalDuration := runTraceLoop(infra, verbose, configure, logln)
	// The event loop has returned, so the sampling totals are final.
	return traceResult(infra.el, finaliseTrace(recorder, infra.el.samplingResult(), totalDuration, logln))
}

// traceResult is the error of a finished trace run: the -plain sink's write
// error (nil in every other mode) joined with the finalisation error. A run
// whose rows could not be written must not exit 0, and a failing flamegraph
// write must not hide it (or vice versa), hence errors.Join rather than
// "first non-nil". Call it only after the event loop has returned.
func traceResult(el *eventLoop, finaliseErr error) error {
	return errors.Join(el.outputError(), finaliseErr)
}

// traceInfra is the runtime infrastructure of one trace run - BPF module and
// probe manager, event channel and ring buffer, trace context, profiling
// control and event loop - together with the teardown stack that releases it.
//
// Each setup step registers its own cleanup the moment that step has
// succeeded, so a failure part-way through releases exactly what was built and
// nothing else. That replaces five hand-written error arms which each had to
// repeat the canonical teardown call with positionally-correct nils for the
// collaborators that did not exist yet: two audit findings (domain-10 F2/F3,
// discarded teardown errors and probes left attached on early abort) and one
// -pprof leak that made the next trace fail with "cpu profiling already in
// use" were all a mis-permuted arm, and the arms were the place a newly added
// setup step had to remember to appear in four times over.
type traceInfra struct {
	ch        <-chan []byte
	ctx       context.Context
	cancel    context.CancelFunc
	profiling *profilingControl
	el        *eventLoop
	mgr       *probemanager.Manager

	// rb and stopSignals are read by the BPF-side cleanup when it runs rather
	// than captured when it is registered, because later steps create them.
	// A nil field is exactly the "not built yet" that each error arm used to
	// spell out as an explicit nil argument to closeTraceInfra. rb is typed as
	// the interface so an absent ring buffer stays a true nil instead of a
	// typed nil pointer, which would defeat that function's nil checks -
	// (*bpf.RingBuffer).Stop dereferences its receiver immediately.
	//
	// mgr above may stay a concrete pointer only because the cleanup captures
	// the local, which setupBPFModule never returns nil alongside a nil error.
	// Reading it from the field at call time instead would put it in exactly
	// the position rb is in here.
	rb          ringBufferStopper
	stopSignals func()
	shutdownLog func(...any)
	progress    func(completed, total int)
	releasing   func()

	// targetGone reports that the -pid process or -tid thread exited or its id
	// was recycled (targetWatch.gone); nil when there is nothing to watch (no
	// -pid / -tid, the TUI). Set by runTraceWithContext, whose watch predates the probe attach.
	targetGone func() bool

	cleanups []func()
}

// onClose registers a cleanup for Close to run. Call it only after the step
// that created the resource has succeeded, so the stack always describes what
// actually exists.
func (in *traceInfra) onClose(cleanup func()) {
	in.cleanups = append(in.cleanups, cleanup)
}

// Close releases everything the run has built. The trace context is cancelled
// first - goroutines watching it (the signal forwarder, the exec-trace timer)
// have to be told to stop before what they touch goes away - and the
// registered cleanups then run in reverse registration order, so every step is
// undone before the step it was built on. Safe on a nil receiver and on a
// partially built traceInfra, and a second sequential Close runs no cleanup
// twice - a repeated probe detach or module close is not safe. It is not safe
// against concurrent callers, which it does not need to be: each traceInfra
// has exactly one, through the caller's defer.
func (in *traceInfra) Close() {
	if in == nil {
		return
	}
	cleanups := in.cleanups
	in.cleanups = nil
	// The inner closure preserves defer isolation and LIFO ordering: one
	// cleanup that panics cannot strand the remaining resources. Completion is
	// logged only after the closure returns normally; a panic must not print a
	// false claim that every resource was released.
	func() {
		for i := range cleanups {
			defer cleanups[i]()
		}
		if in.cancel != nil {
			defer in.cancel()
		}
	}()
	if len(cleanups) > 0 && in.shutdownLog != nil {
		in.shutdownLog("Shutdown complete.")
	}
}

// setupTraceInfra creates all the BPF/runtime infrastructure for a trace run:
// BPF module + probe manager, event channel + ring buffer, trace context,
// profiling control, and event loop. The returned traceInfra owns the teardown
// of every step that succeeded and its Close must be deferred by the caller;
// on failure setup closes it here and returns no infra at all.
// started is signalled once setup completes (nil in non-TUI modes) - and only
// after the last step that can still fail, because in TUI mode that signal is
// what makes the starter report success (see tuiTraceStarterFromRunTrace).
func setupTraceInfra(
	parentCtx context.Context,
	cfg flags.Config,
	started chan<- struct{},
	hooks traceSetupHooks,
	logln func(...any),
) (*traceInfra, error) {
	return setupTraceInfraWithEventLoop(parentCtx, cfg, started, hooks, logln, newTraceEventLoop)
}

// setupTraceInfraWithEventLoop owns the setup sequence shared by interactive,
// raw, and headless Parquet traces. The factory preserves the one intentional
// mode difference: regular traces wire the syscall aggregate source, while
// headless Parquet wires it only when the run samples (it has no TUI aggregate
// sink, so nothing else would consume it).
//
// It also owns the setup warning collector, because a failed setup is the one
// moment the collector would otherwise be lost: the warnings are replayed
// only when the event loop starts, so on failure runTraceSetup returns early
// and the libbpf WARN lines that explain the failed load or attach (the
// returned error is often just "failed to load BPF object: -22") never
// reached the user, least of all in the TUI where stderr is not available.
// Every failure therefore leaves through explainFailure, which appends the
// still-undelivered warnings (bounded and escaped) to the error.
func setupTraceInfraWithEventLoop(
	parentCtx context.Context,
	cfg flags.Config,
	started chan<- struct{},
	hooks traceSetupHooks,
	logln func(...any),
	buildEventLoop traceEventLoopFactory,
) (*traceInfra, error) {
	warnings := &setupWarnings{}
	infra, err := runTraceSetup(parentCtx, cfg, started, hooks, logln, buildEventLoop, warnings)
	if err != nil {
		return nil, warnings.explainFailure(err)
	}
	return infra, nil
}

// runTraceSetup is the setup sequence itself; setupTraceInfraWithEventLoop
// wraps it to attach the collected warnings to a failure.
// The BPF load/attach half lives in setupTraceInfraBPF; the filter guard, the
// event-loop build and the start signal stay in this body because the
// ior_setup_test.go structural tests pin their relative order here.
func runTraceSetup(
	parentCtx context.Context,
	cfg flags.Config,
	started chan<- struct{},
	hooks traceSetupHooks,
	logln func(...any),
	buildEventLoop traceEventLoopFactory,
	warnings *setupWarnings,
) (*traceInfra, error) {
	// Reject a filter the trace cannot honour before touching the kernel:
	// newEventLoop below matches comm/path patterns against fixed-size kernel
	// event fields and refuses over-long ones. Doing it here means the caller
	// gets that error instead of a running trace that never matches, and it
	// costs no probe attach/detach cycle.
	if err := traceFilterFromConfig(cfg).ValidateTracepointFields(); err != nil {
		return nil, err
	}

	// Non-fatal setup degradations are collected and replayed as event-loop
	// warnings once output is wired (see setupWarnings); on failure the caller
	// appends them to the returned error instead.
	warnSetup := warnings.add

	infra, bpfModule, err := setupTraceInfraBPF(parentCtx, cfg, hooks, logln, warnSetup)
	if err != nil {
		return nil, err
	}

	if err := infra.setupRuntime(parentCtx, cfg, bpfModule, started, logln); err != nil {
		infra.Close()
		return nil, err
	}

	el, err := buildEventLoop(cfg, bpfModule, warnSetup)
	if err != nil {
		infra.Close()
		return nil, err
	}
	infra.el = el
	wireEventLoopLogging(el, logln, warnings)
	// Report sampling only for syscalls that really attached (raw modes; a
	// no-op for the TUI, which has no tally). It stays after the two lines
	// above, which the structural setup tests require to be adjacent.
	if infra.mgr != nil {
		el.restrictSamplingToActive(infra.mgr.IsActive)
	}

	// Nothing fallible may follow. Every step above still reaches the caller
	// through err, and in TUI mode that is the only path an error has: once
	// started is closed the starter has already reported success and nobody is
	// left to receive one. Pinned by
	// TestSetupTraceInfraSignalsStartAfterEveryFallibleStep.
	signalTraceStarted(started)
	return infra, nil
}

// setupTraceInfraBPF loads the BPF module, attaches the probes (publishing the
// probe manager to hooks.probes), and returns the new traceInfra that owns
// their release, with its shutdown progress wired to hooks.shutdown. Status
// output goes to logln and non-fatal degradations to warnSetup. On failure
// nothing is left attached and no infra is returned.
func setupTraceInfraBPF(
	parentCtx context.Context,
	cfg flags.Config,
	hooks traceSetupHooks,
	logln func(...any),
	warnSetup func(...any),
) (*traceInfra, *bpf.Module, error) {
	// Teardown errors must stay visible in every mode: the mode-dependent
	// logln is a no-op in TUI mode, which previously silently discarded
	// probe-detach failures (audit domain-10 F2).
	logTeardown := newLogger(true)
	// libbpf's WARN lines explain a failed load or attach. In TUI mode they
	// join the setup warnings for the duration of the load/attach only (the
	// collector is drained once: when the event loop starts, or into the
	// error of a failed setup); headless they already went to stderr and
	// this is a no-op. The route belongs to this
	// call: ending it never disturbs a newer session's routing.
	endLibbpfRouting := libbpfLog.routeWarnings(warnSetup)
	defer endLibbpfRouting()
	bpfModule, mgr, releaseBindings, err := setupBPFModule(parentCtx, cfg, hooks.probes, bpfSetupLog{status: logln, warn: warnSetup, teardown: logTeardown})
	if err != nil {
		return nil, nil, err
	}

	infra := newTraceInfra(mgr, hooks.shutdown, logln)
	// The BPF side is released as one unit in closeTraceInfra's canonical
	// order (ring buffer, probes, bindings, module, signal handler), which is
	// why it is one cleanup rather than one per resource. Registering it here
	// is what detaches the probes on every later abort (audit domain-10 F3).
	infra.onClose(func() {
		closeTraceInfra(logTeardown, infra.rb, mgr, releaseBindings, bpfModule, infra.stopSignals, infra.progress, infra.releasing)
	})
	return infra, bpfModule, nil
}

// newTraceInfra returns the still-empty infrastructure of one run, with its
// shutdown progress wired: every phase is logged through logln and, when the
// session has a TUI shutdown reporter, published to it as well.
func newTraceInfra(mgr *probemanager.Manager, reporter *runtime.TraceShutdownReporter, logln func(...any)) *traceInfra {
	publish := func(progress runtime.TraceShutdownProgress) {
		if reporter != nil {
			reporter.Publish(progress)
		}
	}
	return &traceInfra{
		mgr:         mgr,
		shutdownLog: logln,
		progress: func(completed, total int) {
			if completed == 0 {
				logln("Detaching", total, "active BPF probe pairs...")
			}
			publish(runtime.TraceShutdownProgress{
				Phase:     runtime.TraceShutdownDetaching,
				Completed: completed,
				Total:     total,
			})
		},
		releasing: func() {
			logln("Releasing remaining BPF resources...")
			publish(runtime.TraceShutdownProgress{Phase: runtime.TraceShutdownReleasing})
		},
	}
}

// setupRuntime builds the post-attach runtime of a run - event channel and
// ring buffer, trace context and profiling - on top of an already loaded BPF
// module. Each resource is stored or registered for Close the moment it
// exists; on error the caller closes infra, which then releases exactly what
// was built.
func (in *traceInfra) setupRuntime(
	parentCtx context.Context,
	cfg flags.Config,
	bpfModule *bpf.Module,
	started chan<- struct{},
	logln func(...any),
) error {
	eventCh, rb, err := setupEventChannel(bpfModule)
	if err != nil {
		return err
	}
	in.ch, in.rb = eventCh, rb

	in.ctx, in.cancel, in.stopSignals = setupTraceContext(parentCtx, cfg, logln)

	profiling, err := setupProfiling(in.ctx, cfg, started)
	if err != nil {
		return err
	}
	in.profiling = profiling
	// Profiling is running from here on and the caller cannot see it until
	// setup returns, so nothing else would stop it: with -pprof the CPU
	// profile would stay active and the next trace fail with "cpu profiling
	// already in use" instead of reporting whatever really went wrong.
	in.onClose(func() { profiling.stop(logln) })
	return nil
}

// newTraceEventLoop builds the event loop and wires its kernel-side data
// sources. Every fallible step of the event-loop construction lives here (the
// other post-attach steps, setupEventChannel and setupProfiling, can fail too
// and stay in setupTraceInfra above), so that this is the last thing that can
// fail before the trace-started signal: an invalid filter (newEventLoop) or a BPF object without
// syscall_aggregate_map (newSyscallAggregateConsumer) used to fail after the
// TUI had already been told the trace was running, which left the dashboard
// live-looking and permanently empty.
func newTraceEventLoop(cfg flags.Config, bpfModule *bpf.Module, warnSetup func(...any)) (*eventLoop, error) {
	el, err := newEventLoop(newEventLoopConfig(cfg))
	if err != nil {
		return nil, err
	}
	aggregateSrc, err := openAggregateSource(bpfModule)
	if err != nil {
		return nil, err
	}
	el.aggregateSrc = aggregateSrc
	// Deliberately non-fatal, see attachRingbufDropCounter.
	attachRingbufDropCounter(el, bpfModule, warnSetup)
	return el, nil
}

// openAggregateSource opens the kernel's syscall_aggregate_map of a loaded BPF
// module as an aggregate source. It is a variable so a test can give the trace
// setup (newTraceEventLoop, newHeadlessParquetEventLoop) a fake source instead
// of a real module, which is what makes their wiring testable without root.
// The error path returns an untyped nil source, never a nil *consumer wrapped
// in a non-nil interface.
var openAggregateSource = func(module *bpf.Module) (syscallAggregateSource, error) {
	consumer, err := newSyscallAggregateConsumer(module)
	if err != nil {
		return nil, err
	}
	return consumer, nil
}

// attachRingbufDropCounter wires the kernel-side ring-buffer drop counter into
// the event loop so lost events are reported instead of vanishing silently
// (audit findings D2 F1 / D9 Y2). A missing map is deliberately non-fatal: it
// only means this binary was linked against an older BPF object, and losing
// the drop telemetry must not abort an otherwise healthy trace. warnSetup is
// the setup-warning collector, which replays the message as an event-loop
// warning: a warning row in the TUI (instead of stderr text written over the
// screen on every trace start) and stderr in the headless modes.
func attachRingbufDropCounter(el *eventLoop, bpfModule *bpf.Module, warnSetup func(...any)) {
	dropCounter, err := newRingbufDropCounter(bpfModule)
	if err != nil {
		warnSetup("Ring-buffer drop counter unavailable (kernel-side drops will not be reported):", err)
		return
	}
	el.dropSrc = dropCounter
}

// ringBufferStopper abstracts the ring-buffer polling control for teardown.
type ringBufferStopper interface {
	Stop()
}

// probeCloser abstracts the probe manager, whose Close reports detach
// failures.
type probeCloser interface {
	Close() error
}

// progressProbeCloser is implemented by the production probe manager. The
// optional extension keeps the teardown helper compatible with narrow test
// doubles while allowing exact progress over synchronous link destruction.
type progressProbeCloser interface {
	CloseWithProgress(func(completed, total int)) error
}

// moduleCloser abstracts the BPF module, whose libbpfgo Close releases the
// module without reporting an error.
type moduleCloser interface {
	Close()
}

// closeTraceInfra tears down trace infrastructure in the canonical order:
// stop ring-buffer polling first (it is idempotent; the module Close also
// releases the underlying C ring buffer), detach probes, release bindings,
// close the module, then stop signal handling. Collaborators that a failed
// setup step has not created yet must be passed as explicit nil (a typed nil
// pointer would defeat the nil checks). Probe-detach failures are routed to
// logErr instead of being propagated, so an in-flight setup error stays the
// visible failure. In production logErr always writes to stderr: the
// mode-dependent logger is a no-op in TUI mode, which previously silently
// discarded teardown errors (audit domain-10 F2).
func closeTraceInfra(
	logErr func(...any),
	rb ringBufferStopper,
	mgr probeCloser,
	releaseBindings func(),
	bpfModule moduleCloser,
	stopSignals func(),
	progress func(completed, total int),
	releasing func(),
) {
	if rb != nil {
		rb.Stop()
	}
	if mgr != nil {
		var err error
		if progressMgr, ok := mgr.(progressProbeCloser); ok {
			err = progressMgr.CloseWithProgress(progress)
		} else {
			err = mgr.Close()
		}
		if err != nil {
			logErr("BPF probe manager close error:", err)
		}
	}
	if releasing != nil {
		releasing()
	}
	if releaseBindings != nil {
		releaseBindings()
	}
	if bpfModule != nil {
		bpfModule.Close()
	}
	if stopSignals != nil {
		stopSignals()
	}
}

func chainEventLoopConfigure(fns ...func(*eventLoop)) func(*eventLoop) {
	return func(el *eventLoop) {
		for _, fn := range fns {
			if fn == nil {
				continue
			}
			fn(el)
		}
	}
}

func signalTraceStarted(started chan<- struct{}) {
	if started == nil {
		return
	}
	close(started)
}

func shouldAutoStopByDuration(cfg flags.Config) bool {
	return cfg.PlainMode || cfg.FlamegraphOutput || isHeadlessParquetMode(cfg)
}
