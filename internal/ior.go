package internal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"ior/internal/event"
	"ior/internal/flags"
	"ior/internal/flamegraph"
	"ior/internal/globalfilter"
	"ior/internal/parquet"
	"ior/internal/probemanager"
	"ior/internal/runtime"
	"ior/internal/statsengine"
	"ior/internal/streamrow"

	bpf "github.com/aquasecurity/libbpfgo"
)

// tuiRunFunc is the function type for launching the TUI with a given config
// and trace starter. Concrete implementations live in the tui layer; they are
// injected at startup via SetTUIRunners so that the core package (internal)
// never imports the TUI layer.
type tuiRunFunc func(flags.Config, runtime.TraceStarter) error

var (
	runTraceFn            = runTrace
	runParquetFn          = runHeadlessParquet
	runTraceWithContextFn = runTraceWithContext
	// runTUIFn, runTUITestFlamesFn, runTUITestLiveFlamesFn are injected by
	// main (via SetTUIRunners) before Run is called. They default to nil so
	// that test files can replace individual runners without importing tui.
	runTUIFn               tuiRunFunc
	runTUITestFlamesFn     tuiRunFunc
	runTUITestLiveFlamesFn tuiRunFunc
	getEUID                = os.Geteuid

	errRootPrivilegesRequired = errors.New("tracing requires root privileges (run with sudo)")
)

// SetTUIRunners injects the concrete TUI runner functions from the cmd layer
// so the core internal package does not need to import the TUI packages.
// This must be called before Run when running in TUI mode.
func SetTUIRunners(
	runTUI tuiRunFunc,
	runTUITestFlames tuiRunFunc,
	runTUITestLiveFlames tuiRunFunc,
) {
	runTUIFn = runTUI
	runTUITestFlamesFn = runTUITestFlames
	runTUITestLiveFlamesFn = runTUITestLiveFlames
}

// streamEventSink is the write-side contract for the stream ring buffer used
// by the TUI trace starter. It is identical to runtime.EventSink but defined
// here to avoid a second import alias at the call sites below.
type streamEventSink = runtime.EventSink

// Run is the main entry point for the ior binary.
// cfg must be provided by the caller; it should not be fetched from the global singleton here.
func Run(cfg flags.Config) error {
	flags.PrintVersion()
	return dispatchRun(cfg)
}

func dispatchRun(cfg flags.Config) error {
	if err := validateRunConfig(cfg); err != nil {
		return err
	}
	if cfg.TestFlames {
		return runTUITestFlamesFn(cfg, tuiTestFlamesStarter(cfg))
	}
	if cfg.TestLiveFlames {
		return runTUITestLiveFlamesFn(cfg, tuiTestLiveFlamesStarter(cfg))
	}
	// All remaining modes require tracing, which needs root. Fail fast here so
	// the TUI never starts (and hangs) when we already know it cannot trace.
	if getEUID() != 0 {
		return errRootPrivilegesRequired
	}
	if isHeadlessParquetMode(cfg) {
		return runParquetFn(cfg)
	}
	if shouldRunTraceMode(cfg) {
		return runTraceFn(cfg)
	}
	return runTUIFn(cfg, tuiTraceStarterFromRunTrace(cfg, runTraceWithContextFn))
}

func validateRunConfig(cfg flags.Config) error {
	if isHeadlessParquetMode(cfg) {
		if cfg.TestFlames {
			return errors.New("--testflames cannot be combined with -parquet")
		}
		if cfg.TestLiveFlames {
			return errors.New("--testliveflames cannot be combined with -parquet")
		}
		if cfg.PlainMode {
			return errors.New("-parquet and -plain are mutually exclusive")
		}
		if cfg.FlamegraphOutput {
			return errors.New("-parquet and -flamegraph are mutually exclusive")
		}
		if hasHeadlessParquetContentFilters(cfg) {
			return errors.New("-parquet cannot be combined with content filters (-comm, -path, -pid, -tid)")
		}
	}
	if cfg.TestFlames && cfg.PlainMode {
		return errors.New("--testflames cannot be combined with -plain")
	}
	if cfg.TestFlames && cfg.FlamegraphOutput {
		return errors.New("--testflames cannot be combined with -flamegraph")
	}
	if cfg.TestLiveFlames && cfg.PlainMode {
		return errors.New("--testliveflames cannot be combined with -plain")
	}
	if cfg.TestLiveFlames && cfg.FlamegraphOutput {
		return errors.New("--testliveflames cannot be combined with -flamegraph")
	}
	if cfg.PlainMode && cfg.FlamegraphOutput {
		return errors.New("-plain and -flamegraph are mutually exclusive")
	}
	if cfg.TestFlames && cfg.TestLiveFlames {
		return errors.New("--testflames and --testliveflames are mutually exclusive")
	}
	return nil
}

// tuiTestFlamesStarter returns a TraceStarter that seeds static test flame data
// into the runtime bindings without starting BPF tracing.
func tuiTestFlamesStarter(cfg flags.Config) runtime.TraceStarter {
	return func(ctx context.Context) error {
		engine, streamBuf, liveTrie := buildTestFlamesRuntime(cfg)
		// Only setter methods are needed here; use the narrower publisher interface.
		if bindings, ok := runtime.RuntimePublisherFromContext(ctx); ok {
			bindings.SetDashboardSnapshotSource(engine)
			bindings.SetEventStreamSource(streamBuf)
			bindings.SetLiveTrie(liveTrie)
		}
		return nil
	}
}

// tuiTestLiveFlamesStarter returns a TraceStarter that seeds a continuously
// updating synthetic flame data source into the runtime bindings.
func tuiTestLiveFlamesStarter(cfg flags.Config) runtime.TraceStarter {
	return func(ctx context.Context) error {
		engine, streamBuf, liveTrie := buildTestLiveFlamesRuntime(ctx, cfg)
		// Only setter methods are needed here; use the narrower publisher interface.
		if bindings, ok := runtime.RuntimePublisherFromContext(ctx); ok {
			bindings.SetDashboardSnapshotSource(engine)
			bindings.SetEventStreamSource(streamBuf)
			bindings.SetLiveTrie(liveTrie)
		}
		return nil
	}
}

// buildTestFlamesRuntime allocates a stats engine, stream buffer, and seeded
// live trie for static test-flames mode. Component allocation is delegated to
// RuntimeBuilder so this function focuses on the seed step only.
func buildTestFlamesRuntime(cfg flags.Config) (*statsengine.Engine, *streamrow.RingBuffer, *flamegraph.LiveTrie) {
	components := newRuntimeBuilder(cfg).Build()
	flamegraph.SeedTestFlameData(components.liveTrie)
	return components.engine, components.streamBuf, components.liveTrie
}

// buildTestLiveFlamesRuntime allocates a stats engine, stream buffer, and live
// trie for live test-flames mode, then launches a goroutine to update the trie.
// Component allocation is delegated to RuntimeBuilder; this function handles
// only the seed step and the background updater goroutine.
func buildTestLiveFlamesRuntime(ctx context.Context, cfg flags.Config) (*statsengine.Engine, *streamrow.RingBuffer, *flamegraph.LiveTrie) {
	components := newRuntimeBuilder(cfg).Build()
	flamegraph.SeedTestLiveFlameData(components.liveTrie, 0)

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

func shouldRunTraceMode(cfg flags.Config) bool {
	return cfg.PlainMode || cfg.FlamegraphOutput || isHeadlessParquetMode(cfg)
}

// tuiRuntime holds all the per-restart state that the TUI trace starter
// allocates and wires into the runtime bindings before each trace goroutine.
type tuiRuntime struct {
	engine      *statsengine.Engine
	streamBuf   streamEventSink
	streamSrc   runtime.StreamSource
	streamSeq   *streamrow.Sequencer
	liveTrie    *flamegraph.LiveTrie
	recorder    *parquet.Recorder
	filterEpoch uint64
}

// buildTUIRuntime constructs fresh trace-session components via RuntimeBuilder
// and then wires them into any persistent runtime bindings found in ctx.
// Construction (allocating engine, buffer, sequencer, trie) is handled by
// RuntimeBuilder; this function focuses on the wiring: reusing the persistent
// stream buffer and sequencer from the TUI, reading the recorder and filter
// epoch, and publishing the new components back to the runtime bindings.
func buildTUIRuntime(ctx context.Context, cfg flags.Config) (*tuiRuntime, error) {
	components := newRuntimeBuilder(cfg).Build()
	rt := &tuiRuntime{
		engine:    components.engine,
		streamBuf: components.streamBuf,
		streamSrc: components.streamBuf,
		streamSeq: components.streamSeq,
		liveTrie:  components.liveTrie,
	}

	if bindings, ok := runtime.RuntimeBindingsFromContext(ctx); ok {
		if err := wireRuntimeBindings(rt, bindings); err != nil {
			return nil, err
		}
	}
	return rt, nil
}

// wireRuntimeBindings reuses persistent TUI-owned state (stream buffer,
// sequencer, recorder, filter epoch) from bindings and publishes the freshly
// built components back to the TUI so the new trace session is visible.
// It is called only when a TraceRuntimeBindings is present in the context.
func wireRuntimeBindings(rt *tuiRuntime, bindings runtime.TraceRuntimeBindings) error {
	if persistent := bindings.StreamBuffer(); persistent != nil {
		rt.streamSrc = persistent
		sink, ok := persistent.(streamEventSink)
		if !ok {
			return fmt.Errorf("runtime stream source does not support event pushes")
		}
		rt.streamBuf = sink
	}
	if persistentSeq := bindings.StreamSequencer(); persistentSeq != nil {
		rt.streamSeq = persistentSeq
	}
	rt.recorder = bindings.Recorder()
	rt.filterEpoch = bindings.FilterEpoch()
	bindings.SetDashboardSnapshotSource(rt.engine)
	bindings.SetEventStreamSource(rt.streamSrc)
	bindings.SetLiveTrie(rt.liveTrie)
	return nil
}

// makeTUIEventLoopConfigurer returns the func(*eventLoop) callback that wires
// the event loop into the TUI runtime: it sets the initial filter, installs
// the print callback that fans out to engine/stream/trie, and registers the
// live-filter setter so the TUI can swap filters without restarting BPF probes.
func makeTUIEventLoopConfigurer(ctx context.Context, cfg flags.Config, rt *tuiRuntime) func(*eventLoop) {
	var recorderWarningOnce sync.Once
	return func(el *eventLoop) {
		// Seed the event loop's filter from config so subsequent reads via
		// el.Filter() see the same filter the trace was started with.
		el.SetFilter(cfg.GlobalFilter)
		el.printCb = func(ep *event.Pair) {
			if !shouldIngestTracePair(el.Filter(), ep) {
				ep.Recycle()
				return
			}
			row := streamrow.New(rt.streamSeq.Next(), ep)
			rt.engine.Ingest(ep)
			rt.streamBuf.Push(row)
			if rt.recorder != nil {
				if err := rt.recorder.Record(row, rt.filterEpoch); err != nil {
					recorderWarningOnce.Do(func() {
						if el.warningCb != nil {
							el.warningCb(fmt.Sprintf("Parquet recorder failed: %v", err))
						}
					})
				}
			}
			rt.liveTrie.Ingest(ep)
			// Both downstream consumers snapshot the pair synchronously, so
			// the pooled pair can be recycled immediately afterwards.
			ep.Recycle()
		}
		el.warningCb = func(message string) {
			rt.streamBuf.Push(streamrow.NewWarning(rt.streamSeq.Next(), message))
		}
		if bindings, ok := runtime.RuntimeBindingsFromContext(ctx); ok {
			bindings.SetLiveFilterSetter(el.SetFilter)
		}
	}
}

// tuiTraceStarterFromRunTrace returns a runtime.TraceStarter that drives a
// full BPF trace session from within the TUI lifecycle. It allocates
// per-restart state via buildTUIRuntime, wires the event loop via
// makeTUIEventLoopConfigurer, and starts the trace in a goroutine, signalling
// the TUI once BPF probes are attached (via startedCh) or returning an error
// if startup fails.
func tuiTraceStarterFromRunTrace(
	baseCfg flags.Config,
	startTrace func(context.Context, flags.Config, chan<- struct{}, func(*eventLoop)) error,
) runtime.TraceStarter {
	return func(ctx context.Context) error {
		bpf.SetLoggerCbs(bpf.Callbacks{Log: func(int, string) {}})

		cfg := baseCfg
		if filter, ok := runtime.TraceFiltersFromContext(ctx); ok {
			cfg.GlobalFilter = filter.Clone()
			applyTraceScopeFromGlobalFilter(&cfg, filter)
		}

		rt, err := buildTUIRuntime(ctx, cfg)
		if err != nil {
			return err
		}
		configureEl := makeTUIEventLoopConfigurer(ctx, cfg, rt)

		startedCh := make(chan struct{})
		errCh := make(chan error, 1)
		go func() {
			err := startTrace(ctx, cfg, startedCh, configureEl)
			if bindings, ok := runtime.RuntimeBindingsFromContext(ctx); ok {
				bindings.SetLiveFilterSetter(nil)
			}
			errCh <- err
			close(errCh)
		}()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-startedCh:
			return nil
		case err := <-errCh:
			return err
		}
	}
}

func shouldIngestTracePair(filter globalfilter.Filter, pair *event.Pair) bool {
	if !filter.IsActive() {
		return true
	}
	return filter.MatchPair(pair)
}

func applyTraceScopeFromGlobalFilter(cfg *flags.Config, filter globalfilter.Filter) {
	if cfg == nil {
		return
	}
	cfg.PidFilter = -1
	cfg.TidFilter = -1
	if pid, ok := filter.PID.EqValue(); ok {
		cfg.PidFilter = pid
	}
	if tid, ok := filter.TID.EqValue(); ok {
		cfg.TidFilter = tid
	}
}

func runTrace(cfg flags.Config) error {
	return runTraceWithContext(context.Background(), cfg, nil, nil)
}

func newEventLoopConfig(cfg flags.Config) eventLoopConfig {
	fields := make([]string, len(cfg.CollapsedFields))
	copy(fields, cfg.CollapsedFields)
	return eventLoopConfig{
		pidFilter:       cfg.PidFilter,
		filter:          traceFilterFromConfig(cfg),
		collapsedFields: fields,
		countField:      cfg.CountField,
		pprofEnable:     cfg.PprofEnable,
		plainMode:       cfg.PlainMode,
	}
}

// traceFilterFromConfig delegates to the canonical Config.TraceFilter method.
func traceFilterFromConfig(cfg flags.Config) globalfilter.Filter {
	return cfg.TraceFilter()
}

func newLogger(verbose bool) func(...any) {
	if !verbose {
		return func(...any) {}
	}
	return func(args ...any) { _, _ = fmt.Println(args...) }
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
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
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

func configureEventLoopOutput(el *eventLoop, mgr *probemanager.Manager, configure func(*eventLoop)) {
	if configure != nil {
		configure(el)
	}
	origPrintCb := el.printCb
	el.printCb = func(ep *event.Pair) {
		if !mgr.IsActive(ep.EnterEv.GetTraceId().Name()) {
			ep.Recycle()
			return
		}
		if origPrintCb != nil {
			origPrintCb(ep)
		}
	}
}

func startTraceShutdownWatcher(ctx context.Context, verbose bool, el *eventLoop, profiling *profilingControl, logln func(...any)) {
	go func() {
		<-ctx.Done()
		if verbose {
			fmt.Println(el.stats())
		}
		profiling.stop(logln)
	}()
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
		el.printCb = func(ep *event.Pair) {
			recorder.AddPair(ep)
			ep.Recycle()
		}
	}
	return chainEventLoopConfigure(recordOutput, configure), recorder
}

// finaliseTrace waits for profiling to finish, flushes the flamegraph recorder
// if one was created, and logs the total run duration.
func finaliseTrace(recorder *flamegraph.Recorder, profiling *profilingControl, totalDuration time.Duration, logln func(...any)) error {
	<-profiling.done
	if recorder != nil {
		if err := recorder.Write(); err != nil {
			return err
		}
	}
	logln("Good bye... (unloading BPF tracepoints will take a few seconds...) after", totalDuration)
	return nil
}

func runTraceWithContext(parentCtx context.Context, cfg flags.Config, started chan<- struct{}, configure func(*eventLoop)) error {
	if getEUID() != 0 {
		return errRootPrivilegesRequired
	}

	verbose := started == nil
	logln := newLogger(verbose)
	configure, recorder := maybePrependFlamegraphConfigure(cfg, configure)

	bpfModule, mgr, releaseBindings, err := setupBPFModule(parentCtx, cfg)
	if err != nil {
		return err
	}
	defer bpfModule.Close()
	defer mgr.Close()
	defer releaseBindings()

	ch, err := setupEventChannel(bpfModule)
	if err != nil {
		return err
	}
	ctx, cancel, stopSignals := setupTraceContext(parentCtx, cfg, logln)
	defer cancel()
	defer stopSignals()

	profiling, err := setupProfiling(ctx, cfg, started)
	if err != nil {
		return err
	}
	// Guarantee the profiling file descriptors (cpu/mem/exec-trace profiles) are
	// closed even if a later setup step fails before the shutdown watcher is
	// registered. profiling.stop is idempotent via sync.Once, so double-calling
	// it from the watcher goroutine and from this defer is safe.
	defer profiling.stop(logln)

	signalTraceStarted(started)

	el, err := newEventLoop(newEventLoopConfig(cfg))
	if err != nil {
		return err
	}
	configureEventLoopOutput(el, mgr, configure)
	startTraceShutdownWatcher(ctx, verbose, el, profiling, logln)

	startTime := time.Now()
	el.run(ctx, ch)
	return finaliseTrace(recorder, profiling, time.Since(startTime), logln)
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
