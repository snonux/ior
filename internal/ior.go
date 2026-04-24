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
	"ior/internal/statsengine"
	"ior/internal/tui"
	"ior/internal/tui/eventstream"

	bpf "github.com/aquasecurity/libbpfgo"
)

var (
	runTraceFn             = runTrace
	runParquetFn           = runHeadlessParquet
	runTraceWithContextFn  = runTraceWithContext
	runTUIFn               = tui.RunWithTraceStarterConfig
	runTUITestFlamesFn     = tui.RunTestFlamesWithTraceStarterConfig
	runTUITestLiveFlamesFn = tui.RunTestFlamesWithTraceStarterConfig // same runner; starter differs (static vs live)
	getEUID                = os.Geteuid

	errRootPrivilegesRequired = errors.New("tracing requires root privileges (run with sudo)")
)

type streamEventSink interface {
	eventstream.Source
	Push(eventstream.StreamEvent)
}

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

func tuiTestFlamesStarter(cfg flags.Config) tui.TraceStarter {
	return func(ctx context.Context) error {
		engine, streamBuf, liveTrie := buildTestFlamesRuntime(cfg)
		// Only setter methods are needed here; use the narrower publisher interface.
		if bindings, ok := tui.RuntimePublisherFromContext(ctx); ok {
			bindings.SetDashboardSnapshotSource(engine)
			bindings.SetEventStreamSource(streamBuf)
			bindings.SetLiveTrie(liveTrie)
		}
		return nil
	}
}

func tuiTestLiveFlamesStarter(cfg flags.Config) tui.TraceStarter {
	return func(ctx context.Context) error {
		engine, streamBuf, liveTrie := buildTestLiveFlamesRuntime(ctx, cfg)
		// Only setter methods are needed here; use the narrower publisher interface.
		if bindings, ok := tui.RuntimePublisherFromContext(ctx); ok {
			bindings.SetDashboardSnapshotSource(engine)
			bindings.SetEventStreamSource(streamBuf)
			bindings.SetLiveTrie(liveTrie)
		}
		return nil
	}
}

func buildTestFlamesRuntime(cfg flags.Config) (*statsengine.Engine, *eventstream.RingBuffer, *flamegraph.LiveTrie) {
	engine := statsengine.NewEngine(64)
	streamBuf := eventstream.NewRingBuffer()
	liveTrie := flamegraph.NewLiveTrie(cfg.CollapsedFields, cfg.CountField)
	flamegraph.SeedTestFlameData(liveTrie)
	return engine, streamBuf, liveTrie
}

func buildTestLiveFlamesRuntime(ctx context.Context, cfg flags.Config) (*statsengine.Engine, *eventstream.RingBuffer, *flamegraph.LiveTrie) {
	engine := statsengine.NewEngine(64)
	streamBuf := eventstream.NewRingBuffer()
	liveTrie := flamegraph.NewLiveTrie(cfg.CollapsedFields, cfg.CountField)
	flamegraph.SeedTestLiveFlameData(liveTrie, 0)

	interval := cfg.LiveInterval
	if interval <= 0 {
		interval = 200 * time.Millisecond
	}
	go runSyntheticLiveFlames(ctx, liveTrie, interval)
	return engine, streamBuf, liveTrie
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

func tuiTraceStarterFromRunTrace(
	baseCfg flags.Config,
	startTrace func(context.Context, flags.Config, chan<- struct{}, func(*eventLoop)) error,
) tui.TraceStarter {
	return func(ctx context.Context) error {
		bpf.SetLoggerCbs(bpf.Callbacks{
			Log: func(int, string) {},
		})

		cfg := baseCfg
		if filter, ok := tui.TraceFiltersFromContext(ctx); ok {
			cfg.GlobalFilter = filter.Clone()
			applyTraceScopeFromGlobalFilter(&cfg, filter)
		}
		engine := statsengine.NewEngine(64)
		streamBuf := streamEventSink(eventstream.NewRingBuffer())
		streamSource := eventstream.Source(streamBuf)
		streamSeq := eventstream.NewSequencer(0)
		liveTrie := flamegraph.NewLiveTrie(cfg.CollapsedFields, cfg.CountField)
		filterEpoch := uint64(0)
		var recorderWarningOnce sync.Once
		var recorder *parquet.Recorder
		if bindings, ok := tui.RuntimeBindingsFromContext(ctx); ok {
			if persistent := bindings.StreamBuffer(); persistent != nil {
				streamSource = persistent
				if sink, ok := persistent.(streamEventSink); ok {
					streamBuf = sink
				} else {
					return fmt.Errorf("runtime stream source does not support event pushes")
				}
			}
			if persistentSeq := bindings.StreamSequencer(); persistentSeq != nil {
				streamSeq = persistentSeq
			}
			recorder = bindings.Recorder()
			filterEpoch = bindings.FilterEpoch()
			bindings.SetDashboardSnapshotSource(engine)
			bindings.SetEventStreamSource(streamSource)
			bindings.SetLiveTrie(liveTrie)
		}
		startedCh := make(chan struct{})
		errCh := make(chan error, 1)

		go func() {
			err := startTrace(ctx, cfg, startedCh, func(el *eventLoop) {
				el.printCb = func(ep *event.Pair) {
					if !shouldIngestTracePair(cfg.GlobalFilter, ep) {
						ep.Recycle()
						return
					}
					row := eventstream.NewStreamEvent(streamSeq.Next(), ep)
					engine.Ingest(ep)
					streamBuf.Push(row)
					if recorder != nil {
						if err := recorder.Record(row, filterEpoch); err != nil {
							recorderWarningOnce.Do(func() {
								if el.warningCb != nil {
									el.warningCb(fmt.Sprintf("Parquet recorder failed: %v", err))
								}
							})
						}
					}
					liveTrie.Ingest(ep)
					// Both downstream consumers snapshot the pair synchronously, so
					// the pooled pair can be recycled immediately afterwards.
					ep.Recycle()
				}
				el.warningCb = func(message string) {
					streamBuf.Push(eventstream.NewWarningEvent(streamSeq.Next(), message))
				}
			})
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

func runTraceWithContext(parentCtx context.Context, cfg flags.Config, started chan<- struct{}, configure func(*eventLoop)) error {
	if getEUID() != 0 {
		return errRootPrivilegesRequired
	}

	verbose := started == nil
	logln := newLogger(verbose)
	var recorder *flamegraph.Recorder
	if cfg.FlamegraphOutput {
		recorder = flamegraph.NewRecorder(cfg.OutputName)
	}

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
	if recorder != nil {
		recordOutput := func(el *eventLoop) {
			el.printCb = func(ep *event.Pair) {
				recorder.AddPair(ep)
				ep.Recycle()
			}
		}
		configure = chainEventLoopConfigure(recordOutput, configure)
	}
	configureEventLoopOutput(el, mgr, configure)
	startTraceShutdownWatcher(ctx, verbose, el, profiling, logln)

	startTime := time.Now()
	el.run(ctx, ch)
	totalDuration := time.Since(startTime)
	<-profiling.done
	if recorder != nil {
		if err := recorder.Write(); err != nil {
			return err
		}
	}
	logln("Good bye... (unloading BPF tracepoints will take a few seconds...) after", totalDuration)
	return nil
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
