package internal

import "C"

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sync"
	"syscall"
	"time"

	appconfig "ior/internal/config"
	"ior/internal/event"
	"ior/internal/flags"
	"ior/internal/flamegraph"
	"ior/internal/globalfilter"
	"ior/internal/probemanager"
	"ior/internal/statsengine"
	"ior/internal/tracepoints"
	"ior/internal/tui"
	"ior/internal/tui/eventstream"

	bpf "github.com/aquasecurity/libbpfgo"
)

var (
	runTraceFn             = runTrace
	runTraceWithContextFn  = runTraceWithContext
	runTUIFn               = tui.RunWithTraceStarterConfig
	runTUITestFlamesFn     = tui.RunTestFlamesWithTraceStarterConfig
	runTUITestLiveFlamesFn = tui.RunTestFlamesWithTraceStarterConfig
	getEUID                = os.Geteuid

	errRootPrivilegesRequired = errors.New("tracing requires root privileges (run with sudo)")
)

type libbpfTracepointProgram struct {
	prog *bpf.BPFProg
}

func (p libbpfTracepointProgram) AttachTracepoint(category, name string) (probemanager.Link, error) {
	return p.prog.AttachTracepoint(category, name)
}

type libbpfTracepointModule struct {
	module *bpf.Module
}

type streamEventSink interface {
	eventstream.Source
	Push(eventstream.StreamEvent)
}

func (m libbpfTracepointModule) GetProgram(progName string) (probemanager.Program, error) {
	prog, err := m.module.GetProgram(progName)
	if err != nil {
		return nil, err
	}
	return libbpfTracepointProgram{prog: prog}, nil
}

// Run is the main entry point for the ior binary.
func Run() error {
	flags.PrintVersion()
	return dispatchRun(flags.Get())
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
	if shouldRunTraceMode(cfg) {
		return runTraceFn(cfg)
	}
	return runTUIFn(cfg, tuiTraceStarterFromRunTrace(cfg, runTraceWithContextFn))
}

func validateRunConfig(cfg flags.Config) error {
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
		if bindings, ok := tui.RuntimeBindingsFromContext(ctx); ok {
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
		if bindings, ok := tui.RuntimeBindingsFromContext(ctx); ok {
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
	return cfg.PlainMode || cfg.FlamegraphOutput
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
		liveTrie := flamegraph.NewLiveTrie(cfg.CollapsedFields, cfg.CountField)
		if bindings, ok := tui.RuntimeBindingsFromContext(ctx); ok {
			if persistent := bindings.StreamBuffer(); persistent != nil {
				streamSource = persistent
				if sink, ok := persistent.(streamEventSink); ok {
					streamBuf = sink
				} else {
					return fmt.Errorf("runtime stream source does not support event pushes")
				}
			}
			bindings.SetDashboardSnapshotSource(engine)
			bindings.SetEventStreamSource(streamSource)
			bindings.SetLiveTrie(liveTrie)
		}
		streamEvents := make(chan eventstream.StreamEvent, appconfig.DefaultChannelBufferSize)
		streamSeq := eventstream.NewSequencer(0)

		go func() {
			for ev := range streamEvents {
				streamBuf.Push(ev)
			}
		}()

		startedCh := make(chan struct{})
		errCh := make(chan error, 1)

		go func() {
			err := startTrace(ctx, cfg, startedCh, func(el *eventLoop) {
				el.printCb = func(ep *event.Pair) {
					if !shouldIngestTracePair(cfg.GlobalFilter, ep) {
						ep.Recycle()
						return
					}
					engine.Ingest(ep)
					streamEvents <- eventstream.NewStreamEvent(streamSeq.Next(), ep)
					liveTrie.Ingest(ep)
					// Both downstream consumers snapshot the pair synchronously, so
					// the pooled pair can be recycled immediately afterwards.
					ep.Recycle()
				}
				el.warningCb = func(message string) {
					// Drop warning notifications if the stream channel is saturated.
					select {
					case streamEvents <- eventstream.NewWarningEvent(streamSeq.Next(), message):
					default:
					}
				}
			})
			close(streamEvents)
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
	if pid, ok := eqFilterValue(filter.PID); ok {
		cfg.PidFilter = pid
	}
	if tid, ok := eqFilterValue(filter.TID); ok {
		cfg.TidFilter = tid
	}
}

func eqFilterValue(filter *globalfilter.NumericFilter) (int, bool) {
	if filter == nil || filter.Op != globalfilter.OpEq || filter.Value <= 0 {
		return 0, false
	}
	return int(filter.Value), true
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

func traceFilterFromConfig(cfg flags.Config) globalfilter.Filter {
	filter := cfg.GlobalFilter.Clone()
	if filter.IsActive() {
		return filter
	}
	if cfg.CommFilter != "" {
		filter.Comm = &globalfilter.StringFilter{Pattern: cfg.CommFilter}
	}
	if cfg.PathFilter != "" {
		filter.File = &globalfilter.StringFilter{Pattern: cfg.PathFilter}
	}
	if cfg.PidFilter > 0 {
		filter.PID = &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: int64(cfg.PidFilter)}
	}
	if cfg.TidFilter > 0 {
		filter.TID = &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: int64(cfg.TidFilter)}
	}
	return filter
}

type profilingControl struct {
	done          chan struct{}
	enabled       bool
	cpuProfile    *os.File
	memProfile    *os.File
	stopExecTrace func()
	stopOnce      sync.Once
}

func newLogger(verbose bool) func(...any) {
	if !verbose {
		return func(...any) {}
	}
	return func(args ...any) { _, _ = fmt.Println(args...) }
}

func setupBPFModuleError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("setup BPF module: %s: %w", stage, err)
}

func setupBPFModule(parentCtx context.Context, cfg flags.Config) (*bpf.Module, *probemanager.Manager, func(), error) {
	releaseBindings := func() {}

	bpfModule, stage, err := loadBPFModule()
	if err != nil {
		return nil, nil, releaseBindings, setupBPFModuleError(stage, err)
	}
	if err := resizeBPFMaps(cfg, bpfModule); err != nil {
		bpfModule.Close()
		return nil, nil, releaseBindings, setupBPFModuleError("resize maps", err)
	}
	if err := setBPFGlobals(cfg, bpfModule); err != nil {
		bpfModule.Close()
		return nil, nil, releaseBindings, setupBPFModuleError("set globals", err)
	}
	if err := bpfModule.BPFLoadObject(); err != nil {
		bpfModule.Close()
		return nil, nil, releaseBindings, setupBPFModuleError("load object", err)
	}

	mgr := probemanager.NewManager(libbpfTracepointModule{module: bpfModule})
	if err := mgr.AttachAll(cfg.ShouldIAttachTracepoint, tracepoints.List); err != nil {
		mgr.Close()
		bpfModule.Close()
		return nil, nil, releaseBindings, setupBPFModuleError("attach probes", err)
	}
	if bindings, ok := tui.RuntimeBindingsFromContext(parentCtx); ok {
		bindings.SetProbeManager(mgr)
		releaseBindings = func() { bindings.SetProbeManager(nil) }
	}
	return bpfModule, mgr, releaseBindings, nil
}

func setupEventChannel(bpfModule *bpf.Module) (chan []byte, error) {
	ch := make(chan []byte, appconfig.DefaultChannelBufferSize)
	rb, err := bpfModule.InitRingBuf("event_map", ch)
	if err != nil {
		return nil, err
	}
	rb.Poll(300)
	return ch, nil
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

func setupProfiling(ctx context.Context, cfg flags.Config, started chan<- struct{}) (*profilingControl, error) {
	control := &profilingControl{
		done:          make(chan struct{}),
		stopExecTrace: func() {},
	}
	if !cfg.PprofEnable {
		close(control.done)
		return control, nil
	}

	control.enabled = true
	isTUIMode := started != nil
	cpuProfilePath, memProfilePath, execTracePath, execTraceDuration := profilingFilesForMode(isTUIMode)

	cpuProfile, err := os.Create(cpuProfilePath)
	if err != nil {
		return nil, err
	}
	memProfile, err := os.Create(memProfilePath)
	if err != nil {
		_ = cpuProfile.Close()
		return nil, err
	}
	control.cpuProfile = cpuProfile
	control.memProfile = memProfile

	if execTracePath != "" {
		execTraceProfile, err := os.Create(execTracePath)
		if err != nil {
			_ = cpuProfile.Close()
			_ = memProfile.Close()
			return nil, err
		}
		if err := trace.Start(execTraceProfile); err != nil {
			_ = cpuProfile.Close()
			_ = memProfile.Close()
			_ = execTraceProfile.Close()
			return nil, err
		}
		var stopOnce sync.Once
		control.stopExecTrace = func() {
			stopOnce.Do(func() {
				trace.Stop()
				_ = execTraceProfile.Close()
			})
		}
		go func() {
			timer := time.NewTimer(execTraceDuration)
			defer timer.Stop()
			select {
			case <-ctx.Done():
			case <-timer.C:
			}
			control.stopExecTrace()
		}()
	}

	if err := pprof.StartCPUProfile(cpuProfile); err != nil {
		control.stopExecTrace()
		_ = cpuProfile.Close()
		_ = memProfile.Close()
		return nil, err
	}
	return control, nil
}

func (p *profilingControl) stop(logln func(...any)) {
	p.stopOnce.Do(func() {
		if !p.enabled {
			return
		}
		logln("Stopping profiling and writing profile files")
		pprof.StopCPUProfile()
		runtime.GC()
		_ = pprof.WriteHeapProfile(p.memProfile)
		p.stopExecTrace()
		_ = p.cpuProfile.Close()
		_ = p.memProfile.Close()
		close(p.done)
	})
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
	return cfg.PlainMode || cfg.FlamegraphOutput
}

func profilingFilesForMode(tuiMode bool) (cpuProfilePath, memProfilePath, execTracePath string, execTraceDuration time.Duration) {
	if tuiMode {
		return "ior-tui-cpu.prof", "ior-tui-mem.prof", "ior-tui-trace.out", 10 * time.Second
	}
	return "ior.cpuprofile", "ior.memprofile", "", 0
}
