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

	"ior/internal/event"
	"ior/internal/flags"
	"ior/internal/flamegraph"
	"ior/internal/probemanager"
	"ior/internal/statsengine"
	"ior/internal/tracepoints"
	"ior/internal/tui"
	"ior/internal/tui/eventstream"

	bpf "github.com/aquasecurity/libbpfgo"
)

type tracepointProgram interface {
	attachTracepoint(category, name string) (tracepointLink, error)
}

type tracepointLink interface {
	Destroy() error
}

var (
	runTraceFn             = runTrace
	runTraceWithContextFn  = runTraceWithContext
	runTUIFn               = tui.RunWithTraceStarterConfig
	runTUITestFlamesFn     = tui.RunTestFlamesWithTraceStarterConfig
	runTUITestLiveFlamesFn = tui.RunTestFlamesWithTraceStarterConfig
	getEUID                = os.Geteuid

	errRootPrivilegesRequired = errors.New("tracing requires root privileges (run with sudo)")
)

type tracepointModule interface {
	getProgram(progName string) (tracepointProgram, error)
}

type libbpfTracepointProgram struct {
	prog *bpf.BPFProg
}

func (p libbpfTracepointProgram) AttachTracepoint(category, name string) (probemanager.Link, error) {
	return p.prog.AttachTracepoint(category, name)
}

func (p libbpfTracepointProgram) attachTracepoint(category, name string) (tracepointLink, error) {
	return p.AttachTracepoint(category, name)
}

type libbpfTracepointModule struct {
	module *bpf.Module
}

func (m libbpfTracepointModule) getProgram(progName string) (tracepointProgram, error) {
	prog, err := m.module.GetProgram(progName)
	if err != nil {
		return nil, err
	}
	return libbpfTracepointProgram{prog: prog}, nil
}

func (m libbpfTracepointModule) GetProgram(progName string) (probemanager.Program, error) {
	prog, err := m.module.GetProgram(progName)
	if err != nil {
		return nil, err
	}
	return libbpfTracepointProgram{prog: prog}, nil
}

func attachTracepointsWith(module tracepointModule, shouldAttach func(string) bool, tracepointNames []string, verbose bool) error {
	logln := func(...any) {}
	logf := func(string, ...any) {}
	if verbose {
		logln = func(args ...any) { _, _ = fmt.Println(args...) }
		logf = func(format string, args ...any) { _, _ = fmt.Printf(format, args...) }
	}

	for _, name := range tracepointNames {
		if !shouldAttach(name) {
			continue
		}
		logln("Attaching tracepoint", name)

		prog, err := module.getProgram(fmt.Sprintf("handle_%s", name))
		if err != nil {
			return fmt.Errorf("failed to get BPF program handle_%s: %w", name, err)
		}
		logln("Attached prog handle_", name)

		if _, err = prog.attachTracepoint("syscalls", name); err != nil {
			// OK, older Kernel versions may not have this tracepoint!
			logf("Failed to attach to %s tracepoint: %v, kernel version may be too old, skipping", name, err)
			continue
		}
		logln("Attached tracepoint ", name)
	}

	return nil
}

// Run is the main entry point for the ior binary.
func Run() error {
	flags.PrintVersion()
	return dispatchRun(flags.Get())
}

func dispatchRun(cfg flags.Flags) error {
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

func validateRunConfig(cfg flags.Flags) error {
	if cfg.TestFlames && cfg.PlainMode {
		return errors.New("--testflames cannot be combined with -plain")
	}
	if cfg.TestLiveFlames && cfg.PlainMode {
		return errors.New("--testliveflames cannot be combined with -plain")
	}
	if cfg.TestFlames && cfg.TestLiveFlames {
		return errors.New("--testflames and --testliveflames are mutually exclusive")
	}
	return nil
}

func tuiTestFlamesStarter(cfg flags.Flags) tui.TraceStarter {
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

func tuiTestLiveFlamesStarter(cfg flags.Flags) tui.TraceStarter {
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

func buildTestFlamesRuntime(cfg flags.Flags) (*statsengine.Engine, *eventstream.RingBuffer, *flamegraph.LiveTrie) {
	engine := statsengine.NewEngine(64)
	streamBuf := eventstream.NewRingBuffer()
	liveTrie := flamegraph.NewLiveTrie(cfg.CollapsedFields, cfg.CountField)
	flamegraph.SeedTestFlameData(liveTrie)
	return engine, streamBuf, liveTrie
}

func buildTestLiveFlamesRuntime(ctx context.Context, cfg flags.Flags) (*statsengine.Engine, *eventstream.RingBuffer, *flamegraph.LiveTrie) {
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

func shouldRunTraceMode(cfg flags.Flags) bool {
	return cfg.PlainMode
}

func tuiTraceStarterFromRunTrace(
	baseCfg flags.Flags,
	startTrace func(context.Context, flags.Flags, chan<- struct{}, func(*eventLoop)) error,
) tui.TraceStarter {
	return func(ctx context.Context) error {
		bpf.SetLoggerCbs(bpf.Callbacks{
			Log: func(int, string) {},
		})

		cfg := baseCfg
		if pidFilter, tidFilter, ok := tui.TraceFiltersFromContext(ctx); ok {
			cfg.PidFilter = pidFilter
			cfg.TidFilter = tidFilter
		}
		engine := statsengine.NewEngine(64)
		streamBuf := eventstream.NewRingBuffer()
		liveTrie := flamegraph.NewLiveTrie(cfg.CollapsedFields, cfg.CountField)
		if bindings, ok := tui.RuntimeBindingsFromContext(ctx); ok {
			bindings.SetDashboardSnapshotSource(engine)
			bindings.SetEventStreamSource(streamBuf)
			bindings.SetLiveTrie(liveTrie)
		}
		streamEvents := make(chan eventstream.StreamEvent, 4096)

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
					engine.Ingest(ep)
					streamEvents <- eventstream.NewStreamEvent(ep.EnterEv.GetTime(), ep)
					liveTrie.Ingest(ep)
				}
				el.warningCb = func(message string) {
					// Drop warning notifications if the stream channel is saturated.
					select {
					case streamEvents <- eventstream.NewWarningEvent(message):
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

func runTrace(cfg flags.Flags) error {
	return runTraceWithContext(context.Background(), cfg, nil, nil)
}

func newEventLoopConfig(cfg flags.Flags) eventLoopConfig {
	fields := make([]string, len(cfg.CollapsedFields))
	copy(fields, cfg.CollapsedFields)
	return eventLoopConfig{
		pidFilter:       cfg.PidFilter,
		commFilter:      cfg.CommFilter,
		pathFilter:      cfg.PathFilter,
		collapsedFields: fields,
		countField:      cfg.CountField,
		pprofEnable:     cfg.PprofEnable,
		plainMode:       cfg.PlainMode,
	}
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

func setupBPFModule(parentCtx context.Context, cfg flags.Flags) (*bpf.Module, *probemanager.Manager, func(), error) {
	releaseBindings := func() {}

	bpfModule, err := bpf.NewModuleFromFile("ior.bpf.o")
	if err != nil {
		return nil, nil, releaseBindings, err
	}
	if err := resizeBPFMaps(cfg, bpfModule); err != nil {
		bpfModule.Close()
		return nil, nil, releaseBindings, err
	}
	if err := setBPFGlobals(cfg, bpfModule); err != nil {
		bpfModule.Close()
		return nil, nil, releaseBindings, err
	}
	if err := bpfModule.BPFLoadObject(); err != nil {
		bpfModule.Close()
		return nil, nil, releaseBindings, err
	}

	mgr := probemanager.NewManager(libbpfTracepointModule{module: bpfModule})
	if err := mgr.AttachAll(cfg.ShouldIAttachTracepoint, tracepoints.List); err != nil {
		mgr.Close()
		bpfModule.Close()
		return nil, nil, releaseBindings, err
	}
	if bindings, ok := tui.RuntimeBindingsFromContext(parentCtx); ok {
		bindings.SetProbeManager(mgr)
		releaseBindings = func() { bindings.SetProbeManager(nil) }
	}
	return bpfModule, mgr, releaseBindings, nil
}

func setupEventChannel(bpfModule *bpf.Module) (chan []byte, error) {
	// 4096 channel size minimizes event drops.
	ch := make(chan []byte, 4096)
	rb, err := bpfModule.InitRingBuf("event_map", ch)
	if err != nil {
		return nil, err
	}
	rb.Poll(300)
	return ch, nil
}

func setupTraceContext(parentCtx context.Context, cfg flags.Flags, logln func(...any)) (context.Context, context.CancelFunc, func()) {
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

func setupProfiling(ctx context.Context, cfg flags.Flags, started chan<- struct{}) (*profilingControl, error) {
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

func runTraceWithContext(parentCtx context.Context, cfg flags.Flags, started chan<- struct{}, configure func(*eventLoop)) error {
	if getEUID() != 0 {
		return errRootPrivilegesRequired
	}

	verbose := started == nil
	logln := newLogger(verbose)

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
	configureEventLoopOutput(el, mgr, configure)
	startTraceShutdownWatcher(ctx, verbose, el, profiling, logln)

	startTime := time.Now()
	el.run(ctx, ch)
	totalDuration := time.Since(startTime)
	<-profiling.done
	logln("Good bye... (unloading BPF tracepoints will take a few seconds...) after", totalDuration)
	return nil
}

func signalTraceStarted(started chan<- struct{}) {
	if started == nil {
		return
	}
	close(started)
}

func shouldAutoStopByDuration(cfg flags.Flags) bool {
	return cfg.PlainMode
}

func profilingFilesForMode(tuiMode bool) (cpuProfilePath, memProfilePath, execTracePath string, execTraceDuration time.Duration) {
	if tuiMode {
		return "ior-tui-cpu.prof", "ior-tui-mem.prof", "ior-tui-trace.out", 10 * time.Second
	}
	return "ior.cpuprofile", "ior.memprofile", "", 0
}
