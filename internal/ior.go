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
	runTUIFn               = tui.RunWithTraceStarter
	runTUITestFlamesFn     = tui.RunTestFlamesWithTraceStarter
	runTUITestLiveFlamesFn = tui.RunTestFlamesWithTraceStarter
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
		return runTUITestFlamesFn(tuiTestFlamesStarter())
	}
	if cfg.TestLiveFlames {
		return runTUITestLiveFlamesFn(tuiTestLiveFlamesStarter())
	}
	if shouldRunTraceMode(cfg) {
		return runTraceFn()
	}
	return runTUIFn(tuiTraceStarterFromRunTrace(runTraceWithContextFn))
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

func tuiTestFlamesStarter() tui.TraceStarter {
	return func(ctx context.Context) error {
		engine, streamBuf, liveTrie := buildTestFlamesRuntime(flags.Get())
		if bindings, ok := tui.RuntimeBindingsFromContext(ctx); ok {
			bindings.SetDashboardSnapshotSource(engine)
			bindings.SetEventStreamSource(streamBuf)
			bindings.SetLiveTrie(liveTrie)
		}
		return nil
	}
}

func tuiTestLiveFlamesStarter() tui.TraceStarter {
	return func(ctx context.Context) error {
		engine, streamBuf, liveTrie := buildTestLiveFlamesRuntime(ctx, flags.Get())
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
	startTrace func(context.Context, chan<- struct{}, func(*eventLoop)) error,
) tui.TraceStarter {
	return func(ctx context.Context) error {
		bpf.SetLoggerCbs(bpf.Callbacks{
			Log: func(int, string) {},
		})

		cfg := flags.Get()
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
			err := startTrace(ctx, startedCh, func(el *eventLoop) {
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

func runTrace() error {
	return runTraceWithContext(context.Background(), nil, nil)
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

func runTraceWithContext(parentCtx context.Context, started chan<- struct{}, configure func(*eventLoop)) error {
	if getEUID() != 0 {
		return errRootPrivilegesRequired
	}

	verbose := started == nil
	logln := func(...any) {}
	if verbose {
		logln = func(args ...any) { _, _ = fmt.Println(args...) }
	}
	cfg := flags.Get()

	bpfModule, err := bpf.NewModuleFromFile("ior.bpf.o")
	if err != nil {
		return err
	}
	defer bpfModule.Close()

	if err := resizeBPFMaps(cfg, bpfModule); err != nil {
		return err
	}

	if err := setBPFGlobals(cfg, bpfModule); err != nil {
		return err
	}

	if err := bpfModule.BPFLoadObject(); err != nil {
		return err
	}

	mgr := probemanager.NewManager(libbpfTracepointModule{module: bpfModule})
	defer mgr.Close()
	if err := mgr.AttachAll(cfg.ShouldIAttachTracepoint, tracepoints.List); err != nil {
		return err
	}
	if bindings, ok := tui.RuntimeBindingsFromContext(parentCtx); ok {
		bindings.SetProbeManager(mgr)
		defer bindings.SetProbeManager(nil)
	}

	// 4096 channel size, minimises event drops
	ch := make(chan []byte, 4096)
	rb, err := bpfModule.InitRingBuf("event_map", ch)
	if err != nil {
		return err
	}
	rb.Poll(300)

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
	defer cancel()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signalCh)

	go func() {
		select {
		case <-signalCh:
			logln("Received signal, shutting down...")
			cancel()
		case <-ctx.Done():
			return
		}
	}()

	pprofDone := make(chan struct{})
	var cpuProfile, memProfile, execTraceProfile *os.File
	stopExecTrace := func() {}
	if cfg.PprofEnable {
		isTUIMode := started != nil
		cpuProfilePath, memProfilePath, execTracePath, execTraceDuration := profilingFilesForMode(isTUIMode)

		if cpuProfile, err = os.Create(cpuProfilePath); err != nil {
			return err
		}
		if memProfile, err = os.Create(memProfilePath); err != nil {
			_ = cpuProfile.Close()
			return err
		}

		if execTracePath != "" {
			if execTraceProfile, err = os.Create(execTracePath); err != nil {
				_ = cpuProfile.Close()
				_ = memProfile.Close()
				return err
			}
			if err := trace.Start(execTraceProfile); err != nil {
				_ = cpuProfile.Close()
				_ = memProfile.Close()
				_ = execTraceProfile.Close()
				return err
			}

			// TUI profiling workflow:
			//   go tool pprof -http=:8080 ior-tui-cpu.prof
			//   go tool trace ior-tui-trace.out
			var stopOnce sync.Once
			stopExecTrace = func() {
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
				stopExecTrace()
			}()
		}

		if err := pprof.StartCPUProfile(cpuProfile); err != nil {
			stopExecTrace()
			_ = cpuProfile.Close()
			_ = memProfile.Close()
			return err
		}
	} else {
		close(pprofDone)
	}

	signalTraceStarted(started)

	el, err := newEventLoop(newEventLoopConfig(cfg))
	if err != nil {
		return err
	}
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

	go func() {
		<-ctx.Done()
		if verbose {
			fmt.Println(el.stats())
		}
		if cfg.PprofEnable {
			logln("Stopping profiling and writing profile files")
			pprof.StopCPUProfile()
			runtime.GC()
			_ = pprof.WriteHeapProfile(memProfile)
			stopExecTrace()
			_ = cpuProfile.Close()
			_ = memProfile.Close()
			close(pprofDone)
		}
	}()

	startTime := time.Now()
	el.run(ctx, ch)
	totalDuration := time.Since(startTime)
	<-pprofDone
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
