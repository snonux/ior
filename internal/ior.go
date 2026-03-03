package internal

import "C"

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime/pprof"
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
	runTraceFn            = runTrace
	runTraceWithContextFn = runTraceWithContext
	runTUIFn              = tui.RunWithTraceStarter
	getEUID               = os.Geteuid

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
			return fmt.Errorf("Failed to get BPF program handle_%s: %v", name, err)
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
//
// When -ior=<trace.ior.zst> is provided it reads the compressed trace data, generates
// a native flamegraph SVG (using the selected fields and count metric) and then serves
// it via an embedded HTTP server. Without -ior, Run either executes trace mode or
// starts the TUI, depending on the active flags.
func Run() error {
	flags.PrintVersion()
	cfg := flags.Get()
	iorFile := cfg.IorDataFile
	var noTraceRun bool

	if iorFile != "" {
		if cfg.IorWatchInterval < 0 {
			return errors.New("-iorWatchInterval must be >= 0")
		}
		noTraceRun = true
		native := flamegraph.NewNativeSVG(cfg.CollapsedFields, cfg.CountField)
		svgFile, err := writeIorOutputs(native, iorFile, cfg.FlamegraphJSON)
		if err != nil {
			return err
		}

		done := make(chan struct{})
		defer close(done)
		if cfg.IorWatchInterval > 0 {
			go watchIorOutputs(done, cfg.IorWatchInterval, iorFile, native, cfg.FlamegraphJSON)
			err = flamegraph.ServeSVGAutoReload(svgFile, cfg.IorWatchInterval)
		} else {
			err = flamegraph.ServeSVG(svgFile)
		}
		if err != nil {
			return err
		}
	}

	if noTraceRun {
		return nil
	}
	return dispatchRun(cfg)
}

func writeIorOutputs(native flamegraph.NativeSVG, iorFile string, writeJSON bool) (string, error) {
	svgFile, err := native.WriteSVGFromFile(iorFile)
	if err != nil {
		return "", err
	}
	if !writeJSON {
		return svgFile, nil
	}
	if _, err := native.WriteJSONFromFile(iorFile); err != nil {
		return "", err
	}
	return svgFile, nil
}

func watchIorOutputs(done <-chan struct{}, interval time.Duration, iorFile string,
	native flamegraph.NativeSVG, writeJSON bool) {

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lastMod := fileModTime(iorFile)

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			mod := fileModTime(iorFile)
			if !mod.After(lastMod) {
				continue
			}
			if _, err := writeIorOutputs(native, iorFile, writeJSON); err != nil {
				_, _ = fmt.Printf("Failed to refresh flamegraph outputs: %v\n", err)
				continue
			}
			lastMod = mod
			_, _ = fmt.Printf("Refreshed flamegraph outputs at %s\n", time.Now().Format(time.RFC3339))
		}
	}
}

func fileModTime(path string) time.Time {
	stat, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return stat.ModTime()
}

func dispatchRun(cfg flags.Flags) error {
	if err := validateRunConfig(cfg); err != nil {
		return err
	}
	if shouldRunTraceMode(cfg) {
		return runTraceFn()
	}
	return runTUIFn(tuiTraceStarterFromRunTrace(runTraceWithContextFn))
}

func validateRunConfig(cfg flags.Flags) error {
	if cfg.LiveFlamegraph && cfg.FlamegraphEnable {
		return errors.New("-live and -flamegraph are mutually exclusive")
	}
	if cfg.IorWatchInterval > 0 && cfg.IorDataFile == "" {
		return errors.New("-iorWatchInterval requires -ior")
	}
	if cfg.IorWatchInterval < 0 {
		return errors.New("-iorWatchInterval must be >= 0")
	}
	return nil
}

func shouldRunTraceMode(cfg flags.Flags) bool {
	return cfg.PlainMode || cfg.FlamegraphEnable || cfg.LiveFlamegraph || cfg.PprofEnable
}

func tuiTraceStarterFromRunTrace(
	startTrace func(context.Context, chan<- struct{}, func(*eventLoop)) error,
) tui.TraceStarter {
	return func(ctx context.Context) error {
		bpf.SetLoggerCbs(bpf.Callbacks{
			Log: func(int, string) {},
		})

		engine := statsengine.NewEngine(64)
		streamBuf := eventstream.NewRingBuffer()
		if bindings, ok := tui.RuntimeBindingsFromContext(ctx); ok {
			bindings.SetDashboardSnapshotSource(engine)
			bindings.SetEventStreamSource(streamBuf)
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
					ep.Recycle()
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
		pidFilter:        cfg.PidFilter,
		commFilter:       cfg.CommFilter,
		pathFilter:       cfg.PathFilter,
		liveFlamegraph:   cfg.LiveFlamegraph,
		liveInterval:     cfg.LiveInterval,
		liveOpenCommand:  cfg.OpenCommand,
		collapsedFields:  fields,
		countField:       cfg.CountField,
		flamegraphName:   cfg.FlamegraphName,
		flamegraphEnable: cfg.FlamegraphEnable,
		pprofEnable:      cfg.PprofEnable,
		plainMode:        cfg.PlainMode,
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

	pprofDone := make(chan struct{})
	var cpuProfile, memProfile *os.File
	if cfg.PprofEnable {
		if cpuProfile, err = os.Create("ior.cpuprofile"); err != nil {
			return err
		}
		if memProfile, err = os.Create("ior.memprofile"); err != nil {
			return err
		}
		pprof.StartCPUProfile(cpuProfile)
	} else {
		close(pprofDone)
	}

	signalTraceStarted(started)

	el := newEventLoop(newEventLoopConfig(cfg))
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

	go func() {
		<-ctx.Done()
		if verbose {
			fmt.Println(el.stats())
		}
		if cfg.PprofEnable {
			logln("Stoppig profiling, writing ior.cpuprofile and ior.memprofile")
			pprof.StopCPUProfile()
			pprof.WriteHeapProfile(memProfile)
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
	return cfg.PlainMode || cfg.FlamegraphEnable || cfg.LiveFlamegraph || cfg.PprofEnable
}
