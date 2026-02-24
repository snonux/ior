package internal

import "C"

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"
	"time"

	"ior/internal/event"
	"ior/internal/flags"
	"ior/internal/flamegraph"
	"ior/internal/statsengine"
	"ior/internal/tracepoints"
	"ior/internal/tui"

	bpf "github.com/aquasecurity/libbpfgo"
)

type tracepointProgram interface {
	attachTracepoint(category, name string) error
}

var (
	runTraceFn            = runTrace
	runTraceWithContextFn = runTraceWithContext
	runTUIFn              = tui.RunWithTraceStarter
)

type tracepointModule interface {
	getProgram(progName string) (tracepointProgram, error)
}

type libbpfTracepointProgram struct {
	prog *bpf.BPFProg
}

func (p libbpfTracepointProgram) attachTracepoint(category, name string) error {
	_, err := p.prog.AttachTracepoint(category, name)
	return err
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

func attachTracepoints(bpfModule *bpf.Module) error {
	return attachTracepointsWith(libbpfTracepointModule{module: bpfModule}, flags.Get().ShouldIAttachTracepoint, tracepoints.List, true)
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

		if err = prog.attachTracepoint("syscalls", name); err != nil {
			// OK, older Kernel versions may not have this tracepoint!
			logf("Failed to attach to %s tracepoint: %v, kernel version may be too old, skipping", name, err)
			continue
		}
		logln("Attached tracepoint ", name)
	}

	return nil
}

func Run() error {
	flags.PrintVersion()
	cfg := flags.Get()
	iorFile := cfg.IorDataFile
	var noTraceRun bool

	if iorFile != "" {
		noTraceRun = true
		var svgFile string
		if cfg.FlamegraphTool != "" {
			collapsed := flamegraph.NewCollapsed(iorFile, cfg.CollapsedFields, cfg.CountField)
			collapsedFile, err := collapsed.Write(iorFile)
			if err != nil {
				return err
			}

			tool, err := flamegraph.NewTool(collapsedFile)
			if err != nil {
				return err
			}
			if err := tool.WriteSVG(); err != nil {
				return err
			}
			svgFile = tool.OutFile()
		} else {
			native := flamegraph.NewNativeSVG(cfg.CollapsedFields, cfg.CountField)
			var err error
			svgFile, err = native.WriteSVGFromFile(iorFile)
			if err != nil {
				return err
			}
		}

		if err := flamegraph.ServeSVG(svgFile); err != nil {
			return err
		}
	}

	if noTraceRun {
		return nil
	}
	return dispatchRun(cfg)
}

func dispatchRun(cfg flags.Flags) error {
	if shouldRunTraceMode(cfg) {
		return runTraceFn()
	}
	return runTUIFn(tuiTraceStarterFromRunTrace(runTraceWithContextFn))
}

func shouldRunTraceMode(cfg flags.Flags) bool {
	return cfg.PlainMode || cfg.FlamegraphEnable || cfg.PprofEnable
}

func tuiTraceStarterFromRunTrace(
	startTrace func(context.Context, chan<- struct{}, func(*eventLoop)) error,
) tui.TraceStarter {
	return func(ctx context.Context) error {
		bpf.SetLoggerCbs(bpf.Callbacks{
			Log: func(int, string) {},
		})

		engine := statsengine.NewEngine(64)
		tui.SetDashboardSnapshotSource(engine)

		startedCh := make(chan struct{})
		errCh := make(chan error, 1)

		go func() {
			errCh <- startTrace(ctx, startedCh, func(el *eventLoop) {
				el.printCb = func(ep *event.Pair) {
					engine.Ingest(ep)
					ep.Recycle()
				}
			})
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

func runTraceWithContext(parentCtx context.Context, started chan<- struct{}, configure func(*eventLoop)) error {
	verbose := started == nil
	logln := func(...any) {}
	if verbose {
		logln = func(args ...any) { _, _ = fmt.Println(args...) }
	}

	bpfModule, err := bpf.NewModuleFromFile("ior.bpf.o")
	if err != nil {
		return err
	}
	defer bpfModule.Close()

	if err := flags.Get().ResizeBPFMaps(bpfModule); err != nil {
		return err
	}

	if err := flags.Get().SetBPF(bpfModule); err != nil {
		return err
	}

	if err := bpfModule.BPFLoadObject(); err != nil {
		return err
	}

	if err := attachTracepointsWith(libbpfTracepointModule{module: bpfModule}, flags.Get().ShouldIAttachTracepoint, tracepoints.List, verbose); err != nil {
		return err
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
	if flags.Get().PprofEnable {
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

	el := newEventLoop()
	if configure != nil {
		configure(el)
	}
	duration := time.Duration(flags.Get().Duration) * time.Second
	logln("Probing for", duration)
	ctx, cancel := context.WithTimeout(parentCtx, duration)
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
		if flags.Get().PprofEnable {
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
