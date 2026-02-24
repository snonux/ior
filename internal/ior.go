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
	return attachTracepointsWith(libbpfTracepointModule{module: bpfModule}, flags.Get().ShouldIAttachTracepoint, tracepoints.List)
}

func attachTracepointsWith(module tracepointModule, shouldAttach func(string) bool, tracepointNames []string) error {
	for _, name := range tracepointNames {
		if !shouldAttach(name) {
			continue
		}
		fmt.Println("Attaching tracepoint", name)

		prog, err := module.getProgram(fmt.Sprintf("handle_%s", name))
		if err != nil {
			return fmt.Errorf("Failed to get BPF program handle_%s: %v", name, err)
		}
		fmt.Println("Attached prog handle_", name)

		if err = prog.attachTracepoint("syscalls", name); err != nil {
			// OK, older Kernel versions may not have this tracepoint!
			fmt.Printf("Failed to attach to %s tracepoint: %v, kernel version may be too old, skipping", name, err)
			continue
		}
		fmt.Println("Attached tracepoint ", name)
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

	if err := attachTracepoints(bpfModule); err != nil {
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
	fmt.Println("Probing for", duration)
	ctx, cancel := context.WithTimeout(parentCtx, duration)
	defer cancel()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signalCh)

	go func() {
		select {
		case <-signalCh:
			fmt.Println("Received signal, shutting down...")
			cancel()
		case <-ctx.Done():
			return
		}
	}()

	go func() {
		<-ctx.Done()
		fmt.Println(el.stats())
		if flags.Get().PprofEnable {
			fmt.Println("Stoppig profiling, writing ior.cpuprofile and ior.memprofile")
			pprof.StopCPUProfile()
			pprof.WriteHeapProfile(memProfile)
			close(pprofDone)
		}
	}()

	startTime := time.Now()
	el.run(ctx, ch)
	totalDuration := time.Since(startTime)
	<-pprofDone
	fmt.Println("Good bye... (unloading BPF tracepoints will take a few seconds...) after", totalDuration)
	return nil
}

func signalTraceStarted(started chan<- struct{}) {
	if started == nil {
		return
	}
	close(started)
}
