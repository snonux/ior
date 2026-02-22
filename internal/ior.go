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

	"ior/internal/flags"
	"ior/internal/flamegraph"
	"ior/internal/tracepoints"

	bpf "github.com/aquasecurity/libbpfgo"
)

type tracepointProgram interface {
	attachTracepoint(category, name string) error
}

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
	iorFile := flags.Get().IorDataFile
	var noTraceRun bool

	if iorFile != "" {
		noTraceRun = true
		collapsed := flamegraph.NewCollapsed(iorFile, flags.Get().CollapsedFields, flags.Get().CountField)
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
	return runTrace()
}

func runTrace() error {
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

	el := newEventLoop()
	duration := time.Duration(flags.Get().Duration) * time.Second
	fmt.Println("Probing for", duration)
	ctx, cancel := context.WithTimeout(context.Background(), duration)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signalCh
		fmt.Println("Received signal, shutting down...")
		cancel()
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
