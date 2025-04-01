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
	"ior/internal/tracepoints"

	bpf "github.com/aquasecurity/libbpfgo"
)

// TODO: Generally, write unit tests
// TODO: Integration tests, write C or Cgo code to simulate I/O?
func attachTracepoints(bpfModule *bpf.Module) error {
	for _, name := range tracepoints.List {
		if !flags.Get().ShouldIAttachTracepoint(name) {
			continue
		}
		fmt.Println("Attaching tracepoint", name)

		prog, err := bpfModule.GetProgram(fmt.Sprintf("handle_%s", name))
		if err != nil {
			return fmt.Errorf("Failed to get BPF program handle_%s: %v", name, err)
		}
		fmt.Println("Attached prog handle_", name)

		if _, err = prog.AttachTracepoint("syscalls", name); err != nil {
			// OK, older Kernel versions may not have this tracepoint!
			fmt.Printf("Failed to attach to %s tracepoint: %v, kernel version may be too old, skipping", name, err)
			continue
		}
		fmt.Println("Attached tracepoint ", name)
	}

	return nil
}

func Run() error {
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

	loop := newEventLoop()
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
		fmt.Println(loop.stats())
		if flags.Get().PprofEnable {
			fmt.Println("Stoppig profiling, writing ior.cpuprofile and ior.memprofile")
			pprof.StopCPUProfile()
			pprof.WriteHeapProfile(memProfile)
			close(pprofDone)
		}
	}()

	startTime := time.Now()
	loop.run(ctx, ch)
	totalDuration := time.Since(startTime)
	<-pprofDone
	fmt.Println("Good bye... (unloading BPF tracepoints will take a few seconds...) after", totalDuration)
	return nil
}
