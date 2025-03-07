package internal

import "C"

import (
	"fmt"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"

	"ior/internal/flags"
	"ior/internal/generated/tracepoints"

	bpf "github.com/aquasecurity/libbpfgo"
)

func attachTracepoints(bpfModule *bpf.Module) error {
	for _, name := range tracepoints.List {
		prog, err := bpfModule.GetProgram(fmt.Sprintf("handle_%s", name))
		if err != nil {
			return fmt.Errorf("Failed to get BPF program handle_%s: %v", name, err)
		}
		fmt.Println("Attached prog handle_" + name)

		if _, err = prog.AttachTracepoint("syscalls", name); err != nil {
			// OK, older Kernel versions may not have this tracepoint!
			fmt.Println(fmt.Errorf("Failed to attach to %s tracepoint: %v", name, err))
			continue
		}
		fmt.Println("Attached tracepoint " + name)
	}

	return nil
}

func Run(flags flags.Flags) {
	bpfModule, err := bpf.NewModuleFromFile("ior.bpf.o")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()

	if err := flags.ResizeBPFMaps(bpfModule); err != nil {
		panic(err)
	}

	if err := flags.SetBPF(bpfModule); err != nil {
		panic(err)
	}

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}

	if err := attachTracepoints(bpfModule); err != nil {
		panic(err)
	}

	// 4096 channel size, minimises event drops
	ch := make(chan []byte, 4096)
	rb, err := bpfModule.InitRingBuf("event_map", ch)
	if err != nil {
		panic(err)
	}
	rb.Poll(300)

	var cpuProfile, memProfile *os.File
	if flags.PprofEnable {
		if cpuProfile, err = os.Create("ior.cpuprofile"); err != nil {
			panic(err)
		}
		if memProfile, err = os.Create("ior.memprofile"); err != nil {
			panic(err)
		}
		pprof.StartCPUProfile(cpuProfile)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("Good bye...")
		if flags.PprofEnable {
			fmt.Println("Stoppig profiling, writing ior.cpuprofile and ior.memprofile")
			pprof.StopCPUProfile()
			pprof.WriteHeapProfile(memProfile)
		}
		os.Exit(0)
	}()

	newEventLoop(flags).run(ch)
}
