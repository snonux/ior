package internal

import "C"

import (
	"fmt"

	"ioriotng/internal/debugfs"
	"ioriotng/internal/flags"
	"ioriotng/internal/generated/tracepoints"

	bpf "github.com/aquasecurity/libbpfgo"
)

func attachTracepoints(bpfModule *bpf.Module) error {
	for _, name := range tracepoints.List {
		prog, err := bpfModule.GetProgram(fmt.Sprintf("handle_%s", name))
		if err != nil {
			return fmt.Errorf("Failed to get BPF program handle_%s: %v", name, err)
		}
		fmt.Println("Attached prog handle_" + name)

		if _, err = prog.AttachTracepoint("syscalls", fmt.Sprintf("sys_%s", name)); err != nil {
			return fmt.Errorf("Failed to attach to sys_%s tracepoint: %v", name, err)
		}
		fmt.Println("Attached tracepoint sys_" + name)
	}

	return nil
}

func Run(flags flags.Flags) {
	// Print out tracepoints with fd to consider for implementation!
	fmt.Println(debugfs.TracepointsWithFd())

	bpfModule, err := bpf.NewModuleFromFile("ioriotng.bpf.o")
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
	eventLoop(bpfModule, ch)

	fmt.Println("Good bye")
}
