package tracepoints

import (
	"fmt"
	"ioriotng/internal/generated"

	bpf "github.com/aquasecurity/libbpfgo"
)

func AttachSyscalls(bpfModule *bpf.Module) error {
	for _, name := range generated.TracepointList {
		// Attach to tracepoint
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
