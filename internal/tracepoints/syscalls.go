package tracepoints

import (
	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
)

func AttachSyscalls(bpfModule *bpf.Module, names ...string) error {
	for _, name := range names {
		// Attach to tracepoint
		prog, err := bpfModule.GetProgram(fmt.Sprintf("handle_%s", name))
		if err != nil {
			return fmt.Errorf("Failed to get BPF program handle_%s: %v", name, err)
		}
		if _, err = prog.AttachTracepoint("syscalls", fmt.Sprintf("sys_%s", name)); err != nil {
			return fmt.Errorf("Failed to attach to sys_%s tracepoint: %v", name, err)
		}
	}
	return nil
}
