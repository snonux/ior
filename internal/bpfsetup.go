package internal

import (
	"fmt"
	"os"

	"ior/internal/flags"

	bpf "github.com/aquasecurity/libbpfgo"
)

func setBPFGlobals(cfg flags.Config, bpfModule *bpf.Module) error {
	// Ignore `ior` process itself from the filter.
	if err := bpfModule.InitGlobalVariable("IOR_PID_FILTER", uint32(os.Getpid())); err != nil {
		return fmt.Errorf("unable set IOR_PID_FILTER: %w", err)
	}
	if err := bpfModule.InitGlobalVariable("PID_FILTER", uint32(cfg.PidFilter)); err != nil {
		return fmt.Errorf("unable to set up PID_FILTER global variable: %w", err)
	}
	if err := bpfModule.InitGlobalVariable("TID_FILTER", uint32(cfg.TidFilter)); err != nil {
		return fmt.Errorf("unable to set up TID_FILTER global variable: %w", err)
	}
	return nil
}

func resizeBPFMaps(cfg flags.Config, bpfModule *bpf.Module) error {
	if err := resizeBPFMap(bpfModule, "event_map", uint32(cfg.EventMapSize)); err != nil {
		return fmt.Errorf("event_map: %w", err)
	}
	return nil
}

func resizeBPFMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap(name)
	if err != nil {
		return err
	}
	if err = m.SetMaxEntries(size); err != nil {
		return err
	}
	if actual := m.MaxEntries(); actual != size {
		return fmt.Errorf("map resize to %d failed, expected %v, actual %v", size, size, actual)
	}
	return nil
}
