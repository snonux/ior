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
	// resizeBPFMap already includes the map name in any error it returns,
	// so no additional wrapping is needed here.
	return resizeBPFMap(bpfModule, "event_map", uint32(cfg.EventMapSize))
}

func resizeBPFMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap(name)
	if err != nil {
		// Wrap with map name so callers know which map lookup failed.
		return fmt.Errorf("resize map %s: get map: %w", name, err)
	}
	if err = m.SetMaxEntries(size); err != nil {
		// Wrap with map name and target size so callers know which map failed
		// and what size was requested.
		return fmt.Errorf("resize map %s to %d: %w", name, size, err)
	}
	if actual := m.MaxEntries(); actual != size {
		return fmt.Errorf("resize map %s to %d failed: actual size is %d", name, size, actual)
	}
	return nil
}
