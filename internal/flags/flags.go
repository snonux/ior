package flags

import (
	"flag"
	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
)

type Flags struct {
	PidFilter    int
	EventMapSize int
}

func New() (flags Flags) {
	flag.IntVar(&flags.PidFilter, "pid", 0, "Filter for processes ID")
	flag.IntVar(&flags.EventMapSize, "mapSize", 4096*16, "BPF FD event ring buffer map size")
	flag.Parse()

	return flags
}

func (flags Flags) SetBPF(bpfModule *bpf.Module) error {
	if err := bpfModule.InitGlobalVariable("PID_FILTER", uint32(flags.PidFilter)); err != nil {
		return fmt.Errorf("unable to set up PID_FILTER global variable: %w", err)
	}
	return nil
}

func (flags Flags) ResizeBPFMaps(bpfModule *bpf.Module) error {
	if err := resizeBPFMap(bpfModule, "event_map", uint32(flags.EventMapSize)); err != nil {
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
