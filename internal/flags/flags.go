package flags

import (
	"flag"
	"fmt"
	"ioriotng/internal/types"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

type Flags struct {
	UidFilter    int
	EventMapSize int
}

func New() (flags Flags) {
	flag.IntVar(&flags.UidFilter, "uid", 0, "Filter for processes with UID")
	flag.IntVar(&flags.EventMapSize, "mapSize", 4096, "BPF FD event ring buffer map size")
	flag.Parse()

	return flags
}

func (flags Flags) SetBPF(bpfModule *bpf.Module) error {
	flagsMap, err := bpfModule.GetMap("flags_map")
	if err != nil {
		return err
	}

	var (
		key         = uint32(1)
		flagsValues = types.FlagValues{uint32(flags.UidFilter)}
	)
	return flagsMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&flagsValues))
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
