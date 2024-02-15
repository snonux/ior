package flags

import (
	"flag"
	"fmt"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

type Flags struct {
	UidFilter        int
	FdEventMapSize   int
	OpenEventMapSize int
}

func New() (flags Flags) {
	flag.IntVar(&flags.UidFilter, "uid", 0, "Filter for processes with UID")
	flag.IntVar(&flags.FdEventMapSize, "fdMapSize", 4096, "BPF FD event map size")
	flag.IntVar(&flags.OpenEventMapSize, "openMapSize", 1024, "BPF open event map size")
	flag.Parse()
	return flags
}

func (flags Flags) SetBPF(bpfModule *bpf.Module) error {
	flagsMap, err := bpfModule.GetMap("flags_map")
	if err != nil {
		return err
	}

	flagsValues := struct {
		UidFilter int32
	}{
		UidFilter: int32(flags.UidFilter),
	}

	key := uint32(1)
	return flagsMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&flagsValues))
}

func (flags Flags) ResizeBPFMaps(bpfModule *bpf.Module) error {
	if err := resizeBPFMap(bpfModule, "open_event_map", uint32(flags.OpenEventMapSize)); err != nil {
		return err
	}
	if err := resizeBPFMap(bpfModule, "fd_event_map", uint32(flags.FdEventMapSize)); err != nil {
		return err
	}
	return nil
}

func resizeBPFMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap("open_event_map")
	if err != nil {
		return err
	}

	if err = m.SetMaxEntries(size); err != nil {
		return err
	}

	if actual := m.MaxEntries(); actual != size {
		return fmt.Errorf("map resize failed, expected %v, actual %v", size, actual)
	}

	return nil
}
