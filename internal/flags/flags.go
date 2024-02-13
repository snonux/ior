package flags

import (
	"flag"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

type Flags struct {
	UidFilter int
}

func New() (flags Flags) {
	flag.IntVar(&flags.UidFilter, "uid", 0, "Filter for processes with UID")
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
