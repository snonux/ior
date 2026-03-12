package internal

import (
	_ "embed"
	"os"

	bpf "github.com/aquasecurity/libbpfgo"
)

const (
	bpfObjectOverrideEnv  = "IOR_BPF_OBJECT"
	embeddedBPFObjectName = "ior.bpf.o"
)

//go:embed c/ior.bpf.o
var embeddedBPFObject []byte

var (
	newBPFModuleFromFile   = bpf.NewModuleFromFile
	newBPFModuleFromBuffer = bpf.NewModuleFromBuffer
)

func loadBPFModule() (*bpf.Module, string, error) {
	if path := os.Getenv(bpfObjectOverrideEnv); path != "" {
		module, err := newBPFModuleFromFile(path)
		return module, "load module from override file", err
	}

	module, err := newBPFModuleFromBuffer(embeddedBPFObject, embeddedBPFObjectName)
	return module, "load embedded module", err
}
