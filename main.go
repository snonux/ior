package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"

	"ioriotng/internal/tracepoints"

	bpf "github.com/aquasecurity/libbpfgo"
)

type openatEvent struct {
	FD       int32
	TID      uint32
	Filename [256]byte
	Comm     [16]byte
}

func (e openatEvent) String() string {
	filename := e.Filename[:]
	comm := e.Comm[:]
	return fmt.Sprintf("tid:%v fd:%v filename:%s, comm:%s",
		e.TID, e.FD, string(filename), string(comm))
}

func resizeMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap("events")
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

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	if err = resizeMap(bpfModule, "events", 8192); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	err = bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load BPF object: %v\n", err)
		os.Exit(-1)
	}

	if err := tracepoints.AttachSyscalls(bpfModule); err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(-1)
	}

	testerMap, err := bpfModule.GetMap("tester")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	if testerMap.Name() != "tester" {
		fmt.Fprintln(os.Stderr, "wrong map")
		os.Exit(-1)
	}

	if testerMap.Type() != bpf.MapTypeHash {
		fmt.Fprintln(os.Stderr, "wrong map type")
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	pb, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	pb.Poll(300)

	ev := <-eventsChannel
	var e openatEvent
	if err := binary.Read(bytes.NewReader(ev), binary.LittleEndian, &e); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)

	}

	fmt.Println("Bytes ", ev)
	fmt.Println("Struct ", e)
	fmt.Println("Human ", e.String())

	pb.Stop()
	pb.Close()
}

func ksymArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	default:
		panic("unsupported architecture")
	}
}
