package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
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
		log.Fatal(err)
	}
	defer bpfModule.Close()

	if err = resizeMap(bpfModule, "events", 8192); err != nil {
		log.Fatal(err)
	}

	err = bpfModule.BPFLoadObject()
	if err != nil {
		log.Fatal(err)
	}

	if err := tracepoints.AttachSyscalls(bpfModule); err != nil {
		log.Fatal(err)
	}

	testerMap, err := bpfModule.GetMap("tester")
	if err != nil {
		log.Fatal(err)
	}

	if testerMap.Name() != "tester" {
		log.Fatal("wrong map")
	}

	if testerMap.Type() != bpf.MapTypeHash {
		log.Fatal("wrong map type")
	}

	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	pb, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1)
	if err != nil {
		log.Fatal(err)
	}

	pb.Poll(300)

	ev := <-eventsChannel
	var e openatEvent
	if err := binary.Read(bytes.NewReader(ev), binary.LittleEndian, &e); err != nil {
		log.Fatal(err)

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
