package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"runtime"
	"sync"

	"ioriotng/internal/tracepoints"

	bpf "github.com/aquasecurity/libbpfgo"
)

type openEvent struct {
	FD        int32
	SyscallID int32
	TID       uint32
	Filename  [256]byte
	Comm      [16]byte
}

func (e openEvent) String() string {
	filename := e.Filename[:]
	comm := e.Comm[:]
	return fmt.Sprintf("syscall:%d tid:%v fd:%v filename:%s, comm:%s",
		e.SyscallID, e.TID, e.FD, string(filename), string(comm))
}

type fdEvent struct {
	FD        int32
	SyscallID int32
	TID       uint32
}

func (e fdEvent) String() string {
	return fmt.Sprintf("syscall:%d tid:%v fd:%v", e.SyscallID, e.TID, e.FD)
}

func resizeMap(module *bpf.Module, name string, size uint32) error {
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

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		log.Fatal(err)
	}
	defer bpfModule.Close()

	if err = resizeMap(bpfModule, "open_event_map", 8192); err != nil {
		log.Fatal(err)
	}

	err = bpfModule.BPFLoadObject()
	if err != nil {
		log.Fatal(err)
	}

	if err := tracepoints.AttachSyscalls(bpfModule); err != nil {
		log.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if err := openEvents(bpfModule); err != nil {
			log.Fatal(err)
		}
	}()

	go func() {
		defer wg.Done()
	}()

	wg.Wait()
	log.Println("Good bye")
}

func openEvents(bpfModule *bpf.Module) error {
	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	pb, err := bpfModule.InitPerfBuf("open_event_map", eventsChannel, lostChannel, 1)
	if err != nil {
		return err
	}
	defer func() {
		pb.Stop()
		pb.Close()
	}()

	pb.Poll(300)
	for ev := range eventsChannel {
		var e openEvent
		if err := binary.Read(bytes.NewReader(ev), binary.LittleEndian, &e); err != nil {
			log.Fatal(err)

		}

		fmt.Println(e)
		pb.Poll(300)
	}

	return nil
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
