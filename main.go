package main

import "C"

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"runtime"
	"sync"

	"ioriotng/internal/tracepoints"

	bpf "github.com/aquasecurity/libbpfgo"
)

type BpfMapper interface {
	String() string
}

type openEvent struct {
	FD       int32
	OpID     int32
	TID      uint32
	Filename [256]byte
	Comm     [16]byte
}

func (e openEvent) String() string {
	filename := e.Filename[:]
	comm := e.Comm[:]
	return fmt.Sprintf("opId:%d tid:%v fd:%v filename:%s, comm:%s",
		e.OpID, e.TID, e.FD, string(filename), string(comm))
}

type fdEvent struct {
	FD   int32
	OpID int32
	TID  uint32
}

func (e fdEvent) String() string {
	return fmt.Sprintf("opId:%d tid:%v fd:%v", e.OpID, e.TID, e.FD)
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

	// Todo, could build a eventListener struct, which is generic.
	if err = resizeMap(bpfModule, "open_event_map", 8192*10); err != nil {
		log.Fatal(err)
	}

	if err = resizeMap(bpfModule, "fd_event_map", 8192*10); err != nil {
		log.Fatal(err)
	}

	err = bpfModule.BPFLoadObject()
	if err != nil {
		log.Fatal(err)
	}

	if err := tracepoints.AttachSyscalls(bpfModule); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for ev := range listenToEvents[fdEvent](ctx, bpfModule, "fd_event_map") {
			log.Println(ev)
		}
	}()
	go func() {
		defer wg.Done()
		for ev := range listenToEvents[openEvent](ctx, bpfModule, "open_event_map") {
			log.Println(ev)
		}
	}()

	go func() {
		defer wg.Done()
	}()

	wg.Wait()
	log.Println("Good bye")
}

func listenToEvents[T BpfMapper](ctx context.Context, bpfModule *bpf.Module, mapName string) <-chan T {
	rawEventsCh := make(chan []byte)
	rawLostCh := make(chan uint64) // TODO: Of any use this channel?
	eventsCh := make(chan T)

	pb, err := bpfModule.InitPerfBuf(mapName, rawEventsCh, rawLostCh, 4096)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		defer func() {
			pb.Stop()
			pb.Close()
			close(eventsCh)
		}()
		pb.Poll(300)
		for {
			select {
			case <-ctx.Done():
				return
			case lost := <-rawLostCh:
				log.Println("Lost", lost, mapName, "events. Consider increasing ring buffer!")
			case rawEv := <-rawEventsCh:
				var ev T
				if err := binary.Read(bytes.NewReader(rawEv), binary.LittleEndian, &ev); err != nil {
					log.Fatal(err)
				}
				eventsCh <- ev
			}
		}
	}()

	return eventsCh
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
