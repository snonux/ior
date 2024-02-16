package internal

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"runtime"

	"ioriotng/internal/debugfs"
	"ioriotng/internal/flags"
	"ioriotng/internal/tracepoints"
	"ioriotng/internal/types"

	bpf "github.com/aquasecurity/libbpfgo"
)

type BpfMapper interface {
	String() string
}

func Run(flags flags.Flags) {
	// To consider for implementation!
	log.Println(debugfs.TracepointsWithFd())

	bpfModule, err := bpf.NewModuleFromFile("ioriotng.bpf.o")
	if err != nil {
		log.Fatal(err)
	}
	defer bpfModule.Close()

	if err := flags.ResizeBPFMaps(bpfModule); err != nil {
		log.Fatal(err)
	}

	err = bpfModule.BPFLoadObject()
	if err != nil {
		log.Fatal(err)
	}

	if err := flags.SetBPF(bpfModule); err != nil {
		log.Fatal(err)
	}

	if err := tracepoints.AttachSyscalls(bpfModule); err != nil {
		log.Fatal(err)
	}

	ch := make(chan []byte, 1024)
	rb, err := bpfModule.InitRingBuf("event_map", ch)
	if err != nil {
		log.Fatal(err)
	}
	rb.Poll(300)

	enter := make(map[uint32]*types.OpenatEnterEvent)

	for raw := range ch {
		switch types.OpId(raw[0]) {
		case types.OPENAT_ENTER_OP_ID:
			ev := types.OpenEnterEventPool.Get().(*types.OpenatEnterEvent)
			if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, ev); err != nil {
				log.Fatal(err)
			}
			enter[ev.Tid] = ev
		case types.OPENAT_EXIT_OP_ID:
			ev := types.FdEventPool.Get().(*types.FdEvent)
			if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, ev); err != nil {
				log.Fatal(err)
			}
			enterEv, ok := enter[ev.Tid]
			if !ok {
				fmt.Println("Dropping", ev)
				types.FdEventPool.Put(ev)
				continue
			}
			fmt.Println(enterEv, ev)
			delete(enter, ev.Tid)
			types.FdEventPool.Put(ev)
			types.OpenEnterEventPool.Put(enterEv)
		case types.CLOSE_ENTER_OP_ID:
			ev := types.FdEventPool.Get().(*types.FdEvent)
			if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, ev); err != nil {
				log.Fatal(err)
			}
			types.FdEventPool.Put(ev)
		case types.CLOSE_EXIT_OP_ID:
			ev := types.NullEventPool.Get().(*types.NullEvent)
			if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, ev); err != nil {
				log.Fatal(err)
			}
			types.NullEventPool.Put(ev)
		default:
			panic(fmt.Sprintf("UNKNOWN Ringbuf data received len:%d raw:%v", len(raw), raw))
		}
	}

	log.Println("Good bye")
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
