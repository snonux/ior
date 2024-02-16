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
		panic(err)
	}
	defer bpfModule.Close()

	if err := flags.ResizeBPFMaps(bpfModule); err != nil {
		panic(err)
	}

	err = bpfModule.BPFLoadObject()
	if err != nil {
		panic(err)
	}

	if err := flags.SetBPF(bpfModule); err != nil {
		panic(err)
	}

	if err := tracepoints.AttachSyscalls(bpfModule); err != nil {
		panic(err)
	}

	ch := make(chan []byte, 1024)
	rb, err := bpfModule.InitRingBuf("event_map", ch)
	if err != nil {
		panic(err)
	}
	rb.Poll(300)

	enterOpen := make(map[uint32]*types.OpenatEnterEvent)
	enterFd := make(map[uint32]*types.FdEvent)
	// To do this, extract the PID from the TID (pid_tid >> 32)
	// openFiles := make(map[

	for raw := range ch {
		switch types.OpId(raw[0]) {
		case types.OPENAT_ENTER_OP_ID:
			ev := types.OpenEnterEventPool.Get().(*types.OpenatEnterEvent)
			if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, ev); err != nil {
				panic(err)
			}
			enterOpen[ev.Tid] = ev
		case types.OPENAT_EXIT_OP_ID:
			ev := types.FdEventPool.Get().(*types.FdEvent)
			if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, ev); err != nil {
				panic(err)
			}
			enterEv, ok := enterOpen[ev.Tid]
			if !ok {
				fmt.Println("Dropping", ev)
				types.FdEventPool.Put(ev)
				continue
			}
			fmt.Println(enterEv, ev)
			delete(enterOpen, ev.Tid)
			types.FdEventPool.Put(ev)
			types.OpenEnterEventPool.Put(enterEv)
		case types.CLOSE_ENTER_OP_ID:
			ev := types.FdEventPool.Get().(*types.FdEvent)
			if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, ev); err != nil {
				panic(err)
			}
			enterFd[ev.Tid] = ev
		case types.CLOSE_EXIT_OP_ID:
			ev := types.NullEventPool.Get().(*types.NullEvent)
			if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, ev); err != nil {
				panic(err)
			}
			enterEv, ok := enterFd[ev.Tid]
			if !ok {
				fmt.Println("Dropping", ev)
				types.NullEventPool.Put(ev)
				continue
			}
			fmt.Println(enterEv, ev)
			delete(enterFd, ev.Tid)
			types.NullEventPool.Put(ev)
			types.FdEventPool.Put(enterEv)
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
