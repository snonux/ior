package internal

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"

	"ioriotng/internal/debugfs"
	"ioriotng/internal/flags"
	"ioriotng/internal/syncpool"
	"ioriotng/internal/tracepoints"
	"ioriotng/internal/types"

	bpf "github.com/aquasecurity/libbpfgo"
)

type BpfMapper interface {
	String() string
}

func Run(flags flags.Flags) {
	// To consider for implementation!
	fmt.Println(debugfs.TracepointsWithFd())

	bpfModule, err := bpf.NewModuleFromFile("ioriotng.bpf.o")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()

	if err := flags.ResizeBPFMaps(bpfModule); err != nil {
		panic(err)
	}

	if err := flags.SetBPF(bpfModule); err != nil {
		panic(err)
	}

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}

	if err := tracepoints.AttachSyscalls(bpfModule); err != nil {
		panic(err)
	}

	ch := make(chan []byte)
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
			ev := readRaw(raw, syncpool.OpenEnterEvent.Get().(*types.OpenatEnterEvent))
			enterOpen[ev.PidTGid] = ev

		case types.OPENAT_EXIT_OP_ID:
			ev := readRaw(raw, syncpool.FdEvent.Get().(*types.FdEvent))
			enterEv, ok := enterOpen[ev.PidTGid]
			if !ok {
				fmt.Println("Dropping", ev)
				syncpool.FdEvent.Put(ev)
				continue
			}
			duration := float64(ev.Time-enterEv.Time) / float64(1_000_000)
			fmt.Println(duration, "ms", enterEv, ev)

			delete(enterOpen, ev.PidTGid)
			syncpool.FdEvent.Put(ev)
			syncpool.OpenEnterEvent.Put(enterEv)

		case types.CLOSE_ENTER_OP_ID:
			ev := readRaw(raw, syncpool.FdEvent.Get().(*types.FdEvent))
			enterFd[ev.PidTGid] = ev

		case types.CLOSE_EXIT_OP_ID:
			ev := readRaw(raw, syncpool.NullEvent.Get().(*types.NullEvent))
			enterEv, ok := enterFd[ev.PidTGid]
			if !ok {
				fmt.Println("Dropping", ev)
				syncpool.NullEvent.Put(ev)
				continue
			}
			duration := float64(ev.Time-enterEv.Time) / float64(1_000_000)
			fmt.Println(duration, "ms", enterEv, ev)

			delete(enterFd, ev.PidTGid)
			syncpool.NullEvent.Put(ev)
			syncpool.FdEvent.Put(enterEv)

		default:
			panic(fmt.Sprintf("UNKNOWN Ringbuf data received len:%d raw:%v", len(raw), raw))
		}
	}

	fmt.Println("Good bye")
}

func readRaw[T any](raw []byte, ev *T) *T {
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, ev); err != nil {
		panic(err)
	}
	return ev
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
