package internal

import "C"

import (
	"fmt"

	. "ioriotng/internal/generated/types"

	bpf "github.com/aquasecurity/libbpfgo"
)

func eventLoop(bpfModule *bpf.Module, ch <-chan []byte) {
	enterOpen := make(map[uint32]*OpenEnterEvent)
	enterFd := make(map[uint32]*FdEvent)
	// To do this, extract the PID from the TID (pid_tid >> 32)
	// openFiles := make(map[

	for raw := range ch {
		switch OpId(raw[0]) {
		case OPENAT_ENTER_OP_ID:
			fallthrough
		case OPEN_ENTER_OP_ID:
			ev := NewOpenEnterEvent(raw)
			enterOpen[ev.PidTgid] = ev

		case OPENAT_EXIT_OP_ID:
			fallthrough
		case OPEN_EXIT_OP_ID:
			ev := NewFdEvent(raw)
			enterEv, ok := enterOpen[ev.PidTgid]
			if !ok {
				fmt.Println("Dropping", ev)
				RecycleFdEvent(ev)
				continue
			}
			duration := float64(ev.Time-enterEv.Time) / float64(1_000_000)
			fmt.Println(duration, "ms", enterEv, ev)

			delete(enterOpen, ev.PidTgid)
			RecycleFdEvent(ev)
			RecycleOpenEnterEvent(enterEv)

		case CLOSE_ENTER_OP_ID:
			fallthrough
		case WRITE_ENTER_OP_ID:
			fallthrough
		case WRITEV_ENTER_OP_ID:
			ev := NewFdEvent(raw)
			enterFd[ev.PidTgid] = ev

		case CLOSE_EXIT_OP_ID:
			fallthrough
		case WRITE_EXIT_OP_ID:
			fallthrough
		case WRITEV_EXIT_OP_ID:
			ev := NewNullEvent(raw)
			enterEv, ok := enterFd[ev.PidTgid]
			if !ok {
				fmt.Println("Dropping", ev)
				RecycleNullEvent(ev)
				continue
			}
			duration := float64(ev.Time-enterEv.Time) / float64(1_000_000)
			fmt.Println(duration, "ms", enterEv, ev)

			delete(enterFd, ev.PidTgid)
			RecycleNullEvent(ev)
			RecycleFdEvent(enterEv)

		default:
			panic(fmt.Sprintf("UNKNOWN Ringbuf data received len:%d raw:%v", len(raw), raw))
		}
	}

	fmt.Println("Good bye")
}
