package internal

import "C"

import (
	"fmt"

	. "ioriotng/internal/generated/types"

	bpf "github.com/aquasecurity/libbpfgo"
)

type openFile struct {
	fd   int32
	path string
}

func (o openFile) String() string {
	return fmt.Sprintf("(%d) %s", o.fd, o.path)
}

type Event interface {
	String() string
	TID() uint32
	Timestamp() uint32
	Recycle()
}

type Syscall struct {
	enterEv, exitEv Event
}

func (s Syscall) String() string {
	return ""
}

func human(enterEv, exitEv Event) string {
	return fmt.Sprintf("%08d µs %s %s",
		exitEv.Timestamp()-enterEv.Timestamp(), enterEv, exitEv)
}

func eventLoop(bpfModule *bpf.Module, ch <-chan []byte) {
	enterEvs := make(map[uint32]Event)

	for raw := range ch {
		var exitEv Event

		switch EventType(raw[0]) {
		case ENTER_OPEN_EVENT:
			ev := NewOpenEnterEvent(raw)
			enterEvs[ev.Tid] = ev
		case EXIT_OPEN_EVENT:
			ev := NewFdEvent(raw)
			if enterEv, ok := enterEvs[ev.Tid]; ok {
				fmt.Println(human(enterEv, ev))
				delete(enterEvs, ev.Tid)
				enterEv.Recycle()
			}
			ev.Recycle()

		case ENTER_FD_EVENT:
			ev := NewFdEvent(raw)
			enterEvs[ev.Tid] = ev
		case EXIT_FD_EVENT:
			exitEv = NewFdEvent(raw)
		case EXIT_NULL_EVENT:
			exitEv = NewNullEvent(raw)
		case EXIT_RET_EVENT:
			exitEv = NewRetEvent(raw)
		default:
			panic(fmt.Sprintf("Unknown event type %s", EventType(raw[0])))
		}

		if exitEv == nil {
			continue
		}

		if enterEv, ok := enterEvs[exitEv.TID()]; ok {
			fmt.Println(human(enterEv, exitEv))
			delete(enterEvs, exitEv.TID())
			enterEv.Recycle()
		}

		exitEv.Recycle()
	}

	fmt.Println("Good bye")
}
