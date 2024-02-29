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

func eventLoop(bpfModule *bpf.Module, ch <-chan []byte) {
	enterEvs := make(map[uint32]enterExitEvent)
	evCh := make(chan enterExitEvent)

	enter := func(enterEv event) {
		enterEvs[enterEv.GetTid()] = enterExitEvent{
			enterEv: enterEv,
		}
	}

	exit := func(exitEv event) {
		ev, ok := enterEvs[exitEv.GetTid()]
		if !ok {
			exitEv.Recycle()
			return
		}
		delete(enterEvs, exitEv.GetTid())
		ev.exitEv = exitEv
		evCh <- ev
	}

	go func() {
		for ev := range evCh {
			fmt.Println(ev.dump())
		}
	}()

	for raw := range ch {
		switch EventType(raw[0]) {
		case ENTER_OPEN_EVENT:
			enter(NewOpenEnterEvent(raw))
		case EXIT_OPEN_EVENT:
			exit(NewFdEvent(raw))
		case ENTER_FD_EVENT:
			enter(NewFdEvent(raw))
		case EXIT_FD_EVENT:
			exit(NewFdEvent(raw))
		case EXIT_NULL_EVENT:
			exit(NewNullEvent(raw))
		case EXIT_RET_EVENT:
			exit(NewRetEvent(raw))
		default:
			panic(fmt.Sprintf("Unknown event type %s", EventType(raw[0])))
		}
	}

	fmt.Println("Good bye")
}
