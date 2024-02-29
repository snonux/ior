package internal

import "C"

import (
	"fmt"

	. "ioriotng/internal/generated/types"

	bpf "github.com/aquasecurity/libbpfgo"
)

func eventLoop(bpfModule *bpf.Module, rawCh <-chan []byte) {
	for ev := range events(rawCh) {
		fmt.Println(ev)
		ev.recycle()
	}
	fmt.Println("Good bye")
}

func events(rawCh <-chan []byte) <-chan enterExitEvent {
	evCh := make(chan enterExitEvent)
	enterEvs := make(map[uint32]enterExitEvent)

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
		defer close(evCh)
		for raw := range rawCh {
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
				panic(fmt.Sprintf("Unhandled event type %s", EventType(raw[0])))
			}
		}
	}()

	return evCh
}
