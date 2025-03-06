package internal

import "C"

import (
	"fmt"

	. "ioriotng/internal/generated/types"
)

type eventLoop struct {
	evCh      chan *eventPair       // Channel of events (enter+exit tracepoint results of a syscall).
	enterEvs  map[uint32]*eventPair // Temp. store of sys_enter tracepoints per Tid.
	files     map[int32]file        // Track all open files by file descriptor.
	comms     map[uint32]string     // Program or thread name of the current Tid.
	prevPairs map[uint32]*eventPair // Previous event (to calculate time differences between two events)
}

func newEventLoop() *eventLoop {
	return &eventLoop{
		evCh:      make(chan *eventPair),
		enterEvs:  make(map[uint32]*eventPair),
		files:     make(map[int32]file),
		comms:     make(map[uint32]string),
		prevPairs: make(map[uint32]*eventPair),
	}
}

func (e *eventLoop) run(rawCh <-chan []byte) {
	fmt.Println(eventStreamHeader)
	for ev := range e.events(rawCh) {
		fmt.Println(ev.String())
		if ev.prevPair != nil {
			// Only recycle the previous event, as the current event is the previous event of the next event!
			ev.prevPair.recycle()
			continue
		}
	}
	fmt.Println("Good bye")
}

func (e *eventLoop) events(rawCh <-chan []byte) <-chan *eventPair {
	// Deserialise raw byte stream from BPF ringbuffer.
	go func() {
		defer close(e.evCh)
		for raw := range rawCh {
			switch EventType(raw[0]) {
			case ENTER_OPEN_EVENT:
				e.syscallEnter(NewOpenEvent(raw))
			case EXIT_OPEN_EVENT:
				e.syscallExit(NewFdEvent(raw))
			case ENTER_FD_EVENT:
				e.syscallEnter(NewFdEvent(raw))
			case EXIT_FD_EVENT:
				e.syscallExit(NewFdEvent(raw))
			case EXIT_NULL_EVENT:
				e.syscallExit(NewNullEvent(raw))
			case EXIT_RET_EVENT:
				e.syscallExit(NewRetEvent(raw))
			case ENTER_NAME_EVENT:
				e.syscallEnter(NewNameEvent(raw))
			case ENTER_PATH_EVENT:
				e.syscallEnter(NewPathEvent(raw))
			default:
				panic(fmt.Sprintf("unhandled event type %v: %v", EventType(raw[0]), raw))
			}
		}
	}()

	return e.evCh
}

func (e *eventLoop) syscallEnter(enterEv event) {
	e.enterEvs[enterEv.GetTid()] = newEventPair(enterEv)
}

func (e *eventLoop) syscallExit(exitEv event) {
	ev, ok := e.enterEvs[exitEv.GetTid()]
	if !ok {
		exitEv.Recycle()
		return
	}
	delete(e.enterEvs, exitEv.GetTid())
	ev.exitEv = exitEv

	// Expect ID one lower, otherwise, enter and exit tracepoints
	// don't match up. E.g.:
	// enterEv:SYS_ENTER_OPEN => exitEv:SYS_EXIT_OPEN
	if ev.enterEv.GetTraceId()-1 != ev.exitEv.GetTraceId() {
		ev.tracepointMismatch = true
	}

	switch v := ev.enterEv.(type) {
	case *OpenEvent:
		openEv := ev.enterEv.(*OpenEvent)

		fd := int32(ev.exitEv.(*RetEvent).Ret)
		file := fdFile{fd, string(openEv.Filename[:])}
		if fd >= 0 {
			e.files[fd] = file
		}
		ev.file = file

		comm := string(openEv.Comm[:])
		e.comms[openEv.Tid] = comm

	case *NameEvent:
		nameEvent := ev.enterEv.(*NameEvent)
		ev.file = oldnameNewnameFile{
			oldname: string(nameEvent.Oldname[:]),
			newname: string(nameEvent.Newname[:]),
		}
		ev.comm, _ = e.comms[ev.enterEv.GetTid()]

	case *PathEvent:
		nameEvent := ev.enterEv.(*PathEvent)
		ev.file = pathnameFile{string(nameEvent.Pathname[:])}
		ev.comm, _ = e.comms[ev.enterEv.GetTid()]

	case *FdEvent:
		fd := ev.enterEv.(*FdEvent).Fd
		if file_, ok := e.files[fd]; ok {
			ev.file = file_
			if ev.is(SYS_ENTER_CLOSE) {
				delete(e.files, fd)
			}
		} else {
			ev.file = fdFile{fd, "?"}
		}
		ev.comm, _ = e.comms[ev.enterEv.GetTid()]

	case *NullEvent:
		ev.comm, _ = e.comms[ev.enterEv.GetTid()]

	default:
		panic(fmt.Sprintf("unknown type: %v", v))
	}

	ev.prevPair, _ = e.prevPairs[ev.enterEv.GetTid()]
	ev.calculateDurations()
	e.prevPairs[ev.enterEv.GetTid()] = ev
	e.evCh <- ev
}
