package internal

import "C"

import (
	"fmt"
	"os"

	"ioriotng/internal/flags"
	. "ioriotng/internal/generated/types"
)

type eventLoop struct {
	filter    *eventFilter
	enterEvs  map[uint32]*eventPair // Temp. store of sys_enter tracepoints per Tid.
	files     map[int32]file        // Track all open files by file descriptor.
	comms     map[uint32]string     // Program or thread name of the current Tid.
	prevPairs map[uint32]*eventPair // Previous event (to calculate time differences between two events)
}

func newEventLoop(flags flags.Flags) *eventLoop {
	return &eventLoop{
		filter:    newEventFilter(flags),
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

// Deserialise raw byte stream from BPF ringbuffer.
func (e *eventLoop) events(rawCh <-chan []byte) <-chan *eventPair {
	ch := make(chan *eventPair)

	go func() {
		defer close(ch)
		for raw := range rawCh {
			switch EventType(raw[0]) {
			case ENTER_OPEN_EVENT:
				if ev, ok := e.filter.openEvent(NewOpenEvent(raw)); ok {
					e.syscallEnter(ev)
				}
			case EXIT_OPEN_EVENT:
				e.syscallExit(NewFdEvent(raw), ch)
			case ENTER_FD_EVENT:
				e.syscallEnter(NewFdEvent(raw))
			case EXIT_FD_EVENT:
				e.syscallExit(NewFdEvent(raw), ch)
			case EXIT_NULL_EVENT:
				e.syscallExit(NewNullEvent(raw), ch)
			case EXIT_RET_EVENT:
				e.syscallExit(NewRetEvent(raw), ch)
			case ENTER_NAME_EVENT:
				e.syscallEnter(NewNameEvent(raw))
			case ENTER_PATH_EVENT:
				e.syscallEnter(NewPathEvent(raw))
			default:
				panic(fmt.Sprintf("unhandled event type %v: %v", EventType(raw[0]), raw))
			}
		}
	}()

	return ch
}

func (e *eventLoop) syscallEnter(enterEv event) {
	e.enterEvs[enterEv.GetTid()] = newEventPair(enterEv)
}

func (e *eventLoop) syscallExit(exitEv event, ch chan<- *eventPair) {
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
		file := newFdFile(fd, string(openEv.Filename[:]))
		if fd >= 0 {
			e.files[fd] = file
		}
		ev.file = file

		comm := string(openEv.Comm[:])
		// TODO: Filter out all other events not matching comm filter as well when comm filter enabled
		e.comms[openEv.Tid] = comm

	case *NameEvent:
		nameEvent := ev.enterEv.(*NameEvent)
		ev.file = oldnameNewnameFile{
			oldname: string(nameEvent.Oldname[:]),
			newname: string(nameEvent.Newname[:]),
		}
		ev.comm = e.comm(ev.enterEv.GetTid())

	case *PathEvent:
		nameEvent := ev.enterEv.(*PathEvent)
		ev.file = pathnameFile{string(nameEvent.Pathname[:])}
		ev.comm = e.comm(ev.enterEv.GetTid())

	case *FdEvent:
		fd := ev.enterEv.(*FdEvent).Fd
		if file_, ok := e.files[fd]; ok {
			ev.file = file_
			if ev.is(SYS_ENTER_CLOSE) {
				delete(e.files, fd)
			}
		} else {
			ev.file = newFdFileWithPid(fd, ev.enterEv.(*FdEvent).Pid)
		}
		ev.comm = e.comm(ev.enterEv.GetTid())

	case *NullEvent:
		ev.comm = e.comm(ev.enterEv.GetTid())

	default:
		panic(fmt.Sprintf("unknown type: %v", v))
	}

	ev.prevPair, _ = e.prevPairs[ev.enterEv.GetTid()]
	ev.calculateDurations()
	e.prevPairs[ev.enterEv.GetTid()] = ev
	ch <- ev
}

func (e *eventLoop) comm(pid uint32) string {
	if comm, ok := e.comms[pid]; ok {
		return comm
	}
	if linkName, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		e.comms[pid] = linkName
		return linkName
	}
	return ""
}
