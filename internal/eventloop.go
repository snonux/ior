package internal

import "C"

import (
	"fmt"

	. "ioriotng/internal/generated/types"

	bpf "github.com/aquasecurity/libbpfgo"
)

func eventLoop(bpfModule *bpf.Module, rawCh <-chan []byte) {
	for ev := range events(rawCh) {
		fmt.Println(ev.String())
		if ev.prevPair != nil {
			// Only recycle the previous event, as the current event is the previous
			// event of the next event!
			ev.prevPair.recycle()
			continue
		}
	}
	fmt.Println("Good bye")
}

func events(rawCh <-chan []byte) <-chan *eventPair {
	// Channel of events (enter+exit tracepoint results of a syscall).
	evCh := make(chan *eventPair)
	// Temp. store of sys_enter tracepoints per Tid.
	enterEvs := make(map[uint32]*eventPair)
	// Track all open files by file descriptor.
	files := make(map[int32]file)
	// Program or thread name of the current Tid.
	comms := make(map[uint32]string)
	// Previous event (to calculate time differences between two events)
	prevPairs := make(map[uint32]*eventPair)

	enter := func(enterEv event) {
		enterEvs[enterEv.GetTid()] = newEventPair(enterEv)
	}

	exit := func(exitEv event) {
		ev, ok := enterEvs[exitEv.GetTid()]
		if !ok {
			exitEv.Recycle()
			return
		}
		delete(enterEvs, exitEv.GetTid())
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
				files[fd] = file
			}
			ev.file = file

			comm := string(openEv.Comm[:])
			comms[openEv.Tid] = comm

		case *NameEvent:
			nameEvent := ev.enterEv.(*NameEvent)
			ev.file = oldnameNewnameFile{
				oldname: string(nameEvent.Oldname[:]),
				newname: string(nameEvent.Newname[:]),
			}
			ev.comm, _ = comms[ev.enterEv.GetTid()]

		case *PathEvent:
			nameEvent := ev.enterEv.(*PathEvent)
			ev.file = pathnameFile{string(nameEvent.Pathname[:])}
			ev.comm, _ = comms[ev.enterEv.GetTid()]

		case *FdEvent:
			fd := ev.enterEv.(*FdEvent).Fd
			if file_, ok := files[fd]; ok {
				ev.file = file_
				if ev.is(SYS_ENTER_CLOSE) {
					delete(files, fd)
				}
			} else {
				ev.file = fdFile{fd, "?"}
			}
			ev.comm, _ = comms[ev.enterEv.GetTid()]

		case *NullEvent:
			ev.comm, _ = comms[ev.enterEv.GetTid()]

		default:
			panic(fmt.Sprintf("unknown type: %v", v))
		}

		ev.prevPair, _ = prevPairs[ev.enterEv.GetTid()]
		ev.calculateDurations()
		prevPairs[ev.enterEv.GetTid()] = ev
		fmt.Println(ev.TimeDebugString())
		evCh <- ev
	}

	// Deserialise raw byte stream from BPF ringbuffer.
	go func() {
		defer close(evCh)
		for raw := range rawCh {
			switch EventType(raw[0]) {
			case ENTER_OPEN_EVENT:
				enter(NewOpenEvent(raw))
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
			case ENTER_NAME_EVENT:
				enter(NewNameEvent(raw))
			case ENTER_PATH_EVENT:
				enter(NewPathEvent(raw))
			default:
				panic(fmt.Sprintf("unhandled event type %v: %v", EventType(raw[0]), raw))
			}
		}
	}()

	return evCh
}
