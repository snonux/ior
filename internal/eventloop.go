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
	// Channel of events (enter+exit tracepoint results of a syscall).
	evCh := make(chan enterExitEvent)
	// Temporally store tracepoints of syscall entering tracepoits (e.g. SYS_ENTER_OPEN).
	enterEvs := make(map[uint32]enterExitEvent)
	// Track all open file by file descriptor.
	files := make(map[int32]file)
	// Program or thread name of the current Tid.
	comms := make(map[uint32]string)

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

		// Expect ID one lower, otherwise, enter and exit tracepoints
		// don't match up. E.g.:
		// enterEv:SYS_ENTER_OPEN => exitEv:SYS_EXIT_OPEN
		if ev.enterEv.GetSyscallId()-1 != ev.exitEv.GetSyscallId() {
			fmt.Println(fmt.Sprintf("Loss of event (not matching) %v", ev))
			ev.enterEv.Recycle()
			exitEv.Recycle()
			return
		}

		// Handle the opening of a file.
		if ev.is(SYS_ENTER_OPENAT) || ev.is(SYS_ENTER_OPEN) {
			openEnterEv := ev.enterEv.(*OpenEnterEvent)

			fd := ev.exitEv.(*FdEvent).Fd
			file := file{fd, string(openEnterEv.Filename[:])}
			if fd >= 0 {
				files[fd] = file
			}
			ev.file = file

			comm := string(openEnterEv.Comm[:])
			comms[openEnterEv.Tid] = comm
			ev.comm = comm

			evCh <- ev
			return
		}

		// Generic handling of any syscall expecting a file descriptor (fd)
		if fdEvent, ok := ev.enterEv.(*FdEvent); ok {
			if file_, ok := files[fdEvent.Fd]; ok {
				ev.file = file_
			} else {
				ev.file = file{fdEvent.Fd, "?"}
			}
			if ev.is(SYS_ENTER_CLOSE) {
				delete(files, fdEvent.Fd)
			}
		}

		ev.comm, _ = comms[ev.enterEv.GetTid()]
		evCh <- ev
	}

	// Deserialise raw byte stream from BPF ringbuffer.
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
