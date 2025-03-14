package internal

import "C"

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/flags"
	"ior/internal/flamegraph"
	. "ior/internal/generated/types"
)

// TODO: Move in its own package?
type eventLoop struct {
	flags      flags.Flags
	filter     *eventFilter
	enterEvs   map[uint32]*event.Pair // Temp. store of sys_enter tracepoints per Tid.
	files      map[int32]file.File    // Track all open files by file descriptor..
	comms      map[uint32]string      // Program or thread name of the current Tid.
	prevPairs  map[uint32]*event.Pair // Previous event (to calculate time differences between two events)
	flamegraph flamegraph.Flamegraph  // Storing all paths in a map structure for analysis

	// Statistics
	numTracepoints          uint
	numTracepointMismatches uint
	numSyscalls             uint
	numSyscallsAfterFilter  uint
	startTime               time.Time
}

func newEventLoop(flags flags.Flags) *eventLoop {
	return &eventLoop{
		flags:      flags,
		filter:     newEventFilter(flags),
		enterEvs:   make(map[uint32]*event.Pair),
		files:      make(map[int32]file.File),
		comms:      make(map[uint32]string),
		prevPairs:  make(map[uint32]*event.Pair),
		flamegraph: flamegraph.New(),
	}
}

// TODO: Could use the table from the gos project to display the stats here
func (e *eventLoop) stats() string {
	duration := time.Since(e.startTime)

	return "Statistics:\n" +
		fmt.Sprintf("\tduration:%v\n", duration) +
		fmt.Sprintf("\ttracepoints:%v (%.2f/s) with %d mismatches (%.2f%%)\n", e.numTracepoints, float64(e.numTracepoints)/duration.Seconds(), e.numTracepointMismatches, (float64(e.numTracepointMismatches)/float64(e.numTracepoints))*100) +
		fmt.Sprintf("\tsyscalls:%d (%.2f/s)\n",
			e.numSyscalls, float64(e.numSyscalls)/duration.Seconds()) +
		fmt.Sprintf("\tsyscalls after filter:%d (%.2f/s)\n",
			e.numSyscallsAfterFilter, float64(e.numSyscallsAfterFilter)/duration.Seconds())
}

func (e *eventLoop) run(ctx context.Context, rawCh <-chan []byte) {
	if e.flags.FlamegraphEnable {
		e.flamegraph.Start(ctx)
	}
	if e.flags.PprofEnable {
		fmt.Println("Profiling, press Ctrl+C to stop")
	}
	if !e.flags.FlamegraphEnable && !e.flags.PprofEnable {
		fmt.Println(event.EventStreamHeader)
	}

	e.startTime = time.Now()
	for ev := range e.events(ctx, rawCh) {
		switch {
		case e.flags.FlamegraphEnable:
			e.flamegraph.Add(ev)
		case e.flags.PprofEnable:
			ev.RecyclePrev()
		default:
			fmt.Println(ev.String())
			ev.RecyclePrev()
		}
		e.numSyscallsAfterFilter++
	}

	if e.flags.FlamegraphEnable {
		fmt.Println("Waiting for flamegraph")
		<-e.flamegraph.Done
	}
}

func (e *eventLoop) events(ctx context.Context, rawCh <-chan []byte) <-chan *event.Pair {
	ch := make(chan *event.Pair)

	go func() {
		defer close(ch)
		for raw := range rawCh {
			select {
			case <-ctx.Done():
				return
			default:
			}

			e.numTracepoints++
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
				if ev, ok := e.filter.nameEvent(NewNameEvent(raw)); ok {
					e.syscallEnter(ev)
				}
			case ENTER_PATH_EVENT:
				if ev, ok := e.filter.pathEvent(NewPathEvent(raw)); ok {
					e.syscallEnter(ev)
				}
			default:
				panic(fmt.Sprintf("unhandled event type %v: %v", EventType(raw[0]), raw))
			}
		}
	}()

	return ch
}

func (e *eventLoop) syscallEnter(enterEv event.Event) {
	tid := enterEv.GetTid()
	if !e.filter.commFilterEnable {
		e.enterEvs[tid] = event.NewPair(enterEv)
		return
	}

	switch enterEv.(type) {
	case *OpenEvent:
		e.enterEvs[tid] = event.NewPair(enterEv)
	default:
		// Only, when we have a comm name
		if _, ok := e.comms[tid]; ok {
			e.enterEvs[tid] = event.NewPair(enterEv)
		}
	}
}

func (e *eventLoop) syscallExit(exitEv event.Event, ch chan<- *event.Pair) {
	ev, ok := e.enterEvs[exitEv.GetTid()]
	if !ok {
		exitEv.Recycle()
		return
	}
	delete(e.enterEvs, exitEv.GetTid())
	ev.ExitEv = exitEv

	// Expect ID one lower, otherwise, enter and exit tracepoints
	// don't match up. E.g.:
	// enterEv:SYS_ENTER_OPEN => exitEv:SYS_EXIT_OPEN
	if ev.EnterEv.GetTraceId()-1 != ev.ExitEv.GetTraceId() {
		ev.TracepointMismatch = true
		e.numTracepointMismatches++
	} else {
		e.numSyscalls++
	}

	switch v := ev.EnterEv.(type) {
	case *OpenEvent:
		openEv := ev.EnterEv.(*OpenEvent)

		fd := int32(ev.ExitEv.(*RetEvent).Ret)
		file := file.NewFd(fd, string(openEv.Filename[:]))
		if fd >= 0 {
			e.files[fd] = file
		}
		ev.File = file
		e.comms[openEv.Tid] = string(openEv.Comm[:])

	case *NameEvent:
		nameEvent := ev.EnterEv.(*NameEvent)
		ev.File = file.OldnameNewnameFile{
			Oldname: string(nameEvent.Oldname[:]),
			Newname: string(nameEvent.Newname[:]),
		}
		ev.Comm = e.comm(ev.EnterEv.GetTid())

	case *PathEvent:
		nameEvent := ev.EnterEv.(*PathEvent)
		ev.File = file.PathnameFile{string(nameEvent.Pathname[:])}
		ev.Comm = e.comm(ev.EnterEv.GetTid())

	case *FdEvent:
		fd := ev.EnterEv.(*FdEvent).Fd
		if file_, ok := e.files[fd]; ok {
			ev.File = file_
			if ev.Is(SYS_ENTER_CLOSE) {
				delete(e.files, fd)
			}
		} else {
			ev.File = file.NewFdWithPid(fd, ev.EnterEv.(*FdEvent).Pid)
		}
		ev.Comm = e.comm(ev.EnterEv.GetTid())
		if !e.filter.eventPair(ev) {
			ev.Recycle()
			return
		}
	case *NullEvent:
		ev.Comm = e.comm(ev.EnterEv.GetTid())
		if !e.filter.eventPair(ev) {
			ev.Recycle()
			return
		}

	default:
		panic(fmt.Sprintf("unknown type: %v", v))
	}

	ev.PrevPair, _ = e.prevPairs[ev.EnterEv.GetTid()]
	ev.CalculateDurations()
	e.prevPairs[ev.EnterEv.GetTid()] = ev
	ch <- ev
}

func (e *eventLoop) comm(tid uint32) string {
	if comm, ok := e.comms[tid]; ok {
		return comm
	}
	if linkName, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", tid)); err == nil {
		linkName = filepath.Base(linkName)
		e.comms[tid] = linkName
		return linkName
	}
	return ""
}
