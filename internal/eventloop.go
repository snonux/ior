package internal

import "C"

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/flags"
	"ior/internal/flamegraph"
	"ior/internal/types"
	. "ior/internal/types"
)

// TOOD: read and write syscalls: can also collect amount of bytes!
type eventLoop struct {
	filter        *eventFilter
	enterEvs      map[uint32]*event.Pair      // Temp. store of sys_enter tracepoints per Tid.
	files         map[int32]file.File         // Track all open files by file descriptor..
	comms         map[uint32]string           // Program or thread name of the current Tid.
	prevPairTimes map[uint32]uint64           // Previous event's time (to calculate time differences between two events)
	flamegraph    flamegraph.IorDataCollector // Storing all paths in a map structure for analysis
	printCb       func(ep *event.Pair)        // Callback to print the event

	// Statistics
	numTracepoints          uint
	numTracepointMismatches uint
	numSyscalls             uint
	numSyscallsAfterFilter  uint
	startTime               time.Time
	done                    chan struct{}
}

func newEventLoop() *eventLoop {
	return &eventLoop{
		filter:        newEventFilter(),
		enterEvs:      make(map[uint32]*event.Pair),
		files:         make(map[int32]file.File),
		comms:         make(map[uint32]string),
		prevPairTimes: make(map[uint32]uint64),
		printCb:       func(ep *event.Pair) { fmt.Println(ep); ep.Recycle() },
		flamegraph:    flamegraph.New(),
		done:          make(chan struct{}),
	}
}

func (e *eventLoop) stats() string {
	fmt.Println("Waiting for stats to be ready")
	<-e.done
	duration := time.Since(e.startTime)

	stats := fmt.Sprintf(
		"Statistics:\n"+
			"\tduration: %v\n"+
			"\ttracepoints: %v (%.2f/s) with %d mismatches (%.2f%%)\n"+
			"\tsyscalls: %d (%.2f/s)\n"+
			"\tsyscalls after filter: %d (%.2f/s)\n",
		duration,
		e.numTracepoints, float64(e.numTracepoints)/duration.Seconds(), e.numTracepointMismatches, (float64(e.numTracepointMismatches)/float64(e.numTracepoints))*100,
		e.numSyscalls, float64(e.numSyscalls)/duration.Seconds(),
		e.numSyscallsAfterFilter, float64(e.numSyscallsAfterFilter)/duration.Seconds(),
	)

	return stats
}

func (e *eventLoop) run(ctx context.Context, rawCh <-chan []byte) {
	defer close(e.done)

	if flags.Get().FlamegraphEnable {
		fmt.Println("Collecting flame graph stats, press Ctrl+C to stop")
		e.flamegraph.Start(ctx)
	}
	if flags.Get().PprofEnable {
		fmt.Println("Profiling, press Ctrl+C to stop")
	}
	if !flags.Get().FlamegraphEnable && !flags.Get().PprofEnable {
		fmt.Println(event.EventStreamHeader)
	}

	e.startTime = time.Now()
	for ep := range e.events(ctx, rawCh) {
		switch {
		case flags.Get().FlamegraphEnable:
			e.flamegraph.Ch <- ep
		case flags.Get().PprofEnable:
			ep.Recycle()
		default:
			e.printCb(ep)
		}
		e.numSyscallsAfterFilter++
	}

	if flags.Get().FlamegraphEnable {
		fmt.Println("Waiting for flamegraph")
		<-e.flamegraph.Done
	}
}

func (e *eventLoop) events(ctx context.Context, rawCh <-chan []byte) <-chan *event.Pair {
	ch := make(chan *event.Pair)

	go func() {
		defer close(ch)

		for {
			select {
			case raw, ok := <-rawCh:
				if !ok {
					return
				}
				if len(raw) == 0 {
					continue
				}
				e.processRawEvent(raw, ch)
			case <-ctx.Done():
				fmt.Println("Stopping event loop")
				return
			default:
				time.Sleep(time.Millisecond * 10)
			}
		}
	}()

	return ch
}

func (e *eventLoop) processRawEvent(raw []byte, ch chan<- *event.Pair) {
	e.numTracepoints++
	switch EventType(raw[0]) {
	case ENTER_OPEN_EVENT:
		if ev, ok := e.filter.openEvent(NewOpenEvent(raw)); ok {
			e.tracepointEntered(ev)
		}
	case EXIT_OPEN_EVENT:
		e.tracepointExited(NewRetEvent(raw), ch)
	case ENTER_FD_EVENT:
		e.tracepointEntered(NewFdEvent(raw))
	case EXIT_FD_EVENT:
		e.tracepointExited(NewFdEvent(raw), ch)
	case ENTER_NULL_EVENT:
		e.tracepointEntered(NewNullEvent(raw))
	case EXIT_NULL_EVENT:
		e.tracepointExited(NewNullEvent(raw), ch)
	case EXIT_RET_EVENT:
		e.tracepointExited(NewRetEvent(raw), ch)
	case ENTER_NAME_EVENT:
		if ev, ok := e.filter.nameEvent(NewNameEvent(raw)); ok {
			e.tracepointEntered(ev)
		}
	case ENTER_PATH_EVENT:
		if ev, ok := e.filter.pathEvent(NewPathEvent(raw)); ok {
			e.tracepointEntered(ev)
		}
	case ENTER_FCNTL_EVENT:
		e.tracepointEntered(NewFcntlEvent(raw))
	case ENTER_DUP3_EVENT:
		e.tracepointEntered(NewDup3Event(raw))
	default:
		panic(fmt.Sprintf("unhandled event type %v: %v", EventType(raw[0]), raw))
	}
}

func (e *eventLoop) tracepointEntered(enterEv event.Event) {
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
		} else {
			// Probably not an issue.
			fmt.Println("WARN: No comm name for", enterEv, "process probably already vanished?")
		}
	}
}

func (e *eventLoop) tracepointExited(exitEv event.Event, ch chan<- *event.Pair) {
	ep, ok := e.enterEvs[exitEv.GetTid()]
	if !ok {
		exitEv.Recycle()
		return
	}
	delete(e.enterEvs, exitEv.GetTid())
	ep.ExitEv = exitEv
	e.numSyscalls++

	// Expect ID one lower, otherwise, enter and exit tracepoints
	// don't match up. E.g.:
	// enterEv:SYS_ENTER_OPEN => exitEv:SYS_EXIT_OPEN
	if ep.EnterEv.GetTraceId()-1 != ep.ExitEv.GetTraceId() {
		e.numTracepointMismatches++
		ep.Recycle()
		return
	}

	switch v := ep.EnterEv.(type) {
	case *OpenEvent:
		openEv := ep.EnterEv.(*OpenEvent)
		comm := types.StringValue(openEv.Comm[:])
		if fd := int32(ep.ExitEv.(*RetEvent).Ret); fd >= 0 {
			file := file.NewFd(fd, openEv.Filename[:], v.Flags)
			e.files[fd] = file
			ep.File = file
			ep.Comm = comm
		}
		e.comms[openEv.Tid] = comm

	// TODO: Unit test this
	case *NameEvent:
		nameEvent := ep.EnterEv.(*NameEvent)
		ep.File = file.NewOldnameNewname(nameEvent.Oldname[:], nameEvent.Newname[:])
		ep.Comm = e.comm(ep.EnterEv.GetTid())

	// TODO: Unit test this
	case *PathEvent:
		nameEvent := ep.EnterEv.(*PathEvent)
		if ep.Is(SYS_ENTER_CREAT) {
			if fd := int32(ep.ExitEv.(*RetEvent).Ret); fd >= 0 {
				file := file.NewFd(fd, nameEvent.Pathname[:],
					syscall.O_CREAT|syscall.O_WRONLY|syscall.O_TRUNC)
				e.files[fd] = file
				ep.File = file
			}
		} else {
			ep.File = file.NewPathname(nameEvent.Pathname[:])
		}
		ep.Comm = e.comm(ep.EnterEv.GetTid())

	// TODO: Unit test this
	case *FdEvent:
		fd := ep.EnterEv.(*FdEvent).Fd
		if file_, ok := e.files[fd]; ok {
			ep.File = file_
			if ep.Is(SYS_ENTER_CLOSE) {
				delete(e.files, fd)
			}
		} else {
			ep.File = file.NewFdWithPid(fd, v.Pid)
		}
		ep.Comm = e.comm(ep.EnterEv.GetTid())
		if !e.filter.eventPair(ep) {
			ep.Recycle()
			return
		}
		if ep.Is(SYS_ENTER_DUP) || ep.Is(SYS_ENTER_DUP2) {
			fdFile, ok := ep.File.(file.FdFile)
			if !ok {
				panic("expected a file.FdFile")
			}
			// Duplicating fd
			newFd := int32(ep.ExitEv.(*RetEvent).Ret)
			if newFd != -1 {
				e.files[newFd] = fdFile.Dup(newFd)
			}
		}

	// TODO: Unit test this
	case *Dup3Event:
		dup3Event := ep.EnterEv.(*Dup3Event)
		fd := int32(dup3Event.Fd)
		if file_, ok := e.files[fd]; ok {
			ep.File = file_
		} else {
			ep.File = file.NewFdWithPid(fd, v.Pid)
		}
		ep.Comm = e.comm(ep.EnterEv.GetTid())
		if !e.filter.eventPair(ep) {
			ep.Recycle()
			return
		}
		// Duplicating fd
		fdFile, ok := ep.File.(file.FdFile)
		if !ok {
			panic("expected a file.FdFile")
		}
		newFd := int32(ep.ExitEv.(*RetEvent).Ret)
		if newFd != -1 {
			duppedFdFile := fdFile.Dup(newFd)
			duppedFdFile.AddFlags(dup3Event.Flags & syscall.O_CLOEXEC)
			e.files[newFd] = duppedFdFile
		}

	// TODO: Unit test this
	case *NullEvent:
		ep.Comm = e.comm(ep.EnterEv.GetTid())
		if !e.filter.eventPair(ep) {
			ep.Recycle()
			return
		}

	// TODO: Unit test this
	case *FcntlEvent:
		ep.Comm = e.comm(ep.EnterEv.GetTid())
		fd := int32(v.Fd)
		if file_, ok := e.files[fd]; ok {
			ep.File = file_
		} else {
			ep.File = file.NewFdWithPid(fd, v.Pid)
		}
		if !e.filter.eventPair(ep) {
			ep.Recycle()
			return
		}

		retEvent, ok := exitEv.(*types.RetEvent)
		if !ok {
			panic("expected *types.RetEvent")
		}
		// Syscall returned -1, nothing was changed with the fd
		if retEvent.Ret == -1 {
			break
		}

		fdFile, ok := ep.File.(file.FdFile)
		if !ok {
			panic("expected a file.FdFile")
		}

		// See fcntl(2) for implementation details
		switch v.Cmd {
		case syscall.F_SETFL:
			const canChange = syscall.O_APPEND | syscall.O_ASYNC | syscall.O_DIRECT | syscall.O_NOATIME | syscall.O_NONBLOCK
			fdFile.AddFlags((int32(v.Arg) & int32(canChange)))
			ep.File = fdFile
			e.files[fd] = fdFile
		case syscall.F_DUPFD:
			newFd := int32(retEvent.Ret)
			e.files[newFd] = fdFile.Dup(newFd)
		case syscall.F_DUPFD_CLOEXEC:
			newFd := int32(retEvent.Ret)
			duppedFdFile := fdFile.Dup(newFd)
			duppedFdFile.AddFlags(syscall.O_CLOEXEC)
			e.files[newFd] = duppedFdFile
		}

	default:
		panic(fmt.Sprintf("unknown type: %v", v))
	}
	// TODO: implement dup3 syscall
	// TODO: implement copy_file_range
	// TODO: open_by_handle_at
	// TODO: name_to_handle_at
	// TODO: mmap, msync...
	// TODO: getcwd?
	// TODO: sync_file_range
	// TODO: https://man7.org/linux/man-pages/man2/io_uring_enter.2.html (already captured but without FDs)

	prevPairTime, _ := e.prevPairTimes[ep.EnterEv.GetTid()]
	ep.CalculateDurations(prevPairTime)
	e.prevPairTimes[ep.EnterEv.GetTid()] = ep.ExitEv.GetTime()
	ch <- ep
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
