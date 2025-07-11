package internal

import (
	"context"
	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
	"syscall"
	"testing"
	"time"
)

const (
	defaulTime = 1234567
	defaultPid = 10
	defaultTid = 11
)

type testData struct {
	// All the raw tracepoints sent to the event loop
	rawTracepoints [][]byte
	// Validation functions to be called on the event loop output
	validates []func(t *testing.T, el *eventLoop, ev *event.Pair)
}

func TestEventloop(t *testing.T) {
	testTable := map[string]testData{
		"OpenEventTest1": makeOpenEventTestData1(t),
		"OpenEventTest2": makeOpenEventTestData2(t),
		"OpenEventTest3": makeOpenEventTestData3(t),
		// FdEvent tests
		"ReadEventTest":      makeReadEventTestData(t),
		"WriteEventTest":     makeWriteEventTestData(t),
		"CloseEventTest":     makeCloseEventTestData(t),
		"FsyncEventTest":     makeFsyncEventTestData(t),
		"FtruncateEventTest": makeFtruncateEventTestData(t),
		// PathEvent tests
		"MkdirEventTest":  makeMkdirEventTestData(t),
		"UnlinkEventTest": makeUnlinkEventTestData(t),
		"CreatEventTest":  makeCreatEventTestData(t),
		"StatEventTest":   makeStatEventTestData(t),
		"AccessEventTest": makeAccessEventTestData(t),
		// NameEvent tests
		"RenameEventTest":  makeRenameEventTestData(t),
		"LinkEventTest":    makeLinkEventTestData(t),
		"SymlinkEventTest": makeSymlinkEventTestData(t),
		// NullEvent tests
		"SyncEventTest":         makeSyncEventTestData(t),
		"IoUringSetupEventTest": makeIoUringSetupEventTestData(t),
		// Dup3Event tests
		"Dup3EventTest":       makeDup3EventTestData(t),
		"Dup3WithCloexecTest": makeDup3WithCloexecTestData(t),
		"Dup2Test":            makeDup2TestData(t),
		// FcntlEvent tests
		"FcntlSetFlagsTest":     makeFcntlSetFlagsTestData(t),
		"FcntlDupfdTest":        makeFcntlDupfdTestData(t),
		"FcntlDupfdCloexecTest": makeFcntlDupfdCloexecTestData(t),
		"FcntlErrorTest":        makeFcntlErrorTestData(t),
		"FcntlInvalidFdTest":    makeFcntlInvalidFdTestData(t),
		// FD Lifecycle tests
		"FdLifecycleTest": makeFdLifecycleTestData(t),
		"FdDupTest":       makeFdDupTestData(t),
		"MultipleFdsTest": makeMultipleFdsTestData(t),
		// Edge case tests
		"ExitOnlyTest":       makeExitOnlyEventTestData(t),
		"EnterOnlyTest":      makeEnterOnlyEventTestData(t),
		"MismatchedPairTest": makeMismatchedPairEventTestData(t),
		"OutOfOrderTest":     makeOutOfOrderEventTestData(t),
		"CrossThreadTest":    makeCrossThreadEventTestData(t),
	}

	for testName, td := range testTable {
		t.Run(testName, func(t *testing.T) {
			// Create a fresh eventloop for each test
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			inCh := make(chan []byte)
			outCh := make(chan *event.Pair)

			el := newEventLoop()
			el.printCb = func(ev *event.Pair) { outCh <- ev }
			go el.run(ctx, inCh)

			go func() {
				for _, raw := range td.rawTracepoints {
					t.Log("Sending raw tracepoint", raw, "simulating BPF sending this")
					inCh <- raw
					// Small delay to simulate real BPF event timing
					time.Sleep(time.Microsecond)
				}
			}()
			for _, validate := range td.validates {
				ep := <-outCh
				t.Log("Received", ep)
				validate(t, el, ep)
			}
			// Give a small delay to ensure any unexpected events would have arrived
			time.Sleep(10 * time.Millisecond)
			select {
			case x := <-outCh:
				t.Errorf("Expected no more events but got '%v'", x)
			default:
			}

			// Special checks for edge case tests
			switch testName {
			case "EnterOnlyTest":
				// Give time for events to be processed
				time.Sleep(20 * time.Millisecond)
				// Verify enter events are still pending
				// Only the OpenEvent is guaranteed to be stored (FdEvent requires comm name)
				verifyEnterEventPending(t, el, defaultTid)
			case "MismatchedPairTest":
				// Give time for all events to be processed
				time.Sleep(50 * time.Millisecond)
				// Verify mismatch counter was incremented
				if el.numTracepointMismatches < 2 {
					t.Errorf("Expected at least 2 tracepoint mismatches but got %d", el.numTracepointMismatches)
				}
			}
		})
	}
}

// Tests a simple enter/exit pair of tracepoints.
func makeOpenEventTestData1(t *testing.T) (td testData) {
	enterEv, enterEvBytes := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	exitEv, exitEvBytes := makeExitOpenEvent(t, defaulTime, defaultPid, defaultTid)
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv, ep.EnterEv)
		}
		if !exitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv, ep.ExitEv)
		}

		filenameA := ep.FileName()
		filenameB := types.StringValue(enterEv.Filename[:])
		if filenameA != filenameB {
			t.Errorf("Expected file name '%v' but got '%v'", filenameB, filenameA)
		}
		comm := types.StringValue(enterEv.Comm[:])
		if ep.Comm != comm {
			t.Errorf("Expected comm name '%v' but got '%v'", comm, ep.Comm)
		}
	})

	return td
}

// Tests skipping of incomplete enter/exit tracepoints.
func makeOpenEventTestData2(t *testing.T) (td testData) {
	// Almost the same, but with duplicates
	td1 := makeOpenEventTestData1(t)
	td.rawTracepoints = append(td.rawTracepoints, td1.rawTracepoints[1]) // Will be ignored by the event loop
	td.rawTracepoints = append(td.rawTracepoints, td1.rawTracepoints[0]) // Will be used by the event loop
	td.rawTracepoints = append(td.rawTracepoints, td1.rawTracepoints[0]) // Will be ignored by the event loop
	td.rawTracepoints = append(td.rawTracepoints, td1.rawTracepoints[1]) // Will be used by the event loop
	td.rawTracepoints = append(td.rawTracepoints, td1.rawTracepoints[1]) // Will be ignored by the event loop
	td.validates = td1.validates

	return td
}

// Tests 2 parallel tracepoints but from different threads.
func makeOpenEventTestData3(t *testing.T) (td testData) {
	enterEv1, enterEvBytes1 := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	enterEv2, enterEvBytes2 := makeEnterOpenEvent(t, defaulTime+1, defaultPid, defaultTid+1)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes1)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes2)

	exitEv1, exitEvBytes1 := makeExitOpenEvent(t, defaulTime+2, defaultPid, defaultTid)
	exitEv2, exitEvBytes2 := makeExitOpenEvent(t, defaulTime+3, defaultPid, defaultTid+1)
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes1)
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes2)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv1.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv1, ep.EnterEv)
		}
		if !exitEv1.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv1, ep.ExitEv)
		}
	})
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv2.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv2, ep.EnterEv)
		}
		if !exitEv2.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv2, ep.ExitEv)
		}
	})

	return td
}

func makeEnterOpenEvent(t *testing.T, time uint64, pid, tid uint32) (types.OpenEvent, []byte) {
	ev := types.OpenEvent{
		EventType: types.ENTER_OPEN_EVENT,
		TraceId:   types.SYS_ENTER_OPENAT,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
		Flags:     syscall.O_RDWR,
		Filename:  [types.MAX_FILENAME_LENGTH]byte{},
		Comm:      [types.MAX_PROGNAME_LENGTH]byte{},
	}
	copy(ev.Filename[:], "testfile.txt")
	copy(ev.Comm[:], "testcomm")

	bytes, err := ev.Bytes()
	if err != nil {
		t.Error(err)
	}
	return ev, bytes
}

func makeExitOpenEvent(t *testing.T, time uint64, pid, tid uint32) (types.RetEvent, []byte) {
	ev := types.RetEvent{
		EventType: types.EXIT_OPEN_EVENT,
		TraceId:   types.SYS_EXIT_OPENAT,
		Time:      time,
		Ret:       42,
		Pid:       pid,
		Tid:       tid,
	}

	bytes, err := ev.Bytes()
	if err != nil {
		t.Error(err)
	}
	return ev, bytes
}

// Helper functions for FdEvent
func makeEnterFdEvent(t *testing.T, time uint64, pid, tid uint32, fd int32, traceId types.TraceId) (types.FdEvent, []byte) {
	ev := types.FdEvent{
		EventType: types.ENTER_FD_EVENT,
		TraceId:   traceId,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
		Fd:        fd,
	}

	bytes, err := ev.Bytes()
	if err != nil {
		t.Error(err)
	}
	return ev, bytes
}

func makeExitFdEvent(t *testing.T, time uint64, pid, tid uint32, fd int32, traceId types.TraceId) (types.FdEvent, []byte) {
	ev := types.FdEvent{
		EventType: types.EXIT_FD_EVENT,
		TraceId:   traceId,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
		Fd:        fd,
	}

	bytes, err := ev.Bytes()
	if err != nil {
		t.Error(err)
	}
	return ev, bytes
}

// Helper function to create exit RetEvent
func makeExitRetEvent(t *testing.T, time uint64, pid, tid uint32, traceId types.TraceId, ret int64) (types.RetEvent, []byte) {
	ev := types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   traceId,
		Time:      time,
		Ret:       ret,
		Pid:       pid,
		Tid:       tid,
	}

	bytes, err := ev.Bytes()
	if err != nil {
		t.Error(err)
	}
	return ev, bytes
}

// Test data functions for FdEvent syscalls
func makeReadEventTestData(t *testing.T) (td testData) {
	fd := int32(42) // Assume file descriptor 42
	enterEv, enterEvBytes := makeEnterFdEvent(t, defaulTime, defaultPid, defaultTid, fd, types.SYS_ENTER_READ)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	exitEv, exitEvBytes := makeExitFdEvent(t, defaulTime+100, defaultPid, defaultTid, fd, types.SYS_EXIT_READ)
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv, ep.EnterEv)
		}
		if !exitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv, ep.ExitEv)
		}
	})

	return td
}

func makeWriteEventTestData(t *testing.T) (td testData) {
	fd := int32(43)
	enterEv, enterEvBytes := makeEnterFdEvent(t, defaulTime, defaultPid, defaultTid, fd, types.SYS_ENTER_WRITE)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	exitEv, exitEvBytes := makeExitFdEvent(t, defaulTime+100, defaultPid, defaultTid, fd, types.SYS_EXIT_WRITE)
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv, ep.EnterEv)
		}
		if !exitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv, ep.ExitEv)
		}
	})

	return td
}

func makeCloseEventTestData(t *testing.T) (td testData) {
	fd := int32(44)
	enterEv, enterEvBytes := makeEnterFdEvent(t, defaulTime, defaultPid, defaultTid, fd, types.SYS_ENTER_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	exitEv, exitEvBytes := makeExitFdEvent(t, defaulTime+100, defaultPid, defaultTid, fd, types.SYS_EXIT_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv, ep.EnterEv)
		}
		if !exitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv, ep.ExitEv)
		}
	})

	return td
}

func makeFsyncEventTestData(t *testing.T) (td testData) {
	fd := int32(45)
	enterEv, enterEvBytes := makeEnterFdEvent(t, defaulTime, defaultPid, defaultTid, fd, types.SYS_ENTER_FSYNC)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	exitEv, exitEvBytes := makeExitFdEvent(t, defaulTime+100, defaultPid, defaultTid, fd, types.SYS_EXIT_FSYNC)
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv, ep.EnterEv)
		}
		if !exitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv, ep.ExitEv)
		}
	})

	return td
}

func makeFtruncateEventTestData(t *testing.T) (td testData) {
	fd := int32(46)
	enterEv, enterEvBytes := makeEnterFdEvent(t, defaulTime, defaultPid, defaultTid, fd, types.SYS_ENTER_FTRUNCATE)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	exitEv, exitEvBytes := makeExitFdEvent(t, defaulTime+100, defaultPid, defaultTid, fd, types.SYS_EXIT_FTRUNCATE)
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv, ep.EnterEv)
		}
		if !exitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv, ep.ExitEv)
		}
	})

	return td
}

// Helper functions for PathEvent
func makeEnterPathEvent(t *testing.T, time uint64, pid, tid uint32, pathname string, traceId types.TraceId) (types.PathEvent, []byte) {
	ev := types.PathEvent{
		EventType: types.ENTER_PATH_EVENT,
		TraceId:   traceId,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
		Pathname:  [types.MAX_FILENAME_LENGTH]byte{},
	}
	copy(ev.Pathname[:], pathname)

	bytes, err := ev.Bytes()
	if err != nil {
		t.Error(err)
	}
	return ev, bytes
}

// Helper functions for NameEvent
func makeEnterNameEvent(t *testing.T, time uint64, pid, tid uint32, oldname, newname string, traceId types.TraceId) (types.NameEvent, []byte) {
	ev := types.NameEvent{
		EventType: types.ENTER_NAME_EVENT,
		TraceId:   traceId,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
		Oldname:   [types.MAX_FILENAME_LENGTH]byte{},
		Newname:   [types.MAX_FILENAME_LENGTH]byte{},
	}
	copy(ev.Oldname[:], oldname)
	copy(ev.Newname[:], newname)

	bytes, err := ev.Bytes()
	if err != nil {
		t.Error(err)
	}
	return ev, bytes
}

// Helper functions for NullEvent
func makeEnterNullEvent(t *testing.T, time uint64, pid, tid uint32, traceId types.TraceId) (types.NullEvent, []byte) {
	ev := types.NullEvent{
		EventType: types.ENTER_NULL_EVENT,
		TraceId:   traceId,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
	}

	bytes, err := ev.Bytes()
	if err != nil {
		t.Error(err)
	}
	return ev, bytes
}

func makeExitNullEvent(t *testing.T, time uint64, pid, tid uint32, traceId types.TraceId) (types.NullEvent, []byte) {
	ev := types.NullEvent{
		EventType: types.EXIT_NULL_EVENT,
		TraceId:   traceId,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
	}

	bytes, err := ev.Bytes()
	if err != nil {
		t.Error(err)
	}
	return ev, bytes
}

// Helper functions for Dup3Event
func makeEnterDup3Event(t *testing.T, time uint64, pid, tid uint32, fd int32, flags int32) (types.Dup3Event, []byte) {
	ev := types.Dup3Event{
		EventType: types.ENTER_DUP3_EVENT,
		TraceId:   types.SYS_ENTER_DUP3,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
		Fd:        fd,
		Flags:     flags,
	}

	bytes, err := ev.Bytes()
	if err != nil {
		t.Error(err)
	}
	return ev, bytes
}

func makeEnterFcntlEvent(t *testing.T, time uint64, pid, tid uint32, fd uint32, cmd uint32, arg uint64) (types.FcntlEvent, []byte) {
	ev := types.FcntlEvent{
		EventType: types.ENTER_FCNTL_EVENT,
		TraceId:   types.SYS_ENTER_FCNTL,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
		Fd:        fd,
		Cmd:       cmd,
		Arg:       arg,
	}

	bytes, err := ev.Bytes()
	if err != nil {
		t.Error(err)
	}
	return ev, bytes
}

// Test data functions for PathEvent syscalls
func makeMkdirEventTestData(t *testing.T) (td testData) {
	pathname := "/tmp/testdir"
	enterEv, enterEvBytes := makeEnterPathEvent(t, defaulTime, defaultPid, defaultTid, pathname, types.SYS_ENTER_MKDIR)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	exitEv, exitEvBytes := makeExitRetEvent(t, defaulTime+100, defaultPid, defaultTid, types.SYS_EXIT_MKDIR, 0)
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv, ep.EnterEv)
		}
		if !exitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv, ep.ExitEv)
		}
		filenameA := types.StringValue(enterEv.Pathname[:])
		if ep.File == nil {
			t.Errorf("Expected file to be set")
		} else if ep.File.Name() != filenameA {
			t.Errorf("Expected file name '%v' but got '%v'", filenameA, ep.File.Name())
		}
	})

	return td
}

func makeUnlinkEventTestData(t *testing.T) (td testData) {
	pathname := "/tmp/testfile.txt"
	enterEv, enterEvBytes := makeEnterPathEvent(t, defaulTime, defaultPid, defaultTid, pathname, types.SYS_ENTER_UNLINK)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	exitEv, exitEvBytes := makeExitRetEvent(t, defaulTime+100, defaultPid, defaultTid, types.SYS_EXIT_UNLINK, 0)
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv, ep.EnterEv)
		}
		if !exitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv, ep.ExitEv)
		}
		filenameA := types.StringValue(enterEv.Pathname[:])
		if ep.File == nil {
			t.Errorf("Expected file to be set")
		} else if ep.File.Name() != filenameA {
			t.Errorf("Expected file name '%v' but got '%v'", filenameA, ep.File.Name())
		}
	})

	return td
}

func makeCreatEventTestData(t *testing.T) (td testData) {
	pathname := "/tmp/newfile.txt"
	enterEv, enterEvBytes := makeEnterPathEvent(t, defaulTime, defaultPid, defaultTid, pathname, types.SYS_ENTER_CREAT)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	exitEv, exitEvBytes := makeExitRetEvent(t, defaulTime+100, defaultPid, defaultTid, types.SYS_EXIT_CREAT, 47) // fd = 47
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv, ep.EnterEv)
		}
		if !exitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv, ep.ExitEv)
		}
		// For creat, we expect the file to be tracked with the returned fd
		if ep.File == nil {
			t.Errorf("Expected file to be set")
		}
	})

	return td
}

func makeStatEventTestData(t *testing.T) (td testData) {
	pathname := "/tmp/existingfile.txt"
	enterEv, enterEvBytes := makeEnterPathEvent(t, defaulTime, defaultPid, defaultTid, pathname, types.SYS_ENTER_NEWSTAT)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	exitEv, exitEvBytes := makeExitRetEvent(t, defaulTime+100, defaultPid, defaultTid, types.SYS_EXIT_NEWSTAT, 0)
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv, ep.EnterEv)
		}
		if !exitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv, ep.ExitEv)
		}
		filenameA := types.StringValue(enterEv.Pathname[:])
		if ep.File == nil {
			t.Errorf("Expected file to be set")
		} else if ep.File.Name() != filenameA {
			t.Errorf("Expected file name '%v' but got '%v'", filenameA, ep.File.Name())
		}
	})

	return td
}

func makeAccessEventTestData(t *testing.T) (td testData) {
	pathname := "/tmp/checkfile.txt"
	enterEv, enterEvBytes := makeEnterPathEvent(t, defaulTime, defaultPid, defaultTid, pathname, types.SYS_ENTER_ACCESS)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	exitEv, exitEvBytes := makeExitRetEvent(t, defaulTime+100, defaultPid, defaultTid, types.SYS_EXIT_ACCESS, 0)
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv, ep.EnterEv)
		}
		if !exitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv, ep.ExitEv)
		}
		filenameA := types.StringValue(enterEv.Pathname[:])
		if ep.File == nil {
			t.Errorf("Expected file to be set")
		} else if ep.File.Name() != filenameA {
			t.Errorf("Expected file name '%v' but got '%v'", filenameA, ep.File.Name())
		}
	})

	return td
}

// Test data functions for NameEvent syscalls
func makeRenameEventTestData(t *testing.T) (td testData) {
	oldname := "/tmp/oldfile.txt"
	newname := "/tmp/newfile.txt"
	enterEv, enterEvBytes := makeEnterNameEvent(t, defaulTime, defaultPid, defaultTid, oldname, newname, types.SYS_ENTER_RENAME)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	exitEv, exitEvBytes := makeExitRetEvent(t, defaulTime+100, defaultPid, defaultTid, types.SYS_EXIT_RENAME, 0)
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv, ep.EnterEv)
		}
		if !exitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv, ep.ExitEv)
		}
		if ep.File == nil {
			t.Errorf("Expected file to be set")
		} else if ep.File.Name() != newname {
			t.Errorf("Expected file name '%v' but got '%v'", newname, ep.File.Name())
		}
	})

	return td
}

func makeLinkEventTestData(t *testing.T) (td testData) {
	oldname := "/tmp/original.txt"
	newname := "/tmp/hardlink.txt"
	enterEv, enterEvBytes := makeEnterNameEvent(t, defaulTime, defaultPid, defaultTid, oldname, newname, types.SYS_ENTER_LINK)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	exitEv, exitEvBytes := makeExitRetEvent(t, defaulTime+100, defaultPid, defaultTid, types.SYS_EXIT_LINK, 0)
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv, ep.EnterEv)
		}
		if !exitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv, ep.ExitEv)
		}
		if ep.File == nil {
			t.Errorf("Expected file to be set")
		} else if ep.File.Name() != newname {
			t.Errorf("Expected file name '%v' but got '%v'", newname, ep.File.Name())
		}
	})

	return td
}

func makeSymlinkEventTestData(t *testing.T) (td testData) {
	oldname := "/tmp/target.txt"
	newname := "/tmp/symlink.txt"
	enterEv, enterEvBytes := makeEnterNameEvent(t, defaulTime, defaultPid, defaultTid, oldname, newname, types.SYS_ENTER_SYMLINK)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	exitEv, exitEvBytes := makeExitRetEvent(t, defaulTime+100, defaultPid, defaultTid, types.SYS_EXIT_SYMLINK, 0)
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv, ep.EnterEv)
		}
		if !exitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv, ep.ExitEv)
		}
		if ep.File == nil {
			t.Errorf("Expected file to be set")
		} else if ep.File.Name() != newname {
			t.Errorf("Expected file name '%v' but got '%v'", newname, ep.File.Name())
		}
	})

	return td
}

// Test data functions for NullEvent syscalls
func makeSyncEventTestData(t *testing.T) (td testData) {
	enterEv, enterEvBytes := makeEnterNullEvent(t, defaulTime, defaultPid, defaultTid, types.SYS_ENTER_SYNC)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	exitEv, exitEvBytes := makeExitNullEvent(t, defaulTime+100, defaultPid, defaultTid, types.SYS_EXIT_SYNC)
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv, ep.EnterEv)
		}
		if !exitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv, ep.ExitEv)
		}
	})

	return td
}

func makeIoUringSetupEventTestData(t *testing.T) (td testData) {
	enterEv, enterEvBytes := makeEnterNullEvent(t, defaulTime, defaultPid, defaultTid, types.SYS_ENTER_IO_URING_SETUP)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	// io_uring_setup returns a file descriptor on success
	exitEv, exitEvBytes := makeExitRetEvent(t, defaulTime+100, defaultPid, defaultTid, types.SYS_EXIT_IO_URING_SETUP, 48) // fd = 48
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv, ep.EnterEv)
		}
		if !exitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv, ep.ExitEv)
		}
	})

	return td
}

// Test data functions for Dup3Event syscalls
func makeDup3EventTestData(t *testing.T) (td testData) {
	oldFd := int32(49)
	enterEv, enterEvBytes := makeEnterDup3Event(t, defaulTime, defaultPid, defaultTid, oldFd, syscall.O_CLOEXEC)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	newFd := int32(50)
	exitEv, exitEvBytes := makeExitRetEvent(t, defaulTime+100, defaultPid, defaultTid, types.SYS_EXIT_DUP3, int64(newFd))
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !enterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv, ep.EnterEv)
		}
		if !exitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", exitEv, ep.ExitEv)
		}
	})

	return td
}

// Test for dup3 with O_CLOEXEC flag and file descriptor tracking
func makeDup3WithCloexecTestData(t *testing.T) (td testData) {
	origFd := int32(51)
	newFd := int32(52)
	filename := "dup3_cloexec_test.txt"

	// Step 1: Open file to get original fd
	openEnterEv, openEnterBytes := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	copy(openEnterEv.Filename[:], filename)
	openEnterBytes, _ = openEnterEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openEnterBytes)

	openExitEv, openExitBytes := makeExitOpenEvent(t, defaulTime+100, defaultPid, defaultTid)
	openExitEv.Ret = int64(origFd)
	openExitBytes, _ = openExitEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openExitBytes)

	// Validate open created the fd
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFileDescriptor(t, el, origFd, filename)
	})

	// Step 2: Dup3 with O_CLOEXEC flag
	_, dup3EnterBytes := makeEnterDup3Event(t, defaulTime+200, defaultPid, defaultTid, origFd, syscall.O_CLOEXEC)
	td.rawTracepoints = append(td.rawTracepoints, dup3EnterBytes)

	_, dup3ExitBytes := makeExitRetEvent(t, defaulTime+300, defaultPid, defaultTid, types.SYS_EXIT_DUP3, int64(newFd))
	td.rawTracepoints = append(td.rawTracepoints, dup3ExitBytes)

	// Validate dup3 created new fd with same file and O_CLOEXEC flag
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		// Both fds should be tracked
		verifyFileDescriptor(t, el, origFd, filename)
		verifyFileDescriptor(t, el, newFd, filename)

		// Verify the new fd has O_CLOEXEC flag
		if newFile, ok := el.files[newFd]; ok {
			fdFile, ok := newFile.(file.FdFile)
			if !ok {
				t.Errorf("Expected file to be FdFile type")
			} else if !fdFile.Flags().Is(syscall.O_CLOEXEC) {
				t.Errorf("Expected new fd %d to have O_CLOEXEC flag set", newFd)
			}
		}
	})

	// Step 3: Read from new fd to verify it works
	_, readEnterBytes := makeEnterFdEvent(t, defaulTime+400, defaultPid, defaultTid, newFd, types.SYS_ENTER_READ)
	td.rawTracepoints = append(td.rawTracepoints, readEnterBytes)

	_, readExitBytes := makeExitFdEvent(t, defaulTime+500, defaultPid, defaultTid, newFd, types.SYS_EXIT_READ)
	td.rawTracepoints = append(td.rawTracepoints, readExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.File == nil || ep.File.Name() != filename {
			t.Errorf("Expected read to use file '%s'", filename)
		}
	})

	// Step 4: Close both fds
	_, closeOrigEnterBytes := makeEnterFdEvent(t, defaulTime+600, defaultPid, defaultTid, origFd, types.SYS_ENTER_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeOrigEnterBytes)

	_, closeOrigExitBytes := makeExitFdEvent(t, defaulTime+700, defaultPid, defaultTid, origFd, types.SYS_EXIT_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeOrigExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFdNotTracked(t, el, origFd)
		verifyFileDescriptor(t, el, newFd, filename) // newFd should still be tracked
	})

	_, closeNewEnterBytes := makeEnterFdEvent(t, defaulTime+800, defaultPid, defaultTid, newFd, types.SYS_ENTER_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeNewEnterBytes)

	_, closeNewExitBytes := makeExitFdEvent(t, defaulTime+900, defaultPid, defaultTid, newFd, types.SYS_EXIT_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeNewExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFdNotTracked(t, el, origFd)
		verifyFdNotTracked(t, el, newFd)
	})

	return td
}

// Test for dup2 syscall
func makeDup2TestData(t *testing.T) (td testData) {
	origFd := int32(53)
	targetFd := int32(54)
	filename := "dup2_test.txt"

	// Step 1: Open file to get original fd
	openEnterEv, openEnterBytes := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	copy(openEnterEv.Filename[:], filename)
	openEnterBytes, _ = openEnterEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openEnterBytes)

	openExitEv, openExitBytes := makeExitOpenEvent(t, defaulTime+100, defaultPid, defaultTid)
	openExitEv.Ret = int64(origFd)
	openExitBytes, _ = openExitEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openExitBytes)

	// Validate open created the fd
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFileDescriptor(t, el, origFd, filename)
	})

	// Step 2: Dup2 (uses FdEvent, not Dup3Event)
	_, dup2EnterBytes := makeEnterFdEvent(t, defaulTime+200, defaultPid, defaultTid, origFd, types.SYS_ENTER_DUP2)
	td.rawTracepoints = append(td.rawTracepoints, dup2EnterBytes)

	_, dup2ExitBytes := makeExitRetEvent(t, defaulTime+300, defaultPid, defaultTid, types.SYS_EXIT_DUP2, int64(targetFd))
	td.rawTracepoints = append(td.rawTracepoints, dup2ExitBytes)

	// Validate dup2 created new fd without O_CLOEXEC
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		// Both fds should be tracked
		verifyFileDescriptor(t, el, origFd, filename)
		verifyFileDescriptor(t, el, targetFd, filename)

		// Verify the new fd does NOT have O_CLOEXEC flag (unlike dup3)
		if newFile, ok := el.files[targetFd]; ok {
			fdFile, ok := newFile.(file.FdFile)
			if !ok {
				t.Errorf("Expected file to be FdFile type")
			} else if fdFile.Flags().Is(syscall.O_CLOEXEC) {
				t.Errorf("Expected dup2 target fd %d to NOT have O_CLOEXEC flag", targetFd)
			}
		}
	})

	// Step 3: Write to target fd to verify it works
	_, writeEnterBytes := makeEnterFdEvent(t, defaulTime+400, defaultPid, defaultTid, targetFd, types.SYS_ENTER_WRITE)
	td.rawTracepoints = append(td.rawTracepoints, writeEnterBytes)

	_, writeExitBytes := makeExitFdEvent(t, defaulTime+500, defaultPid, defaultTid, targetFd, types.SYS_EXIT_WRITE)
	td.rawTracepoints = append(td.rawTracepoints, writeExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.File == nil || ep.File.Name() != filename {
			t.Errorf("Expected write to use file '%s'", filename)
		}
	})

	// Step 4: Close both fds
	_, closeOrigEnterBytes := makeEnterFdEvent(t, defaulTime+600, defaultPid, defaultTid, origFd, types.SYS_ENTER_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeOrigEnterBytes)

	_, closeOrigExitBytes := makeExitFdEvent(t, defaulTime+700, defaultPid, defaultTid, origFd, types.SYS_EXIT_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeOrigExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFdNotTracked(t, el, origFd)
		verifyFileDescriptor(t, el, targetFd, filename) // targetFd should still be tracked
	})

	_, closeTargetEnterBytes := makeEnterFdEvent(t, defaulTime+800, defaultPid, defaultTid, targetFd, types.SYS_ENTER_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeTargetEnterBytes)

	_, closeTargetExitBytes := makeExitFdEvent(t, defaulTime+900, defaultPid, defaultTid, targetFd, types.SYS_EXIT_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeTargetExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFdNotTracked(t, el, origFd)
		verifyFdNotTracked(t, el, targetFd)
	})

	return td
}

// Helper functions for FD lifecycle tests
func verifyFileDescriptor(t *testing.T, el *eventLoop, fd int32, expectedFileName string) {
	if file, ok := el.files[fd]; ok {
		if file.Name() != expectedFileName {
			t.Errorf("Expected fd %d to map to file '%s' but got '%s'", fd, expectedFileName, file.Name())
		}
	} else {
		t.Errorf("Expected fd %d to be tracked but it wasn't found", fd)
	}
}

func verifyFdNotTracked(t *testing.T, el *eventLoop, fd int32) {
	if _, ok := el.files[fd]; ok {
		t.Errorf("Expected fd %d to not be tracked but it was found", fd)
	}
}

// Helper functions for edge case tests
func verifyNoEventOutput(t *testing.T, outCh <-chan *event.Pair, timeout time.Duration) {
	select {
	case ev := <-outCh:
		t.Errorf("Expected no event output but got: %v", ev)
	case <-time.After(timeout):
		// Good, no output as expected
	}
}

func verifyEnterEventPending(t *testing.T, el *eventLoop, tid uint32) {
	if _, ok := el.enterEvs[tid]; !ok {
		t.Errorf("Expected enter event for tid %d to be pending but it wasn't found", tid)
	}
}

func verifyNoEnterEventPending(t *testing.T, el *eventLoop, tid uint32) {
	if _, ok := el.enterEvs[tid]; ok {
		t.Errorf("Expected no enter event for tid %d but one was found", tid)
	}
}

func verifyMismatchCount(t *testing.T, el *eventLoop, expectedCount uint) {
	if el.numTracepointMismatches != expectedCount {
		t.Errorf("Expected %d tracepoint mismatches but got %d", expectedCount, el.numTracepointMismatches)
	}
}

func verifyCommName(t *testing.T, el *eventLoop, tid uint32, expectedComm string) {
	if comm, ok := el.comms[tid]; !ok {
		t.Errorf("Expected comm name for tid %d but it wasn't found", tid)
	} else if comm != expectedComm {
		t.Errorf("Expected comm name '%s' for tid %d but got '%s'", expectedComm, tid, comm)
	}
}

// Test fcntl F_SETFL flag modification
func makeFcntlSetFlagsTestData(t *testing.T) (td testData) {
	// TODO: Investigate why this test is failing - temporarily disabled
	// The test fails with panic "expected a file.FdFile" during fcntl event processing
	// Returning empty test data to skip this test case
	// return td

	fd := uint32(60)
	filename := "fcntl_setfl_test.txt"

	// Step 1: Open file to get fd
	openEnterEv, openEnterBytes := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	copy(openEnterEv.Filename[:], filename)
	openEnterBytes, _ = openEnterEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openEnterBytes)

	openExitEv, openExitBytes := makeExitOpenEvent(t, defaulTime+100, defaultPid, defaultTid)
	openExitEv.Ret = int64(fd)
	openExitBytes, _ = openExitEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openExitBytes)

	// Validate open created the fd
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFileDescriptor(t, el, int32(fd), filename)
	})

	// // Step 2: Call fcntl F_SETFL to add O_NONBLOCK and O_APPEND flags
	const newFlags = syscall.O_NONBLOCK | syscall.O_APPEND
	fcntlEnterEv, fcntlEnterBytes := makeEnterFcntlEvent(t, defaulTime+200, defaultPid, defaultTid, fd, syscall.F_SETFL, uint64(newFlags))
	td.rawTracepoints = append(td.rawTracepoints, fcntlEnterBytes)

	fcntlExitEv, fcntlExitBytes := makeExitRetEvent(t, defaulTime+300, defaultPid, defaultTid, types.SYS_EXIT_FCNTL, 0)
	td.rawTracepoints = append(td.rawTracepoints, fcntlExitBytes)

	// Validate fcntl updated the flags
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !fcntlEnterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", fcntlEnterEv, ep.EnterEv)
		}
		if !fcntlExitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", fcntlExitEv, ep.ExitEv)
		}

		// Verify flags were updated on the file descriptor
		if f, ok := el.files[int32(fd)]; ok {
			fdFile, ok := f.(file.FdFile)
			if !ok {
				t.Errorf("Expected file to be FdFile type")
			} else {
				// Check that O_NONBLOCK and O_APPEND were set
				if !fdFile.Flags().Is(syscall.O_NONBLOCK) {
					t.Errorf("Expected fd %d to have O_NONBLOCK flag set", fd)
				}
				if !fdFile.Flags().Is(syscall.O_APPEND) {
					t.Errorf("Expected fd %d to have O_APPEND flag set", fd)
				}
			}
		} else {
			t.Errorf("Expected fd %d to be tracked", fd)
		}
	})

	// Step 3: Call fcntl F_SETFL again to test flag changes (remove O_NONBLOCK, keep O_APPEND)
	const modifiedFlags = syscall.O_APPEND | syscall.O_DIRECT
	fcntlEnterEv2, fcntlEnterBytes2 := makeEnterFcntlEvent(t, defaulTime+400, defaultPid, defaultTid, fd, syscall.F_SETFL, uint64(modifiedFlags))
	td.rawTracepoints = append(td.rawTracepoints, fcntlEnterBytes2)

	fcntlExitEv2, fcntlExitBytes2 := makeExitRetEvent(t, defaulTime+500, defaultPid, defaultTid, types.SYS_EXIT_FCNTL, 0)
	td.rawTracepoints = append(td.rawTracepoints, fcntlExitBytes2)

	// Validate second fcntl updated the flags correctly
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !fcntlEnterEv2.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", fcntlEnterEv2, ep.EnterEv)
		}
		if !fcntlExitEv2.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", fcntlExitEv2, ep.ExitEv)
		}

		// Verify flags were updated correctly
		if f, ok := el.files[int32(fd)]; ok {
			fdFile, ok := f.(file.FdFile)
			if !ok {
				t.Errorf("Expected file to be FdFile type")
			} else {
				// O_NONBLOCK should be removed, O_APPEND should remain, O_DIRECT should be added
				if fdFile.Flags().Is(syscall.O_NONBLOCK) {
					t.Errorf("Expected fd %d to NOT have O_NONBLOCK flag", fd)
				}
				if !fdFile.Flags().Is(syscall.O_APPEND) {
					t.Errorf("Expected fd %d to have O_APPEND flag set", fd)
				}
				if !fdFile.Flags().Is(syscall.O_DIRECT) {
					t.Errorf("Expected fd %d to have O_DIRECT flag set", fd)
				}
			}
		} else {
			t.Errorf("Expected fd %d to be tracked", fd)
		}
	})

	// Step 4: Close the fd
	_, closeEnterBytes := makeEnterFdEvent(t, defaulTime+600, defaultPid, defaultTid, int32(fd), types.SYS_ENTER_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeEnterBytes)

	_, closeExitBytes := makeExitFdEvent(t, defaulTime+700, defaultPid, defaultTid, int32(fd), types.SYS_EXIT_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFdNotTracked(t, el, int32(fd))
	})

	return td
}

// Test fcntl F_DUPFD file descriptor duplication
func makeFcntlDupfdTestData(t *testing.T) (td testData) {
	origFd := uint32(61)
	newFd := uint32(62)
	filename := "fcntl_dupfd_test.txt"

	// Step 1: Open file to get original fd
	openEnterEv, openEnterBytes := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	copy(openEnterEv.Filename[:], filename)
	openEnterBytes, _ = openEnterEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openEnterBytes)

	openExitEv, openExitBytes := makeExitOpenEvent(t, defaulTime+100, defaultPid, defaultTid)
	openExitEv.Ret = int64(origFd)
	openExitBytes, _ = openExitEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openExitBytes)

	// Validate open created the fd
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFileDescriptor(t, el, int32(origFd), filename)
	})

	// Step 2: Call fcntl F_DUPFD to duplicate the file descriptor
	fcntlEnterEv, fcntlEnterBytes := makeEnterFcntlEvent(t, defaulTime+200, defaultPid, defaultTid, origFd, syscall.F_DUPFD, 0)
	td.rawTracepoints = append(td.rawTracepoints, fcntlEnterBytes)

	fcntlExitEv, fcntlExitBytes := makeExitRetEvent(t, defaulTime+300, defaultPid, defaultTid, types.SYS_EXIT_FCNTL, int64(newFd))
	td.rawTracepoints = append(td.rawTracepoints, fcntlExitBytes)

	// Validate fcntl duplicated the fd
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !fcntlEnterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", fcntlEnterEv, ep.EnterEv)
		}
		if !fcntlExitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", fcntlExitEv, ep.ExitEv)
		}

		// Both fds should be tracked and point to the same file
		verifyFileDescriptor(t, el, int32(origFd), filename)
		verifyFileDescriptor(t, el, int32(newFd), filename)

		// Verify the new fd does NOT have O_CLOEXEC flag (F_DUPFD doesn't set it)
		if f, ok := el.files[int32(newFd)]; ok {
			fdFile, ok := f.(file.FdFile)
			if !ok {
				t.Errorf("Expected file to be FdFile type")
			} else if fdFile.Flags().Is(syscall.O_CLOEXEC) {
				t.Errorf("Expected new fd %d to NOT have O_CLOEXEC flag", newFd)
			}
		}
	})

	// Step 3: Read from the new fd to verify it works
	_, readEnterBytes := makeEnterFdEvent(t, defaulTime+400, defaultPid, defaultTid, int32(newFd), types.SYS_ENTER_READ)
	td.rawTracepoints = append(td.rawTracepoints, readEnterBytes)

	_, readExitBytes := makeExitFdEvent(t, defaulTime+500, defaultPid, defaultTid, int32(newFd), types.SYS_EXIT_READ)
	td.rawTracepoints = append(td.rawTracepoints, readExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.File == nil || ep.File.Name() != filename {
			t.Errorf("Expected read from new fd to use file '%s'", filename)
		}
	})

	// Step 4: Close original fd and verify new fd still works
	_, closeOrigEnterBytes := makeEnterFdEvent(t, defaulTime+600, defaultPid, defaultTid, int32(origFd), types.SYS_ENTER_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeOrigEnterBytes)

	_, closeOrigExitBytes := makeExitFdEvent(t, defaulTime+700, defaultPid, defaultTid, int32(origFd), types.SYS_EXIT_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeOrigExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFdNotTracked(t, el, int32(origFd))
		verifyFileDescriptor(t, el, int32(newFd), filename) // newFd should still be tracked
	})

	// Step 5: Write to new fd to verify it still works after original was closed
	_, writeEnterBytes := makeEnterFdEvent(t, defaulTime+800, defaultPid, defaultTid, int32(newFd), types.SYS_ENTER_WRITE)
	td.rawTracepoints = append(td.rawTracepoints, writeEnterBytes)

	_, writeExitBytes := makeExitFdEvent(t, defaulTime+900, defaultPid, defaultTid, int32(newFd), types.SYS_EXIT_WRITE)
	td.rawTracepoints = append(td.rawTracepoints, writeExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.File == nil || ep.File.Name() != filename {
			t.Errorf("Expected write to new fd to use file '%s'", filename)
		}
	})

	// Step 6: Close the new fd
	_, closeNewEnterBytes := makeEnterFdEvent(t, defaulTime+1000, defaultPid, defaultTid, int32(newFd), types.SYS_ENTER_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeNewEnterBytes)

	_, closeNewExitBytes := makeExitFdEvent(t, defaulTime+1100, defaultPid, defaultTid, int32(newFd), types.SYS_EXIT_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeNewExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFdNotTracked(t, el, int32(origFd))
		verifyFdNotTracked(t, el, int32(newFd))
	})

	return td
}

// Test fcntl F_DUPFD_CLOEXEC with O_CLOEXEC flag
func makeFcntlDupfdCloexecTestData(t *testing.T) (td testData) {
	origFd := uint32(63)
	newFd := uint32(64)
	filename := "fcntl_dupfd_cloexec_test.txt"

	// Step 1: Open file to get original fd
	openEnterEv, openEnterBytes := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	copy(openEnterEv.Filename[:], filename)
	openEnterBytes, _ = openEnterEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openEnterBytes)

	openExitEv, openExitBytes := makeExitOpenEvent(t, defaulTime+100, defaultPid, defaultTid)
	openExitEv.Ret = int64(origFd)
	openExitBytes, _ = openExitEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openExitBytes)

	// Validate open created the fd
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFileDescriptor(t, el, int32(origFd), filename)
		// Verify original fd doesn't have O_CLOEXEC
		if f, ok := el.files[int32(origFd)]; ok {
			fdFile, ok := f.(file.FdFile)
			if !ok {
				t.Errorf("Expected file to be FdFile type")
			} else if fdFile.Flags().Is(syscall.O_CLOEXEC) {
				t.Errorf("Expected original fd %d to NOT have O_CLOEXEC flag", origFd)
			}
		}
	})

	// Step 2: Call fcntl F_DUPFD_CLOEXEC to duplicate with O_CLOEXEC
	fcntlEnterEv, fcntlEnterBytes := makeEnterFcntlEvent(t, defaulTime+200, defaultPid, defaultTid, origFd, syscall.F_DUPFD_CLOEXEC, 0)
	td.rawTracepoints = append(td.rawTracepoints, fcntlEnterBytes)

	fcntlExitEv, fcntlExitBytes := makeExitRetEvent(t, defaulTime+300, defaultPid, defaultTid, types.SYS_EXIT_FCNTL, int64(newFd))
	td.rawTracepoints = append(td.rawTracepoints, fcntlExitBytes)

	// Validate fcntl duplicated the fd with O_CLOEXEC
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !fcntlEnterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", fcntlEnterEv, ep.EnterEv)
		}
		if !fcntlExitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", fcntlExitEv, ep.ExitEv)
		}

		// Both fds should be tracked and point to the same file
		verifyFileDescriptor(t, el, int32(origFd), filename)
		verifyFileDescriptor(t, el, int32(newFd), filename)

		// Verify the new fd has O_CLOEXEC flag
		if f, ok := el.files[int32(newFd)]; ok {
			fdFile, ok := f.(file.FdFile)
			if !ok {
				t.Errorf("Expected file to be FdFile type")
			} else if !fdFile.Flags().Is(syscall.O_CLOEXEC) {
				t.Errorf("Expected new fd %d to have O_CLOEXEC flag set", newFd)
			}
		}

		// Verify original fd still doesn't have O_CLOEXEC
		if f, ok := el.files[int32(origFd)]; ok {
			fdFile, ok := f.(file.FdFile)
			if !ok {
				t.Errorf("Expected file to be FdFile type")
			} else if fdFile.Flags().Is(syscall.O_CLOEXEC) {
				t.Errorf("Expected original fd %d to NOT have O_CLOEXEC flag", origFd)
			}
		}
	})

	// Step 3: Perform operations on both fds to verify they work independently
	_, readOrigEnterBytes := makeEnterFdEvent(t, defaulTime+400, defaultPid, defaultTid, int32(origFd), types.SYS_ENTER_READ)
	td.rawTracepoints = append(td.rawTracepoints, readOrigEnterBytes)

	_, readOrigExitBytes := makeExitFdEvent(t, defaulTime+500, defaultPid, defaultTid, int32(origFd), types.SYS_EXIT_READ)
	td.rawTracepoints = append(td.rawTracepoints, readOrigExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.File == nil || ep.File.Name() != filename {
			t.Errorf("Expected read from original fd to use file '%s'", filename)
		}
	})

	_, readNewEnterBytes := makeEnterFdEvent(t, defaulTime+600, defaultPid, defaultTid, int32(newFd), types.SYS_ENTER_READ)
	td.rawTracepoints = append(td.rawTracepoints, readNewEnterBytes)

	_, readNewExitBytes := makeExitFdEvent(t, defaulTime+700, defaultPid, defaultTid, int32(newFd), types.SYS_EXIT_READ)
	td.rawTracepoints = append(td.rawTracepoints, readNewExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.File == nil || ep.File.Name() != filename {
			t.Errorf("Expected read from new fd to use file '%s'", filename)
		}
	})

	// Step 4: Close both fds
	_, closeOrigEnterBytes := makeEnterFdEvent(t, defaulTime+800, defaultPid, defaultTid, int32(origFd), types.SYS_ENTER_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeOrigEnterBytes)

	_, closeOrigExitBytes := makeExitFdEvent(t, defaulTime+900, defaultPid, defaultTid, int32(origFd), types.SYS_EXIT_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeOrigExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFdNotTracked(t, el, int32(origFd))
		verifyFileDescriptor(t, el, int32(newFd), filename) // newFd should still be tracked
	})

	_, closeNewEnterBytes := makeEnterFdEvent(t, defaulTime+1000, defaultPid, defaultTid, int32(newFd), types.SYS_ENTER_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeNewEnterBytes)

	_, closeNewExitBytes := makeExitFdEvent(t, defaulTime+1100, defaultPid, defaultTid, int32(newFd), types.SYS_EXIT_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeNewExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFdNotTracked(t, el, int32(origFd))
		verifyFdNotTracked(t, el, int32(newFd))
	})

	return td
}

// Test fcntl error handling (ret=-1)
func makeFcntlErrorTestData(t *testing.T) (td testData) {
	fd := uint32(65)
	filename := "fcntl_error_test.txt"

	// Step 1: Open file to get fd
	openEnterEv, openEnterBytes := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	copy(openEnterEv.Filename[:], filename)
	openEnterBytes, _ = openEnterEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openEnterBytes)

	openExitEv, openExitBytes := makeExitOpenEvent(t, defaulTime+100, defaultPid, defaultTid)
	openExitEv.Ret = int64(fd)
	openExitBytes, _ = openExitEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openExitBytes)

	// Validate open created the fd
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFileDescriptor(t, el, int32(fd), filename)
	})

	// Step 2: Call fcntl with invalid command that will fail
	fcntlEnterEv, fcntlEnterBytes := makeEnterFcntlEvent(t, defaulTime+200, defaultPid, defaultTid, fd, 999999, 0) // Invalid cmd
	td.rawTracepoints = append(td.rawTracepoints, fcntlEnterBytes)

	fcntlExitEv, fcntlExitBytes := makeExitRetEvent(t, defaulTime+300, defaultPid, defaultTid, types.SYS_EXIT_FCNTL, -1) // Error return
	td.rawTracepoints = append(td.rawTracepoints, fcntlExitBytes)

	// Validate fcntl error didn't change anything
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !fcntlEnterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", fcntlEnterEv, ep.EnterEv)
		}
		if !fcntlExitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", fcntlExitEv, ep.ExitEv)
		}

		// File descriptor should still be tracked unchanged
		verifyFileDescriptor(t, el, int32(fd), filename)
	})

	// Step 3: Call fcntl F_SETFL with error
	fcntlEnterEv2, fcntlEnterBytes2 := makeEnterFcntlEvent(t, defaulTime+400, defaultPid, defaultTid, fd, syscall.F_SETFL, uint64(syscall.O_NONBLOCK))
	td.rawTracepoints = append(td.rawTracepoints, fcntlEnterBytes2)

	fcntlExitEv2, fcntlExitBytes2 := makeExitRetEvent(t, defaulTime+500, defaultPid, defaultTid, types.SYS_EXIT_FCNTL, -1) // Error return
	td.rawTracepoints = append(td.rawTracepoints, fcntlExitBytes2)

	// Validate F_SETFL error didn't change flags
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !fcntlEnterEv2.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", fcntlEnterEv2, ep.EnterEv)
		}
		if !fcntlExitEv2.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", fcntlExitEv2, ep.ExitEv)
		}

		// Verify flags were NOT updated due to error
		if f, ok := el.files[int32(fd)]; ok {
			fdFile, ok := f.(file.FdFile)
			if !ok {
				t.Errorf("Expected file to be FdFile type")
			} else if fdFile.Flags().Is(syscall.O_NONBLOCK) {
				t.Errorf("Expected fd %d to NOT have O_NONBLOCK flag after error", fd)
			}
		}
	})

	// Step 4: Call fcntl F_DUPFD with error
	fcntlEnterEv3, fcntlEnterBytes3 := makeEnterFcntlEvent(t, defaulTime+600, defaultPid, defaultTid, fd, syscall.F_DUPFD, 0)
	td.rawTracepoints = append(td.rawTracepoints, fcntlEnterBytes3)

	fcntlExitEv3, fcntlExitBytes3 := makeExitRetEvent(t, defaulTime+700, defaultPid, defaultTid, types.SYS_EXIT_FCNTL, -1) // Error return
	td.rawTracepoints = append(td.rawTracepoints, fcntlExitBytes3)

	// Validate F_DUPFD error didn't create new fd
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !fcntlEnterEv3.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", fcntlEnterEv3, ep.EnterEv)
		}
		if !fcntlExitEv3.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", fcntlExitEv3, ep.ExitEv)
		}

		// Only original fd should be tracked
		if len(el.files) != 1 {
			t.Errorf("Expected only 1 fd to be tracked, got %d", len(el.files))
		}
		verifyFileDescriptor(t, el, int32(fd), filename)
	})

	// Step 5: Close the fd
	_, closeEnterBytes := makeEnterFdEvent(t, defaulTime+800, defaultPid, defaultTid, int32(fd), types.SYS_ENTER_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeEnterBytes)

	_, closeExitBytes := makeExitFdEvent(t, defaulTime+900, defaultPid, defaultTid, int32(fd), types.SYS_EXIT_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFdNotTracked(t, el, int32(fd))
	})

	return td
}

// Test fcntl with invalid file descriptors
func makeFcntlInvalidFdTestData(t *testing.T) (td testData) {
	invalidFd := uint32(999) // Non-existent fd

	// Step 1: Call fcntl F_SETFL on invalid fd
	fcntlEnterEv, fcntlEnterBytes := makeEnterFcntlEvent(t, defaulTime, defaultPid, defaultTid, invalidFd, syscall.F_SETFL, uint64(syscall.O_NONBLOCK))
	td.rawTracepoints = append(td.rawTracepoints, fcntlEnterBytes)

	fcntlExitEv, fcntlExitBytes := makeExitRetEvent(t, defaulTime+100, defaultPid, defaultTid, types.SYS_EXIT_FCNTL, -1) // Error return
	td.rawTracepoints = append(td.rawTracepoints, fcntlExitBytes)

	// Validate fcntl on invalid fd
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !fcntlEnterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", fcntlEnterEv, ep.EnterEv)
		}
		if !fcntlExitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", fcntlExitEv, ep.ExitEv)
		}

		// Verify the file is created as a placeholder FdFile
		if ep.File == nil {
			t.Errorf("Expected file to be created for invalid fd")
		} else {
			_, ok := ep.File.(file.FdFile)
			if !ok {
				t.Errorf("Expected file to be FdFile type")
			}
			// FdFile struct has private fd field, so we can't check it directly
		}
	})

	// Step 2: Open a real file
	realFd := uint32(66)
	filename := "fcntl_invalid_test.txt"

	openEnterEv, openEnterBytes := makeEnterOpenEvent(t, defaulTime+200, defaultPid, defaultTid)
	copy(openEnterEv.Filename[:], filename)
	openEnterBytes, _ = openEnterEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openEnterBytes)

	openExitEv, openExitBytes := makeExitOpenEvent(t, defaulTime+300, defaultPid, defaultTid)
	openExitEv.Ret = int64(realFd)
	openExitBytes, _ = openExitEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFileDescriptor(t, el, int32(realFd), filename)
	})

	// Step 3: Close the real fd
	_, closeEnterBytes := makeEnterFdEvent(t, defaulTime+400, defaultPid, defaultTid, int32(realFd), types.SYS_ENTER_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeEnterBytes)

	_, closeExitBytes := makeExitFdEvent(t, defaulTime+500, defaultPid, defaultTid, int32(realFd), types.SYS_EXIT_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFdNotTracked(t, el, int32(realFd))
	})

	// Step 4: Call fcntl on the closed fd (should fail)
	fcntlEnterEv2, fcntlEnterBytes2 := makeEnterFcntlEvent(t, defaulTime+600, defaultPid, defaultTid, realFd, syscall.F_DUPFD, 0)
	td.rawTracepoints = append(td.rawTracepoints, fcntlEnterBytes2)

	fcntlExitEv2, fcntlExitBytes2 := makeExitRetEvent(t, defaulTime+700, defaultPid, defaultTid, types.SYS_EXIT_FCNTL, -1) // Error return
	td.rawTracepoints = append(td.rawTracepoints, fcntlExitBytes2)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !fcntlEnterEv2.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", fcntlEnterEv2, ep.EnterEv)
		}
		if !fcntlExitEv2.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", fcntlExitEv2, ep.ExitEv)
		}

		// The closed fd should not be tracked and no new fd should be created
		verifyFdNotTracked(t, el, int32(realFd))
	})

	return td
}

// Test open→read→write→close lifecycle
func makeFdLifecycleTestData(t *testing.T) (td testData) {
	fd := int32(42)
	filename := "lifecycle_test.txt"

	// Step 1: Open file
	openEnterEv, openEnterBytes := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	copy(openEnterEv.Filename[:], filename)
	openEnterBytes, _ = openEnterEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openEnterBytes)

	openExitEv, openExitBytes := makeExitOpenEvent(t, defaulTime+100, defaultPid, defaultTid)
	openExitEv.Ret = int64(fd)
	openExitBytes, _ = openExitEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openExitBytes)

	// Validate open created the fd
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if !openEnterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", openEnterEv, ep.EnterEv)
		}
		if !openExitEv.Equals(ep.ExitEv) {
			t.Errorf("Expected '%v' but got '%v'", openExitEv, ep.ExitEv)
		}
		// Verify fd is now tracked
		verifyFileDescriptor(t, el, fd, filename)
	})

	// Step 2: Read from fd
	_, readEnterBytes := makeEnterFdEvent(t, defaulTime+200, defaultPid, defaultTid, fd, types.SYS_ENTER_READ)
	td.rawTracepoints = append(td.rawTracepoints, readEnterBytes)

	_, readExitBytes := makeExitFdEvent(t, defaulTime+300, defaultPid, defaultTid, fd, types.SYS_EXIT_READ)
	td.rawTracepoints = append(td.rawTracepoints, readExitBytes)

	// Validate read has correct file
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.File == nil {
			t.Errorf("Expected file to be set for read operation")
		} else if ep.File.Name() != filename {
			t.Errorf("Expected file name '%s' but got '%s'", filename, ep.File.Name())
		}
		// Verify fd is still tracked
		verifyFileDescriptor(t, el, fd, filename)
	})

	// Step 3: Write to fd
	_, writeEnterBytes := makeEnterFdEvent(t, defaulTime+400, defaultPid, defaultTid, fd, types.SYS_ENTER_WRITE)
	td.rawTracepoints = append(td.rawTracepoints, writeEnterBytes)

	_, writeExitBytes := makeExitFdEvent(t, defaulTime+500, defaultPid, defaultTid, fd, types.SYS_EXIT_WRITE)
	td.rawTracepoints = append(td.rawTracepoints, writeExitBytes)

	// Validate write has correct file
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.File == nil {
			t.Errorf("Expected file to be set for write operation")
		} else if ep.File.Name() != filename {
			t.Errorf("Expected file name '%s' but got '%s'", filename, ep.File.Name())
		}
		// Verify fd is still tracked
		verifyFileDescriptor(t, el, fd, filename)
	})

	// Step 4: Close fd
	_, closeEnterBytes := makeEnterFdEvent(t, defaulTime+600, defaultPid, defaultTid, fd, types.SYS_ENTER_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeEnterBytes)

	_, closeExitBytes := makeExitFdEvent(t, defaulTime+700, defaultPid, defaultTid, fd, types.SYS_EXIT_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeExitBytes)

	// Validate close removed the fd
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.File == nil {
			t.Errorf("Expected file to be set for close operation")
		} else if ep.File.Name() != filename {
			t.Errorf("Expected file name '%s' but got '%s'", filename, ep.File.Name())
		}
		// Verify fd is no longer tracked after close
		verifyFdNotTracked(t, el, fd)
	})

	return td
}

// Test dup/dup2 FD duplication
func makeFdDupTestData(t *testing.T) (td testData) {
	origFd := int32(42)
	dupFd := int32(43)
	filename := "dup_test.txt"

	// Step 1: Open file to get original fd
	openEnterEv, openEnterBytes := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	copy(openEnterEv.Filename[:], filename)
	openEnterBytes, _ = openEnterEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openEnterBytes)

	openExitEv, openExitBytes := makeExitOpenEvent(t, defaulTime+100, defaultPid, defaultTid)
	openExitEv.Ret = int64(origFd)
	openExitBytes, _ = openExitEv.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openExitBytes)

	// Validate open created the fd
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFileDescriptor(t, el, origFd, filename)
	})

	// Step 2: Dup the fd
	_, dupEnterBytes := makeEnterFdEvent(t, defaulTime+200, defaultPid, defaultTid, origFd, types.SYS_ENTER_DUP)
	td.rawTracepoints = append(td.rawTracepoints, dupEnterBytes)

	_, dupExitBytes := makeExitRetEvent(t, defaulTime+300, defaultPid, defaultTid, types.SYS_EXIT_DUP, int64(dupFd))
	td.rawTracepoints = append(td.rawTracepoints, dupExitBytes)

	// Validate dup created new fd pointing to same file
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		// Both fds should be tracked
		verifyFileDescriptor(t, el, origFd, filename)
		verifyFileDescriptor(t, el, dupFd, filename)
	})

	// Step 3: Read from original fd
	_, readOrigEnterBytes := makeEnterFdEvent(t, defaulTime+400, defaultPid, defaultTid, origFd, types.SYS_ENTER_READ)
	td.rawTracepoints = append(td.rawTracepoints, readOrigEnterBytes)

	_, readOrigExitBytes := makeExitFdEvent(t, defaulTime+500, defaultPid, defaultTid, origFd, types.SYS_EXIT_READ)
	td.rawTracepoints = append(td.rawTracepoints, readOrigExitBytes)

	// Validate read from original fd
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.File == nil {
			t.Errorf("Expected file to be set for read operation on original fd")
		} else if ep.File.Name() != filename {
			t.Errorf("Expected file name '%s' but got '%s'", filename, ep.File.Name())
		}
	})

	// Step 4: Read from dup'd fd
	_, readDupEnterBytes := makeEnterFdEvent(t, defaulTime+600, defaultPid, defaultTid, dupFd, types.SYS_ENTER_READ)
	td.rawTracepoints = append(td.rawTracepoints, readDupEnterBytes)

	_, readDupExitBytes := makeExitFdEvent(t, defaulTime+700, defaultPid, defaultTid, dupFd, types.SYS_EXIT_READ)
	td.rawTracepoints = append(td.rawTracepoints, readDupExitBytes)

	// Validate read from dup'd fd
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.File == nil {
			t.Errorf("Expected file to be set for read operation on dup'd fd")
		} else if ep.File.Name() != filename {
			t.Errorf("Expected file name '%s' but got '%s'", filename, ep.File.Name())
		}
	})

	// Step 5: Close original fd
	_, closeOrigEnterBytes := makeEnterFdEvent(t, defaulTime+800, defaultPid, defaultTid, origFd, types.SYS_ENTER_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeOrigEnterBytes)

	_, closeOrigExitBytes := makeExitFdEvent(t, defaulTime+900, defaultPid, defaultTid, origFd, types.SYS_EXIT_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeOrigExitBytes)

	// Validate original fd is closed but dup'd fd still works
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		// Original fd should be untracked
		verifyFdNotTracked(t, el, origFd)
		// Dup'd fd should still be tracked
		verifyFileDescriptor(t, el, dupFd, filename)
	})

	// Step 6: Read from dup'd fd after original is closed
	_, readDup2EnterBytes := makeEnterFdEvent(t, defaulTime+1000, defaultPid, defaultTid, dupFd, types.SYS_ENTER_READ)
	td.rawTracepoints = append(td.rawTracepoints, readDup2EnterBytes)

	_, readDup2ExitBytes := makeExitFdEvent(t, defaulTime+1100, defaultPid, defaultTid, dupFd, types.SYS_EXIT_READ)
	td.rawTracepoints = append(td.rawTracepoints, readDup2ExitBytes)

	// Validate dup'd fd still works after original is closed
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.File == nil {
			t.Errorf("Expected file to be set for read operation on dup'd fd after original closed")
		} else if ep.File.Name() != filename {
			t.Errorf("Expected file name '%s' but got '%s'", filename, ep.File.Name())
		}
	})

	// Step 7: Close dup'd fd
	_, closeDupEnterBytes := makeEnterFdEvent(t, defaulTime+1200, defaultPid, defaultTid, dupFd, types.SYS_ENTER_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeDupEnterBytes)

	_, closeDupExitBytes := makeExitFdEvent(t, defaulTime+1300, defaultPid, defaultTid, dupFd, types.SYS_EXIT_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeDupExitBytes)

	// Validate both fds are now untracked
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFdNotTracked(t, el, origFd)
		verifyFdNotTracked(t, el, dupFd)
	})

	return td
}

// Test multiple files being tracked simultaneously
func makeMultipleFdsTestData(t *testing.T) (td testData) {
	fd1 := int32(42)
	fd2 := int32(43)
	fd3 := int32(44)
	filename1 := "multi_test1.txt"
	filename2 := "multi_test2.txt"
	filename3 := "multi_test3.txt"

	// Open 3 files in sequence
	// File 1
	openEnterEv1, openEnterBytes1 := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	copy(openEnterEv1.Filename[:], filename1)
	openEnterBytes1, _ = openEnterEv1.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openEnterBytes1)

	openExitEv1, openExitBytes1 := makeExitOpenEvent(t, defaulTime+100, defaultPid, defaultTid)
	openExitEv1.Ret = int64(fd1)
	openExitBytes1, _ = openExitEv1.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openExitBytes1)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		verifyFileDescriptor(t, el, fd1, filename1)
	})

	// File 2
	openEnterEv2, openEnterBytes2 := makeEnterOpenEvent(t, defaulTime+200, defaultPid, defaultTid)
	copy(openEnterEv2.Filename[:], filename2)
	openEnterBytes2, _ = openEnterEv2.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openEnterBytes2)

	openExitEv2, openExitBytes2 := makeExitOpenEvent(t, defaulTime+300, defaultPid, defaultTid)
	openExitEv2.Ret = int64(fd2)
	openExitBytes2, _ = openExitEv2.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openExitBytes2)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		// Verify both fd1 and fd2 are tracked
		verifyFileDescriptor(t, el, fd1, filename1)
		verifyFileDescriptor(t, el, fd2, filename2)
	})

	// File 3
	openEnterEv3, openEnterBytes3 := makeEnterOpenEvent(t, defaulTime+400, defaultPid, defaultTid)
	copy(openEnterEv3.Filename[:], filename3)
	openEnterBytes3, _ = openEnterEv3.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openEnterBytes3)

	openExitEv3, openExitBytes3 := makeExitOpenEvent(t, defaulTime+500, defaultPid, defaultTid)
	openExitEv3.Ret = int64(fd3)
	openExitBytes3, _ = openExitEv3.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, openExitBytes3)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		// Verify all 3 fds are tracked
		verifyFileDescriptor(t, el, fd1, filename1)
		verifyFileDescriptor(t, el, fd2, filename2)
		verifyFileDescriptor(t, el, fd3, filename3)
	})

	// Read from fd2
	_, readEnterBytes := makeEnterFdEvent(t, defaulTime+600, defaultPid, defaultTid, fd2, types.SYS_ENTER_READ)
	td.rawTracepoints = append(td.rawTracepoints, readEnterBytes)

	_, readExitBytes := makeExitFdEvent(t, defaulTime+700, defaultPid, defaultTid, fd2, types.SYS_EXIT_READ)
	td.rawTracepoints = append(td.rawTracepoints, readExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.File == nil {
			t.Errorf("Expected file to be set for read operation on fd2")
		} else if ep.File.Name() != filename2 {
			t.Errorf("Expected file name '%s' but got '%s'", filename2, ep.File.Name())
		}
	})

	// Close files in different order: fd2, fd1, fd3
	// Close fd2
	_, closeEnterBytes2 := makeEnterFdEvent(t, defaulTime+800, defaultPid, defaultTid, fd2, types.SYS_ENTER_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeEnterBytes2)

	_, closeExitBytes2 := makeExitFdEvent(t, defaulTime+900, defaultPid, defaultTid, fd2, types.SYS_EXIT_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeExitBytes2)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		// fd2 should be untracked, fd1 and fd3 still tracked
		verifyFileDescriptor(t, el, fd1, filename1)
		verifyFdNotTracked(t, el, fd2)
		verifyFileDescriptor(t, el, fd3, filename3)
	})

	// Close fd1
	_, closeEnterBytes1 := makeEnterFdEvent(t, defaulTime+1000, defaultPid, defaultTid, fd1, types.SYS_ENTER_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeEnterBytes1)

	_, closeExitBytes1 := makeExitFdEvent(t, defaulTime+1100, defaultPid, defaultTid, fd1, types.SYS_EXIT_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeExitBytes1)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		// fd1 and fd2 should be untracked, fd3 still tracked
		verifyFdNotTracked(t, el, fd1)
		verifyFdNotTracked(t, el, fd2)
		verifyFileDescriptor(t, el, fd3, filename3)
	})

	// Write to fd3 (verify it still works)
	_, writeEnterBytes := makeEnterFdEvent(t, defaulTime+1200, defaultPid, defaultTid, fd3, types.SYS_ENTER_WRITE)
	td.rawTracepoints = append(td.rawTracepoints, writeEnterBytes)

	_, writeExitBytes := makeExitFdEvent(t, defaulTime+1300, defaultPid, defaultTid, fd3, types.SYS_EXIT_WRITE)
	td.rawTracepoints = append(td.rawTracepoints, writeExitBytes)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.File == nil {
			t.Errorf("Expected file to be set for write operation on fd3")
		} else if ep.File.Name() != filename3 {
			t.Errorf("Expected file name '%s' but got '%s'", filename3, ep.File.Name())
		}
	})

	// Close fd3
	_, closeEnterBytes3 := makeEnterFdEvent(t, defaulTime+1400, defaultPid, defaultTid, fd3, types.SYS_ENTER_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeEnterBytes3)

	_, closeExitBytes3 := makeExitFdEvent(t, defaulTime+1500, defaultPid, defaultTid, fd3, types.SYS_EXIT_CLOSE)
	td.rawTracepoints = append(td.rawTracepoints, closeExitBytes3)

	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		// All fds should be untracked
		verifyFdNotTracked(t, el, fd1)
		verifyFdNotTracked(t, el, fd2)
		verifyFdNotTracked(t, el, fd3)
	})

	return td
}

// Test exit event without corresponding enter event
func makeExitOnlyEventTestData(t *testing.T) (td testData) {
	// Test with FdEvent - send only exit event
	fd := int32(99)
	_, exitFdBytes := makeExitFdEvent(t, defaulTime, defaultPid, defaultTid, fd, types.SYS_EXIT_READ)
	td.rawTracepoints = append(td.rawTracepoints, exitFdBytes)

	// Test with RetEvent - send only exit event for open
	_, exitOpenBytes := makeExitOpenEvent(t, defaulTime+100, defaultPid, defaultTid)
	td.rawTracepoints = append(td.rawTracepoints, exitOpenBytes)

	// No validates - we expect no output
	// The test framework will verify no events are produced

	return td
}

// Test enter event without corresponding exit event
func makeEnterOnlyEventTestData(t *testing.T) (td testData) {
	// Test with OpenEvent - send only enter event
	_, enterOpenBytes := makeEnterOpenEvent(t, defaulTime, defaultPid, defaultTid)
	td.rawTracepoints = append(td.rawTracepoints, enterOpenBytes)

	// Test with FdEvent - send only enter event
	// Note: This event will not be stored in enterEvs unless comm filter is disabled
	// or the tid already has a comm name established
	_, enterFdBytes := makeEnterFdEvent(t, defaulTime+100, defaultPid, defaultTid+1, 50, types.SYS_ENTER_READ)
	td.rawTracepoints = append(td.rawTracepoints, enterFdBytes)

	// No output expected, but OpenEvent should remain in enterEvs map
	// FdEvent may not be stored due to comm filter requirements

	return td
}

// Test mismatched enter/exit trace IDs
func makeMismatchedPairEventTestData(t *testing.T) (td testData) {
	// Send enter for READ but exit for WRITE (mismatched)
	fd := int32(60)
	_, enterReadBytes := makeEnterFdEvent(t, defaulTime, defaultPid, defaultTid, fd, types.SYS_ENTER_READ)
	td.rawTracepoints = append(td.rawTracepoints, enterReadBytes)

	// Wrong exit type
	_, exitWriteBytes := makeExitFdEvent(t, defaulTime+100, defaultPid, defaultTid, fd, types.SYS_EXIT_WRITE)
	td.rawTracepoints = append(td.rawTracepoints, exitWriteBytes)

	// No output expected due to mismatch

	// Send enter OPEN but exit with wrong trace ID
	_, enterOpenBytes := makeEnterOpenEvent(t, defaulTime+200, defaultPid, defaultTid+1)
	td.rawTracepoints = append(td.rawTracepoints, enterOpenBytes)

	// Create a malformed exit event with wrong trace ID
	exitEv := types.RetEvent{
		EventType: types.EXIT_OPEN_EVENT,
		TraceId:   types.SYS_EXIT_READ, // Wrong! Should be SYS_EXIT_OPENAT
		Time:      defaulTime + 300,
		Ret:       42,
		Pid:       defaultPid,
		Tid:       defaultTid + 1,
	}
	exitBytes, err := exitEv.Bytes()
	if err != nil {
		t.Error(err)
	}
	td.rawTracepoints = append(td.rawTracepoints, exitBytes)

	// No output expected due to trace ID mismatch

	return td
}

// Test out-of-order events
func makeOutOfOrderEventTestData(t *testing.T) (td testData) {
	// Send exit before enter for same tid
	fd := int32(70)
	_, exitBytes := makeExitFdEvent(t, defaulTime, defaultPid, defaultTid, fd, types.SYS_EXIT_READ)
	td.rawTracepoints = append(td.rawTracepoints, exitBytes)

	_, enterBytes := makeEnterFdEvent(t, defaulTime+100, defaultPid, defaultTid, fd, types.SYS_ENTER_READ)
	td.rawTracepoints = append(td.rawTracepoints, enterBytes)

	// No output expected - exit came before enter

	// Send multiple enters before exit (only last should match)
	_, enter1Bytes := makeEnterFdEvent(t, defaulTime+200, defaultPid, defaultTid+1, fd, types.SYS_ENTER_WRITE)
	td.rawTracepoints = append(td.rawTracepoints, enter1Bytes)

	_, enter2Bytes := makeEnterFdEvent(t, defaulTime+300, defaultPid, defaultTid+1, fd, types.SYS_ENTER_WRITE)
	td.rawTracepoints = append(td.rawTracepoints, enter2Bytes)

	_, exit2Bytes := makeExitFdEvent(t, defaulTime+400, defaultPid, defaultTid+1, fd, types.SYS_EXIT_WRITE)
	td.rawTracepoints = append(td.rawTracepoints, exit2Bytes)

	// Should get one output for the second enter/exit pair
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.EnterEv.GetTime() != defaulTime+300 {
			t.Errorf("Expected the second enter event to match, but got time %d", ep.EnterEv.GetTime())
		}
	})

	return td
}

// Test cross-thread event handling
func makeCrossThreadEventTestData(t *testing.T) (td testData) {
	tidA := uint32(100)
	tidB := uint32(200)

	// Send enter from thread A
	enterA := types.OpenEvent{
		EventType: types.ENTER_OPEN_EVENT,
		TraceId:   types.SYS_ENTER_OPENAT,
		Time:      defaulTime,
		Pid:       defaultPid,
		Tid:       tidA,
		Flags:     syscall.O_RDWR,
		Filename:  [types.MAX_FILENAME_LENGTH]byte{},
		Comm:      [types.MAX_PROGNAME_LENGTH]byte{},
	}
	copy(enterA.Filename[:], "fileA.txt")
	copy(enterA.Comm[:], "testcomm")
	enterABytes, err := enterA.Bytes()
	if err != nil {
		t.Error(err)
	}
	td.rawTracepoints = append(td.rawTracepoints, enterABytes)

	// Send enter from thread B
	enterB := types.OpenEvent{
		EventType: types.ENTER_OPEN_EVENT,
		TraceId:   types.SYS_ENTER_OPENAT,
		Time:      defaulTime + 100,
		Pid:       defaultPid,
		Tid:       tidB,
		Flags:     syscall.O_RDWR,
		Filename:  [types.MAX_FILENAME_LENGTH]byte{},
		Comm:      [types.MAX_PROGNAME_LENGTH]byte{},
	}
	copy(enterB.Filename[:], "fileB.txt")
	copy(enterB.Comm[:], "testcomm")
	enterBBytes, err := enterB.Bytes()
	if err != nil {
		t.Error(err)
	}
	td.rawTracepoints = append(td.rawTracepoints, enterBBytes)

	// Send exit for thread B first
	exitB, exitBBytes := makeExitOpenEvent(t, defaulTime+200, defaultPid, tidB)
	exitB.Ret = 43
	exitBBytes, _ = exitB.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, exitBBytes)

	// Validate thread B event
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.EnterEv.GetTid() != tidB {
			t.Errorf("Expected event from thread B (tid %d) but got tid %d", tidB, ep.EnterEv.GetTid())
		}
		if ep.FileName() != "fileB.txt" {
			t.Errorf("Expected fileB.txt but got %s", ep.FileName())
		}
	})

	// Send exit for thread A
	exitA, exitABytes := makeExitOpenEvent(t, defaulTime+300, defaultPid, tidA)
	exitA.Ret = 42
	exitABytes, _ = exitA.Bytes()
	td.rawTracepoints = append(td.rawTracepoints, exitABytes)

	// Validate thread A event
	td.validates = append(td.validates, func(t *testing.T, el *eventLoop, ep *event.Pair) {
		if ep.EnterEv.GetTid() != tidA {
			t.Errorf("Expected event from thread A (tid %d) but got tid %d", tidA, ep.EnterEv.GetTid())
		}
		if ep.FileName() != "fileA.txt" {
			t.Errorf("Expected fileA.txt but got %s", ep.FileName())
		}
	})

	return td
}
