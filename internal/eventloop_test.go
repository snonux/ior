package internal

import (
	"context"
	"ior/internal/event"
	"ior/internal/types"
	"syscall"
	"testing"
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
		"ReadEventTest":     makeReadEventTestData(t),
		"WriteEventTest":    makeWriteEventTestData(t),
		"CloseEventTest":    makeCloseEventTestData(t),
		"FsyncEventTest":    makeFsyncEventTestData(t),
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
		"SyncEventTest": makeSyncEventTestData(t),
		// Dup3Event tests
		"Dup3EventTest": makeDup3EventTestData(t),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	inCh := make(chan []byte)
	outCh := make(chan *event.Pair)

	el := newEventLoop()
	el.printCb = func(ev *event.Pair) { outCh <- ev }
	go el.run(ctx, inCh)

	for testName, td := range testTable {
		t.Run(testName, func(t *testing.T) {
			go func() {
				for _, raw := range td.rawTracepoints {
					t.Log("Sending raw tracepoint", raw, "simulating BPF sending this")
					inCh <- raw
				}
			}()
			for _, validate := range td.validates {
				ep := <-outCh
				t.Log("Received", ep)
				validate(t, el, ep)
			}
			select {
			case x := <-outCh:
				t.Errorf("Expected no more events but got '%v'", x)
			default:
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