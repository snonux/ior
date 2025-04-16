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
