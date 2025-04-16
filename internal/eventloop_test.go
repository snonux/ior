package internal

import (
	"context"
	"fmt"
	"ior/internal/event"
	"ior/internal/types"
	"syscall"
	"testing"
)

type testData struct {
	rawTracepoints [][]byte                             // All the raw tracepoints sent to the event loop
	validates      []func(t *testing.T, ev *event.Pair) // Validation functions to be called on the event loop output
}

func TestEventloop(t *testing.T) {
	testTable := map[string]testData{
		"OpenEventTest1": makeOpenEventTestData1(t),
		"OpenEventTest2": makeOpenEventTestData2(t),
	}

	ctx, cancel := context.WithCancel(context.Background())
	inCh := make(chan []byte)
	outCh := make(chan *event.Pair)
	defer func() {
		cancel()
		close(inCh)
		close(outCh)
	}()

	ev := newEventLoop()
	ev.printCb = func(ev *event.Pair) { outCh <- ev }
	go ev.run(ctx, inCh)

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
				validate(t, ep)
			}
			select {
			case x := <-outCh:
				t.Errorf("Expected no more events but got '%v'", x)
			default:
			}
		})
	}
}

func makeOpenEventTestData1(t *testing.T) (td testData) {
	enterEv, enterEvBytes := makeEnterOpenEvent(t)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	_, exitEvBytes := makeExitOpenEvent(t)
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, ep *event.Pair) {
		if !enterEv.Equals(ep.EnterEv) {
			t.Errorf("Expected '%v' but got '%v'", enterEv, ep.EnterEv)
			return
		}
		filenameA := ep.FileName()
		filenameB := types.StringValue(enterEv.Filename[:])
		if filenameA != filenameB {
			t.Errorf("Expected file name '%v' but got '%v'", filenameB, filenameA)
			return
		}
		comm := types.StringValue(enterEv.Comm[:])
		if ep.Comm != comm {
			t.Errorf("Expected comm name '%v' but got '%v'", comm, ep.Comm)
			return
		}
		t.Log(fmt.Sprintf("Event pair '%v' appears fine", ep))
	})

	return td
}
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

func makeEnterOpenEvent(t *testing.T) (types.OpenEvent, []byte) {
	ev := types.OpenEvent{
		EventType: types.ENTER_OPEN_EVENT,
		TraceId:   types.SYS_ENTER_OPENAT,
		Time:      123456789,
		Pid:       10,
		Tid:       11,
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

func makeExitOpenEvent(t *testing.T) (types.RetEvent, []byte) {
	ev := types.RetEvent{
		EventType: types.EXIT_OPEN_EVENT,
		TraceId:   types.SYS_EXIT_OPENAT,
		Time:      123456789,
		Ret:       42,
		Pid:       10,
		Tid:       11,
	}

	bytes, err := ev.Bytes()
	if err != nil {
		t.Error(err)
	}
	return ev, bytes
}
