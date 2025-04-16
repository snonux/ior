package internal

import (
	"context"
	"fmt"
	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
	"syscall"
	"testing"
)

type validateFunc func(t *testing.T, ev *event.Pair)

type testData struct {
	rawTracepoints [][]byte       // All the raw tracepoints sent to the event loop
	validates      []validateFunc // Validation functions to check the event pairs
}

func TestEventloop(t *testing.T) {
	testTable := map[string]testData{
		"OpenEventTest": makeOpenEventTestData(t),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	inCh := make(chan []byte)
	defer close(inCh)

	outCh := make(chan *event.Pair)
	defer close(outCh)

	ev := newEventLoop()
	ev.printCb = func(ev *event.Pair) { outCh <- ev }
	go ev.run(ctx, inCh)

	for testName, td := range testTable {
		t.Run(testName, func(t *testing.T) {
			go func() {
				for _, raw := range td.rawTracepoints {
					inCh <- raw
				}
			}()
			for _, validate := range td.validates {
				validate(t, <-outCh)
			}
			select {
			case x := <-outCh:
				t.Errorf("Expected no more events but got '%v'", x)
			default:
			}
		})
	}
}

func makeOpenEventTestData(t *testing.T) (td testData) {
	enterEv, enterEvBytes := makeEnterOpenEvent(t)
	td.rawTracepoints = append(td.rawTracepoints, enterEvBytes)

	_, exitEvBytes := makeExitOpenEvent(t)
	td.rawTracepoints = append(td.rawTracepoints, exitEvBytes)

	td.validates = append(td.validates, func(t *testing.T, ep *event.Pair) {
		if ep.EnterEv.GetTraceId() != enterEv.TraceId {
			t.Errorf("Expected TraceId '%v' but got '%v'", enterEv.TraceId, ep.EnterEv.GetTraceId())
			return
		}
		filenameA := ep.FileName()
		filenameB := file.StringValue(enterEv.Filename[:])
		if filenameA != filenameB {
			t.Errorf("Expected file name '%v' but got '%v'", filenameB, filenameA)
			return
		}
		comm := file.StringValue(enterEv.Comm[:])
		if ep.Comm != comm {
			t.Errorf("Expected comm name '%v' but got '%v'", comm, ep.Comm)
			return
		}
		t.Log(fmt.Sprintf("Event pair '%v' appears fine", ep))
	})

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
