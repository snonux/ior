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

func TestEventloop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	inCh := make(chan []byte)
	outCh := make(chan *event.Pair)
	validateCh := make(chan validateFunc)

	go func() {
		defer close(inCh)
		defer close(validateCh)

		addTests(t, inCh, validateCh)
	}()

	go func() {
		for ev := range outCh {
			t.Run(ev.EnterEv.String(), func(t *testing.T) {
				t.Log("Received", ev)
				validate := <-validateCh
				validate(t, ev)
			})
		}
	}()

	ev := newEventLoop()
	ev.printCb = func(ev *event.Pair) {
		outCh <- ev
	}
	ev.run(ctx, inCh)
}

func addTests(t *testing.T, inCh chan []byte, validateCh chan validateFunc) {
	addOpenFileTest1(t, inCh, validateCh)
	addOpenFileTest2(t, inCh, validateCh)
}

func addOpenFileTest1(t *testing.T, inCh chan<- []byte, validateCh chan<- validateFunc) {
	enterEv, enterEvBytes := makeEnterOpenEvent(t)
	inCh <- enterEvBytes // Should be discarded by the event loop automatically
	inCh <- enterEvBytes
	_, exitEvBytes := makeExitOpenEvent(t)
	inCh <- exitEvBytes
	inCh <- exitEvBytes // Should be discarded by the event loop automatically

	validateCh <- func(t *testing.T, ep *event.Pair) {
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
	}
}

func addOpenFileTest2(t *testing.T, inCh chan<- []byte, validateCh chan<- validateFunc) {

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
