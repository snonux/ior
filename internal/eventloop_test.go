package internal

import (
	"context"
	"fmt"
	"ior/internal/event"
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

		enterEv, exitEv, validate := openFileTestdata(t)
		inCh <- enterEv
		inCh <- exitEv
		validateCh <- validate
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
		t.Log("printCb", ev)
		outCh <- ev
	}
	ev.run(ctx, inCh)
}

func openFileTestdata(t *testing.T) (enterEvBytes, exitEvBytes []byte, validate validateFunc) {
	enterEv := types.OpenEvent{
		EventType: types.ENTER_OPEN_EVENT,
		TraceId:   types.SYS_ENTER_OPENAT,
		Time:      123456789,
		Pid:       10,
		Tid:       11,
		Flags:     syscall.O_RDWR,
		Filename:  [types.MAX_FILENAME_LENGTH]byte{},
		Comm:      [types.MAX_PROGNAME_LENGTH]byte{},
	}
	copy(enterEv.Filename[:], "testfile.txt")
	copy(enterEv.Comm[:], "testcomm")

	var err error

	enterEvBytes, err = enterEv.Bytes()
	if err != nil {
		t.Error(err)
	}

	exitEv := types.RetEvent{
		EventType: types.EXIT_OPEN_EVENT,
		TraceId:   types.SYS_EXIT_OPENAT,
		Time:      123456789,
		Ret:       42,
		Pid:       10,
		Tid:       11,
	}
	exitEvBytes, err = exitEv.Bytes()
	if err != nil {
		t.Error(err)

	}

	validate = func(t *testing.T, ev *event.Pair) {
		if ev.EnterEv.GetTraceId() != enterEv.TraceId {
			t.Errorf("Expected TraceId '%v' but got '%v'", enterEv.TraceId, ev.EnterEv.GetTraceId())
		}
		t.Log(fmt.Sprintf("Event pair '%v' appears fine", ev))
	}

	return
}
