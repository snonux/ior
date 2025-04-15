package internal

import (
	"context"
	"ior/internal/event"
	"ior/internal/types"
	"syscall"
	"testing"
)

// TODO: Finish this test
func TestEventloop(t *testing.T) {
	T = t

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inCh := make(chan []byte)
	outCh := make(chan *event.Pair, 2)

	go func() {
		defer close(inCh)
		sendOpenFileTracepoints(t, inCh)
	}()

	go func() {
		for ev := range outCh {
			t.Log("Received", ev)
		}
	}()

	ev := newEventLoop()
	ev.printCb = func(ev *event.Pair) {
		t.Log("printCb", ev)
		outCh <- ev
	}
	ev.run(ctx, inCh)
}

func sendOpenFileTracepoints(t *testing.T, ch chan<- []byte) {
	enterOpenEvent := types.OpenEvent{
		EventType: types.ENTER_OPEN_EVENT,
		TraceId:   types.SYS_ENTER_OPENAT,
		Time:      123456789,
		Pid:       10,
		Tid:       10,
		Flags:     syscall.O_RDWR,
		Filename:  [types.MAX_FILENAME_LENGTH]byte{},
		Comm:      [types.MAX_PROGNAME_LENGTH]byte{},
	}
	copy(enterOpenEvent.Filename[:], "testfile.txt")
	copy(enterOpenEvent.Comm[:], "testcomm")

	bytes, err := enterOpenEvent.Bytes()
	if err != nil {
		t.Error(err)
	}
	t.Log("Sending", enterOpenEvent, bytes)
	ch <- bytes

	exitOpenEvent := types.RetEvent{
		EventType: types.EXIT_OPEN_EVENT,
		TraceId:   types.SYS_EXIT_OPENAT,
		Time:      123456789,
		Ret:       42,
		Pid:       10,
		Tid:       10,
	}
	bytes, err = exitOpenEvent.Bytes()
	if err != nil {
		t.Error(err)
	}
	t.Log("Sending", exitOpenEvent, bytes)
	ch <- bytes
}
