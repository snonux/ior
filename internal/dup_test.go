package internal

import (
	"ior/internal/types"
	"syscall"
	"testing"
)

// TODO: Finish this test
func TestDup3(t *testing.T) {
	// loop := newEventLoop()

	dup3Event := types.Dup3Event{
		EventType: types.ENTER_DUP3_EVENT,
		TraceId:   types.SYS_ENTER_DUP3,
		Time:      0,
		Pid:       1,
		Tid:       2,
		Fd:        100,
		Flags:     syscall.O_CLOEXEC,
	}

	t.Log(dup3Event.Bytes())
}
