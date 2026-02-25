package eventstream

import (
	"ior/internal/event"
	"ior/internal/types"
)

type StreamEvent struct {
	Seq        uint64
	TimeNs     uint64
	Syscall    string
	Comm       string
	PID        uint32
	TID        uint32
	FileName   string
	DurationNs uint64
	GapNs      uint64
	Bytes      uint64
	RetVal     int64
	IsError    bool
}

func NewStreamEvent(seq uint64, pair *event.Pair) StreamEvent {
	e := StreamEvent{
		Seq:        seq,
		TimeNs:     pair.EnterEv.GetTime(),
		Syscall:    pair.EnterEv.GetTraceId().Name(),
		Comm:       pair.Comm,
		PID:        pair.EnterEv.GetPid(),
		TID:        pair.EnterEv.GetTid(),
		FileName:   pair.FileName(),
		DurationNs: pair.Duration,
		GapNs:      pair.DurationToPrev,
		Bytes:      pair.Bytes,
	}

	if retEv, ok := pair.ExitEv.(*types.RetEvent); ok {
		e.RetVal = retEv.Ret
		e.IsError = retEv.Ret < 0
	}

	return e
}
