package eventstream

import (
	"time"

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
	FD         int32
}

// UnknownFD marks events that are not associated with a file descriptor.
const UnknownFD int32 = -1

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
		FD:         UnknownFD,
	}
	if fd, ok := pair.FileDescriptor(); ok {
		e.FD = fd
	}

	if retEv, ok := pair.ExitEv.(*types.RetEvent); ok {
		e.RetVal = retEv.Ret
		e.IsError = retEv.Ret < 0
	}

	return e
}

// NewWarningEvent creates a synthetic stream row for non-fatal runtime warnings.
func NewWarningEvent(message string) StreamEvent {
	now := uint64(time.Now().UnixNano())
	return StreamEvent{
		Seq:      now,
		TimeNs:   now,
		Syscall:  "warning",
		Comm:     "ior",
		FileName: message,
		FD:       UnknownFD,
		RetVal:   -1,
		IsError:  true,
	}
}
