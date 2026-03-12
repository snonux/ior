package eventstream

import (
	"ior/internal/event"
	"ior/internal/streamrow"
)

type StreamEvent = streamrow.Row
type Sequencer = streamrow.Sequencer

// UnknownFD marks events that are not associated with a file descriptor.
const UnknownFD = streamrow.UnknownFD

func NewSequencer(start uint64) *Sequencer {
	return streamrow.NewSequencer(start)
}

func NewStreamEvent(seq uint64, pair *event.Pair) StreamEvent {
	return streamrow.New(seq, pair)
}

// NewWarningEvent creates a synthetic stream row for non-fatal runtime warnings.
func NewWarningEvent(seq uint64, message string) StreamEvent {
	return streamrow.NewWarning(seq, message)
}
