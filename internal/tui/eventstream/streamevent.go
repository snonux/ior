package eventstream

import (
	"ior/internal/event"
	"ior/internal/streamrow"
)

// StreamEvent is the stream tab's name for the shared row model.
type StreamEvent = streamrow.Row

// Sequencer is the stream tab's name for the shared row sequencer.
type Sequencer = streamrow.Sequencer

// UnknownFD marks events that are not associated with a file descriptor.
const UnknownFD = streamrow.UnknownFD

// NewSequencer constructs a monotonic sequencer starting after start.
func NewSequencer(start uint64) *Sequencer {
	return streamrow.NewSequencer(start)
}

// NewStreamEvent converts one syscall pair into a stream row.
func NewStreamEvent(seq uint64, pair *event.Pair) StreamEvent {
	return streamrow.New(seq, pair)
}

// NewWarningEvent creates a synthetic stream row for non-fatal runtime warnings.
func NewWarningEvent(seq uint64, message string) StreamEvent {
	return streamrow.NewWarning(seq, message)
}
