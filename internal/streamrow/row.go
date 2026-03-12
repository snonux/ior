package streamrow

import (
	"sync/atomic"
	"time"

	"ior/internal/event"
	"ior/internal/types"
)

// Row is the shared syscall stream row model used by live TUI views,
// snapshot export, and future recording outputs.
type Row struct {
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

func (r Row) SyscallValue() string {
	return r.Syscall
}

func (r Row) CommValue() string {
	return r.Comm
}

func (r Row) FileValue() string {
	return r.FileName
}

func (r Row) PIDValue() uint32 {
	return r.PID
}

func (r Row) TIDValue() uint32 {
	return r.TID
}

func (r Row) FDValue() int32 {
	return r.FD
}

func (r Row) LatencyValue() uint64 {
	return r.DurationNs
}

func (r Row) GapValue() uint64 {
	return r.GapNs
}

func (r Row) BytesValue() uint64 {
	return r.Bytes
}

func (r Row) ReturnValue() int64 {
	return r.RetVal
}

func (r Row) ErrorValue() bool {
	return r.IsError
}

// UnknownFD marks events that are not associated with a file descriptor.
const UnknownFD int32 = -1

// Sequencer hands out strictly increasing row sequence numbers.
type Sequencer struct {
	next atomic.Uint64
}

// NewSequencer constructs a monotonic sequence generator. The first call to
// Next returns start+1.
func NewSequencer(start uint64) *Sequencer {
	s := &Sequencer{}
	s.next.Store(start)
	return s
}

// Next returns the next sequence number.
func (s *Sequencer) Next() uint64 {
	if s == nil {
		return 0
	}
	return s.next.Add(1)
}

// New converts one syscall pair into the shared row model.
func New(seq uint64, pair *event.Pair) Row {
	row := Row{
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
		row.FD = fd
	}

	if retEv, ok := pair.ExitEv.(*types.RetEvent); ok {
		row.RetVal = retEv.Ret
		row.IsError = retEv.Ret < 0
	}

	return row
}

// NewWarning creates a synthetic row for non-fatal runtime warnings.
func NewWarning(seq uint64, message string) Row {
	now := uint64(time.Now().UnixNano())
	return Row{
		Seq:      seq,
		TimeNs:   now,
		Syscall:  "warning",
		Comm:     "ior",
		FileName: message,
		FD:       UnknownFD,
		RetVal:   -1,
		IsError:  true,
	}
}
