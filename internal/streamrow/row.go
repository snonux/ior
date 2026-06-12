package streamrow

import (
	"sync/atomic"
	"time"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

// Row is the shared syscall stream row model used by live TUI views,
// snapshot export, and future recording outputs.
type Row struct {
	Seq        uint64
	TimeNs     uint64
	Syscall    string
	Family     string
	Comm       string
	PID        uint32
	TID        uint32
	FileName   string
	DurationNs uint64
	GapNs      uint64
	Bytes      uint64
	// AddressSpaceBytes tracks memory-region extent for memory-management syscalls.
	AddressSpaceBytes uint64
	// RequestedSleepNs stores requested sleep duration metadata for sleep syscalls.
	RequestedSleepNs int64
	RetVal           int64
	IsError          bool
	FD               int32
	// EpollOp is the epoll_ctl operation as a readable token (ADD/MOD/DEL),
	// empty for non-epoll_ctl rows. EpollTargetFD and EpollEvents hold the
	// registered descriptor (args[2]) and requested event mask (args[3]->events)
	// for epoll_ctl rows; both are zero when EpollOp is empty.
	EpollOp       string
	EpollTargetFD int32
	EpollEvents   uint32
	// OldName is the source/old path for rename-family (rename/renameat/
	// renameat2) and link-family (link/linkat/symlink/symlinkat) syscalls;
	// FileName carries the "new" path. Empty for every other syscall.
	OldName string
}

func (r Row) SyscallValue() string {
	return r.Syscall
}

func (r Row) FamilyValue() string {
	return r.Family
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
		Seq:               seq,
		TimeNs:            pair.EnterEv.GetTime(),
		Syscall:           pair.EnterEv.GetTraceId().Name(),
		Family:            string(pair.EnterEv.GetTraceId().Family()),
		Comm:              pair.Comm,
		PID:               pair.EnterEv.GetPid(),
		TID:               pair.EnterEv.GetTid(),
		FileName:          pair.FileName(),
		DurationNs:        pair.Duration,
		GapNs:             pair.DurationToPrev,
		Bytes:             pair.Bytes,
		AddressSpaceBytes: pair.AddressSpaceBytes,
		RequestedSleepNs:  pair.RequestedSleepNs,
		FD:                UnknownFD,
		// OldName carries the rename/link source path; FileName is the new path.
		// Empty for non-rename/link syscalls (pair.Oldname is zero there).
		OldName: pair.Oldname,
	}
	if fd, ok := pair.FileDescriptor(); ok {
		row.FD = fd
	}

	// Surface epoll_ctl control metadata when present. The Pair's FD/File still
	// reflect the epoll instance (epfd); these fields expose the target fd and
	// operation so consumers can see which descriptor was registered.
	if pair.HasEpoll {
		row.EpollOp = pair.Epoll.OpName()
		row.EpollTargetFD = pair.Epoll.TargetFD
		row.EpollEvents = pair.Epoll.Events
	}

	if retEv, ok := pair.ExitEv.(*types.RetEvent); ok {
		row.RetVal = retEv.Ret
		row.IsError = retEv.Ret < 0
	}

	return row
}

// --- compile-time interface satisfaction assertion ---
//
// Row must satisfy globalfilter.Candidate so the TUI eventstream model can
// pass stream rows directly into Filter.Matches for live filtering. All
// Candidate methods are defined on the value receiver so both Row and *Row
// satisfy the interface; we assert the value form as it is the common usage.

var _ globalfilter.Candidate = Row{}

// NewWarning creates a synthetic row for non-fatal runtime warnings.
func NewWarning(seq uint64, message string) Row {
	now := uint64(time.Now().UnixNano())
	return Row{
		Seq:      seq,
		TimeNs:   now,
		Syscall:  "warning",
		Family:   string(types.FamilyMisc),
		Comm:     "ior",
		FileName: message,
		FD:       UnknownFD,
		RetVal:   -1,
		IsError:  true,
	}
}
