package event

import (
	"fmt"
	"ior/internal/file"
	. "ior/internal/generated/types"
	"strconv"
	"strings"
	"sync"
)

var poolOfEventPairs = sync.Pool{
	New: func() interface{} { return &Pair{} },
}

type Event interface {
	String() string
	GetTraceId() TraceId
	GetPid() uint32
	GetTid() uint32
	GetTime() uint64
	Recycle()
}

// Represents a pair of enter and exit events (e.g. entering the syscall + exiting it)
type Pair struct {
	EnterEv, ExitEv    Event
	File               file.File
	Comm               string
	Duration           uint64
	TracepointMismatch bool

	// To calculate the time difference from the previoud event.
	PrevPair       *Pair
	durationToPrev uint64
}

func NewPair(enterEv Event) *Pair {
	e := poolOfEventPairs.Get().(*Pair)
	e.EnterEv = enterEv
	return e
}

func (e *Pair) CalculateDurations() {
	e.Duration = e.ExitEv.GetTime() - e.EnterEv.GetTime()

	if e.PrevPair != nil {
		e.durationToPrev = e.EnterEv.GetTime() - e.PrevPair.ExitEv.GetTime()
	}
}

func (e *Pair) Is(id TraceId) bool {
	return e.EnterEv.GetTraceId() == id
}

const EventStreamHeader = "durationToPrevNs,durationNs,comm,pid.tid,name,ret,notice,file"

func (e *Pair) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("%08d,%08d", e.durationToPrev, e.Duration))

	sb.WriteString(",")
	sb.WriteString(e.Comm)

	sb.WriteString(",")
	sb.WriteString(strconv.FormatInt(int64(e.EnterEv.GetPid()), 10))
	sb.WriteString(".")
	sb.WriteString(strconv.FormatInt(int64(e.EnterEv.GetTid()), 10))

	sb.WriteString(",")
	sb.WriteString(e.EnterEv.GetTraceId().Name())

	sb.WriteString(",")
	if retEv, ok := e.ExitEv.(*RetEvent); ok {
		sb.WriteString(strconv.FormatInt(int64(retEv.Ret), 10))
	}

	sb.WriteString(",")
	sb.WriteString(e.File.String())

	if e.TracepointMismatch {
		sb.WriteString(",MISMATCH")
	}
	return sb.String()
}

func (e *Pair) Dump() string {
	return fmt.Sprintf("%v with enterEv(%v) and exitEv(%v)", e, e.EnterEv, e.ExitEv)
}

func (e *Pair) Recycle() {
	e.EnterEv.Recycle()
	e.ExitEv.Recycle()
	e.PrevPair = nil
	poolOfEventPairs.Put(e)
}

// Only recycle the previous event, as the current event is the previous event of the next event!
// And the previous event is required for calculation of durationToPrev!
func (e *Pair) RecyclePrev() {
	if e.PrevPair == nil {
		return
	}
	e.PrevPair.Recycle()
}
