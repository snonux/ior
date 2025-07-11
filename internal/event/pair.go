package event

import (
	"fmt"
	"ior/internal/file"
	"ior/internal/types"
	"strconv"
	"strings"
)

// Represents a pair of enter and exit events (e.g. entering the syscall + exiting it)
type Pair struct {
	EnterEv, ExitEv Event
	File            file.File
	Comm            string
	Duration        uint64
	DurationToPrev  uint64
	Equals          bool
}

func NewPair(enterEv Event) *Pair {
	e := poolOfEventPairs.Get().(*Pair)
	e.EnterEv = enterEv
	e.ExitEv = nil
	e.File = nil
	e.Comm = ""
	e.Duration = 0
	e.DurationToPrev = 0
	e.Equals = false
	return e
}

func (e *Pair) CalculateDurations(prevPairTime uint64) {
	e.Duration = e.ExitEv.GetTime() - e.EnterEv.GetTime()
	if prevPairTime > 0 {
		e.DurationToPrev = e.EnterEv.GetTime() - prevPairTime
	}
}

func (e *Pair) Is(id types.TraceId) bool {
	return e.EnterEv.GetTraceId() == id
}

const EventStreamHeader = "durationToPrevNs,durationNs,comm,pid.tid,name,ret,notice,file"

func (e *Pair) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("%08d,%08d", e.DurationToPrev, e.Duration))

	sb.WriteString(",")
	sb.WriteString(e.Comm)

	sb.WriteString("@")
	sb.WriteString(strconv.FormatInt(int64(e.EnterEv.GetPid()), 10))
	sb.WriteString(".")
	sb.WriteString(strconv.FormatInt(int64(e.EnterEv.GetTid()), 10))

	sb.WriteString(",")
	sb.WriteString(e.EnterEv.GetTraceId().Name())

	sb.WriteString("=>")
	if retEv, ok := e.ExitEv.(*types.RetEvent); ok {
		sb.WriteString(strconv.FormatInt(int64(retEv.Ret), 10))
	}

	sb.WriteString(",")
	if e.File == nil {
		sb.WriteString("N:file")
	} else {
		sb.WriteString(e.File.String())
	}

	return sb.String()
}

func (e *Pair) Flags() file.Flags {
	if e.File == nil {
		return file.Flags(0)
	}
	return e.File.Flags()
}

func (e *Pair) FileName() string {
	if e.File == nil {
		return "N:file"
	}
	return e.File.Name()
}

func (e *Pair) Dump() string {
	return fmt.Sprintf("%v with enterEv(%v) and exitEv(%v)", e, e.EnterEv, e.ExitEv)
}

func (e *Pair) Recycle() {
	e.EnterEv.Recycle()
	e.ExitEv.Recycle()
	e.File = nil
	e.Comm = ""
	e.Duration = 0
	e.DurationToPrev = 0
	e.Equals = false
	poolOfEventPairs.Put(e)
}
