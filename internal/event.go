package internal

import (
	"fmt"
	. "ioriotng/internal/generated/types"
	"strconv"
	"strings"
	"sync"
)

var poolOfEventPairs = sync.Pool{
	New: func() interface{} { return &eventPair{} },
}

type event interface {
	String() string
	GetTraceId() TraceId
	GetPid() uint32
	GetTid() uint32
	GetTime() uint32
	Recycle()
}

// Represents a pair of enter and exit events (e.g. entering the syscall + exiting it)
type eventPair struct {
	enterEv, exitEv    event
	file               file
	comm               string
	duration           uint32
	tracepointMismatch bool
	// To calculate the time difference from the previoud event.
	prevPair       *eventPair
	durationToPrev uint32
}

func newEventPair(enterEv event) *eventPair {
	e := poolOfEventPairs.Get().(*eventPair)
	e.enterEv = enterEv
	return e
}

func (e *eventPair) calculateDurations() {
	e.duration = e.exitEv.GetTime() - e.enterEv.GetTime()
	if e.prevPair != nil {
		e.durationToPrev = e.enterEv.GetTime() - e.prevPair.exitEv.GetTime()
	}
}

func (e *eventPair) is(id TraceId) bool {
	return e.enterEv.GetTraceId() == id
}

func (e *eventPair) String() string {
	var sb strings.Builder

	if e.tracepointMismatch {
		sb.WriteString("MISMATCH ")
	}

	sb.WriteString(fmt.Sprintf("%08dµs %08dµs", e.durationToPrev, e.duration))

	sb.WriteString(" ")
	sb.WriteString(e.comm)

	sb.WriteString(" ")
	sb.WriteString(strconv.FormatInt(int64(e.enterEv.GetPid()), 10))
	sb.WriteString(".")
	sb.WriteString(strconv.FormatInt(int64(e.enterEv.GetTid()), 10))

	sb.WriteString(" ")
	sb.WriteString(e.enterEv.GetTraceId().Name())
	if retEv, ok := e.exitEv.(*RetEvent); ok {
		sb.WriteString(":")
		sb.WriteString(strconv.FormatInt(int64(retEv.Ret), 10))
	}

	sb.WriteString(" ")
	sb.WriteString(e.file.String())

	return sb.String()
}

func (e *eventPair) dump() string {
	return fmt.Sprintf("%v with enterEv(%v) and exitEv(%v)", e, e.enterEv, e.exitEv)
}

func (e *eventPair) recycle() {
	e.enterEv.Recycle()
	e.exitEv.Recycle()
	e.prevPair = nil
	poolOfEventPairs.Put(e)
}
