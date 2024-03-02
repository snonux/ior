package internal

import (
	"fmt"
	. "ioriotng/internal/generated/types"
	"strconv"
	"strings"
)

type event interface {
	String() string
	GetTraceId() TraceId
	GetPid() uint32
	GetTid() uint32
	GetTime() uint32
	Recycle()
}

type enterExitEvent struct {
	enterEv, exitEv    event
	file               file
	comm               string
	tracepointMismatch bool
}

func (e enterExitEvent) is(id TraceId) bool {
	return e.enterEv.GetTraceId() == id
}

func (e enterExitEvent) String() string {
	var sb strings.Builder

	if e.tracepointMismatch {
		sb.WriteString("MISMATCH ")
	}

	duration := e.exitEv.GetTime() - e.enterEv.GetTime()
	sb.WriteString(fmt.Sprintf("%08d µs", duration))

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

func (e enterExitEvent) dump() string {
	return fmt.Sprintf("%v with enterEv(%v) and exitEv(%v)", e, e.enterEv, e.exitEv)
}

func (e enterExitEvent) recycle() {
	e.enterEv.Recycle()
	e.exitEv.Recycle()
}
