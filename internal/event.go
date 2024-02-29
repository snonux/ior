package internal

import (
	"fmt"
	. "ioriotng/internal/generated/types"
	"strings"
)

type event interface {
	String() string
	GetSyscallId() SyscallId
	GetPid() uint32
	GetTid() uint32
	GetTime() uint32
	Recycle()
}

type enterExitEvent struct {
	enterEv, exitEv event
}

func (e enterExitEvent) String() string {
	var sb strings.Builder

	duration := e.exitEv.GetTime() - e.enterEv.GetTime()
	sb.WriteString(fmt.Sprintf("%08d µs", duration))

	sb.WriteString(" ")
	sb.WriteString(e.enterEv.GetSyscallId().Name())

	return sb.String()
}

func (e enterExitEvent) dump() string {
	return fmt.Sprintf("%v with enterEv(%v) and exitEv(%v)", e, e.enterEv, e.exitEv)
}

func (e enterExitEvent) recycle() {
	e.enterEv.Recycle()
	e.exitEv.Recycle()
}
