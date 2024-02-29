package internal

import (
	"fmt"
	. "ioriotng/internal/generated/types"
	"strconv"
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
	comm            string
	file            file
}

func (e enterExitEvent) is(enterId, exitId SyscallId) bool {
	return enterId == e.enterEv.GetSyscallId() && exitId == e.exitEv.GetSyscallId()
}

func (e enterExitEvent) String() string {
	var sb strings.Builder

	duration := e.exitEv.GetTime() - e.enterEv.GetTime()
	sb.WriteString(fmt.Sprintf("%08d µs", duration))

	sb.WriteString(" ")
	sb.WriteString(e.comm)

	sb.WriteString(" ")
	sb.WriteString(strconv.FormatInt(int64(e.enterEv.GetPid()), 10))
	sb.WriteString(".")
	sb.WriteString(strconv.FormatInt(int64(e.enterEv.GetTid()), 10))

	sb.WriteString(" ")
	sb.WriteString(e.enterEv.GetSyscallId().Name())
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
