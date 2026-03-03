package benchutil

import (
	"fmt"
	"syscall"

	"ior/internal/generate"
	"ior/internal/types"
)

const (
	defaultPairDelta uint64 = 100
	defaultOpenRet   int64  = 42
	defaultOpenFlags int32  = syscall.O_RDWR
	defaultOpenName         = "testfile.txt"
	defaultOpenComm         = "testcomm"
)

type EventGenerator struct {
	PairDelta uint64
}

func NewEventGenerator() EventGenerator {
	return EventGenerator{PairDelta: defaultPairDelta}
}

func (g EventGenerator) EnterOpenEvent(time uint64, pid, tid uint32) (types.OpenEvent, []byte) {
	ev := types.OpenEvent{
		EventType: types.ENTER_OPEN_EVENT,
		TraceId:   types.SYS_ENTER_OPENAT,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
		Flags:     defaultOpenFlags,
		Filename:  [types.MAX_FILENAME_LENGTH]byte{},
		Comm:      [types.MAX_PROGNAME_LENGTH]byte{},
	}
	copy(ev.Filename[:], defaultOpenName)
	copy(ev.Comm[:], defaultOpenComm)
	return ev, mustBytes(&ev)
}

func (g EventGenerator) ExitOpenEvent(time uint64, pid, tid uint32) (types.RetEvent, []byte) {
	ev := types.RetEvent{
		EventType: types.EXIT_OPEN_EVENT,
		TraceId:   types.SYS_EXIT_OPENAT,
		Time:      time,
		Ret:       defaultOpenRet,
		Pid:       pid,
		Tid:       tid,
	}
	return ev, mustBytes(&ev)
}

func (g EventGenerator) EnterFdEvent(time uint64, pid, tid uint32, fd int32, traceID types.TraceId) (types.FdEvent, []byte) {
	ev := types.FdEvent{
		EventType: types.ENTER_FD_EVENT,
		TraceId:   traceID,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
		Fd:        fd,
	}
	return ev, mustBytes(&ev)
}

func (g EventGenerator) ExitFdEvent(time uint64, pid, tid uint32, fd int32, traceID types.TraceId) (types.FdEvent, []byte) {
	ev := types.FdEvent{
		EventType: types.EXIT_FD_EVENT,
		TraceId:   traceID,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
		Fd:        fd,
	}
	return ev, mustBytes(&ev)
}

func (g EventGenerator) EnterNullEvent(time uint64, pid, tid uint32, traceID types.TraceId) (types.NullEvent, []byte) {
	ev := types.NullEvent{
		EventType: types.ENTER_NULL_EVENT,
		TraceId:   traceID,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
	}
	return ev, mustBytes(&ev)
}

func (g EventGenerator) ExitNullEvent(time uint64, pid, tid uint32, traceID types.TraceId) (types.NullEvent, []byte) {
	ev := types.NullEvent{
		EventType: types.EXIT_NULL_EVENT,
		TraceId:   traceID,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
	}
	return ev, mustBytes(&ev)
}

func (g EventGenerator) ExitRetEvent(time uint64, pid, tid uint32, traceID types.TraceId, ret int64) (types.RetEvent, []byte) {
	ev := types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   traceID,
		Time:      time,
		Ret:       ret,
		Pid:       pid,
		Tid:       tid,
		RetType:   retType(traceID),
	}
	return ev, mustBytes(&ev)
}

func (g EventGenerator) EnterPathEvent(time uint64, pid, tid uint32, pathname string, traceID types.TraceId) (types.PathEvent, []byte) {
	ev := types.PathEvent{
		EventType: types.ENTER_PATH_EVENT,
		TraceId:   traceID,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
		Pathname:  [types.MAX_FILENAME_LENGTH]byte{},
	}
	copy(ev.Pathname[:], pathname)
	return ev, mustBytes(&ev)
}

func (g EventGenerator) EnterNameEvent(time uint64, pid, tid uint32, oldname, newname string, traceID types.TraceId) (types.NameEvent, []byte) {
	ev := types.NameEvent{
		EventType: types.ENTER_NAME_EVENT,
		TraceId:   traceID,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
		Oldname:   [types.MAX_FILENAME_LENGTH]byte{},
		Newname:   [types.MAX_FILENAME_LENGTH]byte{},
	}
	copy(ev.Oldname[:], oldname)
	copy(ev.Newname[:], newname)
	return ev, mustBytes(&ev)
}

func (g EventGenerator) EnterFcntlEvent(time uint64, pid, tid uint32, fd uint32, cmd uint32, arg uint64) (types.FcntlEvent, []byte) {
	ev := types.FcntlEvent{
		EventType: types.ENTER_FCNTL_EVENT,
		TraceId:   types.SYS_ENTER_FCNTL,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
		Fd:        fd,
		Cmd:       cmd,
		Arg:       arg,
	}
	return ev, mustBytes(&ev)
}

func (g EventGenerator) EnterDup3Event(time uint64, pid, tid uint32, fd int32, flags int32) (types.Dup3Event, []byte) {
	ev := types.Dup3Event{
		EventType: types.ENTER_DUP3_EVENT,
		TraceId:   types.SYS_ENTER_DUP3,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
		Fd:        fd,
		Flags:     flags,
	}
	return ev, mustBytes(&ev)
}

func (g EventGenerator) EnterOpenByHandleAtEvent(time uint64, pid, tid uint32, flags int32) (types.OpenByHandleAtEvent, []byte) {
	ev := types.OpenByHandleAtEvent{
		EventType: types.ENTER_OPEN_BY_HANDLE_AT_EVENT,
		TraceId:   types.SYS_ENTER_OPEN_BY_HANDLE_AT,
		Time:      time,
		Pid:       pid,
		Tid:       tid,
		Flags:     flags,
	}
	return ev, mustBytes(&ev)
}

func (g EventGenerator) OpenPair(time uint64, pid, tid uint32) ([]byte, []byte) {
	_, enter := g.EnterOpenEvent(time, pid, tid)
	_, exit := g.ExitOpenEvent(time+g.pairDelta(), pid, tid)
	return enter, exit
}

func (g EventGenerator) FdPair(time uint64, pid, tid uint32, fd int32, enterTraceID, exitTraceID types.TraceId, ret int64) ([]byte, []byte) {
	_, enter := g.EnterFdEvent(time, pid, tid, fd, enterTraceID)
	_, exit := g.ExitRetEvent(time+g.pairDelta(), pid, tid, exitTraceID, ret)
	return enter, exit
}

func (g EventGenerator) NullPair(time uint64, pid, tid uint32, enterTraceID, exitTraceID types.TraceId) ([]byte, []byte) {
	_, enter := g.EnterNullEvent(time, pid, tid, enterTraceID)
	_, exit := g.ExitNullEvent(time+g.pairDelta(), pid, tid, exitTraceID)
	return enter, exit
}

func (g EventGenerator) PathPair(time uint64, pid, tid uint32, pathname string, enterTraceID, exitTraceID types.TraceId, ret int64) ([]byte, []byte) {
	_, enter := g.EnterPathEvent(time, pid, tid, pathname, enterTraceID)
	_, exit := g.ExitRetEvent(time+g.pairDelta(), pid, tid, exitTraceID, ret)
	return enter, exit
}

func (g EventGenerator) NamePair(time uint64, pid, tid uint32, oldname, newname string, enterTraceID, exitTraceID types.TraceId, ret int64) ([]byte, []byte) {
	_, enter := g.EnterNameEvent(time, pid, tid, oldname, newname, enterTraceID)
	_, exit := g.ExitRetEvent(time+g.pairDelta(), pid, tid, exitTraceID, ret)
	return enter, exit
}

func (g EventGenerator) FcntlPair(time uint64, pid, tid uint32, fd uint32, cmd uint32, arg uint64, exitTraceID types.TraceId, ret int64) ([]byte, []byte) {
	_, enter := g.EnterFcntlEvent(time, pid, tid, fd, cmd, arg)
	_, exit := g.ExitRetEvent(time+g.pairDelta(), pid, tid, exitTraceID, ret)
	return enter, exit
}

func (g EventGenerator) Dup3Pair(time uint64, pid, tid uint32, fd int32, flags int32, exitTraceID types.TraceId, ret int64) ([]byte, []byte) {
	_, enter := g.EnterDup3Event(time, pid, tid, fd, flags)
	_, exit := g.ExitRetEvent(time+g.pairDelta(), pid, tid, exitTraceID, ret)
	return enter, exit
}

func (g EventGenerator) pairDelta() uint64 {
	if g.PairDelta == 0 {
		return defaultPairDelta
	}
	return g.PairDelta
}

func mustBytes(event interface{ Bytes() ([]byte, error) }) []byte {
	raw, err := event.Bytes()
	if err != nil {
		panic(fmt.Sprintf("event serialization failed: %v", err))
	}
	return raw
}

func retType(traceID types.TraceId) uint32 {
	switch generate.ClassifyRet("sys_exit_" + traceID.Name()) {
	case generate.ReadClassified:
		return types.READ_CLASSIFIED
	case generate.WriteClassified:
		return types.WRITE_CLASSIFIED
	case generate.TransferClassified:
		return types.TRANSFER_CLASSIFIED
	default:
		return types.UNCLASSIFIED
	}
}
