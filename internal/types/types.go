package types

import "fmt"

type OpenEvent struct {
	FD       int32
	TID      uint32
	Time     uint64
	Filename [256]byte // TODO, use same value as in ioriot.bpf.h
	Comm     [16]byte
}

func (e OpenEvent) String() string {
	filename := e.Filename[:]
	comm := e.Comm[:]
	return fmt.Sprintf("%v tid:%d fd:%d filename:%s, comm:%s",
		e.Time, e.TID, e.FD, string(filename), string(comm))
}

type FdEvent struct {
	FD        int32
	OpID      int32
	TID       uint32
	EnterTime uint64
	ExitTime  uint64
}

func (e FdEvent) String() string {
	duration := (e.ExitTime - e.EnterTime) / 1000000000000.0
	return fmt.Sprintf("%vms opId:%d tid:%v fd:%v", duration, e.OpID, e.TID, e.FD)
}
