package types

import "fmt"

type OpenEvent struct {
	FD        int32
	TID       uint32
	EnterTime uint64
	ExitTime  uint64
	Filename  [256]byte // TODO, use same value as in ioriot.bpf.h
	Comm      [16]byte
}

func (e OpenEvent) String() string {
	filename := e.Filename[:]
	comm := e.Comm[:]
	duration := float64(e.ExitTime-e.EnterTime) / float64(1_000_000)
	return fmt.Sprintf("time:(%v=(%v-%v)/1mio) tid:%d fd:%d filename:%s, comm:%s",
		duration, e.EnterTime, e.ExitTime, e.TID, e.FD, string(filename), string(comm))
}

type FdEvent struct {
	FD        int32
	OpID      int32
	TID       uint32
	EnterTime uint64
	ExitTime  uint64
}

func (e FdEvent) String() string {
	duration := float64(e.ExitTime-e.EnterTime) / float64(1_000_000)
	return fmt.Sprintf("time:(%vms=(%v-%v)/1mio) opId:%d tid:%v fd:%v",
		duration, e.EnterTime, e.ExitTime, e.OpID, e.TID, e.FD)
}
