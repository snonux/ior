// These types mirror the C types from types.bpf.h
package types

import (
	"fmt"
)

const (
	MAX_FILENAME_LENGTH = 256
	MAX_PROGNAME_LENGTH = 16
)

const (
	OPENAT_ENTER_OP_ID = iota + 1
	OPENAT_EXIT_OP_ID
	CLOSE_ENTER_OP_ID
	CLOSE_EXIT_OP_ID
)

type NullEvent struct {
	OpID uint32
	Tid  uint32
	Time uint64
}

func (ev NullEvent) String() string {
	return fmt.Sprintf("Tid:%v Time:%v", ev.Tid, ev.Time)
}

type FdEvent struct {
	NullEvent
	Fd int32
}

func (ev FdEvent) String() string {
	return fmt.Sprintf("%s Fd:%v", ev.NullEvent.String(), ev.Fd)
}

type OpenatEnterEvent struct {
	NullEvent
	Filename [MAX_FILENAME_LENGTH]byte
	Comm     [MAX_PROGNAME_LENGTH]byte
}

func (ev OpenatEnterEvent) String() string {
	filename := string(ev.Filename[:])
	comm := string(ev.Comm[:])

	return fmt.Sprintf("%s Filename:%s Comm:%s", ev.NullEvent.String(), filename, comm)
}

type FlagValues struct {
	UidFilter uint32
}

// duration := float64(e.ExitTime-e.EnterTime) / float64(1_000_000)
