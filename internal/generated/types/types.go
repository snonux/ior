// This file was generated - don't change manually!
package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
)

type OpId uint32

func (o OpId) String() string {
	switch o {
	case OPENAT_ENTER_OP_ID:
		return "openat_enter"
	case OPENAT_EXIT_OP_ID:
		return "openat_exit"
	case OPEN_ENTER_OP_ID:
		return "open_enter"
	case OPEN_EXIT_OP_ID:
		return "open_exit"
	case CLOSE_ENTER_OP_ID:
		return "close_enter"
	case CLOSE_EXIT_OP_ID:
		return "close_exit"
	case WRITE_ENTER_OP_ID:
		return "write_enter"
	case WRITE_EXIT_OP_ID:
		return "write_exit"
	case WRITEV_ENTER_OP_ID:
		return "writev_enter"
	case WRITEV_EXIT_OP_ID:
		return "writev_exit"
	default:
		panic(fmt.Sprintf("Unknown OpId: %d", o))
	}
}

const MAX_FILENAME_LENGTH = 256
const MAX_PROGNAME_LENGTH = 16
const OPENAT_ENTER_OP_ID OpId = 1
const OPENAT_EXIT_OP_ID OpId = 2
const OPEN_ENTER_OP_ID OpId = 3
const OPEN_EXIT_OP_ID OpId = 4
const CLOSE_ENTER_OP_ID OpId = 5
const CLOSE_EXIT_OP_ID OpId = 6
const WRITE_ENTER_OP_ID OpId = 7
const WRITE_EXIT_OP_ID OpId = 8
const WRITEV_ENTER_OP_ID OpId = 9
const WRITEV_EXIT_OP_ID OpId = 10

type NullEvent struct {
	OpId    OpId
	PidTgid uint32
	Time    uint64
}

func (n NullEvent) String() string {
	return fmt.Sprintf("OpId:%v PidTgid:%v Time:%v", n.OpId, n.PidTgid, n.Time)
}

var poolOfNullEvents = sync.Pool{
	New: func() interface{} { return &NullEvent{} },
}

func NewNullEvent(raw []byte) *NullEvent {
	ev := poolOfNullEvents.Get().(*NullEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, ev); err != nil {
		fmt.Println(ev, raw, len(raw), err)
		panic(raw)
	}
	return ev
}

func RecycleNullEvent(elem *NullEvent) {
	poolOfNullEvents.Put(elem)
}

type FdEvent struct {
	OpId    OpId
	PidTgid uint32
	Time    uint64
	Fd      int32
}

func (f FdEvent) String() string {
	return fmt.Sprintf("OpId:%v PidTgid:%v Time:%v Fd:%v", f.OpId, f.PidTgid, f.Time, f.Fd)
}

var poolOfFdEvents = sync.Pool{
	New: func() interface{} { return &FdEvent{} },
}

func NewFdEvent(raw []byte) *FdEvent {
	ev := poolOfFdEvents.Get().(*FdEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, ev); err != nil {
		fmt.Println(ev, raw, len(raw), err)
		panic(raw)
	}
	return ev
}

func RecycleFdEvent(elem *FdEvent) {
	poolOfFdEvents.Put(elem)
}

type OpenEnterEvent struct {
	OpId     OpId
	PidTgid  uint32
	Time     uint64
	Filename [MAX_FILENAME_LENGTH]byte
	Comm     [MAX_PROGNAME_LENGTH]byte
}

func (o OpenEnterEvent) String() string {
	return fmt.Sprintf("OpId:%v PidTgid:%v Time:%v Filename:%v Comm:%v", o.OpId, o.PidTgid, o.Time, string(o.Filename[:]), string(o.Comm[:]))
}

var poolOfOpenEnterEvents = sync.Pool{
	New: func() interface{} { return &OpenEnterEvent{} },
}

func NewOpenEnterEvent(raw []byte) *OpenEnterEvent {
	ev := poolOfOpenEnterEvents.Get().(*OpenEnterEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, ev); err != nil {
		fmt.Println(ev, raw, len(raw), err)
		panic(raw)
	}
	return ev
}

func RecycleOpenEnterEvent(elem *OpenEnterEvent) {
	poolOfOpenEnterEvents.Put(elem)
}

type Flags struct {
	UidFilter uint32
}

func (f Flags) String() string {
	return fmt.Sprintf("UidFilter:%v", f.UidFilter)
}
