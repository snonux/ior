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
	OpId OpId
	Pid  uint32
	Tid  uint32
	Time uint64
}

func (n NullEvent) String() string {
	return fmt.Sprintf("OpId:%v Pid:%v Tid:%v Time:%v", n.OpId, n.Pid, n.Tid, n.Time)
}

var poolOfNullEvents = sync.Pool{
	New: func() interface{} { return &NullEvent{} },
}

func NewNullEvent(raw []byte) *NullEvent {
	n := poolOfNullEvents.Get().(*NullEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, n); err != nil {
		fmt.Println(n, raw, len(raw), err)
		panic(raw)
	}
	return n
}

func (n *NullEvent) Recycle() {
	poolOfNullEvents.Put(n)
}

type FdEvent struct {
	OpId OpId
	Pid  uint32
	Tid  uint32
	Time uint64
	Fd   int32
}

func (f FdEvent) String() string {
	return fmt.Sprintf("OpId:%v Pid:%v Tid:%v Time:%v Fd:%v", f.OpId, f.Pid, f.Tid, f.Time, f.Fd)
}

var poolOfFdEvents = sync.Pool{
	New: func() interface{} { return &FdEvent{} },
}

func NewFdEvent(raw []byte) *FdEvent {
	f := poolOfFdEvents.Get().(*FdEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, f); err != nil {
		fmt.Println(f, raw, len(raw), err)
		panic(raw)
	}
	return f
}

func (f *FdEvent) Recycle() {
	poolOfFdEvents.Put(f)
}

type OpenEnterEvent struct {
	OpId     OpId
	Filename [MAX_FILENAME_LENGTH]byte
	Comm     [MAX_PROGNAME_LENGTH]byte
	Pid      uint32
	Tid      uint32
	Time     uint64
}

func (o OpenEnterEvent) String() string {
	return fmt.Sprintf("OpId:%v Filename:%v Comm:%v Pid:%v Tid:%v Time:%v", o.OpId, string(o.Filename[:]), string(o.Comm[:]), o.Pid, o.Tid, o.Time)
}

var poolOfOpenEnterEvents = sync.Pool{
	New: func() interface{} { return &OpenEnterEvent{} },
}

func NewOpenEnterEvent(raw []byte) *OpenEnterEvent {
	o := poolOfOpenEnterEvents.Get().(*OpenEnterEvent)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, o); err != nil {
		fmt.Println(o, raw, len(raw), err)
		panic(raw)
	}
	return o
}

func (o *OpenEnterEvent) Recycle() {
	poolOfOpenEnterEvents.Put(o)
}
