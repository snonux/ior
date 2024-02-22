// This file was generated - don't change manually!
package types

import "fmt"

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
	OpId    uint32
	PidTgid uint32
	Time    uint64
}

func (n NullEvent) String() string {
	return fmt.Sprintf("OpId:%v PidTgid:%v Time:%v", n.OpId, n.PidTgid, n.Time)
}

type FdEvent struct {
	OpId    uint32
	PidTgid uint32
	Time    uint64
	Fd      int32
}

func (f FdEvent) String() string {
	return fmt.Sprintf("OpId:%v PidTgid:%v Time:%v Fd:%v", f.OpId, f.PidTgid, f.Time, f.Fd)
}

type OpenatEnterEvent struct {
	OpId     uint32
	PidTgid  uint32
	Time     uint64
	Filename [MAX_FILENAME_LENGTH]byte
	Comm     [MAX_PROGNAME_LENGTH]byte
}

func (o OpenatEnterEvent) String() string {
	return fmt.Sprintf("OpId:%v PidTgid:%v Time:%v Filename:%v Comm:%v", o.OpId, o.PidTgid, o.Time, string(o.Filename[:]), string(o.Comm[:]))
}

type Flags struct {
	UidFilter uint32
}

func (f Flags) String() string {
	return fmt.Sprintf("UidFilter:%v", f.UidFilter)
}
