// This file was generated - don't change manually!
package types

const MAX_FILENAME_LENGTH = 256
const OPENAT_ENTER_OP_ID = 1
const OPEN_ENTER_OP_ID = 3
const CLOSE_ENTER_OP_ID = 5
const WRITE_ENTER_OP_ID = 7
const WRITEV_ENTER_OP_ID = 9

type NullEvent struct {
	OpId uint32
	PidTgid uint32
	Time uint64
}

func (n null_event) String() string {
	return fmt.Sprintf("OpId:%v PidTgid:%v Time:%v", n.OpId, n.PidTgid, n.Time)
}


type FdEvent struct {
	OpId uint32
	PidTgid uint32
	Time uint64
	Fd int32
}

func (f fd_event) String() string {
	return fmt.Sprintf("OpId:%v PidTgid:%v Time:%v Fd:%v", f.OpId, f.PidTgid, f.Time, f.Fd)
}


type OpenatEnterEvent struct {
	OpId uint32
	PidTgid uint32
	Time uint64
	Filename [MAX_FILENAME_LENGTH]byte
	Comm [MAX_PROGNAME_LENGTH]byte
}

func (o openat_enter_event) String() string {
	return fmt.Sprintf("OpId:%v PidTgid:%v Time:%v Filename:%v Comm:%v", o.OpId, o.PidTgid, o.Time, o.Filename, o.Comm)
}


type Flags struct {
	UidFilter uint32
}

func (f flags) String() string {
	return fmt.Sprintf("UidFilter:%v", f.UidFilter)
}


