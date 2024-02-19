package types

const MAX_PROGNAME_LENGTH = 16
const OPENAT_ENTER_OP_ID = 1
const OPENAT_EXIT_OP_ID = 2
const OPEN_ENTER_OP_ID = 3
const OPEN_EXIT_OP_ID = 4
const CLOSE_ENTER_OP_ID = 5
const CLOSE_EXIT_OP_ID = 6
const WRITE_ENTER_OP_ID = 7
const WRITE_EXIT_OP_ID = 8
const WRITEV_ENTER_OP_ID = 9
const WRITEV_EXIT_OP_ID = 10

type NullEvent struct {
	OpId uint32
	PidTgid uint32
	Time uint64
}

type FdEvent struct {
	OpId uint32
	PidTgid uint32
	Time uint64
	Fd int32
}

type OpenatEnterEvent struct {
	OpId uint32
	PidTgid uint32
	Time uint64
	Filename [MAX_FILENAME_LENGTH]byte
	Comm [MAX_PROGNAME_LENGTH]byte
}

type Flags struct {
	UidFilter uint32
}

