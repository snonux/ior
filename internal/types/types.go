// These types mirror the C types from types.bpf.h
package types

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
	Tid  uint32
	Time uint64
}

type FdEvent struct {
	NullEvent
	Fd int32
}

type OpenatEnterEvent struct {
	NullEvent
	Filename [MAX_FILENAME_LENGTH]byte
	Comm     [MAX_PROGNAME_LENGTH]byte
}

// TODO: Move Flags type struct to here, too

// duration := float64(e.ExitTime-e.EnterTime) / float64(1_000_000)
