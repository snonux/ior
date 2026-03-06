package event

import (
	"sync"

	"ior/internal/types"
)

var poolOfEventPairs = sync.Pool{
	New: func() interface{} { return &Pair{} },
}

// Event is the common contract implemented by decoded syscall trace events.
type Event interface {
	String() string
	GetTraceId() types.TraceId
	GetPid() uint32
	GetTid() uint32
	GetTime() uint64
	Equals(other any) bool
	Recycle()
}
