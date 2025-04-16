package event

import (
	. "ior/internal/types"
	"sync"
)

var poolOfEventPairs = sync.Pool{
	New: func() interface{} { return &Pair{} },
}

type Event interface {
	String() string
	GetTraceId() TraceId
	GetPid() uint32
	GetTid() uint32
	GetTime() uint64
	Equals(other any) bool
	Recycle()
}
