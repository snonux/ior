package event

import (
	"sync"

	"ior/internal/types"
)

var poolOfEventPairs = sync.Pool{
	New: func() any { return &Pair{} },
}

// EventIdentity carries the immutable identifiers of a decoded syscall event:
// which syscall tracepoint fired (TraceId) and the kernel process/thread IDs
// (Pid, Tid). It is embedded by Event and can be used independently wherever
// only identity fields are needed (e.g. routing, filtering, aggregation keys).
type EventIdentity interface {
	GetTraceId() types.TraceId
	GetPid() uint32
	GetTid() uint32
}

// EventLifecycle manages the pool-backed memory lifetime of a decoded event.
// Callers must call Recycle exactly once after the event is no longer needed
// to return the underlying object to its sync.Pool. It is embedded by Event
// and can be used independently wherever only lifecycle management is needed.
type EventLifecycle interface {
	Recycle()
}

// Event is the common contract implemented by decoded syscall trace events.
// It composes EventIdentity (tracepoint + pid/tid) and EventLifecycle (pool
// return) and adds timing, human-readable formatting, and equality comparison.
type Event interface {
	EventIdentity
	EventLifecycle
	String() string
	GetTime() uint64
	Equals(other any) bool
}
