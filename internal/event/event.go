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

// RetCarrier is implemented by every decoded event whose kernel struct carries
// a `ret` field, i.e. the generic exit event (*types.RetEvent) as well as the
// kind-specific exits that need extra payload alongside the return value
// (accept/accept4, pipe/pipe2, socketpair and the eventfd/pidfd family).
//
// The GetRet accessor is emitted by the types generator for any struct with a
// `ret` member (see internal/generate/typesgo.go), so a newly generated
// ret-carrying kind satisfies this interface automatically and consumers such
// as streamrow.New pick up its return value without any change.
type RetCarrier interface {
	GetRet() int64
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
