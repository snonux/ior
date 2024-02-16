package types

import "sync"

func syncPool[T any]() sync.Pool {
	return sync.Pool{
		New: func() interface{} {
			var value T
			return &value
		},
	}
}

var OpenEnterEventPool = syncPool[OpenatEnterEvent]()
var FdEventPool = syncPool[FdEvent]()
var NullEventPool = syncPool[NullEvent]()
