package syncpool

import (
	"ioriotng/internal/types"
	"sync"
)

func syncPool[T any]() sync.Pool {
	return sync.Pool{
		New: func() interface{} {
			var value T
			return &value
		},
	}
}

var OpenEnterEvent = syncPool[types.OpenatEnterEvent]()
var FdEvent = syncPool[types.FdEvent]()
var NullEvent = syncPool[types.NullEvent]()
