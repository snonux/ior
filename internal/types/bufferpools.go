package types

import "sync"

var OpenEnterEventPool = sync.Pool{
	New: func() interface{} {
		return &OpenatEnterEvent{}
	},
}

var FdEventPool = sync.Pool{
	New: func() interface{} {
		return &FdEvent{}
	},
}

var NullEventPool = sync.Pool{
	New: func() interface{} {
		return &NullEvent{}
	},
}
