package common

import "time"

// SelectionWishGrace bounds how long a selection keeps looking for an item
// that vanished from its list or layout (the dashboard tables' stickyKey, the
// flamegraph's wantedPath). Both start it when the wish is first made, so a
// view emptied for an hour does not pull the selection back to its old item,
// while the window still covers two default auto-reset intervals for a
// workload that is quiet after a reset. One constant keeps the two tab kinds
// from drifting apart.
//
// statsengine.ProcessCarryRetention (how long Engine.Reset remembers a silent
// process's identity) must stay at least twice this; wish_test.go pins it.
const SelectionWishGrace = time.Minute
