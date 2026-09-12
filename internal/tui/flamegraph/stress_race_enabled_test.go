//go:build race

package flamegraph

func stressBudgetMultiplier() int {
	return 3
}

// stressByteCeilingPercent scales the render-cost byte ceiling. Pinning the GC
// removes most of the byte total's host-dependence, but not all of it: under
// -race the same unmutated tree measured 1537298-1624470 bytes/pass against a
// deterministic 1466874 outside it, the residual coming from the race
// detector's own allocations. 130% keeps ~1.44x margin over the worst
// observation - including one taken while the whole race suite was running -
// while still catching a gross regression (json.Marshal -> MarshalIndent lands
// at 2613730). The non-race build keeps the tight ceiling, so a regression that
// slips through here is still caught by `mage test`.
func stressByteCeilingPercent() uint64 {
	return 130
}
