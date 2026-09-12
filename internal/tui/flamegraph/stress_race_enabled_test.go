//go:build race

package flamegraph

func stressBudgetMultiplier() int {
	return 3
}

// stressByteCeilingPercent scales the render-cost byte ceiling. Pinning the GC
// triggers removes most of the byte total's host-dependence, but not all of it:
// under -race the same unmutated tree measured 1550467-1589738 bytes/pass
// against 1466874-1473450 outside it, the residual coming from the race
// detector's own allocations. 130% keeps ~1.47x margin over the worst
// observation - including ones taken under GOGC=1, GOMEMLIMIT=16MiB and 16x CPU
// load, and one taken while the whole race suite was running alongside - while
// still catching a gross regression (json.Marshal -> MarshalIndent lands at
// 2678166 here). The non-race build keeps the tight ceiling, so a regression
// that slips through here is still caught by `mage test`.
func stressByteCeilingPercent() uint64 {
	return 130
}
