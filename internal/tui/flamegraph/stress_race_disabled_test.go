//go:build !race

package flamegraph

func stressBudgetMultiplier() int {
	return 1
}

// stressByteCeilingPercent scales the render-cost byte ceiling. Outside -race
// the measurement holds to 0.45% once measureStressRenderCost pins both GC
// triggers (1466874-1473450 idle; 1491120 is the worst reached under GOGC=1,
// GOMEMLIMIT=16MiB, GOMAXPROCS=128 and 16x CPU load), so the ceiling applies as
// written.
func stressByteCeilingPercent() uint64 {
	return 100
}
