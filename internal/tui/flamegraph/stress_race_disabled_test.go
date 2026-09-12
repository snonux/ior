//go:build !race

package flamegraph

func stressBudgetMultiplier() int {
	return 1
}

// stressByteCeilingPercent scales the render-cost byte ceiling. Outside -race
// the measurement is deterministic once measureStressRenderCost pins the GC,
// so the ceiling applies as written.
func stressByteCeilingPercent() uint64 {
	return 100
}
