//go:build !race

package flamegraph

// raceEnabled: see recordsgob_race_test.go.
const raceEnabled = false
