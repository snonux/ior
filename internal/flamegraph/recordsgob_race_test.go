//go:build race

package flamegraph

// raceEnabled skips the heap measurement of recordsgob_test.go: the race
// detector's shadow memory and slower run make the numbers meaningless.
const raceEnabled = true
