//go:build !race

package event

import (
	"testing"

	"ior/internal/file"
	"ior/internal/textsafe"
	"ior/internal/types"
)

// TestPairCSVRowEscaperCostsNothingForCleanRows checks the escaper adds no
// allocation to a row whose fields are already safe (the common case on
// the -plain hot path). Excluded under -race, whose instrumentation can
// allocate on its own and make the two counts differ.
func TestPairCSVRowEscaperCostsNothingForCleanRows(t *testing.T) {
	pair := newStringTestPair("dd", 1, 2, types.SYS_ENTER_READ, types.SYS_EXIT_READ, 1, file.NewFd(0, "/dev/zero", 0))
	raw := testing.AllocsPerRun(100, func() { _ = pair.CSVRow(nil) })
	escaped := testing.AllocsPerRun(100, func() { _ = pair.CSVRow(textsafe.Escape) })
	if escaped != raw {
		t.Fatalf("CSVRow(Escape) allocates %.1f times, CSVRow(nil) %.1f; clean rows must not pay for escaping", escaped, raw)
	}
}

// TestPairAppendCSVRowIsAllocationFree pins the point of the append-based
// formatter: into a reused buffer a clean row costs no allocation, with or
// without the escaper. Excluded under -race for the reason above.
func TestPairAppendCSVRowIsAllocationFree(t *testing.T) {
	pair := newStringTestPair("dd", 1, 2, types.SYS_ENTER_READ, types.SYS_EXIT_READ, 1, file.NewFd(0, "/dev/zero", 0))
	buf := make([]byte, 0, 256)
	for name, escape := range map[string]func(string) string{"raw": nil, "escaped": textsafe.Escape} {
		allocs := testing.AllocsPerRun(100, func() { buf = pair.AppendCSVRow(buf[:0], escape) })
		if allocs != 0 {
			t.Errorf("AppendCSVRow(%s) allocates %.1f times per row, want 0", name, allocs)
		}
	}
}
