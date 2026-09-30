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
