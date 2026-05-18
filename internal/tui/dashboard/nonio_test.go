package dashboard

import (
	"strings"
	"testing"

	"ior/internal/statsengine"
	"ior/internal/types"
)

func TestRenderNonIOIncludesExpectedFamilyRows(t *testing.T) {
	snap := statsengine.NewSnapshotWithFamilies(
		nil,
		nil,
		nil,
		nil,
		[]statsengine.FamilySnapshot{
			{Family: types.FamilyFS, Name: "FS", Count: 99},
			{Family: types.FamilyPolling, Name: "Polling", Count: 7, RatePerSec: 3.5, Errors: 1},
			{Family: types.FamilyProcess, Name: "Process", Count: 2},
		},
		nil,
		nil,
		statsengine.HistogramSnapshot{},
		statsengine.HistogramSnapshot{},
	)

	out := renderNonIO(&snap, 120, 20)
	for _, token := range []string{"Family", "Count", "Rate/s", "Polling", "Process"} {
		if !strings.Contains(out, token) {
			t.Fatalf("expected token %q in non-io table:\n%s", token, out)
		}
	}
	if strings.Contains(out, "FS") {
		t.Fatalf("non-io table should exclude FS rows:\n%s", out)
	}
}
