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

func TestNonIOFamiliesFiltering(t *testing.T) {
	all := []statsengine.FamilySnapshot{
		{Family: types.FamilyFS, Name: "FS"},
		{Family: types.FamilyPolling, Name: "Polling"},
		{Family: types.FamilyProcess, Name: "Process"},
	}

	rows := nonIOFamilies(all)
	if len(rows) != 2 {
		t.Fatalf("nonIOFamilies len = %d, want 2", len(rows))
	}
	if rows[0].Family == types.FamilyFS || rows[1].Family == types.FamilyFS {
		t.Fatalf("nonIOFamilies included FS: %+v", rows)
	}
	if got := nonIOFamiliesCount(all); got != 2 {
		t.Fatalf("nonIOFamiliesCount = %d, want 2", got)
	}
}

func TestIsNonIOSyscallFamily(t *testing.T) {
	tests := []struct {
		family types.SyscallFamily
		want   bool
	}{
		{types.FamilyFS, false},
		{types.FamilyPolling, true},
		{types.FamilyProcess, true},
		{types.FamilyNetwork, true},
		{"", false},
	}
	for _, tt := range tests {
		if got := isNonIOSyscallFamily(tt.family); got != tt.want {
			t.Errorf("isNonIOSyscallFamily(%q) = %v, want %v", tt.family, got, tt.want)
		}
	}
}
