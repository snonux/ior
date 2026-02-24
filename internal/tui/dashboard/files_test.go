package dashboard

import (
	"strings"
	"testing"

	"ior/internal/statsengine"
)

func TestRenderFilesIncludesHeaders(t *testing.T) {
	snap := statsengine.NewSnapshot(
		nil,
		nil,
		nil,
		nil,
		[]statsengine.FileSnapshot{
			{Path: "/var/log/app.log", Accesses: 42, BytesRead: 4096, BytesWritten: 2048, AvgLatencyNs: 1500, MaxLatencyNs: 20_000},
		},
		nil,
		statsengine.HistogramSnapshot{},
		statsengine.HistogramSnapshot{},
	)

	out := renderFiles(&snap, 120, 30)
	for _, token := range []string{"Path", "Accesses", "Bytes Read", "Bytes Written", "Avg Latency", "Max Latency", "app.log"} {
		if !strings.Contains(out, token) {
			t.Fatalf("expected token %q in files table output", token)
		}
	}
}

func TestRenderFilesNoData(t *testing.T) {
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	if got := renderFiles(&snap, 100, 20); got != "Files: no data" {
		t.Fatalf("unexpected no-data output: %q", got)
	}
}

func TestTruncatePathMiddle(t *testing.T) {
	longPath := "/very/long/path/with/high/cardinality/segments/and/filename.log"
	got := truncatePathMiddle(longPath, 24)
	if len(got) != 24 {
		t.Fatalf("expected truncated path length 24, got %d (%q)", len(got), got)
	}
	if !strings.Contains(got, "...") {
		t.Fatalf("expected ellipsis in truncated path, got %q", got)
	}
	if !strings.HasPrefix(got, "/very") || !strings.HasSuffix(got, "e.log") {
		t.Fatalf("expected head and tail preservation, got %q", got)
	}
}
