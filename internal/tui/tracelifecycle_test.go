package tui

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"ior/internal/parquet"
)

func TestFormatRecorderStatusSurfacesDroppedRows(t *testing.T) {
	const shortPath = "recording-20260101-010101.parquet"

	cases := []struct {
		name   string
		status parquet.Status
		want   string
	}{
		{
			name:   "inactive without drops",
			status: parquet.Status{},
			want:   "rec: off",
		},
		{
			name: "active without drops",
			status: parquet.Status{
				Active: true,
				Path:   shortPath,
			},
			want: "rec: " + shortPath,
		},
		{
			name: "active with drops",
			status: parquet.Status{
				Active:      true,
				Path:        shortPath,
				RowsDropped: 42,
			},
			want: "rec: " + shortPath + " (dropped 42)",
		},
		{
			name: "inactive clean stop with drops",
			status: parquet.Status{
				RowsDropped: 7,
			},
			want: "rec: off (dropped 7)",
		},
		{
			name: "error state unchanged",
			status: parquet.Status{
				LastError: errors.New("writer failed"),
			},
			want: "rec err: writer failed",
		},
		{
			name: "long path is shortened",
			status: parquet.Status{
				Active: true,
				// 40 chars exceeds the 36-char budget, so shortenRecordingPath
				// keeps the last 33 chars behind an ellipsis.
				Path: "abcdefghijabcdefghijabcdefghijabcdefghij",
			},
			want: "rec: ...hijabcdefghijabcdefghijabcdefghij",
		},
		{
			name: "long multi-byte path stays valid UTF-8",
			status: parquet.Status{
				Active: true,
				// 45 cells: byte slicing used to split a 3-byte rune here.
				// "..." leaves 33 cells, and a 2-cell rune cannot straddle
				// the cut, so 16 runes (32 cells) are kept.
				Path: "/tmp/" + strings.Repeat("日", 20),
			},
			want: "rec: ..." + strings.Repeat("日", 16),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatRecorderStatus(tc.status); got != tc.want {
				t.Fatalf("formatRecorderStatus() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRecorderStatusNilRecorder(t *testing.T) {
	if got := recorderStatus(nil); got != "rec: unavailable" {
		t.Fatalf("recorderStatus(nil) = %q, want %q", got, "rec: unavailable")
	}
}

func TestRecorderStatusActiveSurfacesLiveDropCount(t *testing.T) {
	recorder := parquet.NewRecorder(parquet.RecorderConfig{})
	status := recorder.Status()
	if status.Active || status.RowsWritten != 0 || status.RowsDropped != 0 {
		t.Fatalf("fresh recorder status = %+v, want inactive zero state", status)
	}
	if got := recorderStatus(recorder); got != "rec: off" {
		t.Fatalf("recorderStatus(fresh) = %q, want %q", got, "rec: off")
	}
}

func TestFormatRecorderStatusDropCountFormatting(t *testing.T) {
	// Guard against accidental formatting drift in the drop suffix, which
	// the status bar parses visually.
	status := parquet.Status{Active: true, Path: "p.parquet", RowsDropped: 12345}
	want := fmt.Sprintf("rec: p.parquet (dropped %d)", status.RowsDropped)
	if got := formatRecorderStatus(status); got != want {
		t.Fatalf("formatRecorderStatus() = %q, want %q", got, want)
	}
}
