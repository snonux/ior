package tui

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
			name: "inactive after suffixed publish names the real file",
			status: parquet.Status{
				Path:          "rec-20260930-135324-1.parquet",
				RequestedPath: "rec-20260930-135324.parquet",
			},
			want: "rec: saved as rec-20260930-135324-1.parquet",
		},
		{
			name: "inactive after in-place publish stays off",
			status: parquet.Status{
				Path:          "a.parquet",
				RequestedPath: "a.parquet",
			},
			want: "rec: off",
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

func TestIsDefaultParquetRecordingName(t *testing.T) {
	if !isDefaultParquetRecordingName(defaultParquetRecordingFilename()) {
		t.Error("the generated default name must be recognised as generated")
	}
	if !isDefaultParquetRecordingName("/var/tmp/ior-recording-20260930-135324.parquet") {
		t.Error("a generated name in another directory is still generated")
	}
	for _, name := range []string{"", "trace.parquet", "ior-recording-mine.parquet", "ior-recording-20260930-135324", "ior-recording-20260930-135324-1.parquet",
		// Strict layout: one-digit hour (09:05:00) and unpadded fields are
		// hand-typed near misses, not generated names.
		"ior-recording-20260930-90500.parquet", "ior-recording-2026930-135324.parquet"} {
		if isDefaultParquetRecordingName(name) {
			t.Errorf("%q was treated as a generated name; user-typed names must be replaced, not suffixed", name)
		}
	}
}

// TestRecorderStartNamePolicy drives the real recorder through recorderStart:
// a user-typed name that already exists is replaced in place, while a
// generated default name that is taken is left alone and the recording lands
// under a "-N" name that the status line then reports.
func TestRecorderStartNamePolicy(t *testing.T) {
	dir := t.TempDir()
	run := func(path string) parquet.Status {
		t.Helper()
		recorder := parquet.NewRecorder(parquet.RecorderConfig{})
		if err := recorderStart(recorder, path, func() {}); err != nil {
			t.Fatalf("recorderStart(%q): %v", path, err)
		}
		if err := recorderStop(recorder, func() {}); err != nil {
			t.Fatalf("recorderStop: %v", err)
		}
		return recorder.Status()
	}

	chosen := filepath.Join(dir, "chosen.parquet")
	if err := os.WriteFile(chosen, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if st := run(chosen); st.Path != chosen {
		t.Errorf("explicit name: Path = %q, want it replaced in place at %q", st.Path, chosen)
	}
	if got, _ := os.ReadFile(chosen); string(got) == "stale" {
		t.Error("explicit name was not replaced")
	}

	auto := filepath.Join(dir, "ior-recording-20260930-135324.parquet")
	if err := os.WriteFile(auto, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	st := run(auto)
	want := filepath.Join(dir, "ior-recording-20260930-135324-1.parquet")
	if st.Path != want {
		t.Errorf("default name: Path = %q, want %q", st.Path, want)
	}
	if got, _ := os.ReadFile(auto); string(got) != "keep" {
		t.Errorf("generated default name was clobbered: %q", got)
	}
	if got := formatRecorderStatus(st); !strings.Contains(got, "saved as") {
		t.Errorf("status line %q should report the suffixed path", got)
	}
}
