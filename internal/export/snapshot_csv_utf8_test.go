package export

import (
	"bytes"
	"encoding/csv"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"ior/internal/statsengine"
	"ior/internal/types"
)

// cutPath returns a path of exactly the BPF capture limit
// (MAX_FILENAME_LENGTH-1 bytes) whose last byte is the lead byte of a cut
// two-byte rune, the way bpf_probe_read_user_str leaves a long non-ASCII path.
func cutPath() string {
	limit := types.MAX_FILENAME_LENGTH - 1
	return "/" + strings.Repeat("a", limit-2) + "\xc3"
}

// snapshotWithText builds a snapshot holding one file with path and one
// process with comm, the two traced free-form strings a snapshot carries.
func snapshotWithText(path, comm string) statsengine.Snapshot {
	return statsengine.NewSnapshot(nil, nil, nil, nil,
		[]statsengine.FileSnapshot{{Path: path, Accesses: 1}},
		[]statsengine.ProcessSnapshot{{PID: 7, Comm: comm, Syscalls: 1}},
		statsengine.NewHistogramSnapshot(0, nil),
		statsengine.NewHistogramSnapshot(0, nil),
	)
}

// snapshotFileCells writes snap and returns the raw CSV bytes and the path
// cells of the file and file_latency_ns rows.
func snapshotFileCells(t *testing.T, snap *statsengine.Snapshot) ([]byte, []string) {
	t.Helper()
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := writeSnapshotRows(w, snap); err != nil {
		t.Fatalf("writeSnapshotRows: %v", err)
	}
	w.Flush()
	raw := append([]byte(nil), buf.Bytes()...)
	records, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	var cells []string
	for _, row := range records {
		if row[0] == "file" || row[0] == "file_latency_ns" {
			cells = append(cells, row[1])
		}
	}
	return raw, cells
}

// TestSnapshotCSVRepairsFreeFormText pins the task 3z2 repair of the file
// path, the only traced text the snapshot writes: invalid bytes become \xHH,
// a rune cut at the capture limit is dropped (the same text the Parquet
// recording and the stream CSV hold), CSV special characters survive the
// round trip through the csv.Writer's quoting, and valid UTF-8 is untouched.
// The comm cases pin that an invalid comm never reaches the file: the process
// rows carry the numeric id only.
func TestSnapshotCSVRepairsFreeFormText(t *testing.T) {
	cut := cutPath()
	tests := []struct {
		name, path, comm, want string
	}{
		{"invalid byte in path", "/tmp/a\xffb", "cat", `/tmp/a\xffb`},
		{"several invalid bytes", "/tmp/\xfe\xc3(\x80", "cat", `/tmp/\xfe\xc3(\x80`},
		{"rune cut at capture limit", cut, "cat", cut[:len(cut)-1]},
		{"invalid comm", "/tmp/x", "bad\xffcomm", "/tmp/x"},
		{"comm cut mid rune", "/tmp/x", "äääääää\xc3", "/tmp/x"},
		// A lone CR: encoding/csv's reader drops a CR in front of an LF
		// inside a quoted field, so CRLF would not round-trip through Go's
		// reader although the writer keeps it.
		{"csv special characters", "/tmp/a,\"b\"\nc\rd", "c,\"m\"", "/tmp/a,\"b\"\nc\rd"},
		{"valid utf-8 untouched", "/tmp/äöü 日本/🦀.txt", "zsh", "/tmp/äöü 日本/🦀.txt"},
		{"valid control char untouched", "/tmp/\x1b[31mred", "cat", "/tmp/\x1b[31mred"},
		{"literal backslash-x kept", `/tmp/\xff`, "cat", `/tmp/\xff`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			snap := snapshotWithText(tc.path, tc.comm)
			raw, cells := snapshotFileCells(t, &snap)
			if !utf8.Valid(raw) {
				t.Fatalf("snapshot CSV is not valid UTF-8:\n%q", raw)
			}
			if len(cells) != 2 {
				t.Fatalf("got %d file cells, want 2 (file, file_latency_ns): %q", len(cells), cells)
			}
			for _, got := range cells {
				if got != tc.want {
					t.Errorf("path cell = %q, want %q", got, tc.want)
				}
			}
			if strings.Contains(string(raw), tc.comm) {
				t.Errorf("comm %q leaked into the snapshot CSV:\n%s", tc.comm, raw)
			}
		})
	}
}

// TestSnapshotCSVFileIsValidUTF8EndToEnd writes a real snapshot file holding
// invalid bytes and CSV special characters through SnapshotCSV and checks the
// published file is valid UTF-8 and parses as CSV with the expected row count.
// When python3 is installed, its strict UTF-8 decoder and csv module must read
// the file too: a stand-in for strict readers such as DuckDB's read_csv, which
// reject the whole file on one invalid byte.
func TestSnapshotCSVFileIsValidUTF8EndToEnd(t *testing.T) {
	t.Chdir(t.TempDir())
	snap := snapshotWithText("/tmp/\xff,\"q\"\nx"+cutPath(), "bad\xffcomm")
	name, err := SnapshotCSV(&snap)
	if err != nil {
		t.Fatalf("SnapshotCSV: %v", err)
	}
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	if !utf8.Valid(data) {
		t.Fatalf("snapshot file is not valid UTF-8:\n%q", data)
	}
	records, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatalf("parse snapshot csv: %v", err)
	}
	// Header, 4 summary rows, 2 file rows and 2 process rows.
	const wantRows = 9
	if len(records) != wantRows {
		t.Fatalf("got %d CSV records, want %d: %q", len(records), wantRows, records)
	}

	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed; strict external reader check skipped")
	}
	script := "import csv,sys\n" +
		"with open(sys.argv[1], encoding='utf-8', errors='strict', newline='') as f:\n" +
		"    print(len(list(csv.reader(f, strict=True))))\n"
	out, err := exec.Command(python, "-c", script, name).CombinedOutput()
	if err != nil {
		t.Fatalf("python3 csv rejected the snapshot: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != strconv.Itoa(wantRows) {
		t.Fatalf("python3 csv read %s records, want %d", got, wantRows)
	}
}
