package eventstream

import (
	"bytes"
	"encoding/csv"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"ior/internal/parquet"
	"ior/internal/types"
)

// csvColumnForParquetTag maps a parquet.Record column to the stream CSV
// column that carries it. Every column keeps its Parquet name except
// is_error, which the CSV has always called `error`.
var csvColumnForParquetTag = map[string]string{"is_error": "error"}

// notExported lists the Parquet columns the CSV export deliberately leaves
// out: filter_epoch is recorder bookkeeping (which filter generation a row was
// recorded under), not a property of the traced syscall.
var notExported = map[string]bool{"filter_epoch": true}

// parquetColumnNames returns the column name of every parquet.Record field,
// read from the `parquet` struct tags - the same names the written files use.
func parquetColumnNames(t *testing.T) []string {
	t.Helper()
	rt := reflect.TypeOf(parquet.Record{})
	names := make([]string, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("parquet")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" {
			t.Fatalf("parquet.Record.%s has no parquet tag; the schema test cannot map it", rt.Field(i).Name)
		}
		names = append(names, name)
	}
	return names
}

// expectedCSVColumns turns Parquet column names into the CSV column names the
// export must have: renamed where csvColumnForParquetTag says so, dropped when
// listed in notExported.
func expectedCSVColumns(parquetCols []string) []string {
	want := make([]string, 0, len(parquetCols))
	for _, col := range parquetCols {
		if notExported[col] {
			continue
		}
		if renamed, ok := csvColumnForParquetTag[col]; ok {
			col = renamed
		}
		want = append(want, col)
	}
	return want
}

// columnDrift compares two column lists as sets (the CSV keeps its legacy
// positional order, which the Parquet struct does not follow) and reports what
// only the CSV has, what only Parquet has, and any duplicates in header.
func columnDrift(header, want []string) (onlyCSV, onlyParquet, duplicates []string) {
	seen := map[string]bool{}
	for _, col := range header {
		if seen[col] {
			duplicates = append(duplicates, col)
		}
		seen[col] = true
		if !slices.Contains(want, col) {
			onlyCSV = append(onlyCSV, col)
		}
	}
	for _, col := range want {
		if !seen[col] {
			onlyParquet = append(onlyParquet, col)
		}
	}
	return onlyCSV, onlyParquet, duplicates
}

// TestStreamCSVHeaderMatchesParquetSchema is the task ts2 drift guard: the CSV
// export promises the per-event schema of the Parquet recording under the same
// names (task rq2), so a column added to or removed from parquet.Record, or
// from streamCSVHeader, without the other side fails here instead of silently
// diverging.
func TestStreamCSVHeaderMatchesParquetSchema(t *testing.T) {
	onlyCSV, onlyParquet, dups := columnDrift(streamCSVHeader, expectedCSVColumns(parquetColumnNames(t)))
	if len(onlyCSV) > 0 || len(onlyParquet) > 0 || len(dups) > 0 {
		t.Fatalf("streamCSVHeader and parquet.Record disagree: only in CSV %v, only in Parquet %v (add it to streamCSVHeader/streamCSVRecord, or to notExported here), duplicated in CSV %v",
			onlyCSV, onlyParquet, dups)
	}
}

// TestColumnDriftDetectsAddedAndRemovedColumns is the negative check for the
// guard above: against the real Parquet schema, a CSV header that gained a
// column, lost one, or repeats one must be reported, so the guard cannot pass
// vacuously.
func TestColumnDriftDetectsAddedAndRemovedColumns(t *testing.T) {
	want := expectedCSVColumns(parquetColumnNames(t))

	added := append(slices.Clone(streamCSVHeader), "new_csv_only")
	if onlyCSV, _, _ := columnDrift(added, want); !reflect.DeepEqual(onlyCSV, []string{"new_csv_only"}) {
		t.Errorf("added CSV column: onlyCSV = %v, want [new_csv_only]", onlyCSV)
	}

	removed := slices.DeleteFunc(slices.Clone(streamCSVHeader), func(c string) bool { return c == "old_file" })
	if _, onlyParquet, _ := columnDrift(removed, want); !reflect.DeepEqual(onlyParquet, []string{"old_file"}) {
		t.Errorf("removed CSV column: onlyParquet = %v, want [old_file]", onlyParquet)
	}

	// A Parquet column the CSV has no mapping for (one added to the struct).
	grown := append(slices.Clone(want), "new_parquet_only")
	if _, onlyParquet, _ := columnDrift(streamCSVHeader, grown); !reflect.DeepEqual(onlyParquet, []string{"new_parquet_only"}) {
		t.Errorf("added Parquet column: onlyParquet = %v, want [new_parquet_only]", onlyParquet)
	}

	doubled := append(slices.Clone(streamCSVHeader), "seq")
	if _, _, dups := columnDrift(doubled, want); !reflect.DeepEqual(dups, []string{"seq"}) {
		t.Errorf("repeated CSV column: duplicates = %v, want [seq]", dups)
	}
}

// TestWriteStreamCSVRepairsInvalidUTF8LikeParquet is the task ts2 regression
// for strict CSV readers (DuckDB read_csv rejects invalid UTF-8): comm, file
// and old_file hold exactly what the Parquet recording holds for the same row,
// so an invalid byte is a \xHH escape and a rune cut at the capture limit is
// dropped, while valid text (including multi-byte runes) is written as is.
func TestWriteStreamCSVRepairsInvalidUTF8LikeParquet(t *testing.T) {
	// Exactly the BPF capture length (MAX_FILENAME_LENGTH minus the NUL), ending
	// in half a rune: the shape of a multi-byte name cut by the capture buffer.
	cutPath := "/" + strings.Repeat("a", types.MAX_FILENAME_LENGTH-3) + "\xc3"
	rows := []StreamEvent{
		{Seq: 1, Syscall: "renameat2", Comm: "bad\xffcomm", FileName: "/tmp/\xfe\xffx", OldName: "/old/\x80", FD: -1},
		{Seq: 2, Syscall: "openat", Comm: "caf\xc3\xa9", FileName: "/tmp/gr\xc3\xbc\xc3\x9f.txt", FD: 3},
		{Seq: 3, Syscall: "openat", Comm: "n\xc3", FileName: cutPath, FD: 3},
	}
	var buf bytes.Buffer
	if err := writeStreamCSV(csv.NewWriter(&buf), rows); err != nil {
		t.Fatalf("writeStreamCSV() error = %v", err)
	}
	records, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}
	col := map[string]int{}
	for i, name := range records[0] {
		col[name] = i
	}

	for i := range rows {
		want := parquet.RecordFromStream(rows[i], 0)
		got := records[i+1]
		for name, wantText := range map[string]string{"comm": want.Comm, "file": want.File, "old_file": want.OldFile} {
			if got[col[name]] != wantText {
				t.Errorf("row %d %s = %q, want the Parquet text %q", i+1, name, got[col[name]], wantText)
			}
		}
	}

	// Spelled out so the shared helper cannot drift unnoticed.
	if got := records[1][col["comm"]]; got != `bad\xffcomm` {
		t.Errorf("invalid comm byte = %q, want %q", got, `bad\xffcomm`)
	}
	if got := records[1][col["file"]]; got != `/tmp/\xfe\xffx` {
		t.Errorf("invalid file bytes = %q, want %q", got, `/tmp/\xfe\xffx`)
	}
	if got := records[1][col["old_file"]]; got != `/old/\x80` {
		t.Errorf("invalid old_file byte = %q, want %q", got, `/old/\x80`)
	}
	if got := records[2][col["comm"]]; got != "café" {
		t.Errorf("valid comm changed: %q", got)
	}
	if got := records[2][col["file"]]; got != "/tmp/grüß.txt" {
		t.Errorf("valid file changed: %q", got)
	}
	if got := records[3][col["file"]]; got != cutPath[:len(cutPath)-1] {
		t.Errorf("cut rune in a full-length path = %q, want it dropped", got)
	}
	if got := records[3][col["comm"]]; got != "n" {
		t.Errorf("cut rune in comm = %q, want it dropped", got)
	}
	if !utf8.ValidString(buf.String()) {
		t.Errorf("the CSV file is not valid UTF-8:\n%q", buf.String())
	}
}
