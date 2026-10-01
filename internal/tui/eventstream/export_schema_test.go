package eventstream

import (
	"bytes"
	"encoding/csv"
	"fmt"
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

// parquetColumn is one parquet.Record field with the column name its
// `parquet` tag gives it - the name the written files use.
type parquetColumn struct {
	name  string
	field int // index into parquet.Record
}

// parquetColumns returns every column of parquet.Record read from the
// `parquet` struct tags. A field tagged `parquet:"-"` is not a column and is
// skipped. An untagged (or embedded) field would be written under a name this
// test cannot know, so it fails loudly instead of being guessed at.
func parquetColumns(t *testing.T) []parquetColumn {
	t.Helper()
	rt := reflect.TypeOf(parquet.Record{})
	cols := make([]parquetColumn, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag, ok := f.Tag.Lookup("parquet")
		name, _, _ := strings.Cut(tag, ",")
		switch {
		case name == "-":
			continue
		case !ok || name == "" || f.Anonymous:
			t.Fatalf("parquet.Record.%s has no plain `parquet:\"name\"` tag (embedded or untagged); teach the schema test how it is written", f.Name)
		}
		cols = append(cols, parquetColumn{name: name, field: i})
	}
	return cols
}

// parquetColumnNames returns just the column names of parquetColumns.
func parquetColumnNames(t *testing.T) []string {
	t.Helper()
	cols := parquetColumns(t)
	names := make([]string, len(cols))
	for i, c := range cols {
		names[i] = c.name
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
	// The same shape for the rename source, with other letters so that a
	// file/old_file mix-up is visible. Without a cut old_file the test would
	// not notice old_file written through SanitizeUTF8 (no capture-limit trim).
	cutOldPath := "/" + strings.Repeat("b", types.MAX_FILENAME_LENGTH-3) + "\xc3"
	rows := []StreamEvent{
		{Seq: 1, Syscall: "renameat2", Comm: "bad\xffcomm", FileName: "/tmp/\xfe\xffx", OldName: "/old/\x80", FD: -1},
		{Seq: 2, Syscall: "openat", Comm: "caf\xc3\xa9", FileName: "/tmp/gr\xc3\xbc\xc3\x9f.txt", FD: 3},
		{Seq: 3, Syscall: "renameat2", Comm: "n\xc3", FileName: cutPath, OldName: cutOldPath, FD: -1},
	}
	var buf bytes.Buffer
	if err := writeStreamCSV(csv.NewWriter(&buf), rows); err != nil {
		t.Fatalf("writeStreamCSV() error = %v", err)
	}
	// Copy the bytes before reading: csv.NewReader drains buf, and the reader
	// itself accepts invalid UTF-8, so the validity check below has to look at
	// the raw bytes that were written.
	raw := bytes.Clone(buf.Bytes())
	records, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}
	col := csvColumnIndex(records[0])

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
	if got := records[3][col["old_file"]]; got != cutOldPath[:len(cutOldPath)-1] {
		t.Errorf("cut rune in a full-length old_file = %q, want it dropped", got)
	}
	if got := records[3][col["comm"]]; got != "n" {
		t.Errorf("cut rune in comm = %q, want it dropped", got)
	}
	if !utf8.Valid(raw) {
		t.Errorf("the CSV file is not valid UTF-8:\n%q", raw)
	}
	for _, bad := range []byte{0xff, 0xfe, 0x80} {
		if bytes.IndexByte(raw, bad) >= 0 {
			t.Errorf("the CSV file still holds the raw invalid byte %#x:\n%q", bad, raw)
		}
	}
}

// csvColumnIndex maps each header name to its position.
func csvColumnIndex(header []string) map[string]int {
	col := make(map[string]int, len(header))
	for i, name := range header {
		col[name] = i
	}
	return col
}

// distinctRow returns a row in which every exported field holds a value no
// other field holds (numbers 1001.., strings named after their column), so a
// cell written from the wrong field cannot match by accident. IsError is the
// only bool and is true, so it differs from the zero value.
func distinctRow() StreamEvent {
	return StreamEvent{
		Seq: 1001, TimeNs: 1002, GapNs: 1003, DurationNs: 1004,
		Comm: "comm-v", PID: 1005, TID: 1006, Syscall: "syscall-v",
		FD: 1007, RetVal: 1008, Bytes: 1009, FileName: "/file-v",
		IsError: true, Family: "family-v", RequestedSleepNs: 1010,
		Nfds: 1011, TimeoutNs: 1012, AddressSpaceBytes: 1013,
		OldName: "/old-file-v", EpollOp: "epoll-op-v",
		EpollTargetFD: 1014, EpollEvents: 1015,
	}
}

// TestStreamCSVCellsMatchParquetRecord is the cell-level half of the ts2 drift
// guard: the header test only checks column names, so two cells filled from
// each other's field (gap_ns from DurationNs, say) would pass it. Here every
// field of one row carries a distinct value, and each CSV cell must equal the
// parquet.Record field of the same column name, so a swapped or missing cell
// fails by name.
func TestStreamCSVCellsMatchParquetRecord(t *testing.T) {
	row := distinctRow()
	rec := reflect.ValueOf(parquet.RecordFromStream(row, 0))

	var buf bytes.Buffer
	if err := writeStreamCSV(csv.NewWriter(&buf), []StreamEvent{row}); err != nil {
		t.Fatalf("writeStreamCSV() error = %v", err)
	}
	records, err := csv.NewReader(&buf).ReadAll()
	if err != nil || len(records) != 2 {
		t.Fatalf("read CSV: %d records, err = %v; want header + 1 row", len(records), err)
	}
	col := csvColumnIndex(records[0])

	seenValue := map[string]string{} // cell value -> column that has it
	for _, pc := range parquetColumns(t) {
		if notExported[pc.name] {
			continue
		}
		name := pc.name
		if renamed, ok := csvColumnForParquetTag[name]; ok {
			name = renamed
		}
		idx, ok := col[name]
		if !ok {
			t.Errorf("CSV has no column %q for parquet column %q", name, pc.name)
			continue
		}
		want := fmt.Sprint(rec.Field(pc.field).Interface())
		if got := records[1][idx]; got != want {
			t.Errorf("CSV column %q = %q, want the parquet.Record %q value %q", name, got, pc.name, want)
		}
		// The check above is only as strong as the row is distinct: a bool
		// has two values, everything else must not repeat and must not be
		// zero or empty. Without the non-zero requirement a field that
		// distinctRow forgot to set would compare "0" against a cell
		// hard-coded to "0" and pass. Bools are exempt because a bool cell
		// is "true" or "false" and distinctRow sets IsError to true, so
		// the false rendering is already what a missing cell would show.
		if rec.Field(pc.field).Kind() != reflect.Bool {
			if want == "0" || want == "" {
				t.Errorf("distinctRow leaves column %q at %q; a cell hard-coded to that zero would pass", name, want)
			}
			if other, dup := seenValue[want]; dup {
				t.Errorf("distinctRow gives columns %q and %q the same value %q; the swap check is blind to them", other, name, want)
			}
			seenValue[want] = name
		}
	}
}
