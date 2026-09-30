package eventstream

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestResolveEditorCommandPrefersEditor(t *testing.T) {
	t.Setenv("SUDO_EDITOR", "nano")
	t.Setenv("VISUAL", "vim")
	t.Setenv("EDITOR", "nvim")

	parts, source, err := resolveEditorCommand()
	if err != nil {
		t.Fatalf("resolve editor: %v", err)
	}
	if source != "EDITOR" {
		t.Fatalf("expected EDITOR source, got %q", source)
	}
	if len(parts) != 1 || parts[0] != "nvim" {
		t.Fatalf("expected nvim command, got %#v", parts)
	}
}

func TestResolveEditorCommandFallsBackToVisualBeforeSudoEditor(t *testing.T) {
	t.Setenv("SUDO_EDITOR", "nano")
	t.Setenv("VISUAL", "vim")
	t.Setenv("EDITOR", "")

	parts, source, err := resolveEditorCommand()
	if err != nil {
		t.Fatalf("resolve editor: %v", err)
	}
	if source != "VISUAL" {
		t.Fatalf("expected VISUAL source, got %q", source)
	}
	if len(parts) != 1 || parts[0] != "vim" {
		t.Fatalf("expected vim command, got %#v", parts)
	}
}

func TestResolveEditorCommandFallsBackToHxWhenAvailable(t *testing.T) {
	t.Setenv("SUDO_EDITOR", "")
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "")

	binDir := t.TempDir()
	hxPath := filepath.Join(binDir, "hx")
	if err := os.WriteFile(hxPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write hx stub: %v", err)
	}
	t.Setenv("PATH", binDir)

	parts, source, err := resolveEditorCommand()
	if err != nil {
		t.Fatalf("resolve editor: %v", err)
	}
	if source != "fallback" {
		t.Fatalf("expected fallback source, got %q", source)
	}
	if len(parts) != 1 || parts[0] != "hx" {
		t.Fatalf("expected hx fallback, got %#v", parts)
	}
}

func TestResolveEditorCommandFallsBackToViWhenHxMissing(t *testing.T) {
	t.Setenv("SUDO_EDITOR", "")
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "")
	t.Setenv("PATH", t.TempDir())

	parts, source, err := resolveEditorCommand()
	if err != nil {
		t.Fatalf("resolve editor: %v", err)
	}
	if source != "fallback" {
		t.Fatalf("expected fallback source, got %q", source)
	}
	if len(parts) != 1 || parts[0] != "vi" {
		t.Fatalf("expected vi fallback, got %#v", parts)
	}
}

// TestResolveEditorCommandSingleQuotedPath verifies that an EDITOR value with
// a single-quoted path containing spaces is not broken into multiple tokens.
func TestResolveEditorCommandSingleQuotedPath(t *testing.T) {
	t.Setenv("SUDO_EDITOR", "")
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "'/My Editor/hx'")

	parts, source, err := resolveEditorCommand()
	if err != nil {
		t.Fatalf("resolve editor: %v", err)
	}
	if source != "EDITOR" {
		t.Fatalf("expected EDITOR source, got %q", source)
	}
	want := []string{"/My Editor/hx"}
	if !reflect.DeepEqual(parts, want) {
		t.Fatalf("expected %#v, got %#v", want, parts)
	}
}

// TestResolveEditorCommandDoubleQuotedPathWithArgs verifies that double-quoted
// paths with trailing arguments are all preserved correctly.
func TestResolveEditorCommandDoubleQuotedPathWithArgs(t *testing.T) {
	t.Setenv("SUDO_EDITOR", "")
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", `"/path/with spaces/hx" --wait`)

	parts, source, err := resolveEditorCommand()
	if err != nil {
		t.Fatalf("resolve editor: %v", err)
	}
	if source != "EDITOR" {
		t.Fatalf("expected EDITOR source, got %q", source)
	}
	want := []string{"/path/with spaces/hx", "--wait"}
	if !reflect.DeepEqual(parts, want) {
		t.Fatalf("expected %#v, got %#v", want, parts)
	}
}

// TestEnsureCSVFilenamePathTraversal verifies that path traversal attempts are
// rejected or stripped so that the resulting filename stays within exportDir.
func TestEnsureCSVFilenamePathTraversal(t *testing.T) {
	cases := []struct {
		input   string
		want    string // empty string means an error is expected
		wantErr bool
	}{
		// Normal names — should pass through unchanged (with .csv if needed).
		{"report", "report.csv", false},
		{"report.csv", "report.csv", false},
		{"Report.CSV", "Report.CSV", false},
		// Directory separators must be stripped — only the base name survives.
		{"../../etc/passwd", "passwd.csv", false},
		{"../secret", "secret.csv", false},
		{"subdir/file.csv", "file.csv", false},
		{"/absolute/path.csv", "path.csv", false},
		// Pure directory references must be rejected.
		{"..", "", true},
		{"some/../..", "", true},
		// Empty / whitespace-only must be rejected.
		{"", "", true},
		{"   ", "", true},
	}

	for _, tc := range cases {
		got, err := ensureCSVFilename(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ensureCSVFilename(%q): expected error, got %q", tc.input, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ensureCSVFilename(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ensureCSVFilename(%q): got %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestExportRowsToCSVPathTraversal verifies that exportRowsToCSV writes the
// output file inside exportDir even when the caller passes a path-traversal
// filename.
func TestExportRowsToCSVPathTraversal(t *testing.T) {
	exportDir := t.TempDir()
	outside := t.TempDir()

	// Craft a filename that would escape exportDir without sanitisation.
	traversal := "../" + outside[len(outside)-1:] // relative path targeting outside dir

	// Use a clearly recognisable traversal pattern.
	maliciousName := "../../escape.csv"

	path, err := exportRowsToCSV(nil, exportDir, maliciousName)
	if err != nil {
		t.Fatalf("exportRowsToCSV returned unexpected error: %v", err)
	}

	// The written file must live inside exportDir, not outside it.
	rel, err := filepath.Rel(exportDir, path)
	if err != nil {
		t.Fatalf("filepath.Rel: %v", err)
	}
	if len(rel) >= 2 && rel[:2] == ".." {
		t.Errorf("output path %q escapes exportDir %q (rel=%q)", path, exportDir, rel)
	}

	_ = traversal // silence unused-variable warning
}

func TestWriteStreamCSVAppendsExtendedColumns(t *testing.T) {
	var buf bytes.Buffer
	rows := []StreamEvent{{
		Seq:              7,
		TimeNs:           100,
		GapNs:            3,
		DurationNs:       5,
		Comm:             "worker",
		PID:              10,
		TID:              11,
		Syscall:          "socketpair",
		FD:               4,
		RetVal:           0,
		Bytes:            0,
		FileName:         "/tmp/sock",
		IsError:          false,
		Family:           "Network",
		RequestedSleepNs: 4_200_000,
		Nfds:             8,
		TimeoutNs:        -1,
	}}

	if err := writeStreamCSV(csv.NewWriter(&buf), rows); err != nil {
		t.Fatalf("writeStreamCSV() error = %v", err)
	}

	records, err := csv.NewReader(bytes.NewReader(buf.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}
	wantHeader := []string{"seq", "time_ns", "gap_ns", "latency_ns", "comm", "pid", "tid", "syscall", "fd", "ret", "bytes", "file", "error", "family", "requested_sleep_ns", "nfds", "timeout_ns"}
	if !reflect.DeepEqual(records[0], wantHeader) {
		t.Fatalf("header = %#v, want %#v", records[0], wantHeader)
	}
	if records[1][8] != "4" || records[1][12] != "false" || records[1][13] != "Network" || records[1][14] != "4200000" {
		t.Fatalf("family should be appended without shifting legacy columns, got %#v", records[1])
	}
	if records[1][15] != "8" || records[1][16] != "-1" {
		t.Fatalf("poll metadata = %q/%q, want 8/-1", records[1][15], records[1][16])
	}
}

// TestShellSplitVariousCases covers the tokenizer with a table-driven approach.
func TestShellSplitVariousCases(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		// Plain tokens — behaviour identical to strings.Fields.
		{"vi", []string{"vi"}},
		{"nvim --wait", []string{"nvim", "--wait"}},
		// Single-quoted path with spaces — the whole quoted span is one token.
		{"'/path/with spaces/hx'", []string{"/path/with spaces/hx"}},
		// Double-quoted path.
		{`"/path/with spaces/hx"`, []string{"/path/with spaces/hx"}},
		// Double-quoted path with escaped double quote inside.
		{`"/path/\"hx\""`, []string{`/path/"hx"`}},
		// Mixed: quoted binary + unquoted flag.
		{`"/My Editor/hx" --wait`, []string{"/My Editor/hx", "--wait"}},
		// Backslash escaping a space outside quotes.
		{`/path/with\ spaces/hx`, []string{"/path/with spaces/hx"}},
		// Empty string returns no tokens.
		{"", nil},
		// Whitespace-only returns no tokens.
		{"   ", nil},
		// Unterminated single quote: treated as implicit close at end.
		{"'unterminated", []string{"unterminated"}},
	}

	for _, tc := range cases {
		got := shellSplit(tc.input)
		// Treat nil and empty slice as equivalent for comparison purposes.
		if len(got) == 0 && len(tc.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("shellSplit(%q): got %#v, want %#v", tc.input, got, tc.want)
		}
	}
}

// TestExportSnapshotMatchesRenameOnEitherName guards the export half of the
// either-name contract. The export command path (ExportSourceSnapshotToCSV,
// the `E` path) filters the
// source snapshot itself rather than reusing m.filtered, so it needs its own
// regression test: without one, reverting it to plain Matches leaves the whole
// package green while the exported CSV silently loses rename rows that the
// Stream tab is showing.
func TestExportSnapshotMatchesRenameOnEitherName(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{
		Seq:      1,
		Syscall:  "renameat2",
		Comm:     "mv",
		FileName: "/tmp/new.txt",
		OldName:  "/tmp/old.txt",
	})
	rb.Push(StreamEvent{
		Seq:      2,
		Syscall:  "openat",
		Comm:     "cat",
		FileName: "/tmp/unrelated.txt",
	})

	dir := t.TempDir()
	path, err := exportSnapshotToCSV(rb, Filter{File: &StringFilter{Pattern: "old.txt"}}, dir, "either-name.csv")
	if err != nil {
		t.Fatalf("exportSnapshotToCSV: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read exported csv: %v", err)
	}
	got := string(content)
	if !strings.Contains(got, "renameat2") {
		t.Fatalf("a rename matched on its oldname must be exported, got:\n%s", got)
	}
	if strings.Contains(got, "openat") {
		t.Fatalf("the export must not include rows the filter rejects, got:\n%s", got)
	}
}

// TestExportRowsToCSVNeverOverwritesDefaultName pins the no-clobber contract
// for generated names: exporting twice under one default name (only accurate
// to the second) keeps both files, the second under a "-1" suffix before the
// extension, and the returned path names it.
func TestExportRowsToCSVNeverOverwritesDefaultName(t *testing.T) {
	dir := t.TempDir()
	first := []StreamEvent{{Seq: 1, Comm: "first", Syscall: "read"}}
	second := []StreamEvent{{Seq: 2, Comm: "second", Syscall: "write"}}
	name := defaultStreamExportFilename()

	p1, err := exportRowsToCSV(first, dir, name)
	if err != nil {
		t.Fatalf("first export: %v", err)
	}
	p2, err := exportRowsToCSV(second, dir, name)
	if err != nil {
		t.Fatalf("second export: %v", err)
	}
	want2 := filepath.Join(dir, strings.TrimSuffix(name, ".csv")+"-1.csv")
	if p1 != filepath.Join(dir, name) || p2 != want2 {
		t.Fatalf("paths = %q, %q; want %s then %s", p1, p2, name, want2)
	}
	for path, want := range map[string]string{p1: "first", p2: "second"} {
		data, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(data), want) {
			t.Errorf("%s = %q (err %v), want it to hold the %q export", path, data, err, want)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Errorf("dir holds %v, want exactly the two exports and no temp files", entries)
	}
}

// TestExportRowsToCSVReplacesUserChosenName pins the least-surprise policy: a
// filename the user typed is theirs, so exporting to it again replaces the
// earlier file in place and reports exactly that path.
func TestExportRowsToCSVReplacesUserChosenName(t *testing.T) {
	dir := t.TempDir()
	first := []StreamEvent{{Seq: 1, Comm: "first", Syscall: "read"}}
	second := []StreamEvent{{Seq: 2, Comm: "second", Syscall: "write"}}

	if _, err := exportRowsToCSV(first, dir, "mine.csv"); err != nil {
		t.Fatalf("first export: %v", err)
	}
	path, err := exportRowsToCSV(second, dir, "mine.csv")
	if err != nil {
		t.Fatalf("second export: %v", err)
	}
	if path != filepath.Join(dir, "mine.csv") {
		t.Fatalf("path = %q, want mine.csv", path)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "second") || strings.Contains(string(data), "first") {
		t.Errorf("mine.csv = %q, want only the second export", data)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("dir holds %v, want only mine.csv", entries)
	}
}

func TestIsDefaultStreamExportName(t *testing.T) {
	if !isDefaultStreamExportName(defaultStreamExportFilename()) {
		t.Error("generated default name not recognised")
	}
	for _, name := range []string{
		"", "mine.csv", "ior-stream-x.csv", "ior-stream-20260930-135324-1.csv",
		// Lenient parsing would accept a one-digit hour (09:05:00) and other
		// non-zero-padded fields; the exact layout must be required.
		"ior-stream-20260930-90500.csv",
		"ior-stream-20260930-9505.csv",
		"ior-stream-2026930-135324.csv",
		// A generated name without its extension is user-chosen, matching the
		// Parquet exporter (ensureCSVFilename would append ".csv" and make
		// it look generated if the check ran after it).
		"ior-stream-20260930-135324",
	} {
		if isDefaultStreamExportName(name) {
			t.Errorf("%q treated as generated; user-typed names must be replaced", name)
		}
	}
}

// TestExportRowsToCSVMissingExtensionIsUserChosen pins the consistency rule
// end to end: a typed name equal to a generated one minus ".csv" replaces the
// existing file instead of being suffixed, while the full generated name is
// never replaced.
func TestExportRowsToCSVMissingExtensionIsUserChosen(t *testing.T) {
	dir := t.TempDir()
	full := "ior-stream-20260930-135324.csv"
	if err := os.WriteFile(filepath.Join(dir, full), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	path, err := exportRowsToCSV(nil, dir, "ior-stream-20260930-135324")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if path != filepath.Join(dir, full) {
		t.Errorf("typed name published as %q, want it to replace %q", path, full)
	}
	if data, _ := os.ReadFile(path); strings.HasPrefix(string(data), "old") {
		t.Error("typed name did not replace the existing file")
	}

	path, err = exportRowsToCSV(nil, dir, full)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if path == filepath.Join(dir, full) {
		t.Error("generated name replaced an existing file")
	}
}

// TestExportRowsToCSVDoesNotFollowPlantedSymlink pins that a symlink sitting
// at a generated export name is neither written through nor replaced, and that
// for a user-typed name the symlink itself is replaced (never written through).
func TestExportRowsToCSVDoesNotFollowPlantedSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	name := defaultStreamExportFilename()
	if err := os.Symlink(victim, filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}

	path, err := exportRowsToCSV(nil, dir, name)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if path == filepath.Join(dir, name) {
		t.Fatal("export replaced the symlink")
	}
	if data, _ := os.ReadFile(victim); string(data) != "precious" {
		t.Errorf("symlink target was overwritten: %q", data)
	}

	if err := os.Symlink(victim, filepath.Join(dir, "typed.csv")); err != nil {
		t.Fatal(err)
	}
	if _, err := exportRowsToCSV(nil, dir, "typed.csv"); err != nil {
		t.Fatalf("export to typed name: %v", err)
	}
	if data, _ := os.ReadFile(victim); string(data) != "precious" {
		t.Errorf("typed-name export wrote through the symlink: %q", data)
	}
}
