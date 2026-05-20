package eventstream

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"reflect"
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

func TestWriteStreamCSVAppendsFamilyColumn(t *testing.T) {
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
		RequestedSleepNs: 0,
	}}
	fail := func(err error) (string, error) { return "", err }

	if err := writeStreamCSV(csv.NewWriter(&buf), rows, fail); err != nil {
		t.Fatalf("writeStreamCSV() error = %v", err)
	}

	records, err := csv.NewReader(bytes.NewReader(buf.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}
	wantHeader := []string{"seq", "time_ns", "gap_ns", "latency_ns", "comm", "pid", "tid", "syscall", "fd", "ret", "bytes", "file", "error", "family", "requested_sleep_ns"}
	if !reflect.DeepEqual(records[0], wantHeader) {
		t.Fatalf("header = %#v, want %#v", records[0], wantHeader)
	}
	if records[1][8] != "4" || records[1][12] != "false" || records[1][13] != "Network" || records[1][14] != "0" {
		t.Fatalf("family should be appended without shifting legacy columns, got %#v", records[1])
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
