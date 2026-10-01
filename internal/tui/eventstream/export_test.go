package eventstream

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ior/internal/atomicfile"
	"ior/internal/event"
	"ior/internal/globalfilter"
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

// TestResolveExportPath pins how the typed export name maps to a path: a bare
// name lands in exportDir, a directory part is honoured (relative to exportDir
// or absolute) and never reduced to its base name (task 9s2), ".csv" is
// appended to the last element only, and names that cannot be a file are
// rejected.
func TestResolveExportPath(t *testing.T) {
	cases := []struct {
		name, input, want string
		wantErr           string // substring; empty means success
	}{
		{name: "bare", input: "report", want: "/exp/report.csv"},
		{name: "bare with extension", input: "report.csv", want: "/exp/report.csv"},
		{name: "upper-case extension kept", input: "Report.CSV", want: "/exp/Report.CSV"},
		{name: "surrounding space trimmed", input: "  report  ", want: "/exp/report.csv"},
		{name: "relative subdirectory", input: "sub/file.csv", want: "/exp/sub/file.csv"},
		{name: "parent reference is honoured", input: "../x", want: "/x.csv"},
		{name: "absolute", input: "/tmp/x.csv", want: "/tmp/x.csv"},
		{name: "absolute gets extension", input: "/tmp/x", want: "/tmp/x.csv"},
		{name: "dot in directory not an extension", input: "a.csv/x", want: "/exp/a.csv/x.csv"},
		{name: "empty", input: "", wantErr: "empty"},
		{name: "blank", input: "   ", wantErr: "empty"},
		{name: "NUL", input: "a\x00b.csv", wantErr: "NUL"},
		{name: "NUL in directory", input: "/tmp/a\x00/b.csv", wantErr: "NUL"},
		{name: "dot", input: ".", wantErr: "directory"},
		{name: "dotdot", input: "..", wantErr: "directory"},
		{name: "cleans to dotdot", input: "some/../..", wantErr: "directory"},
		{name: "cleans to dot", input: "a/..", wantErr: "directory"},
		{name: "trailing slash", input: "out/", wantErr: "directory"},
		{name: "trailing slash dot slash", input: "out/./", wantErr: "directory"},
		{name: "trailing dot element", input: "out/.", wantErr: "directory"},
		{name: "trailing dotdot element", input: "out/..", wantErr: "directory"},
		{name: "absolute trailing dot element", input: "/tmp/out/.", wantErr: "directory"},
		{name: "dot inside is a file name", input: "out/.hidden", want: "/exp/out/.hidden.csv"},
		{name: "dots as a name suffix are a file name", input: "out/a..", want: "/exp/out/a...csv"},
		{name: "longest file name fits", input: strings.Repeat("a", atomicfile.NameMax-4), want: "/exp/" + strings.Repeat("a", atomicfile.NameMax-4) + ".csv"},
		{name: "file name past NAME_MAX", input: strings.Repeat("a", atomicfile.NameMax-3), wantErr: "too long"},
		{name: "long name judged on its last element", input: strings.Repeat("d", atomicfile.NameMax) + "/x", want: "/exp/" + strings.Repeat("d", atomicfile.NameMax) + "/x.csv"},
		{name: "root", input: "/", wantErr: "directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveExportPath("/exp", tc.input)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("resolveExportPath(%q) = %q, %v; want error containing %q", tc.input, got, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveExportPath(%q): unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("resolveExportPath(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestResolveExportPathWithoutExportDir covers the empty exportDir: a relative
// name stays relative (the process working directory), an absolute one is
// untouched.
func TestResolveExportPathWithoutExportDir(t *testing.T) {
	if got, err := resolveExportPath("", "sub/x"); err != nil || got != "sub/x.csv" {
		t.Fatalf("relative: got %q, %v", got, err)
	}
	if got, err := resolveExportPath("", "/tmp/x"); err != nil || got != "/tmp/x.csv" {
		t.Fatalf("absolute: got %q, %v", got, err)
	}
}

// TestExportRowsToCSVHonoursAbsolutePath is the regression for task 9s2: the
// directory part of a typed name used to be dropped, so "/tmp/x.csv" was
// written to ./x.csv in exportDir with nothing said. The file must land where
// it was asked to, and nothing must appear in exportDir.
func TestExportRowsToCSVHonoursAbsolutePath(t *testing.T) {
	exportDir, target := t.TempDir(), t.TempDir()
	want := filepath.Join(target, "x.csv")

	got, err := exportRowsToCSV(nil, exportDir, want)
	if err != nil {
		t.Fatalf("exportRowsToCSV: %v", err)
	}
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("file not written at the typed path: %v", err)
	}
	if entries, _ := os.ReadDir(exportDir); len(entries) != 0 {
		t.Fatalf("exportDir must stay empty, holds %d entries", len(entries))
	}
}

// TestExportRowsToCSVHonoursRelativeSubdirectory checks a relative name with
// a directory part is resolved against exportDir, and that a parent reference
// is followed rather than stripped.
func TestExportRowsToCSVHonoursRelativeSubdirectory(t *testing.T) {
	root := t.TempDir()
	exportDir := filepath.Join(root, "exp")
	for _, d := range []string{exportDir, filepath.Join(exportDir, "sub")} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	got, err := exportRowsToCSV(nil, exportDir, "sub/in.csv")
	if err != nil || got != filepath.Join(exportDir, "sub", "in.csv") {
		t.Fatalf("subdirectory: got %q, %v", got, err)
	}
	got, err = exportRowsToCSV(nil, exportDir, "../up")
	if err != nil || got != filepath.Join(root, "up.csv") {
		t.Fatalf("parent reference: got %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(exportDir, "up.csv")); err == nil {
		t.Fatal("../up must not be reduced to its base name inside exportDir")
	}
}

// TestExportRowsToCSVRejectsUnusableNames pins the negative cases: each is
// refused with an error naming the problem, and leaves no file behind.
func TestExportRowsToCSVRejectsUnusableNames(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "adir.csv"), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, input, wantErr string }{
		{"empty", "", "empty"},
		{"NUL", "a\x00b", "NUL"},
		{"directory reference", "..", "directory"},
		{"trailing dot element", "adir.csv/.", "directory"},
		{"too long", strings.Repeat("a", atomicfile.NameMax), "too long"},
		{"trailing slash", "adir.csv/", "directory"},
		{"existing directory", "adir", "is a directory"},
		{"missing parent", "nope/x.csv", "no such file or directory"},
		{"missing absolute parent", filepath.Join(dir, "nope", "x.csv"), "no such file or directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, err := exportRowsToCSV(nil, dir, tc.input)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %q, %v; want error containing %q", path, err, tc.wantErr)
			}
			if strings.Contains(err.Error(), ".tmp") {
				t.Fatalf("error leaks the internal temp name: %v", err)
			}
		})
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("a rejected export left files behind: %v, %v", entries, err)
	}
}

// TestExportRowsToCSVUnwritableDirectory checks a read-only directory is
// reported as one readable error naming the directory. The chmod variant is
// skipped as root, which ignores directory permissions; the /sys variant
// below covers root.
func TestExportRowsToCSVUnwritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions; see TestExportRowsToCSVUnwritableSysDirectory")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	_, err := exportRowsToCSV(nil, t.TempDir(), filepath.Join(dir, "x.csv"))
	if err == nil || !strings.Contains(err.Error(), "permission denied") || !strings.Contains(err.Error(), dir) {
		t.Fatalf("want a permission error naming %s, got %v", dir, err)
	}
	if strings.Contains(err.Error(), ".tmp") {
		t.Fatalf("error leaks the internal temp name: %v", err)
	}
}

// TestExportRowsToCSVUnwritableSysDirectory is the unwritable-directory check
// that also runs as root: files cannot be created in /sys, root or not
// (EACCES), so no chmod and no skip for root is needed. It is skipped only
// where /sys does not exist. The error must be the single readable message
// naming the directory, once, without the internal temp name.
func TestExportRowsToCSVUnwritableSysDirectory(t *testing.T) {
	for _, dir := range []string{"/sys", "/sys/kernel"} {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			t.Skipf("%s is not available: %v", dir, err)
		}
		path, err := exportRowsToCSV(nil, t.TempDir(), filepath.Join(dir, "x.csv"))
		if err == nil {
			_ = os.Remove(path)
			t.Fatalf("%s accepted an export", dir)
		}
		msg := err.Error()
		if !strings.Contains(msg, "cannot create files in "+dir) || !strings.Contains(msg, "permission denied") ||
			strings.Count(msg, dir) != 1 || strings.Contains(msg, ".tmp") {
			t.Fatalf("%s: want one readable permission error naming the directory, got %v", dir, err)
		}
	}
}

// TestExportRowsToCSVTooLongNameIsRefusedReadably: a final name past NAME_MAX
// passes the probe (it only creates a short temp name) and would fail at the
// publish, so resolveExportPath refuses it up front with one message that
// names the limit, not the temp file, and nothing is left behind.
func TestExportRowsToCSVTooLongNameIsRefusedReadably(t *testing.T) {
	dir := t.TempDir()
	_, err := exportRowsToCSV(nil, dir, strings.Repeat("a", atomicfile.NameMax))
	if err == nil || !strings.Contains(err.Error(), "too long") || !strings.Contains(err.Error(), "255") {
		t.Fatalf("want a too-long error naming the limit, got %v", err)
	}
	if strings.Contains(err.Error(), ".tmp") {
		t.Fatalf("error leaks the internal temp name: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("a refused export left files behind: %v", entries)
	}
}

// TestExportRowsToCSVReplacesExistingTypedFile checks a typed name, also one
// with a directory part, replaces an existing file, and does not follow a
// symlink at the name: the link is replaced, its target left alone.
func TestExportRowsToCSVReplacesExistingTypedFile(t *testing.T) {
	dir, elsewhere := t.TempDir(), t.TempDir()
	victim := filepath.Join(elsewhere, "victim.txt")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "out.csv")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}

	got, err := exportRowsToCSV(nil, t.TempDir(), link)
	if err != nil || got != link {
		t.Fatalf("export over a symlink: got %q, %v", got, err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("the symlink target was written through: %q", b)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("the symlink should have been replaced by a regular file: %v, %v", info, err)
	}
}

// TestExportRowsToCSVGeneratedNameWithDirectoryIsNotReplaced checks the
// generated-name rule is judged on the file name alone, so a default name
// typed with a directory part still never overwrites.
func TestExportRowsToCSVGeneratedNameWithDirectoryIsNotReplaced(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "ior-stream-20260930-135324.csv")
	first, err := exportRowsToCSV(nil, t.TempDir(), name)
	if err != nil || first != name {
		t.Fatalf("first export: %q, %v", first, err)
	}
	second, err := exportRowsToCSV(nil, t.TempDir(), name)
	if err != nil || second == name {
		t.Fatalf("second export must pick a -N name, got %q, %v", second, err)
	}
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
	// Spelled out (not streamCSVHeader) so a reorder or rename fails here:
	// the first 17 columns are a positional contract, the rest are appended.
	wantHeader := []string{"seq", "time_ns", "gap_ns", "latency_ns", "comm", "pid", "tid", "syscall", "fd", "ret", "bytes", "file", "error", "family", "requested_sleep_ns", "nfds", "timeout_ns", "address_space_bytes", "old_file", "epoll_op", "epoll_target_fd", "epoll_events"}
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

// TestWriteStreamCSVCarriesFullPerEventSchema is the task rq2 regression: the
// export used to drop old_file, address_space_bytes and the epoll_* columns
// that the Parquet recording and the README promise ("full per-event
// schema"). Every cell is checked by header name against distinct values, so a
// swapped or missing column fails.
func TestWriteStreamCSVCarriesFullPerEventSchema(t *testing.T) {
	rows := []StreamEvent{
		{Seq: 1, Syscall: "renameat2", FileName: "/new,name", OldName: "/old \"name\"", FD: -1},
		{Seq: 2, Syscall: "mmap", AddressSpaceBytes: 8192, FD: -1},
		{Seq: 3, Syscall: "epoll_ctl", EpollOp: "ADD", EpollTargetFD: 9, EpollEvents: 0x85, FD: 4},
		{Seq: 4, Syscall: "read", FileName: "/f", FD: 3},
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
	want := []map[string]string{
		{"syscall": "renameat2", "file": "/new,name", "old_file": `/old "name"`, "address_space_bytes": "0", "epoll_op": "", "epoll_target_fd": "0", "epoll_events": "0"},
		{"syscall": "mmap", "old_file": "", "address_space_bytes": "8192", "epoll_op": ""},
		{"syscall": "epoll_ctl", "old_file": "", "address_space_bytes": "0", "epoll_op": "ADD", "epoll_target_fd": "9", "epoll_events": "133"},
		{"syscall": "read", "file": "/f", "old_file": "", "epoll_op": "", "epoll_target_fd": "0"},
	}
	if len(records) != len(want)+1 {
		t.Fatalf("got %d records, want header + %d rows", len(records), len(want))
	}
	for i, cells := range want {
		for name, v := range cells {
			if got := records[i+1][col[name]]; got != v {
				t.Errorf("row %d column %s = %q, want %q", i+1, name, got, v)
			}
		}
	}
}

// TestWriteStreamCSVSkipsWarningRows is the task rq2 regression for the
// synthetic warning rows: they used to be exported as a "warning" syscall with
// pid 0, ret -1 and a wall-clock time_ns among boot-clock event rows. A real
// syscall row that merely has the same placeholder-looking values stays.
func TestWriteStreamCSVSkipsWarningRows(t *testing.T) {
	rows := []StreamEvent{
		{Seq: 1, TimeNs: 500, Syscall: "read", FileName: "/f", FD: 3},
		NewWarningEvent(2, "Trace stopped: boom"),
		{Seq: 3, TimeNs: 900, Syscall: "warning", FD: -1},
	}
	var buf bytes.Buffer
	if err := writeStreamCSV(csv.NewWriter(&buf), rows); err != nil {
		t.Fatalf("writeStreamCSV() error = %v", err)
	}
	records, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("got %d records, want header + 2 syscall rows:\n%v", len(records), records)
	}
	if records[1][0] != "1" || records[2][0] != "3" {
		t.Fatalf("seqs = %s,%s, want 1,3 (only the IsWarning row is skipped)", records[1][0], records[2][0])
	}
	if strings.Contains(buf.String(), "boom") {
		t.Fatalf("warning text leaked into the export:\n%s", buf.String())
	}
}

// TestWriteStreamCSVLeavesFilelessFileEmpty is the task pq2 regression for the
// stream CSV export: a row without a file exports an empty file cell and its
// fd -1, not the "N:file" display placeholder, while a file really named
// "N:file" keeps that name (the flag, not the text, tells them apart).
func TestWriteStreamCSVLeavesFilelessFileEmpty(t *testing.T) {
	var buf bytes.Buffer
	rows := []StreamEvent{
		{Seq: 1, Syscall: "sync", FileName: event.NoFileName, NoFile: true, FD: -1},
		{Seq: 2, Syscall: "openat", FileName: event.NoFileName, FD: 3},
		{Seq: 3, Syscall: "read", FileName: "/tmp/f", FD: 3},
	}
	if err := writeStreamCSV(csv.NewWriter(&buf), rows); err != nil {
		t.Fatalf("writeStreamCSV() error = %v", err)
	}
	records, err := csv.NewReader(bytes.NewReader(buf.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}
	const fdCol, fileCol = 8, 11
	for i, want := range []struct{ fd, file string }{{"-1", ""}, {"3", event.NoFileName}, {"3", "/tmp/f"}} {
		got := records[i+1]
		if got[fdCol] != want.fd || got[fileCol] != want.file {
			t.Errorf("row %d fd/file = %q/%q, want %q/%q", i+1, got[fdCol], got[fileCol], want.fd, want.file)
		}
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

// TestExportSnapshotKeepsOldFileAndDropsWarnings drives the real snapshot path
// (ring buffer -> filter -> CSV file) for task rq2: the rename's source path
// reaches the old_file column, and a warning pushed into the ring, as the
// runtime does, is not in the file even when the filter admits it.
func TestExportSnapshotKeepsOldFileAndDropsWarnings(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(StreamEvent{Seq: 1, TimeNs: 10, Syscall: "renameat2", Comm: "mv", FileName: "/tmp/new.txt", OldName: "/tmp/old.txt", FD: -1})
	rb.Push(NewWarningEvent(2, "Dropped malformed event"))

	path, err := exportSnapshotToCSV(rb, Filter{}, t.TempDir(), "full.csv")
	if err != nil {
		t.Fatalf("exportSnapshotToCSV: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	records, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatalf("parse export: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want header + the rename only: %v", len(records), records)
	}
	row := records[1]
	if row[11] != "/tmp/new.txt" || row[18] != "/tmp/old.txt" {
		t.Fatalf("file/old_file = %q/%q, want /tmp/new.txt//tmp/old.txt", row[11], row[18])
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

// readCSVSeqs parses the CSV at path and returns its data rows' seq and
// syscall columns, failing the test on any read or parse error.
func readCSVSeqs(t *testing.T, path string) (seqs, syscalls []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	records, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatalf("parse export: %v", err)
	}
	for _, rec := range records[1:] { // records[0] is the header
		seqs = append(seqs, rec[0])
		syscalls = append(syscalls, rec[7])
	}
	return seqs, syscalls
}

// TestExportsWithActiveFilterKeepRealRowAndDropWarning pins the interplay of
// the two halves of task ur2's fix: filterRows lets synthetic warning rows
// through any user filter (so the Stream tab can explain an empty trace), and
// writeStreamCSV leaves them out of every CSV. With an active PID filter and a
// warning row in the ring, both export paths must contain exactly the one
// matching real row: the snapshot export (the dashboard-wide 'e' path, which
// runs filterRows itself) and the paused x/X export of m.filtered (which
// inherits the warning row from filterRows). Neither may contain the warning
// or the real row the filter rejects. The two paths do not share a skip, so a
// regression in either leaks a fake "warning" syscall into the data file.
func TestExportsWithActiveFilterKeepRealRowAndDropWarning(t *testing.T) {
	rb := NewRingBuffer()
	rb.Push(NewWarningEvent(1, "ior: -tid 1: not a thread of -pid 7: the trace will stay empty"))
	rb.Push(StreamEvent{Seq: 2, TimeNs: 20, Syscall: "read", Family: "FS", Comm: "cat", PID: 7, TID: 7, FD: UnknownFD})
	rb.Push(StreamEvent{Seq: 3, TimeNs: 30, Syscall: "write", Family: "FS", Comm: "dd", PID: 99, TID: 99, FD: UnknownFD})
	filter := Filter{PID: globalfilter.NewEqFilter(7)}

	// want is the single row both exports must hold: the PID 7 read.
	check := func(t *testing.T, path string) {
		t.Helper()
		seqs, syscalls := readCSVSeqs(t, path)
		if !reflect.DeepEqual(seqs, []string{"2"}) || !reflect.DeepEqual(syscalls, []string{"read"}) {
			t.Fatalf("export rows seq=%v syscall=%v, want only seq 2 read (no warning, no pid 99 write)", seqs, syscalls)
		}
	}

	t.Run("snapshot export (e)", func(t *testing.T) {
		path, err := exportSnapshotToCSV(rb, filter, t.TempDir(), "snapshot.csv")
		if err != nil {
			t.Fatalf("exportSnapshotToCSV: %v", err)
		}
		check(t, path)
	})

	t.Run("paused export of m.filtered (x/X)", func(t *testing.T) {
		m := NewModel(rb)
		m.exportDir = t.TempDir()
		m.SetFilter(filter)
		m.Refresh()
		// Precondition: the Stream tab does show the warning row, so the
		// export's own skip is what keeps it out of the file, not a filter
		// that already dropped it.
		if len(m.filtered) != 2 || !m.filtered[0].IsWarning || m.filtered[1].Seq != 2 {
			t.Fatalf("m.filtered = %+v, want the warning row then the pid 7 read", m.filtered)
		}
		if handled, _ := m.HandleKey(" "); !handled || !m.Paused() {
			t.Fatalf("space did not pause the stream (handled=%v paused=%v)", handled, m.Paused())
		}
		if handled, _ := m.HandleKey("x"); !handled || m.lastExportPath == "" {
			t.Fatalf("x did not export (handled=%v status=%q)", handled, m.statusMessage)
		}
		check(t, m.lastExportPath)

		// X (modal) goes through the same exportFilteredToCSV.
		path, err := m.exportFilteredToCSV("modal.csv")
		if err != nil {
			t.Fatalf("exportFilteredToCSV: %v", err)
		}
		check(t, path)
	})
}
