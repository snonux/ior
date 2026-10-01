package eventstream

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"ior/internal/atomicfile"
	"ior/internal/parquet"
)

// shellSplit tokenizes s using POSIX-like shell quoting rules so that paths
// containing spaces (e.g. EDITOR='/My Editor/hx') are preserved as a single
// token.  It supports:
//   - single-quoted strings  : no escape processing inside ' … '
//   - double-quoted strings  : \" and \\ are recognised; other backslashes
//     are kept verbatim
//   - unquoted tokens        : backslash escapes the next character
//
// Unterminated quotes are treated as if the closing delimiter is implicit at
// end-of-string, matching common shell lenient behaviour.
func shellSplit(s string) []string {
	var tokens []string
	var current strings.Builder
	inToken := false

	i := 0
	for i < len(s) {
		ch := s[i]
		switch {
		case ch == '\'':
			inToken = true
			i = consumeSingleQuoted(s, i+1, &current)
		case ch == '"':
			inToken = true
			i = consumeDoubleQuoted(s, i+1, &current)
		case ch == '\\':
			inToken = true
			i = consumeBackslash(s, i, &current)
		case ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r':
			// Whitespace: flush current token if any.
			if inToken {
				tokens = append(tokens, current.String())
				current.Reset()
				inToken = false
			}
			i++
		default:
			inToken = true
			current.WriteByte(ch)
			i++
		}
	}

	if inToken {
		tokens = append(tokens, current.String())
	}
	return tokens
}

// consumeSingleQuoted copies characters verbatim from s starting at i until
// the closing single-quote (or end-of-string). Returns the index after the
// closing quote.
func consumeSingleQuoted(s string, i int, out *strings.Builder) int {
	for i < len(s) && s[i] != '\'' {
		out.WriteByte(s[i])
		i++
	}
	if i < len(s) {
		i++ // consume the closing '
	}
	return i
}

// consumeDoubleQuoted copies characters from s starting at i until the
// closing double-quote, processing \" and \\ escape sequences. Returns the
// index after the closing quote.
func consumeDoubleQuoted(s string, i int, out *strings.Builder) int {
	for i < len(s) && s[i] != '"' {
		if s[i] == '\\' && i+1 < len(s) {
			next := s[i+1]
			if next == '"' || next == '\\' {
				out.WriteByte(next)
				i += 2
				continue
			}
		}
		out.WriteByte(s[i])
		i++
	}
	if i < len(s) {
		i++ // consume the closing "
	}
	return i
}

// consumeBackslash handles a backslash outside any quoted context: if a next
// character exists it is treated as escaped; a trailing backslash is kept as-is.
// i must point at the backslash character. Returns the index after consumed bytes.
func consumeBackslash(s string, i int, out *strings.Builder) int {
	if i+1 < len(s) {
		out.WriteByte(s[i+1])
		return i + 2
	}
	// Trailing backslash: keep it.
	out.WriteByte('\\')
	return i + 1
}

// defaultStreamExportLayout is the time.Format layout of the generated export
// name; isDefaultStreamExportName matches against the same layout so the two
// cannot drift apart.
const defaultStreamExportLayout = "ior-stream-20060102-150405.csv"

func defaultStreamExportFilename() string {
	return time.Now().Format(defaultStreamExportLayout)
}

// isDefaultStreamExportName reports whether name, exactly as the user gave it
// (before resolveExportPath appends ".csv"), is a generated default export
// name rather than one the user typed. Generated names are only accurate to
// the second and are never replaced; a typed name is the user's to overwrite.
// The match is strict (atomicfile.IsGeneratedName: exact zero-padded layout,
// including the extension, judged on the file name only, so a generated name
// typed with a directory part still counts). It is judged on the raw input,
// so a name that only becomes ".csv" after resolveExportPath counts as
// user-chosen, the same rule the Parquet recording name follows.
func isDefaultStreamExportName(name string) bool {
	return atomicfile.IsGeneratedName(name, defaultStreamExportLayout)
}

func exportSnapshotToCSV(source Source, filter Filter, exportDir, filename string) (string, error) {
	name := strings.TrimSpace(filename)
	if name == "" {
		name = defaultStreamExportFilename()
	}

	rows := make([]StreamEvent, 0)
	if source != nil {
		snapshot := source.Snapshot()
		// Same row selection as Model.applyFilter, so the export holds the
		// filtered real rows the Stream tab is showing; the synthetic warning
		// rows filterRows lets through for the tab are excluded here by
		// writeStreamCSV, so they never reach the file.
		rows = filterRows(make([]StreamEvent, 0, len(snapshot)), snapshot, filter)
	}

	return exportRowsToCSV(rows, exportDir, name)
}

// exportRowsToCSV writes rows to a CSV file named filename and returns its
// absolute path. The name is resolved by resolveExportPath: a bare name lands
// in exportDir, a name with a directory part is honoured as typed (relative
// to exportDir, or absolute), exactly like the R recording prompt and
// -parquet; the Stream tab shows the returned path, so the user always sees
// where the file went.
//
// The rows go to a uniquely named temp file first, so a reader never sees a
// partial CSV and a symlink planted at a predictable name is never written
// through. What happens when the target exists depends on who chose the name:
// a generated default name (only accurate to the second) is never replaced -
// a taken name yields a "-N" suffix, and the returned path says so - while a
// name the user typed is atomically replaced, as it always was. Before
// anything is written the target is probed (probeExportPath), so a missing or
// unwritable directory, a directory in place of the file and a name the
// filesystem refuses come back as one readable error naming the directory.
func exportRowsToCSV(rows []StreamEvent, exportDir, filename string) (string, error) {
	path, err := resolveExportPath(exportDir, filename)
	if err != nil {
		return "", err
	}
	generated := isDefaultStreamExportName(filename)
	if err := probeExportPath(path, generated); err != nil {
		return "", err
	}

	write := func(w io.Writer) error { return writeStreamCSV(csv.NewWriter(w), rows) }
	var published string
	if generated {
		published, err = atomicfile.WriteFile(path, ".csv", write)
	} else {
		published, err = atomicfile.ReplaceFile(path, write)
	}
	if err != nil {
		return "", err
	}
	absPath, err := filepath.Abs(published)
	if err != nil {
		return published, nil
	}
	return absPath, nil
}

// probeExportPath checks, before the CSV is rendered, that a file can be
// published at path. It is the same early check the Parquet recording runs
// (atomicfile.ProbeReplace: missing or unwritable directory, an existing
// directory at the name, characters the filesystem refuses), so the message is
// the readable "cannot create files in <dir>: no such file or directory"
// instead of the writer's error about an internal ior-<hex>.tmp name. A
// generated name is never replaced, so the replace-only checks (the name is
// an existing directory) are left to the publish for it: atomicfile.Probe.
func probeExportPath(path string, generated bool) error {
	if generated {
		return atomicfile.Probe(path)
	}
	return atomicfile.ProbeReplace(path)
}

// streamCSVHeader is the stream CSV export's column order. The first 17
// columns are the original layout and must never move: later columns are only
// ever appended, so a script indexing by position keeps working. The trailing
// five (address_space_bytes, old_file, epoll_op, epoll_target_fd,
// epoll_events) complete the export to the per-event schema of the Parquet
// recording, under the same names (docs/parquet-querying.md); only `error`
// (Parquet: is_error) keeps its historical name, and the Parquet-internal
// filter_epoch is not exported. TestStreamCSVHeaderMatchesParquetSchema ties
// this list to the parquet.Record tags, so a column added on one side fails
// the test of the other. streamCSVRecord must emit the cells in exactly this
// order.
var streamCSVHeader = []string{
	"seq", "time_ns", "gap_ns", "latency_ns", "comm", "pid", "tid", "syscall",
	"fd", "ret", "bytes", "file", "error", "family", "requested_sleep_ns",
	"nfds", "timeout_ns",
	"address_space_bytes", "old_file", "epoll_op", "epoll_target_fd", "epoll_events",
}

// writeStreamCSV writes the CSV header and the syscall rows to w and flushes
// it. Synthetic warning rows (streamrow.Row.IsWarning) are skipped: they are
// UI notes whose time_ns is wall-clock and whose pid/ret are placeholders, so
// writing them would put a fake "warning" syscall with a time from another
// clock into the data, unlike the Parquet recording, which never sees them.
func writeStreamCSV(w *csv.Writer, rows []StreamEvent) error {
	if err := w.Write(streamCSVHeader); err != nil {
		return err
	}
	for i := range rows {
		if rows[i].IsWarning {
			continue
		}
		if err := w.Write(streamCSVRecord(&rows[i])); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

// streamCSVRecord renders one row in streamCSVHeader order.
//
// comm, file and old_file are the free-form text columns. Like the Parquet
// recording they go through parquet.RecordFromStream, the single place that
// repairs invalid UTF-8 (a rune cut at the comm/path capture limit is
// dropped, any other invalid byte becomes a \xHH escape), so a strict reader
// such as DuckDB's read_csv accepts the file and the CSV and the Parquet
// recording hold identical text for the same row. Valid text is unchanged.
func streamCSVRecord(ev *StreamEvent) []string {
	// filter_epoch (the second argument) is recorder bookkeeping and not a CSV
	// column, so 0 is passed; only the repaired text fields are used.
	rec := parquet.RecordFromStream(*ev, 0)
	return []string{
		fmt.Sprintf("%d", ev.Seq),
		fmt.Sprintf("%d", ev.TimeNs),
		fmt.Sprintf("%d", ev.GapNs),
		fmt.Sprintf("%d", ev.DurationNs),
		rec.Comm,
		fmt.Sprintf("%d", ev.PID),
		fmt.Sprintf("%d", ev.TID),
		ev.Syscall,
		fmt.Sprintf("%d", ev.FD),
		fmt.Sprintf("%d", ev.RetVal),
		fmt.Sprintf("%d", ev.Bytes),
		// rec.File is built from FileValue, not FileName: the export is a
		// data file, so a fileless row gets an empty file cell like the
		// Parquet column instead of the "N:file" display placeholder (task
		// pq2). The fd column keeps -1 (streamrow.UnknownFD) for "no
		// descriptor".
		rec.File,
		fmt.Sprintf("%t", ev.IsError),
		ev.Family,
		fmt.Sprintf("%d", ev.RequestedSleepNs),
		fmt.Sprintf("%d", ev.Nfds),
		fmt.Sprintf("%d", ev.TimeoutNs),
		fmt.Sprintf("%d", ev.AddressSpaceBytes),
		// Rename/link source path; empty for every other syscall. The
		// file column holds the destination.
		rec.OldFile,
		// Empty/zero for everything but epoll_ctl.
		ev.EpollOp,
		fmt.Sprintf("%d", ev.EpollTargetFD),
		fmt.Sprintf("%d", ev.EpollEvents),
	}
}

// resolveExportPath turns the filename typed into the export modal into the
// path to write. The name is honoured as typed, never rewritten:
//
//   - a bare name ("trace") lands in exportDir;
//   - a relative name with a directory part ("out/trace", "../trace") is
//     resolved against exportDir, an absolute one ("/tmp/trace.csv") is used
//     as is. Nothing confines it to exportDir: the name is typed by the user
//     in their own TUI, no privilege boundary is crossed, and the R recording
//     prompt and -parquet take any path too. (The old behaviour kept only the
//     base name, so "/tmp/x.csv" was silently written to ./x.csv.) Missing
//     parent directories are not created - the probe reports them;
//   - ".csv" is appended to the last element when it lacks it
//     (case-insensitively).
//
// It rejects, with a message the modal shows, an empty name, a NUL byte (no
// path can hold one) and a name that denotes a directory rather than a file
// (trailing separator, ".", "..", or a path that cleans to one of them).
func resolveExportPath(exportDir, name string) (string, error) {
	typed := strings.TrimSpace(name)
	switch {
	case typed == "":
		return "", errors.New("filename cannot be empty")
	case strings.ContainsRune(typed, 0):
		return "", errors.New("filename must not contain a NUL byte")
	case namesDirectory(typed):
		return "", fmt.Errorf("%q is a directory, not a file name", typed)
	}

	path := filepath.Clean(typed)
	if !strings.HasSuffix(strings.ToLower(path), ".csv") {
		path += ".csv"
	}
	if !filepath.IsAbs(path) && exportDir != "" {
		path = filepath.Join(exportDir, path)
	}
	return path, nil
}

// namesDirectory reports whether the typed name can only denote a directory:
// it ends in a path separator, or cleans to the root, "." or ".." (so "a/..",
// "../.." and "." are all refused instead of becoming ".csv" files named
// after a directory reference).
func namesDirectory(typed string) bool {
	if strings.HasSuffix(typed, string(filepath.Separator)) {
		return true
	}
	switch filepath.Base(filepath.Clean(typed)) {
	case ".", "..", string(filepath.Separator):
		return true
	}
	return false
}

// ExportSourceSnapshotToCSV is the export path for callers that must not
// touch a live Model: Bubble Tea runs command closures on their own goroutine,
// and the Model's plain fields (width, height, paused, ...) are mutated by
// Update/View with no lock, so a command goroutine reading them races. This
// function takes the concrete inputs instead — capture them on the Update
// goroutine before returning the command (see Model.ExportInputs and
// tui.runExportCmd). Source.Snapshot itself is RWMutex-guarded
// (streamrow.RingBuffer) and safe to call from any goroutine; the Filter is a
// plain value whose pointed-to sub-filters are replaced wholesale, never
// mutated in place.
func ExportSourceSnapshotToCSV(source Source, filter Filter, exportDir, filename string) (string, error) {
	return exportSnapshotToCSV(source, filter, exportDir, filename)
}

// ExportInputs captures the concrete CSV-export inputs (source, active
// filter, target directory) on the caller's goroutine. Return these from the
// Update path and hand them to the command closure instead of a Model
// pointer: command closures run on their own goroutine while Update/View
// keep mutating this Model (see ExportSourceSnapshotToCSV).
//
// The Source is deliberately the LIVE one even while the stream is paused: the
// dashboard-wide 'e' export is a fresh snapshot of the ring that works outside
// paused mode too (task 364), whereas the Stream tab's x/X export writes the
// frozen paused rows (exportFilteredToCSV). The two differ on purpose, which
// README.md and AGENTS.md state, and the 'e' modal warns about it while the
// stream is paused (export.Model.OpenFor). TestExportInputsStayLiveWhilePaused
// pins it.
func (m *Model) ExportInputs() (Source, Filter, string) {
	return m.source, m.filter, m.exportDir
}

func (m *Model) exportFilteredToCSV(filename string) (string, error) {
	return exportRowsToCSV(m.filtered, m.exportDir, filename)
}

// EditorCommandForPath builds an editor command for the given path.
func EditorCommandForPath(path string) (*exec.Cmd, error) {
	parts, _, err := resolveEditorCommand()
	if err != nil {
		return nil, err
	}
	args := append(parts[1:], path)
	return exec.Command(parts[0], args...), nil
}

func resolveEditorCommand() ([]string, string, error) {
	candidates := []string{"EDITOR", "VISUAL", "SUDO_EDITOR"}
	for _, key := range candidates {
		value := strings.TrimSpace(os.Getenv(key))
		if value == "" {
			continue
		}
		// Use shellSplit instead of strings.Fields so that quoted paths with
		// spaces (e.g. EDITOR='/My Editor/hx') are not broken into multiple
		// tokens.
		parts := shellSplit(value)
		if len(parts) == 0 {
			continue
		}
		return parts, key, nil
	}
	return []string{fallbackEditor()}, "fallback", nil
}

func fallbackEditor() string {
	if _, err := exec.LookPath("hx"); err == nil {
		return "hx"
	}
	return "vi"
}
