package eventstream

import (
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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
			// Single-quote: copy until the matching closing quote verbatim.
			inToken = true
			i++
			for i < len(s) && s[i] != '\'' {
				current.WriteByte(s[i])
				i++
			}
			// Skip closing quote if present; if missing we just fall through.
			if i < len(s) {
				i++ // consume the closing '
			}

		case ch == '"':
			// Double-quote: process backslash escapes for \" and \\.
			inToken = true
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					next := s[i+1]
					if next == '"' || next == '\\' {
						current.WriteByte(next)
						i += 2
						continue
					}
				}
				current.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				i++ // consume the closing "
			}

		case ch == '\\':
			// Backslash outside quotes: escape the next character.
			inToken = true
			if i+1 < len(s) {
				current.WriteByte(s[i+1])
				i += 2
			} else {
				// Trailing backslash: keep it.
				current.WriteByte('\\')
				i++
			}

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

func defaultStreamExportFilename() string {
	return fmt.Sprintf("ior-stream-%s.csv", time.Now().Format("20060102-150405"))
}

func exportSnapshotToCSV(source Source, filter Filter, exportDir, filename string) (string, error) {
	name := strings.TrimSpace(filename)
	if name == "" {
		name = defaultStreamExportFilename()
	}

	rows := make([]StreamEvent, 0)
	if source != nil {
		snapshot := source.Snapshot()
		rows = make([]StreamEvent, 0, len(snapshot))
		for i := range snapshot {
			ev := snapshot[i]
			if filter.Matches(&ev) {
				rows = append(rows, ev)
			}
		}
	}

	return exportRowsToCSV(rows, exportDir, name)
}

func exportRowsToCSV(rows []StreamEvent, exportDir, filename string) (string, error) {
	name, err := ensureCSVFilename(filename)
	if err != nil {
		return "", err
	}
	path := name
	if exportDir != "" {
		path = filepath.Join(exportDir, name)
	}

	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	closed := false
	closeFile := func() error {
		if closed {
			return nil
		}
		closed = true
		return f.Close()
	}
	fail := func(baseErr error) (string, error) {
		if closeErr := closeFile(); closeErr != nil {
			return "", errors.Join(baseErr, closeErr)
		}
		return "", baseErr
	}

	w := csv.NewWriter(f)

	header := []string{"seq", "time_ns", "gap_ns", "latency_ns", "comm", "pid", "tid", "syscall", "fd", "ret", "bytes", "file", "error"}
	if err := w.Write(header); err != nil {
		return fail(err)
	}
	for i := range rows {
		ev := rows[i]
		record := []string{
			fmt.Sprintf("%d", ev.Seq),
			fmt.Sprintf("%d", ev.TimeNs),
			fmt.Sprintf("%d", ev.GapNs),
			fmt.Sprintf("%d", ev.DurationNs),
			ev.Comm,
			fmt.Sprintf("%d", ev.PID),
			fmt.Sprintf("%d", ev.TID),
			ev.Syscall,
			fmt.Sprintf("%d", ev.FD),
			fmt.Sprintf("%d", ev.RetVal),
			fmt.Sprintf("%d", ev.Bytes),
			ev.FileName,
			fmt.Sprintf("%t", ev.IsError),
		}
		if err := w.Write(record); err != nil {
			return fail(err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return fail(err)
	}
	if err := closeFile(); err != nil {
		return "", err
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return path, nil
	}
	return absPath, nil
}

// ensureCSVFilename validates and normalises a user-supplied export filename.
// It strips any directory components (preventing path traversal outside
// exportDir) and rejects names that resolve to "." or "..".  A ".csv"
// extension is appended when the caller omits it.
func ensureCSVFilename(name string) (string, error) {
	clean := strings.TrimSpace(name)
	if clean == "" {
		return "", errors.New("filename cannot be empty")
	}

	// Strip all directory components so that inputs such as
	// "../../etc/passwd" or "/absolute/path.csv" cannot escape exportDir.
	base := filepath.Base(clean)

	// filepath.Base returns "." for empty/dot inputs and ".." for a raw ".."
	// component — both are unusable as a plain filename.
	if base == "." || base == ".." {
		return "", errors.New("filename must not be a directory reference")
	}

	if strings.HasSuffix(strings.ToLower(base), ".csv") {
		return base, nil
	}
	return base + ".csv", nil
}

// ExportSnapshotToCSV exports a fresh filtered snapshot from the current source
// without mutating the model's paused/live view state.
func (m Model) ExportSnapshotToCSV(filename string) (string, error) {
	return exportSnapshotToCSV(m.source, m.filter, m.exportDir, filename)
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
