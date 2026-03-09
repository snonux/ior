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

func ensureCSVFilename(name string) (string, error) {
	clean := strings.TrimSpace(name)
	if clean == "" {
		return "", errors.New("filename cannot be empty")
	}
	if strings.HasSuffix(strings.ToLower(clean), ".csv") {
		return clean, nil
	}
	return clean + ".csv", nil
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
	candidates := []string{"SUDO_EDITOR", "VISUAL", "EDITOR"}
	for _, key := range candidates {
		value := strings.TrimSpace(os.Getenv(key))
		if value == "" {
			continue
		}
		parts := strings.Fields(value)
		if len(parts) == 0 {
			continue
		}
		return parts, key, nil
	}
	return []string{"vi"}, "fallback", nil
}
