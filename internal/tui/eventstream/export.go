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

func (m *Model) exportFilteredToCSV(filename string) (string, error) {
	name, err := ensureCSVFilename(filename)
	if err != nil {
		return "", err
	}
	path := name
	if m.exportDir != "" {
		path = filepath.Join(m.exportDir, name)
	}

	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{"seq", "time_ns", "gap_ns", "latency_ns", "comm", "pid", "tid", "syscall", "fd", "ret", "bytes", "file", "error"}
	if err := w.Write(header); err != nil {
		return "", err
	}
	for i := range m.filtered {
		ev := m.filtered[i]
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
			return "", err
		}
	}
	if err := w.Error(); err != nil {
		return "", err
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return path, nil
	}
	return absPath, nil
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
