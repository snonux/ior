package pidpicker

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ProcessInfo is the metadata shown in the PID picker list.
type ProcessInfo struct {
	Pid     int
	Comm    string
	Cmdline string
}

// ScanProcesses returns process metadata from /proc.
func ScanProcesses() ([]ProcessInfo, error) {
	return scanProcessesFrom("/proc")
}

func scanProcessesFrom(procRoot string) ([]ProcessInfo, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("read proc root %q: %w", procRoot, err)
	}

	processes := make([]ProcessInfo, 0, len(entries))
	for _, entry := range entries {
		process, ok := readProcessInfo(procRoot, entry)
		if !ok {
			continue
		}
		processes = append(processes, process)
	}

	sort.Slice(processes, func(i, j int) bool {
		return processes[i].Pid < processes[j].Pid
	})
	return processes, nil
}

func readProcessInfo(procRoot string, entry fs.DirEntry) (ProcessInfo, bool) {
	if !entry.IsDir() {
		return ProcessInfo{}, false
	}

	pid, err := strconv.Atoi(entry.Name())
	if err != nil {
		return ProcessInfo{}, false
	}

	statPath := filepath.Join(procRoot, entry.Name(), "stat")
	statData, err := os.ReadFile(statPath)
	if err != nil {
		return ProcessInfo{}, false
	}

	comm, err := parseCommFromStat(string(statData))
	if err != nil {
		return ProcessInfo{}, false
	}

	cmdlinePath := filepath.Join(procRoot, entry.Name(), "cmdline")
	cmdlineData, err := os.ReadFile(cmdlinePath)
	if err != nil {
		cmdlineData = nil
	}

	return ProcessInfo{
		Pid:     pid,
		Comm:    comm,
		Cmdline: normalizeCmdline(cmdlineData),
	}, true
}

func parseCommFromStat(statLine string) (string, error) {
	open := strings.IndexByte(statLine, '(')
	close := strings.LastIndexByte(statLine, ')')
	if open < 0 || close < 0 || close <= open+1 {
		return "", fmt.Errorf("invalid stat line")
	}

	comm := statLine[open+1 : close]
	if strings.TrimSpace(comm) == "" {
		return "", fmt.Errorf("empty comm in stat line")
	}
	return comm, nil
}

func normalizeCmdline(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}

	trimmed := bytes.TrimRight(raw, "\x00")
	if len(trimmed) == 0 {
		return ""
	}

	parts := bytes.Split(trimmed, []byte{0})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		out = append(out, string(part))
	}
	return strings.Join(out, " ")
}
