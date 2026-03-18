package pidpicker

import (
	"bytes"
	"cmp"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// ProcessInfo is the metadata shown in the PID picker list.
type ProcessInfo struct {
	Pid       int
	ParentPID int
	Comm      string
	Cmdline   string
}

// ScanProcesses returns process metadata from /proc.
func ScanProcesses() ([]ProcessInfo, error) {
	return scanProcessesFrom("/proc")
}

// ScanThreads returns thread metadata from /proc/<pid>/task for one process.
func ScanThreads(pid int) ([]ProcessInfo, error) {
	return scanThreadsFrom("/proc", pid)
}

// ScanAllThreads returns thread metadata from /proc/*/task.
func ScanAllThreads() ([]ProcessInfo, error) {
	return scanAllThreadsFrom("/proc")
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

	slices.SortFunc(processes, func(a, b ProcessInfo) int {
		return cmp.Compare(a.Pid, b.Pid)
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
		Pid:       pid,
		ParentPID: pid,
		Comm:      comm,
		Cmdline:   normalizeCmdline(cmdlineData),
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

func scanThreadsFrom(procRoot string, pid int) ([]ProcessInfo, error) {
	taskRoot := filepath.Join(procRoot, strconv.Itoa(pid), "task")
	entries, err := os.ReadDir(taskRoot)
	if err != nil {
		return nil, fmt.Errorf("read task root %q: %w", taskRoot, err)
	}

	cmdlineData, _ := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	cmdline := normalizeCmdline(cmdlineData)

	threads := make([]ProcessInfo, 0, len(entries))
	for _, entry := range entries {
		thread, ok := readThreadInfo(taskRoot, entry, cmdline)
		if !ok {
			continue
		}
		threads = append(threads, thread)
	}

	slices.SortFunc(threads, func(a, b ProcessInfo) int {
		return cmp.Compare(a.Pid, b.Pid)
	})
	return threads, nil
}

func readThreadInfo(taskRoot string, entry fs.DirEntry, cmdline string) (ProcessInfo, bool) {
	if !entry.IsDir() {
		return ProcessInfo{}, false
	}

	tid, err := strconv.Atoi(entry.Name())
	if err != nil {
		return ProcessInfo{}, false
	}

	commPath := filepath.Join(taskRoot, entry.Name(), "comm")
	commData, err := os.ReadFile(commPath)
	if err != nil {
		return ProcessInfo{}, false
	}
	comm := strings.TrimSpace(string(commData))
	if comm == "" {
		return ProcessInfo{}, false
	}

	return ProcessInfo{
		Pid:       tid,
		ParentPID: extractPIDFromPath(taskRoot),
		Comm:      comm,
		Cmdline:   cmdline,
	}, true
}

func scanAllThreadsFrom(procRoot string) ([]ProcessInfo, error) {
	processes, err := scanProcessesFrom(procRoot)
	if err != nil {
		return nil, err
	}

	threads := make([]ProcessInfo, 0, len(processes)*8)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)

	for _, p := range processes {
		pid := p.Pid
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			perProc, err := scanThreadsFrom(procRoot, pid)
			if err != nil {
				return
			}
			mu.Lock()
			threads = append(threads, perProc...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	slices.SortFunc(threads, func(a, b ProcessInfo) int {
		if a.Pid != b.Pid {
			return cmp.Compare(a.Pid, b.Pid)
		}
		return cmp.Compare(a.ParentPID, b.ParentPID)
	})
	return threads, nil
}

func extractPIDFromPath(taskRoot string) int {
	parts := strings.Split(filepath.Clean(taskRoot), string(os.PathSeparator))
	if len(parts) < 2 {
		return -1
	}
	pid, err := strconv.Atoi(parts[len(parts)-2])
	if err != nil {
		return -1
	}
	return pid
}
