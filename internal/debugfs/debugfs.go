package debugfs

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Return tracepoints with 'unsigned int fd', which are I/O tracepoints on FDs
func TracepointsWithFd() ([]string, error) {
	return tracepointsWith("unsigned int fd")
}

func tracepointsWith(field string) ([]string, error) {
	var tracepoints []string

	matches, err := filepath.Glob("/sys/kernel/debug/tracing/events/syscalls/*/format")
	if err != nil {
		return tracepoints, err
	}
	if len(matches) == 0 {
		return tracepoints, fmt.Errorf("Unable to gather tracepoints with FDs")
	}

	for _, formatPath := range matches {
		has, err := hasField(formatPath, field)
		if err != nil {
			return tracepoints, err
		}
		if !has {
			continue
		}
		tracepoints = append(tracepoints, filepath.Base(filepath.Dir(formatPath)))
	}

	return tracepoints, nil
}

func hasField(formatPath, field string) (bool, error) {
	file, err := os.Open(formatPath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, fmt.Sprintf("field:%s;", field)) {
			return true, nil
		}
	}

	return false, nil
}
