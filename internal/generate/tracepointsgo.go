package generate

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

var secRe = regexp.MustCompile(`^SEC.*sys_((?:enter|exit)_[a-z_0-9]+)`)
var kindLineRe = regexp.MustCompile(`^(sys_enter_[a-z0-9_]+)\s+is a struct\s+([a-z0-9_]+)(?:\s+.*)?$`)

// ExtractTracepoints reads generated C code and extracts tracepoint names from
// SEC annotations, producing the generated_tracepoints.go content.
func ExtractTracepoints(r io.Reader) (string, error) {
	return ExtractTracepointsWithKinds(r, strings.NewReader(""))
}

// ExtractTracepointsWithKinds reads generated C code and the
// generated_tracepoints_result.txt metadata to produce
// internal/tracepoints/generated_tracepoints.go.
func ExtractTracepointsWithKinds(cReader io.Reader, kindsReader io.Reader) (string, error) {
	tracepoints, err := extractTracepoints(cReader)
	if err != nil {
		return "", err
	}
	syscallKinds, err := extractSyscallKinds(kindsReader)
	if err != nil {
		return "", err
	}
	return formatTracepointsGo(tracepoints, syscallKinds), nil
}

func extractTracepoints(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	var tracepoints []string

	for scanner.Scan() {
		line := scanner.Text()
		if m := secRe.FindStringSubmatch(line); m != nil {
			tracepoints = append(tracepoints, "sys_"+m[1])
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning input: %w", err)
	}
	return tracepoints, nil
}

func extractSyscallKinds(r io.Reader) (map[string]string, error) {
	kinds := make(map[string]string)
	if r == nil {
		return kinds, nil
	}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		m := kindLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		syscall := strings.TrimPrefix(m[1], "sys_enter_")
		kind := normalizeStructKind(m[2])
		if kind == "" {
			continue
		}
		kinds[syscall] = kind
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan kind metadata: %w", err)
	}
	return kinds, nil
}

func normalizeStructKind(structName string) string {
	base := strings.TrimSuffix(structName, "_event")
	switch base {
	case "mq_open":
		return "mq-open"
	case "open_by_handle_at":
		return "open-by-handle-at"
	case "two_fd":
		return "two-fd"
	case "epoll_ctl":
		return "epoll-ctl"
	case "perf_open":
		return "perf-open"
	default:
		return base
	}
}

func formatTracepointsGo(tracepoints []string, syscallKinds map[string]string) string {
	var b strings.Builder
	b.WriteString("// Code generated - don't change manually!\n")
	b.WriteString("package tracepoints\n\n")
	b.WriteString("var List = []string{\n")
	for _, tp := range tracepoints {
		fmt.Fprintf(&b, "\t%q,\n", tp)
	}
	b.WriteString("}\n")
	b.WriteString("\n")
	b.WriteString("var syscallFamilies = map[string]string{\n")
	syscallFamilies := make(map[string]string)
	for _, tp := range tracepoints {
		syscall := strings.TrimPrefix(tp, "sys_enter_")
		syscall = strings.TrimPrefix(syscall, "sys_exit_")
		if syscall == "" {
			continue
		}
		if _, ok := syscallFamilies[syscall]; ok {
			continue
		}
		family := ClassifySyscallFamily("sys_enter_" + syscall)
		syscallFamilies[syscall] = string(family)
	}
	familySyscalls := make([]string, 0, len(syscallFamilies))
	for syscall := range syscallFamilies {
		familySyscalls = append(familySyscalls, syscall)
	}
	sort.Strings(familySyscalls)
	for _, syscall := range familySyscalls {
		fmt.Fprintf(&b, "\t%q: %q,\n", syscall, syscallFamilies[syscall])
	}
	b.WriteString("}\n")
	b.WriteString("\n")
	b.WriteString("var syscallKinds = map[string]string{\n")
	syscalls := make([]string, 0, len(syscallKinds))
	for syscall := range syscallKinds {
		syscalls = append(syscalls, syscall)
	}
	sort.Strings(syscalls)
	for _, syscall := range syscalls {
		fmt.Fprintf(&b, "\t%q: %q,\n", syscall, syscallKinds[syscall])
	}
	b.WriteString("}\n")
	return b.String()
}
