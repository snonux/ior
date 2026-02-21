package generate

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var secRe = regexp.MustCompile(`^SEC.*sys_((?:enter|exit)_[a-z_0-9]+)`)

// ExtractTracepoints reads generated C code and extracts tracepoint names from
// SEC annotations, producing the generated_tracepoints.go content.
func ExtractTracepoints(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	var tracepoints []string

	for scanner.Scan() {
		line := scanner.Text()
		if m := secRe.FindStringSubmatch(line); m != nil {
			tracepoints = append(tracepoints, "sys_"+m[1])
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scanning input: %w", err)
	}

	return formatTracepointsGo(tracepoints), nil
}

func formatTracepointsGo(tracepoints []string) string {
	var b strings.Builder
	b.WriteString("// Code generated - don't change manually!\n")
	b.WriteString("package tracepoints\n\n")
	b.WriteString("var List = []string{\n")
	for _, tp := range tracepoints {
		fmt.Fprintf(&b, "\t%q,\n", tp)
	}
	b.WriteString("}\n")
	return b.String()
}
