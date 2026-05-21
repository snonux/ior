package generate

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

var bytesListItemRE = regexp.MustCompile("`([^`]+)`")

func TestSyscallTracingPlanBytesClassificationStaysInSync(t *testing.T) {
	doc, err := readSyscallTracingPlan()
	if err != nil {
		t.Fatalf("read syscall tracing plan: %v", err)
	}

	documented, err := parseDocListSection(doc, "## Bytes vs Non-Bytes Classification")
	if err != nil {
		t.Fatalf("parse bytes classification section: %v", err)
	}

	expected := map[string][]string{
		"ReadClassified":     {},
		"WriteClassified":    {},
		"TransferClassified": {},
	}
	for syscall, classification := range retClassifications {
		switch classification {
		case ReadClassified:
			expected["ReadClassified"] = append(expected["ReadClassified"], syscall)
		case WriteClassified:
			expected["WriteClassified"] = append(expected["WriteClassified"], syscall)
		case TransferClassified:
			expected["TransferClassified"] = append(expected["TransferClassified"], syscall)
		default:
			t.Fatalf("unexpected classification %q for syscall %q", classification, syscall)
		}
	}
	for key, values := range expected {
		expected[key] = normalizeValues(values)
	}

	if !reflect.DeepEqual(mapKeys(documented), mapKeys(expected)) {
		t.Fatalf("classification groups mismatch: documented=%v expected=%v", mapKeys(documented), mapKeys(expected))
	}

	for key, expectedSyscalls := range expected {
		got := documented[key]
		if !reflect.DeepEqual(got, expectedSyscalls) {
			t.Fatalf("%s mismatch:\ndocumented=%v\nexpected=%v", key, got, expectedSyscalls)
		}
	}
}

func readSyscallTracingPlan() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	content, err := os.ReadFile(filepath.Join(repoRoot, "docs", "syscall-tracing-plan.md"))
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func parseDocListSection(doc, heading string) (map[string][]string, error) {
	lines := strings.Split(doc, "\n")
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == heading {
			start = i + 1
			break
		}
	}
	if start == -1 {
		return nil, fmt.Errorf("heading %q not found", heading)
	}

	out := map[string][]string{}
	for i := start; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "## ") {
			break
		}
		if !strings.HasPrefix(line, "- ") {
			continue
		}
		label, syscalls, err := parseDocBullet(line)
		if err != nil {
			return nil, err
		}
		out[label] = normalizeValues(syscalls)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("heading %q had no bullet rows", heading)
	}
	return out, nil
}

func parseDocBullet(line string) (string, []string, error) {
	entry := strings.TrimSpace(strings.TrimPrefix(line, "- "))
	colon := strings.Index(entry, ":")
	if colon <= 0 {
		return "", nil, fmt.Errorf("invalid list entry %q", line)
	}

	label := strings.TrimSpace(entry[:colon])
	if label == "" {
		return "", nil, fmt.Errorf("missing label in %q", line)
	}

	matches := bytesListItemRE.FindAllStringSubmatch(entry[colon+1:], -1)
	if len(matches) == 0 {
		return "", nil, fmt.Errorf("no syscall list in %q", line)
	}

	items := make([]string, 0, len(matches))
	for _, match := range matches {
		items = append(items, match[1])
	}
	return label, items, nil
}

func normalizeValues(values []string) []string {
	uniq := map[string]struct{}{}
	for _, value := range values {
		uniq[value] = struct{}{}
	}

	out := make([]string, 0, len(uniq))
	for value := range uniq {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func mapKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
