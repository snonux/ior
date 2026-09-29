package tracepoints

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

var docListItemRE = regexp.MustCompile("`([^`]+)`")

func TestSyscallTracingPlanFamiliesStayInSyncWithGeneratedMap(t *testing.T) {
	doc, err := readSyscallTracingPlan()
	if err != nil {
		t.Fatalf("read syscall tracing plan: %v", err)
	}

	documented, err := parseDocListSection(doc, "## Traced Syscalls by Family")
	if err != nil {
		t.Fatalf("parse family section: %v", err)
	}

	generated := groupSyscallsByValue(syscallFamilies)
	assertGroupedEqual(t, "family", documented, generated)
}

func TestSyscallTracingPlanKindsStayInSyncWithGeneratedMap(t *testing.T) {
	doc, err := readSyscallTracingPlan()
	if err != nil {
		t.Fatalf("read syscall tracing plan: %v", err)
	}

	documented, err := parseDocListSection(doc, "## Traced Syscalls by TracepointKind")
	if err != nil {
		t.Fatalf("parse kind section: %v", err)
	}

	generated := groupSyscallsByValue(syscallKinds)
	assertGroupedEqual(t, "kind", documented, generated)
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

	matches := docListItemRE.FindAllStringSubmatch(entry[colon+1:], -1)
	if len(matches) == 0 {
		return "", nil, fmt.Errorf("no syscall list in %q", line)
	}

	items := make([]string, 0, len(matches))
	for _, match := range matches {
		items = append(items, match[1])
	}
	return label, items, nil
}

func groupSyscallsByValue(values map[string]string) map[string][]string {
	grouped := map[string][]string{}
	for syscall, value := range values {
		grouped[value] = append(grouped[value], syscall)
	}
	for key, syscalls := range grouped {
		grouped[key] = normalizeValues(syscalls)
	}
	return grouped
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

func assertGroupedEqual(t *testing.T, section string, documented, generated map[string][]string) {
	t.Helper()

	docKeys := mapKeys(documented)
	genKeys := mapKeys(generated)
	if !reflect.DeepEqual(docKeys, genKeys) {
		t.Fatalf("%s groups mismatch: documented=%v generated=%v", section, docKeys, genKeys)
	}

	for _, key := range genKeys {
		if !reflect.DeepEqual(documented[key], generated[key]) {
			t.Fatalf("%s %q mismatch:\ndocumented=%v\ngenerated=%v", section, key, documented[key], generated[key])
		}
	}
}

func mapKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
