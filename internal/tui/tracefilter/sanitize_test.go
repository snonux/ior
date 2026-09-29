package tracefilter

import (
	"strings"
	"testing"

	"ior/internal/globalfilter"
)

// TestBodyLinesSanitizeTracedPatterns verifies filter patterns pushed from
// traced comm/file values (an OSC 8 link, SGR hidden text) are shown without
// escape bytes while the filter itself keeps the raw pattern (task io2).
func TestBodyLinesSanitizeTracedPatterns(t *testing.T) {
	comm := "ev\x1b[8mil"
	file := "/tmp/\x1b]8;;http://evil\aclick\x1b]8;;\a"
	model := NewModel().Open(globalfilter.Filter{
		Comm: &globalfilter.StringFilter{Pattern: comm},
		File: &globalfilter.StringFilter{Pattern: file},
	})
	body := strings.Join(model.bodyLines(), "\n")
	if strings.ContainsAny(body, "\x1b\a") {
		t.Fatalf("body contains escape bytes: %q", body)
	}
	if !strings.Contains(body, "ev?[8mil") {
		t.Fatalf("body = %q, want sanitised comm pattern", body)
	}
	if got := model.Filter(); got.Comm == nil || got.Comm.Pattern != comm {
		t.Fatalf("filter lost the raw comm pattern: %#v", got.Comm)
	}
}
