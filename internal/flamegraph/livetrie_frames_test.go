package flamegraph

import (
	"slices"
	"strings"
	"testing"
	"unsafe"
)

// splitFramesViaStringByName is the former frame construction: the field's
// StringByName value split on ';' with empty parts dropped. buildFrames must
// produce exactly the same frames without the intermediate strings.
func splitFramesViaStringByName(t *testing.T, record IterRecord, fields []string) []string {
	t.Helper()
	var frames []string
	for _, field := range fields {
		value, err := record.StringByName(field)
		if err != nil {
			continue
		}
		for _, part := range strings.Split(value, ";") {
			if part != "" {
				frames = append(frames, part)
			}
		}
	}
	return frames
}

func TestBuildFramesMatchesStringByNameSplitting(t *testing.T) {
	paths := []string{
		"", "/", "//", "/a", "/a/b/c", "a/b", "relative", "/trailing/",
		"/a;b", "a;/b", ";", "/;/", "/x//y", "/semi;colon;/z",
	}
	comms := []string{"", "svc", "a;b", ";lead", "trail;"}
	fieldSets := [][]string{
		{"path"},
		{"comm", "path"},
		{"path", "comm", "pid"},
		{"comm", "unknown", "path"},
	}
	for _, fields := range fieldSets {
		for _, comm := range comms {
			for _, path := range paths {
				record := IterRecord{Comm: comm, Path: path, Pid: 42}
				got := buildFrames(record, fields)
				want := splitFramesViaStringByName(t, record, fields)
				if !slices.Equal(got, want) {
					t.Fatalf("fields %v comm %q path %q: frames %q, want %q", fields, comm, path, got, want)
				}
			}
		}
	}
}

func TestInsertTriePathClonesNewNodeNames(t *testing.T) {
	// Frames are substrings of the record's path; a long-lived node must own
	// its name instead of pinning the whole record string.
	path := strings.Repeat("/long", 100)
	frames := appendPathFrames(nil, path)
	root := &trieNode{}
	insertTriePath(root, frames[:1], 1, 1)
	node := findChild(root, "/long")
	if node == nil {
		t.Fatal("missing node /long")
	}
	if unsafe.StringData(node.name) == unsafe.StringData(path) {
		t.Fatal("node name shares memory with the record path")
	}
}
