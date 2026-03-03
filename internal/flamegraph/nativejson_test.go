package flamegraph

import (
	"encoding/json"
	"os"
	"testing"
)

type jsonNodeForTest struct {
	Name     string            `json:"name"`
	Value    uint64            `json:"value"`
	Total    uint64            `json:"total"`
	Children []jsonNodeForTest `json:"children"`
}

type jsonFlamegraphForTest struct {
	Fields     []string        `json:"fields"`
	CountField string          `json:"countField"`
	Root       jsonNodeForTest `json:"root"`
}

func TestWriteJSONFromFileContainsFlamegraphTree(t *testing.T) {
	dir := t.TempDir()
	iorFile := writeTestIorZst(t, dir)

	n := NewNativeSVG([]string{"comm", "path", "tracepoint"}, "count")
	outFile, err := n.WriteJSONFromFile(iorFile)
	if err != nil {
		t.Fatalf("WriteJSONFromFile returned error: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read output json: %v", err)
	}

	var payload jsonFlamegraphForTest
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal output json: %v", err)
	}

	if payload.CountField != "count" {
		t.Fatalf("count field = %q, want %q", payload.CountField, "count")
	}
	if len(payload.Fields) != 3 {
		t.Fatalf("fields len = %d, want 3", len(payload.Fields))
	}
	if payload.Root.Name != "root" {
		t.Fatalf("root name = %q, want %q", payload.Root.Name, "root")
	}
	if payload.Root.Total != 1 {
		t.Fatalf("root total = %d, want 1", payload.Root.Total)
	}
	if len(payload.Root.Children) != 1 {
		t.Fatalf("root children len = %d, want 1", len(payload.Root.Children))
	}
	if payload.Root.Children[0].Name != "tester" {
		t.Fatalf("root child name = %q, want %q", payload.Root.Children[0].Name, "tester")
	}
}

func TestWriteJSONFromFileCleansUpPartialOutputOnError(t *testing.T) {
	dir := t.TempDir()
	iorFile := writeTestIorZst(t, dir)

	n := NewNativeSVG([]string{"invalidField"}, "count")
	outFile, err := n.WriteJSONFromFile(iorFile)
	if err == nil {
		t.Fatal("expected error for invalid field, got nil")
	}

	if _, statErr := os.Stat(outFile); !os.IsNotExist(statErr) {
		t.Fatalf("expected partial output to be removed, stat err=%v", statErr)
	}
}
