package probes

import (
	"testing"

	"ior/internal/probemanager"
)

// TestValueFlowMutatorsReturnUpdatedCopy pins the probes modal's value-flow
// contract: Open, reload and clampCursor change only the Model they return
// and never the value they were called on.
func TestValueFlowMutatorsReturnUpdatedCopy(t *testing.T) {
	fm := &fakeManager{states: []probemanager.ProbeState{
		{Syscall: "read", Active: true},
		{Syscall: "write", Active: true},
	}}
	m := NewModel(fm)

	opened := m.Open()
	if m.visible || m.probes != nil {
		t.Fatalf("Open mutated its receiver: visible=%v probes=%+v", m.visible, m.probes)
	}
	if !opened.visible || len(opened.probes) != 2 {
		t.Fatalf("Open returned visible=%v probes=%+v, want visible with both probes", opened.visible, opened.probes)
	}

	fm.states = fm.states[:1]
	reloaded := opened.reload()
	if len(opened.probes) != 2 {
		t.Fatalf("reload mutated its receiver: probes=%+v", opened.probes)
	}
	if len(reloaded.probes) != 1 {
		t.Fatalf("reload returned probes=%+v, want the manager's one probe", reloaded.probes)
	}

	reloaded.cursor = 5
	clamped := reloaded.clampCursor()
	if reloaded.cursor != 5 {
		t.Fatalf("clampCursor mutated its receiver: cursor=%d", reloaded.cursor)
	}
	if clamped.cursor != 0 || clamped.offset != 0 {
		t.Fatalf("clampCursor returned cursor=%d offset=%d, want 0/0 for one probe", clamped.cursor, clamped.offset)
	}
}
