package pidpicker

import (
	"reflect"
	"testing"
)

// TestInitDoesNotMutateModel pins that Init only reads the model: the scan
// it starts reaches the model as a processesLoadedMsg through Update, never
// by writing to the picker from Init.
func TestInitDoesNotMutateModel(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    Model
	}{
		{name: "pid picker", m: NewWithKeys(DefaultKeyMap())},
		{name: "tid picker", m: NewTIDWithKeys(42, DefaultKeyMap())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.m
			m.processes = []ProcessInfo{{Pid: 7, Comm: "bash"}}
			m = m.applyFilter()
			m.selectedIndex = 1
			before := m

			if cmd := m.Init(); cmd == nil {
				t.Fatal("Init must return the initial scan command")
			}
			if !reflect.DeepEqual(before, m) {
				t.Fatalf("Init mutated the picker:\nbefore %+v\nafter  %+v", before, m)
			}
		})
	}
}

// TestApplyFilterReturnsUpdatedCopy pins the value-flow contract: applyFilter
// changes only the Model it returns, never the receiver's caller copy (the
// negative case a pointer-receiver mutator on a value-flow Model gets wrong).
func TestApplyFilterReturnsUpdatedCopy(t *testing.T) {
	m := NewWithKeys(DefaultKeyMap())
	m.processes = []ProcessInfo{
		{Pid: 100, Comm: "bash"},
		{Pid: 200, Comm: "sshd"},
	}
	m.input.SetValue("sshd")
	m.selectedIndex = 2

	updated := m.applyFilter()

	if len(m.filtered) != 0 || m.selectedIndex != 2 {
		t.Fatalf("applyFilter mutated its receiver: filtered=%+v selected=%d", m.filtered, m.selectedIndex)
	}
	if len(updated.filtered) != 1 || updated.filtered[0].Pid != 200 {
		t.Fatalf("filtered = %+v, want only pid 200", updated.filtered)
	}
	if updated.selectedIndex != 1 {
		t.Fatalf("selectedIndex = %d, want it clamped to the one match", updated.selectedIndex)
	}
}
