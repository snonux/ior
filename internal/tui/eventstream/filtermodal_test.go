package eventstream

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestFilterModalOpenClose(t *testing.T) {
	m := NewFilterModal()
	if m.Visible() {
		t.Fatalf("new modal should not be visible")
	}

	m = m.Open(Filter{})
	if !m.Visible() {
		t.Fatalf("modal should be visible after open")
	}

	m = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if m.Visible() {
		t.Fatalf("modal should close on esc")
	}
}

func TestFilterModalNavigateFields(t *testing.T) {
	m := NewFilterModal().Open(Filter{})
	if m.activeField != 0 {
		t.Fatalf("activeField=%d, want 0", m.activeField)
	}

	m = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	if m.activeField != 1 {
		t.Fatalf("activeField=%d, want 1", m.activeField)
	}
	m = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
	if m.activeField != 0 {
		t.Fatalf("activeField=%d, want 0", m.activeField)
	}
}

func TestFilterModalEditAndBuildFilter(t *testing.T) {
	m := NewFilterModal().Open(Filter{})

	// Syscall = read
	m = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("read")})
	m = m.Update(tea.KeyMsg{Type: tea.KeyEnter})

	// PID >= 123
	m = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = m.Update(tea.KeyMsg{Type: tea.KeyTab}) // '=' -> '>'
	m = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("123")})
	m = m.Update(tea.KeyMsg{Type: tea.KeyEnter})

	// Latency >= 1ms
	m = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	m = m.Update(tea.KeyMsg{Type: tea.KeyTab}) // '=' -> '>='
	m = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("1ms")})
	m = m.Update(tea.KeyMsg{Type: tea.KeyEnter})

	// ErrorsOnly = true
	for m.activeField < len(m.fields)-1 {
		m = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	}
	m = m.Update(tea.KeyMsg{Type: tea.KeySpace})

	m = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if m.Visible() {
		t.Fatalf("modal should close on esc")
	}

	f := m.Filter()
	if f.Syscall == nil || f.Syscall.Pattern != "read" {
		t.Fatalf("syscall filter not applied: %+v", f.Syscall)
	}
	if f.PID == nil || f.PID.Op != OpGte || f.PID.Value != 123 {
		t.Fatalf("pid filter mismatch: %+v", f.PID)
	}
	if f.LatencyNs == nil || f.LatencyNs.Op != OpGte || f.LatencyNs.Value != 1_000_000 {
		t.Fatalf("latency filter mismatch: %+v", f.LatencyNs)
	}
	if !f.ErrorsOnly {
		t.Fatalf("errors-only expected true")
	}
}

func TestFilterModalClearAll(t *testing.T) {
	initial := Filter{
		Syscall:    &StringFilter{Pattern: "open"},
		PID:        &NumericFilter{Op: OpEq, Value: 42},
		ErrorsOnly: true,
	}
	m := NewFilterModal().Open(initial)

	m = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("c")})
	m = m.Update(tea.KeyMsg{Type: tea.KeyEsc})

	f := m.Filter()
	if f.IsActive() {
		t.Fatalf("expected cleared filter to be inactive: %+v", f)
	}
}
