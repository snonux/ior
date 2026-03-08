package tracefilter

import (
	"testing"

	"ior/internal/globalfilter"

	tea "charm.land/bubbletea/v2"
)

func TestModelOpenClose(t *testing.T) {
	model := NewModel()
	if model.Visible() {
		t.Fatalf("new modal should not be visible")
	}

	model = model.Open(globalfilter.Filter{})
	if !model.Visible() {
		t.Fatalf("modal should be visible after open")
	}

	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	if model.Visible() {
		t.Fatalf("modal should close on esc")
	}
}

func TestModelNavigateFields(t *testing.T) {
	model := NewModel().Open(globalfilter.Filter{})
	if model.activeField != 0 {
		t.Fatalf("activeField=%d, want 0", model.activeField)
	}

	model = model.Update(tea.KeyPressMsg{Code: []rune("j")[0], Text: string([]rune("j"))})
	if model.activeField != 1 {
		t.Fatalf("activeField=%d, want 1", model.activeField)
	}
	model = model.Update(tea.KeyPressMsg{Code: []rune("k")[0], Text: string([]rune("k"))})
	if model.activeField != 0 {
		t.Fatalf("activeField=%d, want 0", model.activeField)
	}
}

func TestModelEditAndBuildFilter(t *testing.T) {
	model := NewModel().Open(globalfilter.Filter{})

	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	model = model.Update(tea.KeyPressMsg{Code: []rune("read")[0], Text: string([]rune("read"))})
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})

	for model.activeField < 3 {
		model = model.Update(tea.KeyPressMsg{Code: []rune("j")[0], Text: string([]rune("j"))})
	}
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyTab})
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	model = model.Update(tea.KeyPressMsg{Code: []rune("123")[0], Text: string([]rune("123"))})
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})

	model = model.Update(tea.KeyPressMsg{Code: []rune("j")[0], Text: string([]rune("j"))})
	model = model.Update(tea.KeyPressMsg{Code: []rune("j")[0], Text: string([]rune("j"))})
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	model = model.Update(tea.KeyPressMsg{Code: []rune("7")[0], Text: string([]rune("7"))})
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})

	for model.activeField < len(model.fields)-1 {
		model = model.Update(tea.KeyPressMsg{Code: []rune("j")[0], Text: string([]rune("j"))})
	}
	model = model.Update(tea.KeyPressMsg{Code: tea.KeySpace})
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEsc})

	filter := model.Filter()
	if filter.Syscall == nil || filter.Syscall.Pattern != "read" {
		t.Fatalf("syscall filter not applied: %+v", filter.Syscall)
	}
	if filter.PID == nil || filter.PID.Op != globalfilter.OpGte || filter.PID.Value != 123 {
		t.Fatalf("pid filter mismatch: %+v", filter.PID)
	}
	if filter.FD == nil || filter.FD.Value != 7 {
		t.Fatalf("fd filter mismatch: %+v", filter.FD)
	}
	if !filter.ErrorsOnly {
		t.Fatalf("errors-only expected true")
	}
}

func TestModelClearAll(t *testing.T) {
	initial := globalfilter.Filter{
		Syscall:    &globalfilter.StringFilter{Pattern: "open"},
		PID:        &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 42},
		FD:         &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 7},
		ErrorsOnly: true,
	}
	model := NewModel().Open(initial)

	model = model.Update(tea.KeyPressMsg{Code: []rune("c")[0], Text: string([]rune("c"))})
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEsc})

	filter := model.Filter()
	if filter.IsActive() {
		t.Fatalf("expected cleared filter to be inactive: %+v", filter)
	}
}
