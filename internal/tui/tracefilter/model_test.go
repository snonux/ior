package tracefilter

import (
	"reflect"
	"strings"
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

func TestModelEditingAllowsPrintableHotkeyRunes(t *testing.T) {
	model := NewModel().Open(globalfilter.Filter{})

	model = model.Update(tea.KeyPressMsg{Code: []rune("j")[0], Text: string([]rune("j"))})
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	for _, r := range "codexjk" {
		model = model.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEsc})

	filter := model.Filter()
	if filter.Comm == nil || filter.Comm.Pattern != "codexjk" {
		t.Fatalf("expected printable runes preserved while editing, got %+v", filter.Comm)
	}
}

// familyFilter is a filter whose only active dimension is Family, which the
// modal has no field for (it is set outside the modal: the [ / ] family
// cycle or the Syscalls-tab Family row filter).
func familyFilter() globalfilter.Filter {
	return globalfilter.Filter{Family: &globalfilter.StringFilter{Pattern: "Network"}}
}

// fullyPopulatedFilter sets every Filter dimension known when it was
// written, so a round trip through the modal exercises each field. It does
// not see dimensions added to Filter later; TestModelClearAllOwnsEveryField
// is the reflection-based guard for that.
func fullyPopulatedFilter() globalfilter.Filter {
	num := func(op globalfilter.CompareOp, v int64) *globalfilter.NumericFilter {
		return &globalfilter.NumericFilter{Op: op, Value: v}
	}
	return globalfilter.Filter{
		Syscall:    &globalfilter.StringFilter{Pattern: "read"},
		Family:     &globalfilter.StringFilter{Pattern: "Network"},
		Comm:       &globalfilter.StringFilter{Pattern: "nginx"},
		File:       &globalfilter.StringFilter{Pattern: "^/etc"},
		PID:        num(globalfilter.OpEq, 42),
		TID:        num(globalfilter.OpGt, 43),
		FD:         num(globalfilter.OpLt, 7),
		LatencyNs:  num(globalfilter.OpGte, 5_000_000),
		GapNs:      num(globalfilter.OpLte, 3_000),
		Bytes:      num(globalfilter.OpNeq, 4096),
		RetVal:     num(globalfilter.OpEq, -2),
		ErrorsOnly: true,
	}
}

// TestModelOpenEscPreservesUnownedFamily is the co2 regression: open+Esc
// without edits must hand back a filter Equal to the one passed to Open,
// including Family, otherwise the TUI treats the close as a filter change
// (stats/trie reset and an extra undo level).
func TestModelOpenEscPreservesUnownedFamily(t *testing.T) {
	for name, initial := range map[string]globalfilter.Filter{
		"family only":   familyFilter(),
		"family+comm":   {Family: &globalfilter.StringFilter{Pattern: "Network"}, Comm: &globalfilter.StringFilter{Pattern: "nginx"}},
		"all dimension": fullyPopulatedFilter(),
		"empty":         {},
	} {
		t.Run(name, func(t *testing.T) {
			model := NewModel().Open(initial)
			model = model.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
			if got := model.Filter(); !got.Equal(initial) {
				t.Fatalf("open+esc changed the filter:\n got  %+v\n want %+v", got, initial)
			}
		})
	}
}

// TestModelEditPreservesUnownedFamily checks that submitting real edits (both
// from navigation Esc and from Esc while still typing) keeps Family while the
// edited dimension changes.
func TestModelEditPreservesUnownedFamily(t *testing.T) {
	for name, closeWhileEditing := range map[string]bool{"esc after enter": false, "esc while editing": true} {
		t.Run(name, func(t *testing.T) {
			model := NewModel().Open(familyFilter())
			model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter}) // edit Syscall
			model = model.Update(tea.KeyPressMsg{Code: 'w', Text: "write"})
			if !closeWhileEditing {
				model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
			}
			model = model.Update(tea.KeyPressMsg{Code: tea.KeyEsc})

			got := model.Filter()
			if got.Family == nil || got.Family.Pattern != "Network" {
				t.Fatalf("family lost on submit: %+v", got.Family)
			}
			if got.Syscall == nil || got.Syscall.Pattern != "write" {
				t.Fatalf("syscall edit not applied: %+v", got.Syscall)
			}
		})
	}
}

// TestModelEmptiedFieldRemovesConstraint guards the other side of starting
// from the opened filter: a modal-owned dimension the user blanks out must be
// removed, not carried over from the initial filter.
func TestModelEmptiedFieldRemovesConstraint(t *testing.T) {
	initial := fullyPopulatedFilter()
	model := NewModel().Open(initial)
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter}) // edit Syscall
	model.textInput.SetValue("")
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	for model.activeField < int(fieldPID) {
		model = model.Update(tea.KeyPressMsg{Code: 'j', Text: "j"})
	}
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	model.textInput.SetValue("not-a-number") // invalid input drops the constraint
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEsc})

	got := model.Filter()
	if got.Syscall != nil {
		t.Fatalf("emptied syscall should be removed, got %+v", got.Syscall)
	}
	if got.PID != nil {
		t.Fatalf("invalid pid should be removed, got %+v", got.PID)
	}
	want := initial.Clone()
	want.Syscall, want.PID = nil, nil
	if !got.Equal(want) {
		t.Fatalf("untouched dimensions changed:\n got  %+v\n want %+v", got, want)
	}
}

// unownedFilterFields lists the globalfilter.Filter fields the modal has no
// editable field for and therefore carries over unchanged. Adding a Filter
// field means either giving it a modal field or adding it here on purpose.
var unownedFilterFields = map[string]bool{"Family": true}

// setEveryFieldNonZero fills every exported field of f with a non-zero value
// via reflection, so fields added to Filter later are covered automatically.
func setEveryFieldNonZero(t *testing.T, f *globalfilter.Filter) {
	t.Helper()
	v := reflect.ValueOf(f).Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		switch field.Kind() {
		case reflect.Pointer:
			elem := reflect.New(field.Type().Elem())
			setFirstNonZero(t, v.Type().Field(i).Name, elem.Elem())
			field.Set(elem)
		case reflect.Bool:
			field.SetBool(true)
		default:
			t.Fatalf("setEveryFieldNonZero: unhandled kind %s for Filter.%s", field.Kind(), v.Type().Field(i).Name)
		}
	}
}

// setFirstNonZero gives the pointed-to struct a non-zero value so it reads
// as an active constraint (a pattern, or a compare value).
func setFirstNonZero(t *testing.T, name string, s reflect.Value) {
	t.Helper()
	for i := 0; i < s.NumField(); i++ {
		switch f := s.Field(i); f.Kind() {
		case reflect.String:
			f.SetString("x")
			return
		case reflect.Int64:
			f.SetInt(1)
			return
		}
	}
	t.Fatalf("setFirstNonZero: no settable field in Filter.%s", name)
}

// TestModelClearAllOwnsEveryField is the guard against the modal's field
// lists drifting from globalfilter.Filter: with every Filter field set,
// clear-all + Esc must zero every field except the explicit allowlist of
// dimensions the modal does not own (which must survive unchanged).
func TestModelClearAllOwnsEveryField(t *testing.T) {
	var initial globalfilter.Filter
	setEveryFieldNonZero(t, &initial)

	model := NewModel().Open(initial)
	model = model.Update(tea.KeyPressMsg{Code: 'c', Text: "c"})
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEsc})

	got := reflect.ValueOf(model.Filter())
	want := reflect.ValueOf(initial)
	for i := 0; i < got.NumField(); i++ {
		name := got.Type().Field(i).Name
		if unownedFilterFields[name] {
			if !reflect.DeepEqual(got.Field(i).Interface(), want.Field(i).Interface()) {
				t.Errorf("unowned Filter.%s changed: got %v, want %v", name, got.Field(i), want.Field(i))
			}
			continue
		}
		if !got.Field(i).IsZero() {
			t.Errorf("Filter.%s survived clear-all; give it a modal field or add it to unownedFilterFields", name)
		}
	}
}

// TestModelViewShowsCarriedFamily checks that the Family scope the modal
// keeps (on Esc and on "c") is visible as a read-only line, and absent when
// no family scope is active.
func TestModelViewShowsCarriedFamily(t *testing.T) {
	withFamily := NewModel().Open(familyFilter()).View(100, 40)
	if !strings.Contains(withFamily, "Network ([ / ] to change)") {
		t.Fatalf("view should show the carried Family scope:\n%s", withFamily)
	}
	if !strings.Contains(withFamily, "c clear (keeps family)") {
		t.Fatalf("help should say clear keeps family:\n%s", withFamily)
	}
	cleared := NewModel().Open(familyFilter())
	cleared = cleared.Update(tea.KeyPressMsg{Code: 'c', Text: "c"})
	if !strings.Contains(cleared.View(100, 40), "Family:") {
		t.Fatalf("family line should remain visible after clear-all")
	}
	for name, f := range map[string]globalfilter.Filter{
		"no family":     {Comm: &globalfilter.StringFilter{Pattern: "nginx"}},
		"empty pattern": {Family: &globalfilter.StringFilter{}},
	} {
		if view := NewModel().Open(f).View(100, 40); strings.Contains(view, "Family:") {
			t.Fatalf("%s: view should not show a Family line:\n%s", name, view)
		}
	}
}

// TestModelClearAllKeepsUnownedFamily pins the clear-all contract: "c" clears
// every field the modal shows, but Family is not shown there (it is cycled
// outside the modal), so it stays in effect.
func TestModelClearAllKeepsUnownedFamily(t *testing.T) {
	model := NewModel().Open(fullyPopulatedFilter())
	model = model.Update(tea.KeyPressMsg{Code: 'c', Text: "c"})
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEsc})

	if got := model.Filter(); !got.Equal(familyFilter()) {
		t.Fatalf("clear-all should leave only Family:\n got  %+v\n want %+v", got, familyFilter())
	}
}
