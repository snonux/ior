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

// nonCanonicalFilters are filters the modal cannot reproduce by rebuilding
// from its field text (untrimmed or blank patterns, as a row filter on a path
// with leading/trailing blanks produces), keyed by case name.
func nonCanonicalFilters() map[string]globalfilter.Filter {
	return map[string]globalfilter.Filter{
		"untrimmed comm":    {Comm: &globalfilter.StringFilter{Pattern: "foo "}},
		"untrimmed file":    {File: &globalfilter.StringFilter{Pattern: " /tmp/a b "}},
		"empty syscall":     {Syscall: &globalfilter.StringFilter{Pattern: ""}},
		"blank file":        {File: &globalfilter.StringFilter{Pattern: "   "}},
		"mixed with family": {Family: &globalfilter.StringFilter{Pattern: "Network"}, Comm: &globalfilter.StringFilter{Pattern: "\tbash"}},
	}
}

// TestModelOpenEscKeepsNonCanonicalPatterns is the uo2 regression: open+Esc
// (with or without confirming a field unedited) must hand back a filter Equal
// to the opened one even when a pattern is untrimmed or empty; a rebuilt,
// trimmed/nil'd dimension made the TUI reset stats/trie and push an undo level.
func TestModelOpenEscKeepsNonCanonicalPatterns(t *testing.T) {
	for name, initial := range nonCanonicalFilters() {
		t.Run(name+"/esc", func(t *testing.T) {
			model := NewModel().Open(initial)
			model = model.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
			if got := model.Filter(); !got.Equal(initial) {
				t.Fatalf("open+esc changed the filter:\n got  %+v\n want %+v", got, initial)
			}
		})
		t.Run(name+"/enter-enter-esc", func(t *testing.T) {
			model := NewModel().Open(initial)
			for i := range model.fields[:fieldFile+1] {
				model.activeField = i
				model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter}) // start edit
				model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm unedited (trims)
			}
			model = model.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
			if got := model.Filter(); !got.Equal(initial) {
				t.Fatalf("unedited confirm changed the filter:\n got  %+v\n want %+v", got, initial)
			}
		})
	}
}

// TestModelRoundTripsExactRowPatterns covers the patterns dashboard row
// filters (task yo2) and the Stream tab's Enter-on-cell filter (task 2p2)
// emit: ^value$ / ^dir/* (task ip2) with the value's blanks and literal edge ^/$ inside
// the anchors. Opening one and leaving must hand it back unchanged, and
// typing the displayed text into a fresh modal must rebuild the very same
// filter - the anchors put the blanks out of reach of the modal's TrimSpace,
// so the text shown is the text that applies.
func TestModelRoundTripsExactRowPatterns(t *testing.T) {
	for _, initial := range []globalfilter.Filter{
		{File: &globalfilter.StringFilter{Pattern: globalfilter.ExactPattern("/tmp/a ")}},
		{File: &globalfilter.StringFilter{Pattern: globalfilter.ExactPattern(" /tmp/x$")}},
		{File: &globalfilter.StringFilter{Pattern: globalfilter.DirPattern("/var/log")}},
		{File: &globalfilter.StringFilter{Pattern: globalfilter.DirPattern("/")}},
		{File: &globalfilter.StringFilter{Pattern: globalfilter.DirPattern("   ")}},
		{File: &globalfilter.StringFilter{Pattern: globalfilter.DirPattern("/Tmp/a ")}},
		{Comm: &globalfilter.StringFilter{Pattern: globalfilter.ExactPattern("  sh  ")}},
		{Syscall: &globalfilter.StringFilter{Pattern: globalfilter.ExactPattern("read")}},
		{File: &globalfilter.StringFilter{Pattern: globalfilter.ExactPattern("^/tmp/a b$")}},
		{Comm: &globalfilter.StringFilter{Pattern: globalfilter.ExactPattern("x$")}},
		{
			Comm:    &globalfilter.StringFilter{Pattern: globalfilter.ExactPattern(" kworker/0:1 ")},
			Syscall: &globalfilter.StringFilter{Pattern: globalfilter.ExactPattern("openat")},
			File:    &globalfilter.StringFilter{Pattern: globalfilter.ExactPattern("/etc/x ")},
		},
	} {
		model := NewModel().Open(initial)
		model = model.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
		if got := model.Filter(); !got.Equal(initial) {
			t.Fatalf("open+esc changed the filter:\n got  %+v\n want %+v", got, initial)
		}

		typed := NewModel().Open(globalfilter.Filter{})
		for _, key := range []fieldKey{fieldSyscall, fieldComm, fieldFile} {
			text := model.fields[key].value
			if text == "" {
				continue
			}
			typed.activeField = int(key)
			typed = typed.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
			typed.textInput.SetValue(text)
			typed = typed.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
		}
		typed = typed.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
		if got := typed.Filter(); !got.Equal(initial) {
			t.Fatalf("retyping the shown text did not rebuild the filter:\n got  %+v\n want %+v", got, initial)
		}
	}
}

// TestModelEditOfNonCanonicalPatternApplies is the negative side of keeping
// untouched fields verbatim: a real edit of such a field, a blanked field and
// a changed numeric op must still be applied.
func TestModelEditOfNonCanonicalPatternApplies(t *testing.T) {
	initial := globalfilter.Filter{
		Comm: &globalfilter.StringFilter{Pattern: "foo "},
		File: &globalfilter.StringFilter{Pattern: " /tmp/x "},
		PID:  &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 42},
	}
	model := NewModel().Open(initial)
	model.activeField = int(fieldComm)
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	model.textInput.SetValue(" bar ")
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	model.activeField = int(fieldFile)
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	model.textInput.SetValue("  ")
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	model.activeField = int(fieldPID)
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyTab}) // = -> >=
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEsc})

	want := globalfilter.Filter{
		Comm: &globalfilter.StringFilter{Pattern: "bar"},
		PID:  &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: 42},
	}
	if got := model.Filter(); !got.Equal(want) {
		t.Fatalf("edits not applied:\n got  %+v\n want %+v", got, want)
	}
}

// TestModelClearAllDropsNonCanonicalPatterns checks that "c" still removes
// an untrimmed pattern (its field changed from "foo " to ""), while a
// dimension that was already blank stays as opened because clearing it is
// no change.
func TestModelClearAllDropsNonCanonicalPatterns(t *testing.T) {
	initial := globalfilter.Filter{
		Comm:    &globalfilter.StringFilter{Pattern: "foo "},
		Syscall: &globalfilter.StringFilter{Pattern: ""},
	}
	model := NewModel().Open(initial)
	model = model.Update(tea.KeyPressMsg{Code: 'c', Text: "c"})
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEsc})

	got := model.Filter()
	if got.Comm != nil {
		t.Fatalf("clear-all should drop the comm pattern, got %+v", got.Comm)
	}
	if got.IsActive() {
		t.Fatalf("clear-all should leave no active constraint, got %+v", got)
	}
	want := globalfilter.Filter{Syscall: &globalfilter.StringFilter{Pattern: ""}}
	if !got.Equal(want) {
		t.Fatalf("already-blank syscall should stay as opened:\n got  %+v\n want %+v", got, want)
	}
}

// setField edits the field at key to text through the modal's own key flow
// (Enter to start editing, Enter to confirm, which trims).
func setField(model Model, key fieldKey, text string) Model {
	model.activeField = int(key)
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	model.textInput.SetValue(text)
	return model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
}

// cycleOp presses Tab n times on the numeric field at key.
func cycleOp(model Model, key fieldKey, n int) Model {
	model.activeField = int(key)
	for range n {
		model = model.Update(tea.KeyPressMsg{Code: tea.KeyTab})
	}
	return model
}

// TestModelRoundTripEdits pins which edit sequences count as "no change"
// (the close must return a filter Equal to the opened one, so the TUI does
// not reset stats or push an undo level) and which rebuild a dimension.
func TestModelRoundTripEdits(t *testing.T) {
	initial := globalfilter.Filter{
		Comm:      &globalfilter.StringFilter{Pattern: "foo "},
		PID:       &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 42},
		LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGt, Value: 1_000},
	}
	with := func(mut func(*globalfilter.Filter)) globalfilter.Filter {
		f := initial.Clone()
		mut(&f)
		return f
	}
	cases := map[string]struct {
		edit func(Model) Model
		want globalfilter.Filter
	}{
		"clear-all then retype same values": {
			edit: func(m Model) Model {
				m = m.Update(tea.KeyPressMsg{Code: 'c', Text: "c"})
				m = setField(m, fieldComm, "foo")
				m = setField(m, fieldPID, "42")
				m = setField(m, fieldLatency, "1us")
				// clear-all reset the op to "=" (index 2); cycle forward, wrapping, back to ">".
				return cycleOp(m, fieldLatency, (opToIndex(globalfilter.OpGt)-2+len(compareOps))%len(compareOps))
			},
			want: initial,
		},
		"edit then revert text": {
			edit: func(m Model) Model {
				m = setField(m, fieldComm, "bar")
				return setField(m, fieldComm, "foo ")
			},
			want: initial,
		},
		"duration retyped as other unit": {
			edit: func(m Model) Model { return setField(m, fieldLatency, "1000ns") },
			want: initial,
		},
		"op cycled back to start": {
			edit: func(m Model) Model { return cycleOp(m, fieldPID, len(compareOps)) },
			want: initial,
		},
		"op changed rebuilds": {
			edit: func(m Model) Model { return cycleOp(m, fieldPID, 1) },
			want: with(func(f *globalfilter.Filter) { f.PID.Op = globalfilter.OpGte }),
		},
		"value changed rebuilds": {
			edit: func(m Model) Model { return setField(m, fieldLatency, "2us") },
			want: with(func(f *globalfilter.Filter) { f.LatencyNs.Value = 2_000 }),
		},
		"pattern changed rebuilds trimmed": {
			edit: func(m Model) Model { return setField(m, fieldComm, " bar ") },
			want: with(func(f *globalfilter.Filter) { f.Comm.Pattern = "bar" }),
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			model := tc.edit(NewModel().Open(initial))
			model = model.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
			if got := model.Filter(); !got.Equal(tc.want) {
				t.Fatalf("got  %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// Task 4r2: a terminal paste is one tea.PasteMsg, not key presses. The edit
// state must insert it into the field and leave the commit to Enter/Esc.
func TestModelEditingAcceptsBracketedPaste(t *testing.T) {
	model := NewModel().Open(globalfilter.Filter{})
	for range 2 { // Syscall -> Comm -> File
		model = model.Update(tea.KeyPressMsg{Code: 'j', Text: "j"})
	}
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	model = model.Update(tea.PasteMsg{Content: "/var/log/messages"})
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEsc})

	file := model.Filter().File
	if file == nil || file.Pattern != "/var/log/messages" {
		t.Fatalf("expected the pasted text to become the File filter, got %+v", file)
	}
}

// Outside edit mode the navigation keys are commands, so a paste (whose text
// is "cjq", i.e. clear, down, close) must change nothing at all.
func TestModelNavigationIgnoresBracketedPaste(t *testing.T) {
	initial := globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "keep"}}
	model := NewModel().Open(initial)
	model = model.Update(tea.PasteMsg{Content: "cjq"})
	if !model.Visible() || model.TextInputFocused() || model.activeField != 0 {
		t.Fatalf("paste acted as keys: visible=%v editing=%v field=%d",
			model.Visible(), model.TextInputFocused(), model.activeField)
	}
	model = model.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	if comm := model.Filter().Comm; comm == nil || comm.Pattern != "keep" {
		t.Fatalf("paste cleared the filter, got %+v", comm)
	}
}
