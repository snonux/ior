package common

import "charm.land/bubbles/v2/key"

// HelpSection groups related key bindings under a shared heading.
type HelpSection struct {
	Title    string
	Bindings []key.Binding
}

// KeyMap groups all key bindings shared by TUI screens.
type KeyMap struct {
	Tab         key.Binding
	ShiftTab    key.Binding
	One         key.Binding
	Two         key.Binding
	Three       key.Binding
	Four        key.Binding
	Five        key.Binding
	Six         key.Binding
	Seven       key.Binding
	Visualize   key.Binding
	Metric      key.Binding
	Sort        key.Binding
	ReverseSort key.Binding
	DirGroup    key.Binding
	SelectPID   key.Binding
	SelectTID   key.Binding
	Probes      key.Binding
	Filter      key.Binding
	FilterUndo  key.Binding
	PrevFamily  key.Binding
	NextFamily  key.Binding
	Export      key.Binding
	Record      key.Binding
	Quit        key.Binding
	Enter       key.Binding
	Esc         key.Binding
	Refresh     key.Binding
	// AutoReset toggles/cycles the dashboard's auto-reset timer. The
	// timer periodically clears aggregate state (same as Refresh) to
	// prevent unbounded growth of the flamegraph trie and stats engine.
	// Bound to capital `I` because lowercase `t` is the TID picker; we
	// keep `i` unbound so future use isn't blocked.
	AutoReset key.Binding
}

// Keys contains the default shared key map.
var Keys = DefaultKeyMap()

func keyBinding(desc string, keys ...string) key.Binding {
	return key.NewBinding(key.WithKeys(keys...), key.WithHelp(keys[0], desc))
}

// DefaultKeyMap builds the default key bindings used by models.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Tab:         keyBinding("next tab", "tab"),
		ShiftTab:    keyBinding("prev tab", "shift+tab"),
		One:         keyBinding("flame", "1"),
		Two:         keyBinding("overview", "2"),
		Three:       keyBinding("syscalls", "3"),
		Four:        keyBinding("files", "4"),
		Five:        keyBinding("processes", "5"),
		Six:         keyBinding("lat+gaps", "6"),
		Seven:       keyBinding("stream", "7"),
		Visualize:   keyBinding("viz", "v"),
		Metric:      keyBinding("metric", "b"),
		Sort:        keyBinding("sort table", "s"),
		ReverseSort: keyBinding("reverse sort", "S"),
		DirGroup:    keyBinding("dir group", "d"),
		SelectPID:   keyBinding("select pid", "p"),
		SelectTID:   keyBinding("select tid", "t"),
		Probes:      keyBinding("probes", "o"),
		Filter:      keyBinding("filter", "f"),
		FilterUndo:  keyBinding("undo filter", "F"),
		PrevFamily:  keyBinding("prev family", "["),
		NextFamily:  keyBinding("next family", "]"),
		Export:      keyBinding("stream export", "e"),
		Record:      keyBinding("parquet rec", "R"),
		Quit:        keyBinding("quit", "q", "ctrl+c"),
		Enter:       keyBinding("select", "enter"),
		Esc:         keyBinding("back", "esc"),
		Refresh:     keyBinding("reset baseline", "r"),
		AutoReset:   keyBinding("cycle auto-reset", "I"),
	}
}

// DashboardStatusHelp returns expanded bindings for dashboard status bars.
func (k KeyMap) DashboardStatusHelp() []key.Binding {
	sections := k.DashboardStatusHelpSections()
	total := 0
	for _, section := range sections {
		total += len(section.Bindings)
	}
	bindings := make([]key.Binding, 0, total)
	for _, section := range sections {
		bindings = append(bindings, section.Bindings...)
	}
	return bindings
}

// DashboardStatusHelpSections returns grouped bindings for dashboard status bars.
func (k KeyMap) DashboardStatusHelpSections() []HelpSection {
	return []HelpSection{
		{Title: "Global", Bindings: k.globalStatusBindings()},
		{Title: "Dashboard", Bindings: dashboardStatusBindings(k)},
	}
}

// globalStatusBindings returns the global key bindings shown in the status bar,
// appending the optional export binding when it has a non-empty label.
func (k KeyMap) globalStatusBindings() []key.Binding {
	bindings := []key.Binding{
		helpTextBinding("H", "toggle help"),
		k.Tab, k.ShiftTab,
		k.One, k.Two, k.Three, k.Four, k.Five, k.Six, k.Seven,
		k.Visualize, k.Metric, k.Sort, k.ReverseSort,
		k.Filter, k.FilterUndo,
		k.PrevFamily, k.NextFamily,
		k.SelectPID, k.SelectTID,
		k.Probes, k.Record, k.Refresh, k.AutoReset, k.Quit,
	}
	if help := k.Export.Help(); help.Key != "" || help.Desc != "" {
		bindings = append(bindings, k.Export)
	}
	return bindings
}

// dashboardStatusBindings returns the dashboard-specific bindings shown in
// the status bar (table navigation, stream controls, and export shortcuts).
func dashboardStatusBindings(k KeyMap) []key.Binding {
	return []key.Binding{
		k.DirGroup, k.Visualize, k.Metric, k.Sort, k.ReverseSort,
		helpTextBinding("space", "stream pause"),
		helpTextBinding("enter", "selected filter"),
		helpTextBinding("esc", "stream undo filter"),
		helpTextBinding("T", "stream fd-trace"),
		helpTextBinding("g/G", "table top/bottom"),
		helpTextBinding("left/right", "table col"),
		helpTextBinding("h/l", "table col"),
		helpTextBinding("j/k", "table row"),
		helpTextBinding("up/down", "table row"),
		helpTextBinding("pgup/down", "table page"),
		helpTextBinding("/,?", "stream regex search"),
		helpTextBinding("n/N", "stream search next/prev"),
		helpTextBinding("x", "stream export"),
		helpTextBinding("X", "stream export as"),
		helpTextBinding("E", "stream open last"),
	}
}

// DashboardFullHelp returns grouped bindings for dashboard overlays.
func (k KeyMap) DashboardFullHelp() [][]key.Binding {
	controls := []key.Binding{k.Tab, k.ShiftTab}
	if help := k.Export.Help(); help.Key != "" || help.Desc != "" {
		controls = append(controls, k.Export)
	}
	controls = append(controls, k.DirGroup, k.SelectPID, k.SelectTID, k.Probes, k.Record, k.Refresh, k.AutoReset, k.Quit)
	controls = append(controls, k.Visualize, k.Metric, k.Sort, k.ReverseSort, k.Filter, k.FilterUndo, k.PrevFamily, k.NextFamily)

	return [][]key.Binding{
		{k.One, k.Two, k.Three, k.Four, k.Five, k.Six, k.Seven},
		controls,
		{
			helpTextBinding("space", "stream pause"),
			helpTextBinding("enter", "selected filter"),
			helpTextBinding("esc", "stream undo filter"),
			helpTextBinding("T", "stream fd-trace"),
			helpTextBinding("g/G", "table top/bottom"),
			helpTextBinding("left/right", "table col"),
			helpTextBinding("h/l", "table col"),
			helpTextBinding("j/k", "table row"),
			helpTextBinding("up/down", "table row"),
			helpTextBinding("pgup/down", "table page"),
			helpTextBinding("x", "stream export"),
			helpTextBinding("X", "stream export as"),
			helpTextBinding("E", "stream open last"),
			helpTextBinding("/,?", "stream regex search"),
			helpTextBinding("n/N", "stream search next/prev"),
		},
	}
}

// PickerShortHelp returns compact bindings for the PID picker.
func (k KeyMap) PickerShortHelp() []key.Binding {
	return []key.Binding{k.Enter, k.Refresh, k.Esc}
}

func helpTextBinding(keyText, desc string) key.Binding {
	return key.NewBinding(key.WithHelp(keyText, desc))
}
