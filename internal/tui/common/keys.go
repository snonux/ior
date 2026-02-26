package common

import "github.com/charmbracelet/bubbles/key"

// HelpSection groups related key bindings under a shared heading.
type HelpSection struct {
	Title    string
	Bindings []key.Binding
}

// KeyMap groups all key bindings shared by TUI screens.
type KeyMap struct {
	Tab       key.Binding
	ShiftTab  key.Binding
	One       key.Binding
	Two       key.Binding
	Three     key.Binding
	Four      key.Binding
	Five      key.Binding
	Six       key.Binding
	Seven     key.Binding
	DirGroup  key.Binding
	SelectPID key.Binding
	SelectTID key.Binding
	Probes    key.Binding
	Export    key.Binding
	Quit      key.Binding
	Enter     key.Binding
	Esc       key.Binding
	Refresh   key.Binding
}

// Keys contains the default shared key map.
var Keys = DefaultKeyMap()

// DefaultKeyMap builds the default key bindings used by models.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Tab:       key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "next tab")),
		ShiftTab:  key.NewBinding(key.WithKeys("shift+tab"), key.WithHelp("shift+tab", "prev tab")),
		One:       key.NewBinding(key.WithKeys("1"), key.WithHelp("1", "overview")),
		Two:       key.NewBinding(key.WithKeys("2"), key.WithHelp("2", "syscalls")),
		Three:     key.NewBinding(key.WithKeys("3"), key.WithHelp("3", "files")),
		Four:      key.NewBinding(key.WithKeys("4"), key.WithHelp("4", "processes")),
		Five:      key.NewBinding(key.WithKeys("5"), key.WithHelp("5", "lat+gaps")),
		Six:       key.NewBinding(key.WithKeys("6"), key.WithHelp("6", "stream")),
		Seven:     key.NewBinding(key.WithKeys("7"), key.WithHelp("7", "stream")),
		DirGroup:  key.NewBinding(key.WithKeys("d"), key.WithHelp("d", "dir group")),
		SelectPID: key.NewBinding(key.WithKeys("p"), key.WithHelp("p", "select pid")),
		SelectTID: key.NewBinding(key.WithKeys("t"), key.WithHelp("t", "select tid")),
		Probes:    key.NewBinding(key.WithKeys("o"), key.WithHelp("o", "probes")),
		Export:    key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "snapshot export")),
		Quit:      key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
		Enter:     key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "select")),
		Esc:       key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
		Refresh:   key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "refresh")),
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
	global := []key.Binding{
		helpTextBinding("H", "toggle help"),
		k.Tab,
		k.ShiftTab,
		k.One,
		k.Two,
		k.Three,
		k.Four,
		k.Five,
		k.Six,
		k.SelectPID,
		k.SelectTID,
		k.Probes,
		k.Refresh,
		k.Quit,
	}
	if help := k.Export.Help(); help.Key != "" || help.Desc != "" {
		global = append(global, k.Export)
	}
	dashboard := []key.Binding{
		k.DirGroup,
		helpTextBinding("space", "stream pause"),
		helpTextBinding("f", "stream filter"),
		helpTextBinding("g/G", "stream top/tail"),
		helpTextBinding("c", "stream clear"),
		helpTextBinding("enter", "stream add filter"),
		helpTextBinding("esc", "stream undo filter"),
		helpTextBinding("left/right", "stream col"),
		helpTextBinding("h/l", "stream col"),
		helpTextBinding("j/k", "scroll"),
		helpTextBinding("up/down", "scroll"),
		helpTextBinding("/,?", "stream regex search"),
		helpTextBinding("n/N", "stream search next/prev"),
		helpTextBinding("x", "stream export"),
		helpTextBinding("X", "stream export as"),
		helpTextBinding("E", "stream open last"),
	}

	return []HelpSection{
		{Title: "Global", Bindings: global},
		{Title: "Dashboard", Bindings: dashboard},
	}
}

// DashboardFullHelp returns grouped bindings for dashboard overlays.
func (k KeyMap) DashboardFullHelp() [][]key.Binding {
	controls := []key.Binding{k.Tab, k.ShiftTab}
	if help := k.Export.Help(); help.Key != "" || help.Desc != "" {
		controls = append(controls, k.Export)
	}
	controls = append(controls, k.DirGroup, k.SelectPID, k.SelectTID, k.Probes, k.Refresh, k.Quit)

	return [][]key.Binding{
		{k.One, k.Two, k.Three, k.Four, k.Five, k.Six},
		controls,
		{
			helpTextBinding("space", "stream pause"),
			helpTextBinding("f", "stream filter"),
			helpTextBinding("g/G", "stream top/tail"),
			helpTextBinding("c", "stream clear"),
			helpTextBinding("enter", "stream add filter"),
			helpTextBinding("esc", "stream undo filter"),
			helpTextBinding("left/right", "stream col"),
			helpTextBinding("h/l", "stream col"),
			helpTextBinding("j/k", "scroll"),
			helpTextBinding("up/down", "scroll"),
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
