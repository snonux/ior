package common

import "github.com/charmbracelet/bubbles/key"

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
	Probes    key.Binding
	Export    key.Binding
	Quit      key.Binding
	Help      key.Binding
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
		SelectPID: key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "select pid")),
		Probes:    key.NewBinding(key.WithKeys("p"), key.WithHelp("p", "probes")),
		Export:    key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "export")),
		Quit:      key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
		Help:      key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		Enter:     key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "select")),
		Esc:       key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
		Refresh:   key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "refresh")),
	}
}

// DashboardShortHelp returns compact bindings for dashboard help bars.
func (k KeyMap) DashboardShortHelp() []key.Binding {
	bindings := []key.Binding{k.Tab, k.ShiftTab}
	if help := k.Export.Help(); help.Key != "" || help.Desc != "" {
		bindings = append(bindings, k.Export)
	}
	bindings = append(bindings, k.SelectPID, k.Probes, k.Help, k.Quit)
	return bindings
}

// DashboardFullHelp returns grouped bindings for dashboard overlays.
func (k KeyMap) DashboardFullHelp() [][]key.Binding {
	controls := []key.Binding{k.Tab, k.ShiftTab}
	if help := k.Export.Help(); help.Key != "" || help.Desc != "" {
		controls = append(controls, k.Export)
	}
	controls = append(controls, k.DirGroup, k.SelectPID, k.Probes, k.Refresh, k.Help, k.Quit)

	return [][]key.Binding{
		{k.One, k.Two, k.Three, k.Four, k.Five, k.Six},
		controls,
		{
			helpTextBinding("left/right", "tab"),
			helpTextBinding("h/l", "tab"),
			helpTextBinding("j/k", "scroll"),
			helpTextBinding("up/down", "scroll"),
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
