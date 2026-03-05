package flamegraph

import (
	"image/color"
	coreflamegraph "ior/internal/flamegraph"
	common "ior/internal/tui/common"

	tea "charm.land/bubbletea/v2"
)

type snapshotNode struct {
	Name     string          `json:"n"`
	Value    uint64          `json:"v"`
	Total    uint64          `json:"t"`
	Children []*snapshotNode `json:"c,omitempty"`
}

type zoomState struct {
	path        string
	selectedIdx int
}

type frameSpring struct{}

// Model is the Bubble Tea model for the TUI flamegraph tab.
type Model struct {
	liveTrie    *coreflamegraph.LiveTrie
	lastVersion uint64
	snapshot    *snapshotNode

	frames       []tuiFrame
	targetFrames []tuiFrame
	width        int
	height       int

	selectedIdx int
	zoomStack   []zoomState
	zoomRoot    *snapshotNode

	searchActive bool
	searchQuery  string
	matchIndices map[int]bool

	fieldPresets [][]string
	fieldIndex   int

	springs []frameSpring
	paused  bool
	isDark  bool
}

// tuiFrame stores one terminal flamegraph frame cell.
type tuiFrame struct {
	Name    string
	Col     int
	Row     int
	Width   int
	Total   uint64
	Percent float64
	Fill    color.Color
	Depth   int
	Path    string
}

// NewModel constructs a flamegraph tab model with default state.
func NewModel(liveTrie *coreflamegraph.LiveTrie) Model {
	return Model{
		liveTrie:     liveTrie,
		matchIndices: make(map[int]bool),
		fieldPresets: [][]string{
			{"comm", "path"},
			{"tracepoint", "comm", "path"},
			{"pid", "tid", "comm", "path"},
		},
		isDark: true,
	}
}

// Init starts the flamegraph model.
func (m Model) Init() tea.Cmd {
	return nil
}

// Update handles incoming messages.
func (m Model) Update(tea.Msg) (tea.Model, tea.Cmd) {
	return m, nil
}

// View renders the flamegraph viewport.
func (m Model) View() tea.View {
	content := common.PanelStyle.Render("Flame: model scaffold")
	return tea.NewView(content)
}

// SetViewport updates model render dimensions.
func (m *Model) SetViewport(width, height int) {
	m.width = width
	m.height = height
}

// SetDarkMode sets the active color theme mode.
func (m *Model) SetDarkMode(isDark bool) {
	m.isDark = isDark
}
