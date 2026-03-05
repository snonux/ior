package flamegraph

import (
	"encoding/json"
	"fmt"
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
	content := "Flame: waiting for data..."
	if m.snapshot != nil {
		content = fmt.Sprintf("Flame: live snapshot v%d", m.lastVersion)
	}
	content = common.PanelStyle.Render(content)
	return tea.NewView(content)
}

// SetLiveTrie updates the data source used by the flamegraph model.
func (m *Model) SetLiveTrie(liveTrie *coreflamegraph.LiveTrie) {
	m.liveTrie = liveTrie
	m.lastVersion = 0
	m.snapshot = nil
}

// RefreshFromLiveTrie loads a new snapshot when the source version changes.
func (m *Model) RefreshFromLiveTrie() bool {
	if m.liveTrie == nil {
		return false
	}
	version := m.liveTrie.Version()
	if version == m.lastVersion && m.snapshot != nil {
		return false
	}

	payload, version := m.liveTrie.SnapshotJSON()
	var snapshot snapshotNode
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return false
	}
	m.targetFrames = BuildTerminalLayout(&snapshot, m.width, m.height)
	m.frames = append(m.frames[:0], m.targetFrames...)
	m.snapshot = &snapshot
	m.lastVersion = version
	return true
}

// LastVersion returns the latest snapshot version loaded into the model.
func (m Model) LastVersion() uint64 {
	return m.lastVersion
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
