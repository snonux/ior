package flamegraph

import (
	"encoding/json"
	"fmt"
	"image/color"
	coreflamegraph "ior/internal/flamegraph"
	common "ior/internal/tui/common"
	"sort"

	"charm.land/bubbles/v2/key"
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

type flameKeyMap struct {
	MoveShallower key.Binding
	MoveDeeper    key.Binding
	PrevSibling   key.Binding
	NextSibling   key.Binding
}

func defaultFlameKeyMap() flameKeyMap {
	return flameKeyMap{
		MoveShallower: key.NewBinding(key.WithKeys("j", "down")),
		MoveDeeper:    key.NewBinding(key.WithKeys("k", "up")),
		PrevSibling:   key.NewBinding(key.WithKeys("h", "left")),
		NextSibling:   key.NewBinding(key.WithKeys("l", "right")),
	}
}

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
	subtreeSet   map[int]bool

	fieldPresets [][]string
	fieldIndex   int

	springs []frameSpring
	paused  bool
	isDark  bool
	keys    flameKeyMap
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
		subtreeSet:   make(map[int]bool),
		fieldPresets: [][]string{
			{"comm", "path"},
			{"tracepoint", "comm", "path"},
			{"pid", "tid", "comm", "path"},
		},
		isDark: true,
		keys:   defaultFlameKeyMap(),
	}
}

// Init starts the flamegraph model.
func (m Model) Init() tea.Cmd {
	return nil
}

// Update handles incoming messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		prev := m.selectedIdx
		switch {
		case key.Matches(msg, m.keys.MoveShallower):
			m.moveVertical(-1)
		case key.Matches(msg, m.keys.MoveDeeper):
			m.moveVertical(1)
		case key.Matches(msg, m.keys.PrevSibling):
			m.moveSibling(-1)
		case key.Matches(msg, m.keys.NextSibling):
			m.moveSibling(1)
		}
		if m.selectedIdx != prev {
			m.subtreeSet = computeSubtreeSet(m.frames, m.selectedIdx)
		}
	}
	return m, nil
}

// View renders the flamegraph viewport.
func (m Model) View() tea.View {
	content := RenderTerminalView(m.frames, m.width, m.height, m.selectedIdx, m.subtreeSet, m.matchIndices, m.isDark)
	if m.snapshot != nil && len(m.frames) == 0 {
		content = common.PanelStyle.Render(fmt.Sprintf("Flame: snapshot v%d has no visible frames", m.lastVersion))
	}
	return tea.NewView(content)
}

// SetLiveTrie updates the data source used by the flamegraph model.
func (m *Model) SetLiveTrie(liveTrie *coreflamegraph.LiveTrie) {
	m.liveTrie = liveTrie
	m.lastVersion = 0
	m.snapshot = nil
	m.selectedIdx = 0
	m.frames = nil
	m.targetFrames = nil
	m.subtreeSet = make(map[int]bool)
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
	m.clampSelection()
	m.subtreeSet = computeSubtreeSet(m.frames, m.selectedIdx)
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
	m.targetFrames = BuildTerminalLayout(m.snapshot, width, height)
	m.frames = append(m.frames[:0], m.targetFrames...)
	m.clampSelection()
	m.subtreeSet = computeSubtreeSet(m.frames, m.selectedIdx)
}

// SetDarkMode sets the active color theme mode.
func (m *Model) SetDarkMode(isDark bool) {
	m.isDark = isDark
}

func (m *Model) moveVertical(delta int) {
	if len(m.frames) == 0 {
		return
	}
	m.clampSelection()
	current := m.frames[m.selectedIdx]
	targetDepth := current.Depth + delta
	targets := framesAtDepth(m.frames, targetDepth)
	if len(targets) == 0 {
		return
	}
	best := targets[0]
	bestDist := abs(m.frames[best].Col - current.Col)
	for _, idx := range targets[1:] {
		dist := abs(m.frames[idx].Col - current.Col)
		if dist < bestDist {
			best = idx
			bestDist = dist
		}
	}
	m.selectedIdx = best
}

func (m *Model) moveSibling(delta int) {
	if len(m.frames) == 0 {
		return
	}
	m.clampSelection()
	current := m.frames[m.selectedIdx]
	siblings := framesAtDepth(m.frames, current.Depth)
	if len(siblings) <= 1 {
		return
	}
	pos := indexOf(siblings, m.selectedIdx)
	if pos < 0 {
		return
	}
	next := pos + delta
	if next < 0 {
		next = 0
	}
	if next >= len(siblings) {
		next = len(siblings) - 1
	}
	m.selectedIdx = siblings[next]
}

func framesAtDepth(frames []tuiFrame, depth int) []int {
	if depth < 0 {
		return nil
	}
	indices := make([]int, 0)
	for idx, frame := range frames {
		if frame.Depth == depth {
			indices = append(indices, idx)
		}
	}
	sort.Slice(indices, func(i, j int) bool {
		return frames[indices[i]].Col < frames[indices[j]].Col
	})
	return indices
}

func indexOf(values []int, target int) int {
	for idx, value := range values {
		if value == target {
			return idx
		}
	}
	return -1
}

func (m *Model) clampSelection() {
	if len(m.frames) == 0 {
		m.selectedIdx = 0
		return
	}
	if m.selectedIdx < 0 {
		m.selectedIdx = 0
	}
	if m.selectedIdx >= len(m.frames) {
		m.selectedIdx = len(m.frames) - 1
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
