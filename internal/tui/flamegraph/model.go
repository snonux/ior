package flamegraph

import (
	"encoding/json"
	"fmt"
	"image/color"
	coreflamegraph "ior/internal/flamegraph"
	common "ior/internal/tui/common"
	"sort"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

type snapshotNode struct {
	Name     string          `json:"n"`
	Value    uint64          `json:"v"`
	Total    uint64          `json:"t"`
	Children []*snapshotNode `json:"c,omitempty"`
}

type zoomState struct {
	path                string
	previousSelectedIdx int
}

type frameSpring struct{}

type flameKeyMap struct {
	MoveShallower key.Binding
	MoveDeeper    key.Binding
	PrevSibling   key.Binding
	NextSibling   key.Binding
	ZoomIn        key.Binding
	ZoomUndo      key.Binding
	ZoomReset     key.Binding
}

func defaultFlameKeyMap() flameKeyMap {
	return flameKeyMap{
		MoveShallower: key.NewBinding(key.WithKeys("j", "down")),
		MoveDeeper:    key.NewBinding(key.WithKeys("k", "up")),
		PrevSibling:   key.NewBinding(key.WithKeys("h", "left")),
		NextSibling:   key.NewBinding(key.WithKeys("l", "right")),
		ZoomIn:        key.NewBinding(key.WithKeys("enter")),
		ZoomUndo:      key.NewBinding(key.WithKeys("backspace", "u")),
		ZoomReset:     key.NewBinding(key.WithKeys("esc")),
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
	zoomPath    string

	searchActive  bool
	searchInput   textinput.Model
	searchQuery   string
	matchIndices  map[int]bool
	subtreeSet    map[int]bool
	showHelp      bool
	statusMessage string

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
	searchInput := textinput.New()
	searchInput.Prompt = "/"
	searchInput.CharLimit = 0
	searchInput.SetWidth(32)
	searchInput.SetStyles(textinput.DefaultStyles(true))

	return Model{
		liveTrie:     liveTrie,
		matchIndices: make(map[int]bool),
		subtreeSet:   make(map[int]bool),
		searchInput:  searchInput,
		fieldPresets: [][]string{
			{"comm", "path", "tracepoint"},
			{"path", "tracepoint", "comm"},
			{"tracepoint", "comm", "path"},
			{"pid", "path", "tracepoint"},
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
		if m.searchActive {
			switch msg.String() {
			case "esc":
				m.clearSearch()
				return m, nil
			case "enter":
				m.applySearchQuery(m.searchInput.Value())
				m.searchActive = false
				m.searchInput.Blur()
				return m, nil
			}
			var cmd tea.Cmd
			m.searchInput, cmd = m.searchInput.Update(msg)
			_ = cmd
			return m, nil
		}

		prev := m.selectedIdx
		switch {
		case msg.String() == "/":
			m.openSearch()
		case msg.String() == "n":
			m.jumpMatch(1)
		case msg.String() == "N":
			m.jumpMatch(-1)
		case msg.String() == "p":
			m.togglePause()
		case msg.String() == "r":
			m.resetBaseline()
		case msg.String() == "o":
			m.cycleFieldOrder()
		case msg.String() == "?":
			m.toggleHelp()
		case key.Matches(msg, m.keys.ZoomIn):
			m.zoomIn()
		case key.Matches(msg, m.keys.ZoomUndo):
			m.zoomUndo()
		case key.Matches(msg, m.keys.ZoomReset):
			m.zoomReset()
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
	content := RenderTerminalView(m.frames, m.width, m.height, m.selectedIdx, m.subtreeSet, m.matchIndices, m.isDark, m.searchActive, m.searchQuery)
	content = replaceHeaderLine(content, m.toolbarLine())
	if m.searchActive {
		content = replaceFooterLine(content, m.searchFooter())
	}
	if m.snapshot != nil && len(m.frames) == 0 {
		content = common.PanelStyle.Render(fmt.Sprintf("Flame: snapshot v%d has no visible frames", m.lastVersion))
	}
	if m.showHelp {
		content += "\n" + m.helpOverlay()
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
	m.zoomStack = nil
	m.zoomRoot = nil
	m.zoomPath = ""
	m.subtreeSet = make(map[int]bool)
}

// RefreshFromLiveTrie loads a new snapshot when the source version changes.
func (m *Model) RefreshFromLiveTrie() bool {
	if m.liveTrie == nil {
		return false
	}
	if m.paused {
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
	m.snapshot = &snapshot
	if m.zoomPath != "" {
		m.zoomRoot = findNodeByPath(m.snapshot, m.zoomPath)
	} else {
		m.zoomRoot = nil
	}
	m.rebuildFrames()
	m.lastVersion = version
	return true
}

// LastVersion returns the latest snapshot version loaded into the model.
func (m Model) LastVersion() uint64 {
	return m.lastVersion
}

// Paused reports whether live refresh is paused.
func (m Model) Paused() bool {
	return m.paused
}

// SetViewport updates model render dimensions.
func (m *Model) SetViewport(width, height int) {
	m.width = width
	m.height = height
	m.rebuildFrames()
}

// SetDarkMode sets the active color theme mode.
func (m *Model) SetDarkMode(isDark bool) {
	m.isDark = isDark
	m.searchInput.SetStyles(textinput.DefaultStyles(isDark))
}

func (m *Model) rebuildFrames() {
	var root *snapshotNode
	rootPath := ""
	if m.zoomRoot != nil {
		root = m.zoomRoot
		rootPath = m.zoomPath
	} else {
		root = m.snapshot
	}
	m.targetFrames = buildTerminalLayoutWithPath(root, m.width, m.height, rootPath)
	m.frames = append(m.frames[:0], m.targetFrames...)
	m.clampSelection()
	m.subtreeSet = computeSubtreeSet(m.frames, m.selectedIdx)
}

func (m *Model) zoomIn() {
	if len(m.frames) == 0 || m.snapshot == nil {
		return
	}
	m.clampSelection()
	selectedPath := m.frames[m.selectedIdx].Path
	target := findNodeByPath(m.snapshot, selectedPath)
	if target == nil {
		return
	}
	m.zoomStack = append(m.zoomStack, zoomState{
		path:                m.zoomPath,
		previousSelectedIdx: m.selectedIdx,
	})
	m.zoomRoot = target
	m.zoomPath = selectedPath
	m.selectedIdx = 0
	m.rebuildFrames()
}

func (m *Model) zoomUndo() {
	if len(m.zoomStack) == 0 || m.snapshot == nil {
		return
	}
	last := m.zoomStack[len(m.zoomStack)-1]
	m.zoomStack = m.zoomStack[:len(m.zoomStack)-1]
	m.zoomPath = last.path
	if m.zoomPath == "" {
		m.zoomRoot = nil
	} else {
		m.zoomRoot = findNodeByPath(m.snapshot, m.zoomPath)
	}
	m.selectedIdx = last.previousSelectedIdx
	m.rebuildFrames()
}

func (m *Model) zoomReset() {
	if m.zoomRoot == nil && len(m.zoomStack) == 0 {
		return
	}
	m.zoomRoot = nil
	m.zoomPath = ""
	m.zoomStack = nil
	m.rebuildFrames()
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
