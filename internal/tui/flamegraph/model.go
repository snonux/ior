package flamegraph

import (
	"encoding/json"
	"fmt"
	"image/color"
	"sort"
	"strings"
	"time"

	coreflamegraph "ior/internal/flamegraph"
	common "ior/internal/tui/common"

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

type animTickMsg struct{}

const animFrameDuration = 33 * time.Millisecond

type zoomState struct {
	path                string
	previousSelectedIdx int
}

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
	globalTotal uint64

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
	filterVisible map[int]bool
	subtreeSet    map[int]bool
	showHelp      bool
	statusMessage string

	fieldPresets [][]string
	fieldIndex   int

	animation AnimationState
	animating bool
	paused    bool
	isDark    bool
	keys      flameKeyMap
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
		liveTrie:      liveTrie,
		matchIndices:  make(map[int]bool),
		filterVisible: make(map[int]bool),
		subtreeSet:    make(map[int]bool),
		searchInput:   searchInput,
		fieldPresets: [][]string{
			{"comm", "path", "tracepoint"},
			{"path", "tracepoint", "comm"},
			{"tracepoint", "comm", "path"},
			{"pid", "path", "tracepoint"},
		},
		isDark:    true,
		keys:      defaultFlameKeyMap(),
		animation: NewAnimationState(30, 6.0, 1.0),
	}
}

// Init starts the flamegraph model.
func (m Model) Init() tea.Cmd {
	return nil
}

// Update handles incoming messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case animTickMsg:
		if !m.animating {
			return m, nil
		}
		m.animating = m.animation.Tick(0)
		m.frames = m.animation.CurrentFrames()
		m.clampSelection()
		m.subtreeSet = computeSubtreeSetInto(m.frames, m.selectedIdx, m.subtreeSet)
		if m.animating {
			return m, animTickCmd()
		}
		return m, nil
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.rebuildFrames(true)
		if m.animating {
			return m, animTickCmd()
		}
		return m, nil
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
		case isSearchOpenKey(msg):
			m.openSearch()
		case isNextMatchKey(msg):
			m.jumpMatch(1)
		case isPrevMatchKey(msg):
			m.jumpMatch(-1)
		case isPauseKey(msg):
			m.togglePause()
		case isResetBaselineKey(msg):
			m.resetBaseline()
		case isCycleOrderKey(msg):
			m.cycleFieldOrder()
		case isHelpToggleKey(msg):
			m.toggleHelp()
		case isZoomInKey(msg, m.keys):
			m.zoomIn()
		case isZoomUndoKey(msg, m.keys):
			m.zoomUndo()
		case isZoomResetKey(msg, m.keys):
			m.zoomReset()
		case isMoveShallowerKey(msg, m.keys):
			m.moveVerticalWithFallback(-1, 1)
		case isMoveDeeperKey(msg, m.keys):
			m.moveVerticalWithFallback(1, -1)
		case isPrevSiblingKey(msg, m.keys):
			m.moveSibling(-1)
		case isNextSiblingKey(msg, m.keys):
			m.moveSibling(1)
		}
		if m.selectedIdx != prev {
			m.subtreeSet = computeSubtreeSetInto(m.frames, m.selectedIdx, m.subtreeSet)
		}
	}
	return m, nil
}

// ConsumesKey reports whether the flamegraph should handle a key press before
// dashboard- or app-level shortcuts.
func (m Model) ConsumesKey(msg tea.KeyPressMsg) bool {
	if m.searchActive {
		return true
	}
	switch {
	case isSearchOpenKey(msg),
		isNextMatchKey(msg),
		isPrevMatchKey(msg),
		isPauseKey(msg),
		isResetBaselineKey(msg),
		isCycleOrderKey(msg),
		isHelpToggleKey(msg):
		return true
	case isZoomInKey(msg, m.keys),
		isZoomUndoKey(msg, m.keys),
		isZoomResetKey(msg, m.keys),
		isMoveShallowerKey(msg, m.keys),
		isMoveDeeperKey(msg, m.keys),
		isPrevSiblingKey(msg, m.keys),
		isNextSiblingKey(msg, m.keys):
		return true
	default:
		return false
	}
}

// View renders the flamegraph viewport.
func (m Model) View() tea.View {
	content := RenderTerminalView(m.frames, m.width, m.height, m.selectedIdx, m.subtreeSet, m.matchIndices, m.filterVisible, m.globalTotal, m.isDark, m.searchActive, m.searchQuery)
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
	m.globalTotal = 0
	m.selectedIdx = 0
	m.frames = nil
	m.targetFrames = nil
	m.zoomStack = nil
	m.zoomRoot = nil
	m.zoomPath = ""
	m.subtreeSet = make(map[int]bool)
	m.filterVisible = make(map[int]bool)
	m.animation = NewAnimationState(30, 6.0, 1.0)
	m.animating = false
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
	m.globalTotal = snapshotTotal(m.snapshot)
	if m.zoomPath != "" {
		m.zoomRoot = findNodeByPath(m.snapshot, m.zoomPath)
	} else {
		m.zoomRoot = nil
	}
	m.rebuildFrames(true)
	m.lastVersion = version
	return true
}

// LastVersion returns the latest snapshot version loaded into the model.
func (m Model) LastVersion() uint64 {
	return m.lastVersion
}

// HasSnapshot reports whether the flamegraph model has loaded at least one snapshot.
func (m Model) HasSnapshot() bool {
	return m.snapshot != nil
}

// AnimationCmd returns a frame animation tick command when animation is active.
func (m Model) AnimationCmd() tea.Cmd {
	if !m.animating {
		return nil
	}
	return animTickCmd()
}

// Paused reports whether live refresh is paused.
func (m Model) Paused() bool {
	return m.paused
}

// SetViewport updates model render dimensions.
func (m *Model) SetViewport(width, height int) {
	m.width = width
	m.height = height
	m.rebuildFrames(true)
}

// SetDarkMode sets the active color theme mode.
func (m *Model) SetDarkMode(isDark bool) {
	m.isDark = isDark
	m.searchInput.SetStyles(textinput.DefaultStyles(isDark))
}

func (m *Model) rebuildFrames(animate bool) {
	var root *snapshotNode
	rootPath := ""
	if m.zoomRoot != nil {
		root = m.zoomRoot
		rootPath = m.zoomPath
	} else {
		root = m.snapshot
	}
	m.targetFrames = buildTerminalLayoutWithPath(root, m.width, m.height, rootPath)
	m.animation.SetTargets(m.targetFrames)
	if animate && len(m.frames) > 0 && !m.animation.Settled() {
		m.animating = true
		m.frames = m.animation.CurrentFrames()
	} else {
		m.animating = false
		m.frames = append(m.frames[:0], m.targetFrames...)
	}
	m.clampSelection()
	m.recomputeFilterState()
	m.ensureSelectionNavigable()
	m.ensureSelectionVisible()
	m.subtreeSet = computeSubtreeSetInto(m.frames, m.selectedIdx, m.subtreeSet)
}

func (m *Model) zoomIn() {
	if len(m.frames) == 0 || m.snapshot == nil {
		m.statusMessage = "Zoom unavailable: no frame selected"
		return
	}
	m.clampSelection()
	selectedPath := m.frames[m.selectedIdx].Path
	if selectedPath == m.currentRootPath() {
		m.statusMessage = "Zoom unchanged: selected frame is current view root"
		return
	}
	target := findNodeByPath(m.snapshot, selectedPath)
	if target == nil {
		m.statusMessage = "Zoom failed: selected node is unavailable"
		return
	}
	m.zoomStack = append(m.zoomStack, zoomState{
		path:                m.zoomPath,
		previousSelectedIdx: m.selectedIdx,
	})
	m.zoomRoot = target
	m.zoomPath = selectedPath
	m.selectedIdx = 0
	m.rebuildFrames(true)
	m.statusMessage = "Zoom: " + compactFramePath(selectedPath)
}

func (m *Model) zoomUndo() {
	if len(m.zoomStack) == 0 || m.snapshot == nil {
		m.statusMessage = "Zoom undo unavailable"
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
	m.rebuildFrames(true)
	if m.zoomPath == "" {
		m.statusMessage = "Zoom: root"
		return
	}
	m.statusMessage = "Zoom: " + compactFramePath(m.zoomPath)
}

func (m *Model) zoomReset() {
	if m.zoomRoot == nil && len(m.zoomStack) == 0 {
		m.statusMessage = "Zoom already at root"
		return
	}
	m.zoomRoot = nil
	m.zoomPath = ""
	m.zoomStack = nil
	m.rebuildFrames(false)
	m.statusMessage = "Zoom reset to root"
}

func (m *Model) moveVertical(delta int) {
	if len(m.frames) == 0 {
		return
	}
	m.clampSelection()
	m.ensureSelectionNavigable()
	current := m.frames[m.selectedIdx]
	targetDepth := current.Depth + delta
	targets := m.framesAtDepth(targetDepth)
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

func (m *Model) moveVerticalWithFallback(primaryDelta, fallbackDelta int) {
	before := m.selectedIdx
	m.moveVertical(primaryDelta)
	if m.selectedIdx == before && fallbackDelta != 0 {
		m.moveVertical(fallbackDelta)
	}
}

func (m *Model) moveSibling(delta int) {
	if len(m.frames) == 0 {
		return
	}
	m.clampSelection()
	m.ensureSelectionNavigable()
	current := m.frames[m.selectedIdx]
	siblings := m.framesAtDepth(current.Depth)
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
	return framesAtDepthFiltered(frames, depth, nil)
}

func framesAtDepthFiltered(frames []tuiFrame, depth int, include map[int]bool) []int {
	if depth < 0 {
		return nil
	}
	indices := make([]int, 0)
	for idx, frame := range frames {
		if include != nil && !include[idx] {
			continue
		}
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

func animTickCmd() tea.Cmd {
	return tea.Tick(animFrameDuration, func(time.Time) tea.Msg { return animTickMsg{} })
}

func (m Model) currentRootPath() string {
	if m.zoomPath != "" {
		return m.zoomPath
	}
	if len(m.frames) == 0 {
		return ""
	}
	return m.frames[0].Path
}

func (m Model) filterActive() bool {
	return strings.TrimSpace(m.searchQuery) != ""
}

func (m Model) navigableFrameSet() map[int]bool {
	if !m.filterActive() {
		return nil
	}
	return m.filterVisible
}

func (m Model) framesAtDepth(depth int) []int {
	return framesAtDepthFiltered(m.frames, depth, m.navigableFrameSet())
}

func (m Model) frameNavigable(idx int) bool {
	if idx < 0 || idx >= len(m.frames) {
		return false
	}
	if !m.filterActive() {
		return true
	}
	return m.filterVisible[idx]
}

func (m *Model) ensureSelectionNavigable() {
	if len(m.frames) == 0 {
		m.selectedIdx = 0
		return
	}
	m.clampSelection()
	if m.frameNavigable(m.selectedIdx) {
		return
	}

	if len(m.matchIndices) > 0 {
		for _, idx := range orderedMatchIndices(m.matchIndices) {
			if m.frameNavigable(idx) {
				m.selectedIdx = idx
				return
			}
		}
	}

	for idx := range m.frames {
		if m.frameNavigable(idx) {
			m.selectedIdx = idx
			return
		}
	}
}

func keyString(msg tea.KeyPressMsg) string {
	if s := msg.String(); s != "" {
		return s
	}
	return msg.Text
}

func isSearchOpenKey(msg tea.KeyPressMsg) bool { return keyString(msg) == "/" }
func isNextMatchKey(msg tea.KeyPressMsg) bool  { return keyString(msg) == "n" }
func isPrevMatchKey(msg tea.KeyPressMsg) bool  { return keyString(msg) == "N" }
func isPauseKey(msg tea.KeyPressMsg) bool      { return keyString(msg) == "p" }
func isResetBaselineKey(msg tea.KeyPressMsg) bool {
	return keyString(msg) == "r"
}
func isCycleOrderKey(msg tea.KeyPressMsg) bool { return keyString(msg) == "o" }
func isHelpToggleKey(msg tea.KeyPressMsg) bool { return keyString(msg) == "?" }

func isZoomInKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	return key.Matches(msg, keys.ZoomIn) || msg.Code == tea.KeyEnter || strings.EqualFold(keyString(msg), "enter")
}

func isZoomUndoKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	return key.Matches(msg, keys.ZoomUndo) || msg.Code == tea.KeyBackspace
}

func isZoomResetKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	return key.Matches(msg, keys.ZoomReset) || msg.Code == tea.KeyEsc
}

func isMoveShallowerKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	k := keyString(msg)
	return key.Matches(msg, keys.MoveShallower) || msg.Code == tea.KeyDown || keyMatchesDirection(k, "down", 'B')
}

func isMoveDeeperKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	k := keyString(msg)
	return key.Matches(msg, keys.MoveDeeper) || msg.Code == tea.KeyUp || keyMatchesDirection(k, "up", 'A')
}

func isPrevSiblingKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	k := keyString(msg)
	return key.Matches(msg, keys.PrevSibling) || msg.Code == tea.KeyLeft || keyMatchesDirection(k, "left", 'D')
}

func isNextSiblingKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	k := keyString(msg)
	return key.Matches(msg, keys.NextSibling) || msg.Code == tea.KeyRight || keyMatchesDirection(k, "right", 'C')
}

func keyMatchesDirection(keyName, plain string, ansiFinal byte) bool {
	if keyName == plain || strings.HasSuffix(keyName, "+"+plain) {
		return true
	}
	return isArrowEscapeSequence(keyName, ansiFinal)
}

func isArrowEscapeSequence(value string, ansiFinal byte) bool {
	if len(value) < 3 || value[0] != '\x1b' {
		return false
	}
	last := value[len(value)-1]
	if last != ansiFinal {
		return false
	}
	return value[1] == '[' || value[1] == 'O'
}

func (m Model) visibleRowOffset() int {
	if len(m.frames) == 0 {
		return 0
	}
	availableRows := m.height - 2 // toolbar + status
	if availableRows <= 0 {
		return 0
	}
	maxRow := maxFrameRowForSet(m.frames, m.navigableFrameSet())
	if maxRow+1 <= availableRows {
		return 0
	}
	return maxRow + 1 - availableRows
}

func (m *Model) ensureSelectionVisible() {
	if len(m.frames) == 0 {
		return
	}
	m.clampSelection()
	m.ensureSelectionNavigable()
	if !m.frameNavigable(m.selectedIdx) {
		return
	}
	rowOffset := m.visibleRowOffset()
	selected := m.frames[m.selectedIdx]
	if selected.Row >= rowOffset {
		return
	}

	bestIdx := -1
	bestScore := int(^uint(0) >> 1)
	for idx, frame := range m.frames {
		if !m.frameNavigable(idx) {
			continue
		}
		if frame.Row < rowOffset {
			continue
		}
		score := abs(frame.Row-rowOffset)*1000 + abs(frame.Col-selected.Col)
		if score < bestScore {
			bestIdx = idx
			bestScore = score
		}
	}
	if bestIdx >= 0 {
		m.selectedIdx = bestIdx
	}
}
