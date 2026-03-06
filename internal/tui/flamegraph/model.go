package flamegraph

import (
	"encoding/json"
	"fmt"
	"image/color"
	"slices"
	"sort"
	"strings"
	"time"

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

// LiveTrieSource is the minimal trie contract needed by the flamegraph TUI model.
type LiveTrieSource interface {
	Fields() []string
	CountField() string
	Reconfigure([]string) error
	SetCountField(string) error
	Reset()
	Version() uint64
	SnapshotJSON() ([]byte, uint64)
}

type zoomState struct {
	path                string
	previousSelectedIdx int
	lineWidth           int
}

type flameKeyMap struct {
	MoveShallower key.Binding
	MoveDeeper    key.Binding
	PrevSibling   key.Binding
	NextSibling   key.Binding
	JumpTop       key.Binding
	JumpRoot      key.Binding
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
		JumpTop:       key.NewBinding(key.WithKeys("pgup", "pageup")),
		JumpRoot:      key.NewBinding(key.WithKeys("pgdown", "pgdn", "pagedown")),
		ZoomIn:        key.NewBinding(key.WithKeys("enter")),
		ZoomUndo:      key.NewBinding(key.WithKeys("backspace", "u", "esc")),
		ZoomReset:     key.NewBinding(),
	}
}

// Model is the Bubble Tea model for the TUI flamegraph tab.
type Model struct {
	liveTrie    LiveTrieSource
	lastVersion uint64
	snapshot    *snapshotNode
	globalTotal uint64

	frames       []tuiFrame
	targetFrames []tuiFrame
	width        int
	height       int

	selectedIdx   int
	zoomStack     []zoomState
	zoomRoot      *snapshotNode
	zoomPath      string
	zoomLineWidth int

	searchActive  bool
	searchInput   textinput.Model
	searchQuery   string
	matchIndices  map[int]bool
	filterVisible map[int]bool
	subtreeSet    map[int]bool
	showHelp      bool
	statusMessage string
	lastKeyDebug  string

	fieldPresets [][]string
	fieldIndex   int
	countField   string

	animation AnimationState
	animating bool
	paused    bool
	// hasNavigableSnapshot flips once we have at least one selectable non-root frame.
	hasNavigableSnapshot bool
	isDark               bool
	keys                 flameKeyMap
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
func NewModel(liveTrie LiveTrieSource) Model {
	searchInput := textinput.New()
	searchInput.Prompt = "/"
	searchInput.CharLimit = 0
	searchInput.SetWidth(32)
	searchInput.SetStyles(textinput.DefaultStyles(true))

	m := Model{
		liveTrie:      liveTrie,
		matchIndices:  make(map[int]bool),
		filterVisible: make(map[int]bool),
		subtreeSet:    make(map[int]bool),
		searchInput:   searchInput,
		fieldPresets: [][]string{
			{"comm", "tracepoint", "path"},
			{"path", "tracepoint", "comm"},
			{"tracepoint", "comm", "path"},
			{"pid", "tracepoint", "path"},
			{"comm", "path", "tracepoint"},
		},
		isDark:     true,
		keys:       defaultFlameKeyMap(),
		animation:  NewAnimationState(30, 6.0, 1.0),
		countField: "count",
	}
	m.syncFieldPresetToTrie()
	m.syncCountFieldToTrie()
	return m
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
	case tea.MouseClickMsg:
		_ = m.handleMouseClick(msg)
		return m, nil
	case tea.KeyPressMsg:
		if m.searchActive {
			handled := false
			switch msg.String() {
			case "esc":
				handled = true
				m.clearSearch()
				m.recordKeyDebug(msg, handled, false)
				return m, nil
			case "enter":
				handled = true
				m.applySearchQuery(m.searchInput.Value())
				m.searchActive = false
				m.searchInput.Blur()
				m.recordKeyDebug(msg, handled, false)
				return m, nil
			}
			var cmd tea.Cmd
			m.searchInput, cmd = m.searchInput.Update(msg)
			_ = cmd
			m.recordKeyDebug(msg, true, false)
			return m, nil
		}

		prev := m.selectedIdx
		handled := false
		switch {
		case isSearchOpenKey(msg):
			handled = true
			m.openSearch()
		case isNextMatchKey(msg):
			handled = true
			m.jumpMatch(1)
		case isPrevMatchKey(msg):
			handled = true
			m.jumpMatch(-1)
		case isPauseKey(msg):
			handled = true
			m.togglePause()
		case isResetBaselineKey(msg):
			handled = true
			m.resetBaseline()
		case isCycleOrderKey(msg):
			handled = true
			m.cycleFieldOrder()
		case isCycleMetricKey(msg):
			handled = true
			m.toggleCountField()
		case isHelpToggleKey(msg):
			handled = true
			m.toggleHelp()
		case isZoomInKey(msg, m.keys):
			handled = true
			m.zoomIn()
		case isZoomUndoKey(msg, m.keys):
			handled = true
			m.zoomUndo()
		case isZoomResetKey(msg, m.keys):
			handled = true
			m.zoomReset()
		case isMoveShallowerKey(msg, m.keys):
			handled = true
			m.moveVerticalWithFallback(-1, 1, -1)
		case isMoveDeeperKey(msg, m.keys):
			handled = true
			m.moveVerticalWithFallback(1, -1, 1)
		case isPrevSiblingKey(msg, m.keys):
			handled = true
			m.moveSibling(-1)
		case isNextSiblingKey(msg, m.keys):
			handled = true
			m.moveSibling(1)
		case isJumpTopKey(msg, m.keys):
			handled = true
			m.jumpToTop()
		case isJumpRootKey(msg, m.keys):
			handled = true
			m.jumpToRoot()
		}
		if m.selectedIdx != prev {
			m.subtreeSet = computeSubtreeSetInto(m.frames, m.selectedIdx, m.subtreeSet)
		}
		m.recordKeyDebug(msg, handled, m.selectedIdx != prev)
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
		isCycleMetricKey(msg),
		isHelpToggleKey(msg):
		return true
	case isZoomInKey(msg, m.keys),
		isZoomUndoKey(msg, m.keys),
		isZoomResetKey(msg, m.keys),
		isMoveShallowerKey(msg, m.keys),
		isMoveDeeperKey(msg, m.keys),
		isPrevSiblingKey(msg, m.keys),
		isNextSiblingKey(msg, m.keys),
		isJumpTopKey(msg, m.keys),
		isJumpRootKey(msg, m.keys):
		return true
	default:
		return false
	}
}

// View renders the flamegraph viewport.
func (m Model) View() tea.View {
	extraLines := 1 // selection status line
	if m.showHelp {
		extraLines++
	}
	renderHeight := m.height - extraLines
	if renderHeight < 3 {
		renderHeight = 3
	}

	content := RenderTerminalView(m.frames, m.width, renderHeight, m.selectedIdx, m.subtreeSet, m.matchIndices, m.filterVisible, m.globalTotal, m.countFieldLabel(), m.isDark, m.searchActive, m.searchQuery)
	content = replaceHeaderLine(content, m.toolbarLine())
	if m.searchActive {
		content = replaceFooterLine(content, m.searchFooter())
	}
	if m.snapshot != nil && len(m.frames) == 0 {
		content = common.PanelStyle.Render(fmt.Sprintf("Flame: snapshot v%d has no visible frames", m.lastVersion))
	}
	content += "\n" + m.selectionStatusLine()
	if m.showHelp {
		content += "\n" + m.helpOverlay()
	}
	return tea.NewView(content)
}

// SetLiveTrie updates the data source used by the flamegraph model.
func (m *Model) SetLiveTrie(liveTrie LiveTrieSource) {
	m.liveTrie = liveTrie
	m.syncFieldPresetToTrie()
	m.syncCountFieldToTrie()
	m.lastVersion = 0
	m.snapshot = nil
	m.globalTotal = 0
	m.selectedIdx = 0
	m.frames = nil
	m.targetFrames = nil
	m.zoomStack = nil
	m.zoomRoot = nil
	m.zoomPath = ""
	m.zoomLineWidth = 0
	m.subtreeSet = make(map[int]bool)
	m.filterVisible = make(map[int]bool)
	m.animation = NewAnimationState(30, 6.0, 1.0)
	m.animating = false
	m.hasNavigableSnapshot = false
}

func (m *Model) syncFieldPresetToTrie() {
	if m.liveTrie == nil {
		m.fieldIndex = 0
		return
	}
	fields := m.liveTrie.Fields()
	if len(fields) == 0 {
		m.fieldIndex = 0
		return
	}
	for idx, preset := range m.fieldPresets {
		if slices.Equal(preset, fields) {
			m.fieldIndex = idx
			return
		}
	}
	custom := slices.Clone(fields)
	m.fieldPresets = append([][]string{custom}, m.fieldPresets...)
	m.fieldIndex = 0
}

func (m *Model) syncCountFieldToTrie() {
	if m.liveTrie == nil {
		m.countField = "count"
		return
	}
	field := strings.TrimSpace(m.liveTrie.CountField())
	if field == "" {
		field = "count"
	}
	m.countField = field
}

// RefreshFromLiveTrie loads a new snapshot when the source version changes.
func (m *Model) RefreshFromLiveTrie() bool {
	if m.liveTrie == nil {
		return false
	}
	// Once a snapshot exists, paused mode must freeze it regardless of current
	// navigability so selection and percentages remain stable.
	if m.paused && m.snapshot != nil {
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
	prevPath := ""
	if len(m.frames) > 0 && m.selectedIdx >= 0 && m.selectedIdx < len(m.frames) {
		prevPath = m.frames[m.selectedIdx].Path
	}

	var root *snapshotNode
	rootPath := ""
	if m.zoomRoot != nil {
		root = m.zoomRoot
		rootPath = m.zoomPath
	} else {
		root = m.snapshot
	}
	targetFrames := buildTerminalLayoutWithPath(root, m.width, m.height, rootPath)
	if m.zoomPath != "" {
		targetFrames = m.withZoomLineage(targetFrames)
	}
	m.targetFrames = targetFrames
	m.animation.SetTargets(m.targetFrames)
	if animate && len(m.frames) > 0 && !m.animation.Settled() {
		m.animating = true
		m.frames = m.animation.CurrentFrames()
	} else {
		m.animating = false
		m.frames = append(m.frames[:0], m.targetFrames...)
	}
	if len(m.frames) > 1 {
		m.hasNavigableSnapshot = true
	}
	m.restoreSelectionByPath(prevPath)
	m.clampSelection()
	m.recomputeFilterState()
	m.ensureSelectionNavigable()
	m.ensureSelectionVisible()
	m.subtreeSet = computeSubtreeSetInto(m.frames, m.selectedIdx, m.subtreeSet)
}

func (m *Model) restoreSelectionByPath(path string) {
	if path == "" || len(m.frames) == 0 {
		return
	}
	if idx := m.frameIndexByPath(path); idx >= 0 {
		m.selectedIdx = idx
		return
	}
	for idx, frame := range m.frames {
		if hasPathBoundaryPrefix(path, frame.Path) || hasPathBoundaryPrefix(frame.Path, path) {
			m.selectedIdx = idx
			return
		}
	}
}

func (m Model) frameIndexByPath(path string) int {
	for idx, frame := range m.frames {
		if frame.Path == path {
			return idx
		}
	}
	return -1
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
	selectedWidth := m.frames[m.selectedIdx].Width
	if selectedWidth < 1 {
		selectedWidth = 1
	}
	m.zoomStack = append(m.zoomStack, zoomState{
		path:                m.zoomPath,
		previousSelectedIdx: m.selectedIdx,
		lineWidth:           m.zoomLineWidth,
	})
	m.zoomRoot = target
	m.zoomPath = selectedPath
	m.zoomLineWidth = selectedWidth
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
		m.zoomLineWidth = 0
	} else {
		m.zoomRoot = findNodeByPath(m.snapshot, m.zoomPath)
		m.zoomLineWidth = last.lineWidth
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
	m.zoomLineWidth = 0
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

func (m *Model) moveVerticalWithFallback(primaryDelta, fallbackDelta, traversalDelta int) {
	before := m.selectedIdx
	m.moveVertical(primaryDelta)
	if m.selectedIdx == before && fallbackDelta != 0 {
		m.moveVertical(fallbackDelta)
	}
	if m.selectedIdx == before && traversalDelta != 0 {
		m.moveTraversal(traversalDelta)
	}
}

func (m *Model) moveSibling(delta int) {
	if len(m.frames) == 0 {
		return
	}
	before := m.selectedIdx
	m.clampSelection()
	m.ensureSelectionNavigable()
	current := m.frames[m.selectedIdx]
	siblings := m.framesAtDepth(current.Depth)
	if len(siblings) <= 1 {
		m.moveTraversal(delta)
		return
	}
	pos := indexOf(siblings, m.selectedIdx)
	if pos < 0 {
		m.moveTraversal(delta)
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
	if m.selectedIdx == before {
		m.moveTraversal(delta)
	}
}

func (m *Model) jumpToTop() {
	if len(m.frames) == 0 {
		return
	}
	m.clampSelection()
	m.ensureSelectionNavigable()

	include := m.navigableFrameSet()
	currentCol := m.frames[m.selectedIdx].Col
	bestIdx := -1
	bestDepth := -1
	bestDist := int(^uint(0) >> 1)

	for idx, frame := range m.frames {
		if include != nil && !include[idx] {
			continue
		}
		dist := abs(frame.Col - currentCol)
		if frame.Depth > bestDepth {
			bestDepth = frame.Depth
			bestIdx = idx
			bestDist = dist
			continue
		}
		if frame.Depth == bestDepth {
			if dist < bestDist || (dist == bestDist && frame.Col < m.frames[bestIdx].Col) {
				bestIdx = idx
				bestDist = dist
			}
		}
	}
	if bestIdx >= 0 {
		m.selectedIdx = bestIdx
	}
}

func (m *Model) jumpToRoot() {
	if len(m.frames) == 0 {
		return
	}
	m.clampSelection()
	m.ensureSelectionNavigable()

	rootPath := m.currentRootPath()
	if rootPath != "" {
		if idx := m.frameIndexByPath(rootPath); idx >= 0 {
			if !m.filterActive() || m.frameNavigable(idx) {
				m.selectedIdx = idx
				return
			}
		}
	}

	include := m.navigableFrameSet()
	currentCol := m.frames[m.selectedIdx].Col
	bestIdx := -1
	bestDepth := int(^uint(0) >> 1)
	bestDist := int(^uint(0) >> 1)
	for idx, frame := range m.frames {
		if include != nil && !include[idx] {
			continue
		}
		dist := abs(frame.Col - currentCol)
		if frame.Depth < bestDepth {
			bestDepth = frame.Depth
			bestDist = dist
			bestIdx = idx
			continue
		}
		if frame.Depth == bestDepth {
			if dist < bestDist || (dist == bestDist && frame.Col < m.frames[bestIdx].Col) {
				bestDist = dist
				bestIdx = idx
			}
		}
	}
	if bestIdx >= 0 {
		m.selectedIdx = bestIdx
	}
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

func (m *Model) recordKeyDebug(msg tea.KeyPressMsg, handled, moved bool) {
	keyID := keyString(msg)
	if keyID == "" {
		keyID = fmt.Sprintf("code:%d", msg.Code)
	}
	sel := "-"
	selIdx := m.selectedIdx
	if len(m.frames) > 0 && m.selectedIdx >= 0 && m.selectedIdx < len(m.frames) {
		sel = compactFramePath(m.frames[m.selectedIdx].Path)
	}
	m.lastKeyDebug = fmt.Sprintf("dbg frames=%d idx=%d key=%q code=%d handled=%t moved=%t sel=%s", len(m.frames), selIdx, keyID, msg.Code, handled, moved, sel)
}

func (m *Model) moveTraversal(delta int) {
	if len(m.frames) == 0 || delta == 0 {
		return
	}
	order := m.visibleTraversalOrder()
	if len(order) == 0 {
		return
	}
	pos := indexOf(order, m.selectedIdx)
	if pos < 0 {
		pos = 0
	}
	next := pos + delta
	if next < 0 {
		next = 0
	}
	if next >= len(order) {
		next = len(order) - 1
	}
	m.selectedIdx = order[next]
}

func (m Model) visibleTraversalOrder() []int {
	indices := make([]int, 0, len(m.frames))
	include := m.navigableFrameSet()
	for idx := range m.frames {
		if include != nil && !include[idx] {
			continue
		}
		indices = append(indices, idx)
	}
	sort.Slice(indices, func(i, j int) bool {
		left := m.frames[indices[i]]
		right := m.frames[indices[j]]
		if left.Depth != right.Depth {
			return left.Depth < right.Depth
		}
		if left.Col != right.Col {
			return left.Col < right.Col
		}
		if left.Row != right.Row {
			return left.Row < right.Row
		}
		return indices[i] < indices[j]
	})
	return indices
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
func isPauseKey(msg tea.KeyPressMsg) bool {
	k := keyString(msg)
	return k == "p" || k == " " || k == "space" || msg.Code == tea.KeySpace
}
func isResetBaselineKey(msg tea.KeyPressMsg) bool {
	return keyString(msg) == "r"
}
func isCycleOrderKey(msg tea.KeyPressMsg) bool { return keyString(msg) == "o" }
func isCycleMetricKey(msg tea.KeyPressMsg) bool {
	return keyString(msg) == "b"
}
func isHelpToggleKey(msg tea.KeyPressMsg) bool { return keyString(msg) == "?" }

func isZoomInKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	return key.Matches(msg, keys.ZoomIn) || msg.Code == tea.KeyEnter || strings.EqualFold(keyString(msg), "enter")
}

func isZoomUndoKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	return key.Matches(msg, keys.ZoomUndo) || msg.Code == tea.KeyBackspace || msg.Code == tea.KeyEsc
}

func isZoomResetKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	return key.Matches(msg, keys.ZoomReset)
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

func isJumpTopKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	k := strings.ToLower(keyString(msg))
	return key.Matches(msg, keys.JumpTop) || msg.Code == tea.KeyPgUp || k == "pgup" || k == "pageup"
}

func isJumpRootKey(msg tea.KeyPressMsg, keys flameKeyMap) bool {
	k := strings.ToLower(keyString(msg))
	return key.Matches(msg, keys.JumpRoot) || msg.Code == tea.KeyPgDown || k == "pgdown" || k == "pgdn" || k == "pagedown"
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

func (m *Model) handleMouseClick(msg tea.MouseClickMsg) bool {
	if msg.Button != tea.MouseLeft {
		return false
	}
	idx := m.frameIndexAt(msg.X, msg.Y)
	if idx < 0 {
		return false
	}
	clickedPath := m.frames[idx].Path
	currentRoot := m.currentRootPath()
	if m.zoomPath != "" && (clickedPath == currentRoot || hasPathBoundaryPrefix(currentRoot, clickedPath)) {
		for steps := 0; steps < len(m.zoomStack)+1 && m.currentRootPath() != clickedPath; steps++ {
			m.zoomUndo()
		}
		if sel := m.frameIndexByPath(clickedPath); sel >= 0 {
			m.selectedIdx = sel
		}
		m.subtreeSet = computeSubtreeSetInto(m.frames, m.selectedIdx, m.subtreeSet)
		return true
	}
	m.selectedIdx = idx
	m.subtreeSet = computeSubtreeSetInto(m.frames, m.selectedIdx, m.subtreeSet)
	m.zoomIn()
	return true
}

func (m Model) frameIndexAt(x, y int) int {
	if len(m.frames) == 0 || m.width <= 0 || m.height <= 0 {
		return -1
	}
	if x < 0 || x >= m.width || y < 0 {
		return -1
	}

	extraLines := 1 // selection status line
	if m.showHelp {
		extraLines++
	}
	renderHeight := m.height - extraLines
	if renderHeight < 3 {
		renderHeight = 3
	}
	availableRows := renderHeight - 2 // flame toolbar + frame-status line
	if availableRows < 1 {
		return -1
	}

	// Row 0 is flame toolbar, rows 1..availableRows are bars, last row is status.
	if y < 1 || y > availableRows {
		return -1
	}
	dataRow := y - 1

	maxRow := maxFrameRowForSet(m.frames, nil)
	barHeight := computeBarHeight(availableRows, maxRow+1, maxBarVisualHeight)
	visibleDepthRows := availableRows / barHeight
	if visibleDepthRows < 1 {
		visibleDepthRows = 1
	}
	rowOffset := 0
	if maxRow+1 > visibleDepthRows {
		rowOffset = maxRow + 1 - visibleDepthRows
	}
	renderedRows := (maxRow - rowOffset + 1) * barHeight
	padTop := 0
	if renderedRows < availableRows {
		padTop = availableRows - renderedRows
	}
	if dataRow < padTop {
		return -1
	}

	depthFromTop := (dataRow - padTop) / barHeight
	targetRow := maxRow - depthFromTop

	best := -1
	bestWidth := int(^uint(0) >> 1)
	for idx, frame := range m.frames {
		if frame.Row != targetRow || frame.Col >= m.width {
			continue
		}
		right := min(m.width, frame.Col+frame.Width)
		if x < frame.Col || x >= right {
			continue
		}
		if frame.Width < bestWidth {
			best = idx
			bestWidth = frame.Width
		}
	}
	return best
}

func (m Model) withZoomLineage(frames []tuiFrame) []tuiFrame {
	if len(frames) == 0 || m.snapshot == nil {
		return frames
	}
	parts := strings.Split(m.zoomPath, pathSeparator)
	if len(parts) <= 1 {
		return frames
	}

	lineWidth := m.zoomLineWidth
	if lineWidth <= 0 {
		lineWidth = frames[0].Width
	}
	lineWidth = min(max(lineWidth, 3), max(3, m.width/3))
	if lineWidth >= m.width-2 {
		return frames
	}
	gutter := lineWidth + 1
	if m.width-gutter < minFlameWidth/2 {
		return frames
	}

	rowShift := len(parts) - 1
	out := make([]tuiFrame, 0, len(frames)+len(parts))
	for _, frame := range frames {
		if frame.Path == m.zoomPath {
			continue
		}
		frame.Col += gutter
		frame.Row += rowShift
		frame.Depth += rowShift
		out = append(out, frame)
	}

	rootTotal := snapshotTotal(m.snapshot)
	for depth := range parts {
		path := strings.Join(parts[:depth+1], pathSeparator)
		node := findNodeByPath(m.snapshot, path)
		total := uint64(0)
		if node != nil {
			total = snapshotTotal(node)
		}
		percent := 0.0
		if rootTotal > 0 {
			percent = 100 * float64(total) / float64(rootTotal)
		}
		name := parts[depth]
		out = append(out, tuiFrame{
			Name:    name,
			Col:     0,
			Row:     depth,
			Width:   lineWidth,
			Total:   total,
			Percent: percent,
			Fill:    terminalFrameColor(name),
			Depth:   depth,
			Path:    path,
		})
	}
	return out
}
