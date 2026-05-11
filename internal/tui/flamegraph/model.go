package flamegraph

import (
	"cmp"
	"fmt"
	"image/color"
	"slices"
	"strings"
	"time"

	coreflamegraph "ior/internal/flamegraph"
	common "ior/internal/tui/common"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

// snapshotNode aliases the live trie's snapshot type so the TUI can consume
// trees directly via SnapshotTree() without paying for a JSON marshal+unmarshal
// round-trip. The JSON tags on SnapshotNode keep the legacy SnapshotJSON path
// working unchanged.
type snapshotNode = coreflamegraph.SnapshotNode

type animTickMsg struct{}

// flameViewCacheKey captures the View() inputs that determine the rendered
// output. When two consecutive calls produce the same key, the cached content
// string is reused instead of re-running RenderTerminalView.
type flameViewCacheKey struct {
	version       uint64
	selectedIdx   int
	width         int
	height        int
	framesLen     int
	matchCount    int
	visibleCount  int
	searchQuery   string
	statusMessage string
	zoomPath      string
	searchActive  bool
	showHelp      bool
	paused        bool
	isDark        bool
}

type flameViewCache struct {
	key     flameViewCacheKey
	content string
	valid   bool
}

// flameSnapshotReadyMsg carries the result of a background snapshot+layout
// job. It is emitted by RefreshFromLiveTrieCmd and consumed by Update so the
// Bubble Tea goroutine can swap in the new state without blocking on JSON or
// frame layout work.
type flameSnapshotReadyMsg struct {
	version      uint64
	layoutWidth  int
	layoutHeight int
	zoomPath     string
	snapshot     *snapshotNode
	zoomRoot     *snapshotNode
	targetFrames []tuiFrame
	ancestry     frameAncestry
	globalTotal  uint64
}

const animFrameDuration = 33 * time.Millisecond
const flameKeyDebugEnabled = false

// driveWindow defines how recently a key must have been pressed to count as
// "user is actively driving". While inside this window, the flamegraph defers
// snapshot refresh and skips animation so keystrokes land without waiting on
// JSON+layout work or a 1-second animation chain.
const driveWindow = 250 * time.Millisecond

// LiveTrieSource is the minimal trie contract needed by the flamegraph TUI model.
// SnapshotJSON is retained for tests and external callers; SnapshotTree is the
// fast path used by the model's background refresh.
type LiveTrieSource interface {
	Fields() []string
	CountField() string
	Reconfigure([]string) error
	SetCountField(string) error
	Reset()
	Version() uint64
	SnapshotJSON() ([]byte, uint64)
	SnapshotTree() (*snapshotNode, uint64)
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

	// refreshInFlight is true while a background snapshot+layout job is
	// running. It coalesces flameTickMsg dispatches so we never queue more
	// than one snapshot rebuild concurrently.
	refreshInFlight bool

	frames       []tuiFrame
	targetFrames []tuiFrame
	ancestry     frameAncestry
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

	// lastKeyAt records when the user most recently pressed a key. While the
	// user is actively driving the view (lastKeyAt within driveWindow ago),
	// the background snapshot refresh is suppressed and snapshot-ready
	// messages snap directly to target frames without animating. This keeps
	// keystrokes feeling instant under heavy event load.
	lastKeyAt time.Time

	// viewCache memoizes the last rendered string keyed on the inputs that
	// produce it. Bubble Tea may call View() multiple times per state change;
	// caching avoids re-running RenderTerminalView when nothing visible has
	// moved. Lives behind a pointer so the value-receiver View() can update it.
	viewCache *flameViewCache
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
		viewCache:     &flameViewCache{},
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
		m.subtreeSet = subtreeSetUsingAncestry(m.frames, m.selectedIdx, m.ancestry, m.subtreeSet)
		return m, m.animationTickCmd()
	case flameSnapshotReadyMsg:
		return m.handleSnapshotReady(msg)
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.rebuildFrames(true)
		return m, m.animationTickCmd()
	case tea.MouseClickMsg:
		_ = m.handleMouseClick(msg)
		return m, nil
	case tea.KeyPressMsg:
		// Stamp every keypress so RefreshFromLiveTrieCmd and the
		// snapshot-ready handler can detect that the user is actively driving
		// the view and defer / unanimate accordingly.
		m.lastKeyAt = time.Now()
		if m.searchActive {
			return m.handleSearchInput(msg)
		}
		return m.handleKeyNavigation(msg)
	}
	return m, nil
}

// handleSearchInput processes key events while search mode is active.
// Handles escape (cancel search), enter (apply query), and delegates
// all other keys to the text input component for in-place editing.
func (m Model) handleSearchInput(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
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

// handleKeyNavigation processes navigation key events when search is not active.
// Delegates mode-toggle and zoom actions to handleModeKey, movement actions to
// handleMovementKey, then updates the subtree highlight when selection changes.
func (m Model) handleKeyNavigation(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	prev := m.selectedIdx
	handled := m.handleModeKey(msg)
	if !handled {
		handled = m.handleMovementKey(msg)
	}
	if m.selectedIdx != prev {
		m.subtreeSet = subtreeSetUsingAncestry(m.frames, m.selectedIdx, m.ancestry, m.subtreeSet)
	}
	m.recordKeyDebug(msg, handled, m.selectedIdx != prev)
	return m, nil
}

// handleModeKey dispatches search, pause, zoom, and view-toggle key actions.
// Returns true when a key was handled so handleKeyNavigation can skip movement.
func (m *Model) handleModeKey(msg tea.KeyPressMsg) bool {
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
	case isCycleMetricKey(msg):
		m.toggleCountField()
	case isHelpToggleKey(msg):
		m.toggleHelp()
	case isZoomInKey(msg, m.keys):
		m.zoomIn()
	case isZoomUndoKey(msg, m.keys):
		m.zoomUndo()
	case isZoomResetKey(msg, m.keys):
		m.zoomReset()
	default:
		return false
	}
	return true
}

// handleMovementKey dispatches directional and jump key actions.
// Returns true when a key was handled, false otherwise.
func (m *Model) handleMovementKey(msg tea.KeyPressMsg) bool {
	switch {
	case isMoveShallowerKey(msg, m.keys):
		m.moveVerticalWithFallback(-1, 1, -1)
	case isMoveDeeperKey(msg, m.keys):
		m.moveVerticalWithFallback(1, -1, 1)
	case isPrevSiblingKey(msg, m.keys):
		m.moveSibling(-1)
	case isNextSiblingKey(msg, m.keys):
		m.moveSibling(1)
	case isJumpTopKey(msg, m.keys):
		m.jumpToTop()
	case isJumpRootKey(msg, m.keys):
		m.jumpToRoot()
	default:
		return false
	}
	return true
}

// handleSnapshotReady applies the result of a background snapshot+layout job.
// Discards the result if viewport or zoom changed while the job was in flight
// (the next tick will dispatch a fresh refresh), or if the user paused after a
// snapshot already exists. Always clears refreshInFlight so subsequent ticks
// can dispatch the next refresh.
func (m Model) handleSnapshotReady(msg flameSnapshotReadyMsg) (tea.Model, tea.Cmd) {
	m.refreshInFlight = false
	if msg.snapshot == nil {
		return m, nil
	}
	if msg.layoutWidth != m.width || msg.layoutHeight != m.height || msg.zoomPath != m.zoomPath {
		return m, nil
	}
	if m.paused && m.snapshot != nil {
		return m, nil
	}

	prevPath := ""
	if len(m.frames) > 0 && m.selectedIdx >= 0 && m.selectedIdx < len(m.frames) {
		prevPath = m.frames[m.selectedIdx].Path
	}

	m.snapshot = msg.snapshot
	m.globalTotal = msg.globalTotal
	m.zoomRoot = msg.zoomRoot
	m.lastVersion = msg.version
	// Snap directly to target frames while the user is actively pressing keys
	// — animation would just add latency on top of the work the user wants to
	// see. Animation resumes on the next refresh after the drive window
	// expires.
	animate := !m.userDriving()
	m.applyTargetFrames(msg.targetFrames, msg.ancestry, prevPath, animate)
	if !m.animating {
		return m, nil
	}
	return m, m.animationTickCmd()
}

// userDriving reports whether the user has pressed a key within the recent
// drive window. Used to skip snapshot refresh and animation while keystrokes
// are arriving.
func (m Model) userDriving() bool {
	if m.lastKeyAt.IsZero() {
		return false
	}
	return time.Since(m.lastKeyAt) < driveWindow
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

// View renders the flamegraph viewport. Caches the rendered string keyed on
// the inputs that affect output; skips the cache while animating (frames
// change every 33 ms anyway, so cache hits are impossible).
func (m Model) View() tea.View {
	if !m.animating && m.viewCache != nil {
		key := m.currentViewCacheKey()
		if m.viewCache.valid && m.viewCache.key == key {
			return tea.NewView(m.viewCache.content)
		}
		content := m.renderViewContent()
		m.viewCache.key = key
		m.viewCache.content = content
		m.viewCache.valid = true
		return tea.NewView(content)
	}
	return tea.NewView(m.renderViewContent())
}

// renderViewContent assembles the flamegraph string. Pure function over Model
// state — pulled out so View() can decide whether to memoize the result.
func (m Model) renderViewContent() string {
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
	return content
}

// currentViewCacheKey snapshots every Model field that influences View()
// output. If any of these differ between successive View() invocations, the
// cache misses and the content is rebuilt.
func (m Model) currentViewCacheKey() flameViewCacheKey {
	return flameViewCacheKey{
		version:       m.lastVersion,
		selectedIdx:   m.selectedIdx,
		width:         m.width,
		height:        m.height,
		framesLen:     len(m.frames),
		matchCount:    len(m.matchIndices),
		visibleCount:  len(m.filterVisible),
		searchQuery:   m.searchQuery,
		statusMessage: m.statusMessage,
		zoomPath:      m.zoomPath,
		searchActive:  m.searchActive,
		showHelp:      m.showHelp,
		paused:        m.paused,
		isDark:        m.isDark,
	}
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
	m.ancestry = frameAncestry{}
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

// RefreshFromLiveTrie loads a new snapshot synchronously and returns true when
// a new snapshot was applied. Retained as a simple facade for tests; the
// production TUI now uses RefreshFromLiveTrieCmd to do the heavy lifting on a
// background goroutine.
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

	tree, version := m.liveTrie.SnapshotTree()
	if tree == nil {
		return false
	}
	m.snapshot = tree
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

// RefreshFromLiveTrieCmd returns a tea.Cmd that fetches a snapshot, lays out
// frames, and builds the ancestry index on a background goroutine, then
// dispatches a flameSnapshotReadyMsg back to the Bubble Tea Update loop.
//
// Returns nil if no refresh is needed: no live trie configured, paused with an
// existing snapshot, version unchanged, another refresh already in flight, or
// the user is actively pressing keys. Skipping while driving keeps keystrokes
// responsive — the next idle tick picks up the latest version.
//
// Coalescing via refreshInFlight ensures we never queue more than one
// background job at a time. Newer ticks just no-op until the in-flight result
// lands, and the version gate then catches the freshest state.
func (m *Model) RefreshFromLiveTrieCmd() tea.Cmd {
	if m.liveTrie == nil {
		return nil
	}
	if m.paused && m.snapshot != nil {
		return nil
	}
	if m.refreshInFlight {
		return nil
	}
	if m.userDriving() && m.snapshot != nil {
		return nil
	}
	version := m.liveTrie.Version()
	if version == m.lastVersion && m.snapshot != nil {
		return nil
	}
	m.refreshInFlight = true

	// Capture fields the goroutine needs. Avoids reading Model fields
	// concurrently with the Update goroutine.
	liveTrie := m.liveTrie
	width := m.width
	height := m.height
	zoomPath := m.zoomPath
	return func() tea.Msg {
		tree, ver := liveTrie.SnapshotTree()
		if tree == nil {
			return flameSnapshotReadyMsg{version: ver, layoutWidth: width, layoutHeight: height, zoomPath: zoomPath}
		}
		var zoomRoot *snapshotNode
		layoutRoot := tree
		rootPath := ""
		if zoomPath != "" {
			zoomRoot = findNodeByPath(tree, zoomPath)
			if zoomRoot != nil {
				layoutRoot = zoomRoot
				rootPath = zoomPath
			}
		}
		targetFrames := buildTerminalLayoutWithPath(layoutRoot, width, height, rootPath)
		if zoomPath != "" {
			targetFrames = applyZoomLineage(targetFrames, tree, zoomPath, width)
		}
		ancestry := buildFrameAncestry(targetFrames)
		return flameSnapshotReadyMsg{
			version:      ver,
			layoutWidth:  width,
			layoutHeight: height,
			zoomPath:     zoomPath,
			snapshot:     tree,
			zoomRoot:     zoomRoot,
			targetFrames: targetFrames,
			ancestry:     ancestry,
			globalTotal:  snapshotTotal(tree),
		}
	}
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
	return m.animationTickCmd()
}

// Paused reports whether live refresh is paused.
func (m Model) Paused() bool {
	return m.paused
}

// SetViewport updates model render dimensions.
func (m *Model) SetViewport(width, height int) {
	if m.width == width && m.height == height {
		return
	}
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
	ancestry := buildFrameAncestry(targetFrames)
	m.applyTargetFrames(targetFrames, ancestry, prevPath, animate)
}

// applyTargetFrames installs a prebuilt frame layout and ancestry index,
// optionally animating from the previous frames. Shared between the
// synchronous rebuildFrames path and the async snapshot-ready handler so
// post-swap state stays consistent (animation kickoff, selection restore,
// filter recompute, subtree highlight).
func (m *Model) applyTargetFrames(targetFrames []tuiFrame, ancestry frameAncestry, prevPath string, animate bool) {
	m.targetFrames = targetFrames
	m.ancestry = ancestry
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
	m.subtreeSet = subtreeSetUsingAncestry(m.frames, m.selectedIdx, m.ancestry, m.subtreeSet)
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
	prevRootPath := m.zoomPath
	if !m.setZoomPath(selectedPath) {
		m.statusMessage = "Zoom failed: selected node is unavailable"
		return
	}
	m.zoomStack = append(m.zoomStack, zoomState{path: prevRootPath})
	m.statusMessage = "Zoom: " + compactFramePath(selectedPath)
}

func (m *Model) zoomUndo() {
	if len(m.zoomStack) == 0 || m.snapshot == nil {
		m.statusMessage = "Zoom undo unavailable"
		return
	}
	lastIdx := len(m.zoomStack) - 1
	last := m.zoomStack[lastIdx]
	m.zoomStack = m.zoomStack[:lastIdx]
	if !m.setZoomPath(last.path) {
		m.statusMessage = "Zoom undo unavailable"
		return
	}
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
	slices.SortFunc(indices, func(a, b int) int {
		return cmp.Compare(frames[a].Col, frames[b].Col)
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

func (m Model) animationTickCmd() tea.Cmd {
	if !m.animating {
		return nil
	}
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
	if !flameKeyDebugEnabled {
		return
	}
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
	slices.SortFunc(indices, func(a, b int) int {
		left := m.frames[a]
		right := m.frames[b]
		if left.Depth != right.Depth {
			return cmp.Compare(left.Depth, right.Depth)
		}
		if left.Col != right.Col {
			return cmp.Compare(left.Col, right.Col)
		}
		if left.Row != right.Row {
			return cmp.Compare(left.Row, right.Row)
		}
		return cmp.Compare(a, b)
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
	return k == " " || k == "space" || msg.Code == tea.KeySpace
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
	body, ok := strings.CutPrefix(value, "\x1b")
	if !ok || len(body) < 2 {
		return false
	}
	switch body[0] {
	case '[':
		return body[len(body)-1] == ansiFinal
	case 'O':
		return len(body) == 2 && body[1] == ansiFinal
	default:
		return false
	}
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
	if clickedPath == currentRoot {
		m.selectedIdx = idx
		m.subtreeSet = subtreeSetUsingAncestry(m.frames, m.selectedIdx, m.ancestry, m.subtreeSet)
		return true
	}
	if m.zoomPath != "" && hasPathBoundaryPrefix(currentRoot, clickedPath) {
		if !m.setZoomPath(clickedPath) {
			return false
		}
		m.zoomStack = buildZoomStack(clickedPath)
	} else {
		prevRootPath := m.zoomPath
		if !m.setZoomPath(clickedPath) {
			return false
		}
		m.zoomStack = append(m.zoomStack, zoomState{path: prevRootPath})
	}
	if sel := m.frameIndexByPath(clickedPath); sel >= 0 {
		m.selectedIdx = sel
	}
	m.subtreeSet = subtreeSetUsingAncestry(m.frames, m.selectedIdx, m.ancestry, m.subtreeSet)
	m.statusMessage = "Zoom: " + compactFramePath(clickedPath)
	return true
}

func (m *Model) setZoomPath(path string) bool {
	if m.snapshot == nil {
		return false
	}
	rootPath := m.rootSnapshotPath()
	if path == "" || path == rootPath {
		m.zoomRoot = nil
		m.zoomPath = ""
		m.zoomLineWidth = 0
		m.rebuildFrames(false)
		return true
	}
	target := findNodeByPath(m.snapshot, path)
	if target == nil {
		return false
	}
	m.zoomRoot = target
	m.zoomPath = path
	m.zoomLineWidth = 0
	m.rebuildFrames(false)
	return true
}

func (m Model) rootSnapshotPath() string {
	if m.snapshot != nil {
		return frameName(m.snapshot.Name, 0)
	}
	if len(m.frames) > 0 {
		return m.frames[0].Path
	}
	return ""
}

func buildZoomStack(path string) []zoomState {
	parts := strings.Split(path, pathSeparator)
	if len(parts) <= 1 {
		return nil
	}
	stack := []zoomState{{path: ""}}
	for idx := 1; idx < len(parts)-1; idx++ {
		stack = append(stack, zoomState{path: strings.Join(parts[:idx+1], pathSeparator)})
	}
	return stack
}

// frameIndexAt returns the index of the frame rendered at terminal coordinates
// (x, y), or -1 if no frame occupies that cell. Delegates boundary validation
// to frameCoordToTargetRow and frame scanning to findFrameAtRow.
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

	targetRow := m.frameCoordToTargetRow(y-1, availableRows)
	if targetRow < 0 {
		return -1
	}
	return findFrameAtRow(m.frames, targetRow, x, m.width)
}

// frameCoordToTargetRow converts a data-area row offset (0-based, after
// stripping the toolbar row) into the logical frame row index. Returns -1 when
// the coordinate falls in the top padding area above the first visible row.
func (m Model) frameCoordToTargetRow(dataRow, availableRows int) int {
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
	return maxRow - depthFromTop
}

// findFrameAtRow scans frames for the narrowest one that occupies logical row
// targetRow and contains pixel column x within [0, width). Returning the
// narrowest frame resolves overlap between wide parent and narrow child bars.
func findFrameAtRow(frames []tuiFrame, targetRow, x, width int) int {
	best := -1
	bestWidth := int(^uint(0) >> 1)
	for idx, frame := range frames {
		if frame.Row != targetRow || frame.Col >= width {
			continue
		}
		right := min(width, frame.Col+frame.Width)
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
	return applyZoomLineage(frames, m.snapshot, m.zoomPath, m.width)
}

// applyZoomLineage prepends the zoom path's ancestors to a zoomed frame
// layout. Extracted as a free function so the async snapshot refresh can
// reuse it on a background goroutine without referencing Model state directly.
func applyZoomLineage(frames []tuiFrame, snapshot *snapshotNode, zoomPath string, width int) []tuiFrame {
	if len(frames) == 0 || snapshot == nil {
		return frames
	}
	parts := strings.Split(zoomPath, pathSeparator)
	if len(parts) <= 1 {
		return frames
	}

	rowShift := len(parts) - 1
	out := make([]tuiFrame, 0, len(frames)+len(parts))
	for _, frame := range frames {
		if frame.Path == zoomPath {
			continue
		}
		frame.Row += rowShift
		frame.Depth += rowShift
		out = append(out, frame)
	}

	rootTotal := snapshotTotal(snapshot)
	for depth := range parts {
		path := strings.Join(parts[:depth+1], pathSeparator)
		node := findNodeByPath(snapshot, path)
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
			Width:   width,
			Total:   total,
			Percent: percent,
			Fill:    terminalFrameColor(name),
			Depth:   depth,
			Path:    path,
		})
	}
	return out
}
