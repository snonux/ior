package flamegraph

import (
	"fmt"
	"image/color"
	"slices"
	"strings"
	"time"

	coreflamegraph "ior/internal/flamegraph"
	common "ior/internal/tui/common"

	"charm.land/bubbles/v2/key"
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

// Snapshotter is the read-only subset of the trie contract: version polling and
// snapshot retrieval. buildSnapshotMsg and background refresh goroutines use
// only this narrower interface so they cannot accidentally mutate trie state.
type Snapshotter interface {
	// Version returns the monotonically-increasing snapshot generation counter.
	// Callers use it to avoid re-rendering an unchanged trie.
	Version() uint64
	// SnapshotJSON serialises the current trie to JSON for external consumers
	// (retained for tests and CLI callers; not used by the TUI render path).
	SnapshotJSON() ([]byte, uint64)
	// SnapshotTree returns a ready-to-render snapshot tree without a
	// JSON round-trip. It is the fast path used by the background refresh.
	SnapshotTree() (*snapshotNode, uint64)
}

// Configurator is the write/mutating subset of the trie contract: field layout,
// metric selection, and baseline reset. The flamegraph controls (cycleFieldOrder,
// toggleCountField, resetBaseline) call only these methods.
type Configurator interface {
	// Fields returns the current ordered list of grouping fields (e.g. ["comm","path"]).
	Fields() []string
	// HeightField returns the active frame-height metric (e.g. "bytes", "duration").
	HeightField() string
	// CountField returns the active aggregation metric name (e.g. "count", "bytes").
	CountField() string
	// Reconfigure replaces the grouping fields and resets accumulated data so a
	// new baseline begins with the new field order.
	Reconfigure([]string) error
	// SetHeightField changes the frame-height metric and starts a fresh baseline.
	SetHeightField(string) error
	// SetCountField changes the active aggregation metric and starts a fresh baseline.
	SetCountField(string) error
	// Reset clears all accumulated data so the next ingested event starts a new baseline.
	Reset()
}

// LiveTrieSource is the full trie contract needed by the flamegraph TUI model.
// It embeds Snapshotter (read-only snapshot access) and Configurator (mutating
// operations) so each can be used independently where a narrower interface suffices.
type LiveTrieSource interface {
	Snapshotter
	Configurator
}

// --- compile-time interface satisfaction assertions ---
//
// *coreflamegraph.LiveTrie is the sole production implementation of all three
// trie interfaces. The assertions are placed here rather than in the
// flamegraph package itself to avoid an import cycle: runtime imports
// flamegraph, so flamegraph cannot import runtime. The tui/flamegraph package
// already imports coreflamegraph, making it the natural home.
var (
	_ Snapshotter    = (*coreflamegraph.LiveTrie)(nil)
	_ Configurator   = (*coreflamegraph.LiveTrie)(nil)
	_ LiveTrieSource = (*coreflamegraph.LiveTrie)(nil)
)

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
// It delegates zoom, selection, animation, and search concerns to four focused
// sub-controllers: ZoomNavigator, SelectionManager, FrameAnimator, and
// SearchController. The sub-controllers are embedded so existing field names
// (e.g. m.selectedIdx, m.zoomPath) remain accessible directly.
type Model struct {
	// Sub-controllers — each owns a single concern.
	ZoomNavigator    // zoom path, stack, and root node management
	SelectionManager // selected frame index and subtree highlight
	FrameAnimator    // animated frame transitions and ancestry index
	SearchController // search query, match indices, filter-visible set

	liveTrie    LiveTrieSource
	lastVersion uint64
	snapshot    *snapshotNode
	globalTotal uint64

	// refreshInFlight is true while a background snapshot+layout job is
	// running. It coalesces flameTickMsg dispatches so we never queue more
	// than one snapshot rebuild concurrently.
	refreshInFlight bool

	width  int
	height int

	showHelp      bool
	statusMessage string
	lastKeyDebug  string

	fieldPresets [][]string
	fieldIndex   int
	countField   string
	heightField  string

	paused bool

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
// The four embedded sub-controllers (ZoomNavigator, SelectionManager,
// FrameAnimator, SearchController) are initialised here; the Model delegates
// their respective concerns to them.
func NewModel(liveTrie LiveTrieSource) Model {
	m := Model{
		ZoomNavigator:    ZoomNavigator{},
		SelectionManager: newSelectionManager(),
		FrameAnimator:    newFrameAnimator(),
		SearchController: newSearchController(true),
		liveTrie:         liveTrie,
		viewCache:        &flameViewCache{},
		fieldPresets: [][]string{
			{"comm", "tracepoint", "path"},
			{"path", "tracepoint", "comm"},
			{"tracepoint", "comm", "path"},
			{"pid", "tracepoint", "path"},
			{"comm", "path", "tracepoint"},
			{"tracepoint", "comm", "pid"},
		},
		isDark:      true,
		keys:        defaultFlameKeyMap(),
		countField:  "count",
		heightField: "",
	}
	m.syncFieldPresetToTrie()
	m.syncCountFieldToTrie()
	m.syncHeightFieldToTrie()
	return m
}

// Init starts the flamegraph model.
func (m Model) Init() tea.Cmd {
	return nil
}

// Update handles incoming messages. Delegates animation ticks to FrameAnimator,
// snapshot arrivals to handleSnapshotReady, and key/mouse events to the
// appropriate handler.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case animTickMsg:
		if !m.animating {
			return m, nil
		}
		// Delegate animation tick to FrameAnimator; it advances springs,
		// refreshes the frame slice, and updates the subtree highlight.
		m.FrameAnimator.tickAnimation(&m.SelectionManager, &m.SearchController)
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
// Delegates key dispatch (esc/enter/text) to SearchController, then updates
// match state and status message on the Model.
func (m Model) handleSearchInput(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	_, committed, query, cancelled := m.SearchController.handleInput(msg)
	switch {
	case cancelled:
		// ESC: clear search state and close search mode.
		m.statusMessage = m.SearchController.clear()
		m.recordKeyDebug(msg, true, false)
	case committed:
		// Enter: apply query, close search mode, jump to first match.
		m.SearchController.searchActive = false
		statusMsg, jumpDir := m.SearchController.applyQuery(query, m.frames, m.ancestry)
		m.statusMessage = statusMsg
		if jumpDir != 0 {
			m.selectedIdx, m.subtreeSet = jumpMatch(m.frames, m.matchIndices, m.ancestry, m.selectedIdx, jumpDir)
		} else {
			m.SelectionManager.ensureNavigable(m.frames, m.matchIndices, m.searchQuery, m.filterVisible)
		}
		m.recordKeyDebug(msg, true, false)
	default:
		m.recordKeyDebug(msg, true, false)
	}
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
		// Delegate match jump to package-level helper; update selection and subtree.
		m.selectedIdx, m.subtreeSet = jumpMatch(m.frames, m.matchIndices, m.ancestry, m.selectedIdx, 1)
	case isPrevMatchKey(msg):
		m.selectedIdx, m.subtreeSet = jumpMatch(m.frames, m.matchIndices, m.ancestry, m.selectedIdx, -1)
	case isPauseKey(msg):
		m.togglePause()
	case isResetBaselineKey(msg):
		m.resetBaseline()
	case isCycleOrderKey(msg):
		m.cycleFieldOrder()
	case isCycleMetricKey(msg):
		m.toggleCountField()
	case isToggleHeightKey(msg):
		m.toggleHeightField()
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

// handleMovementKey dispatches directional and jump key actions to
// SelectionManager. Returns true when a key was handled, false otherwise.
func (m *Model) handleMovementKey(msg tea.KeyPressMsg) bool {
	sel := &m.SelectionManager
	frames := m.frames
	sq := m.searchQuery
	fv := m.filterVisible
	switch {
	case isMoveShallowerKey(msg, m.keys):
		sel.moveVerticalWithFallback(frames, sq, fv, -1, 1, -1)
	case isMoveDeeperKey(msg, m.keys):
		sel.moveVerticalWithFallback(frames, sq, fv, 1, -1, 1)
	case isPrevSiblingKey(msg, m.keys):
		sel.moveSibling(frames, -1, sq, fv)
	case isNextSiblingKey(msg, m.keys):
		sel.moveSibling(frames, 1, sq, fv)
	case isJumpTopKey(msg, m.keys):
		sel.jumpToTop(frames, sq, fv)
	case isJumpRootKey(msg, m.keys):
		sel.jumpToRoot(frames, m.currentRootPath(), sq, fv)
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

// userDriving delegates to the FrameAnimator helper that checks whether the user
// pressed a key within the drive window.
func (m Model) userDriving() bool {
	return driveWindowActive(m.lastKeyAt)
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
		isToggleHeightKey(msg),
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
	// Assemble the final output using a Builder to avoid repeated string copies
	// for the optional help-overlay suffix.
	var b strings.Builder
	b.WriteString(content)
	b.WriteString("\n")
	b.WriteString(m.selectionStatusLine())
	if m.showHelp {
		b.WriteString("\n")
		b.WriteString(m.helpOverlay())
	}
	return b.String()
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

// SetLiveTrie updates the data source. Resets all sub-controllers and clears
// snapshot state so the new trie starts fresh.
func (m *Model) SetLiveTrie(liveTrie LiveTrieSource) {
	m.liveTrie = liveTrie
	m.syncFieldPresetToTrie()
	m.syncCountFieldToTrie()
	m.syncHeightFieldToTrie()
	m.lastVersion = 0
	m.snapshot = nil
	m.globalTotal = 0
	m.ZoomNavigator = ZoomNavigator{}
	m.SelectionManager = newSelectionManager()
	m.FrameAnimator.reset()
	m.SearchController.reset(false)
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

func (m *Model) syncHeightFieldToTrie() {
	if m.liveTrie == nil {
		m.heightField = ""
		return
	}
	field := strings.TrimSpace(m.liveTrie.HeightField())
	switch field {
	case "", "count", "bytes", "duration":
		m.heightField = field
	default:
		m.heightField = ""
	}
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

// buildSnapshotMsg performs the CPU-heavy snapshot+layout work on a background
// goroutine. It returns a flameSnapshotReadyMsg that the Update loop consumes
// to apply the new frame layout without blocking the UI goroutine.
// Only snapshot reads are needed here, so the parameter is narrowed to
// Snapshotter rather than the full LiveTrieSource.
func buildSnapshotMsg(liveTrie Snapshotter, width, height int, zoomPath string) tea.Msg {
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
	return flameSnapshotReadyMsg{
		version:      ver,
		layoutWidth:  width,
		layoutHeight: height,
		zoomPath:     zoomPath,
		snapshot:     tree,
		zoomRoot:     zoomRoot,
		targetFrames: targetFrames,
		ancestry:     buildFrameAncestry(targetFrames),
		globalTotal:  snapshotTotal(tree),
	}
}

// RefreshFromLiveTrieCmd returns a tea.Cmd that fetches a snapshot, lays out
// frames, and builds the ancestry index on a background goroutine, then
// dispatches a flameSnapshotReadyMsg back to the Bubble Tea Update loop.
//
// Returns nil when no refresh is needed: no live trie, paused with an existing
// snapshot, version unchanged, another refresh in flight, or user driving.
// Coalescing via refreshInFlight ensures at most one background job at a time.
func (m *Model) RefreshFromLiveTrieCmd() tea.Cmd {
	if m.liveTrie == nil || (m.paused && m.snapshot != nil) || m.refreshInFlight {
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
	// Capture the fields needed by the goroutine to avoid concurrent reads of
	// Model fields from outside the Bubble Tea Update goroutine.
	liveTrie, width, height, zoomPath := m.liveTrie, m.width, m.height, m.zoomPath
	return func() tea.Msg {
		return buildSnapshotMsg(liveTrie, width, height, zoomPath)
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

// SetDarkMode sets the active color theme mode. Delegates the text input style
// update to SearchController.
func (m *Model) SetDarkMode(isDark bool) {
	m.isDark = isDark
	m.SearchController.setDarkMode(isDark)
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
// optionally animating from the previous frames. Delegates the swap, selection
// restore, filter recompute, and subtree-highlight update to FrameAnimator so
// the post-swap invariants are enforced in one place.
func (m *Model) applyTargetFrames(targetFrames []tuiFrame, ancestry frameAncestry, prevPath string, animate bool) {
	m.FrameAnimator.applyTargetFrames(targetFrames, ancestry, prevPath, animate, &m.SelectionManager, &m.SearchController, m.height)
}

// restoreSelectionByPath delegates to SelectionManager to restore the selection
// after a frame layout swap.
func (m *Model) restoreSelectionByPath(path string) {
	m.SelectionManager.restoreByPath(m.frames, path)
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

// zoomReset resets the zoom to the full tree. Delegates the "already at root"
// check to ZoomNavigator.alreadyAtRoot, and the state clear to ZoomNavigator.reset.
func (m *Model) zoomReset() {
	if m.ZoomNavigator.alreadyAtRoot() {
		m.statusMessage = "Zoom already at root"
		return
	}
	m.statusMessage = m.ZoomNavigator.reset()
	m.rebuildFrames(false)
}

// clampSelection delegates to SelectionManager to keep selectedIdx in bounds.
func (m *Model) clampSelection() {
	m.SelectionManager.clamp(m.frames)
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

// currentRootPath delegates to ZoomNavigator to return the current view root path.
func (m Model) currentRootPath() string {
	return m.ZoomNavigator.currentRootPath(m.frames)
}

// filterActive reports whether a search filter is applied.
func (m Model) filterActive() bool {
	return filterActive(m.searchQuery)
}

// navigableFrameSet returns the filter-visible set when a filter is active, else nil.
func (m Model) navigableFrameSet() map[int]bool {
	return navigableSet(m.searchQuery, m.filterVisible)
}

// framesAtDepth returns frame indices at the given depth filtered by the
// current search.
func (m Model) framesAtDepth(depth int) []int {
	return framesAtDepthFiltered(m.frames, depth, m.navigableFrameSet())
}

// frameNavigable reports whether a frame can be selected under the current filter.
func (m Model) frameNavigable(idx int) bool {
	return frameNavigable(idx, m.frames, m.searchQuery, m.filterVisible)
}

// ensureSelectionNavigable delegates to SelectionManager to keep the selection
// on a frame that is visible under the current filter.
func (m *Model) ensureSelectionNavigable() {
	m.SelectionManager.ensureNavigable(m.frames, m.matchIndices, m.searchQuery, m.filterVisible)
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

// moveTraversal delegates depth-then-column traversal to SelectionManager.
func (m *Model) moveTraversal(delta int) {
	m.SelectionManager.moveTraversal(m.frames, delta, m.searchQuery, m.filterVisible)
}

// visibleTraversalOrder delegates to SelectionManager for the sorted traversal order.
func (m Model) visibleTraversalOrder() []int {
	return visibleTraversalOrder(m.frames, m.searchQuery, m.filterVisible)
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
func isToggleHeightKey(msg tea.KeyPressMsg) bool { return keyString(msg) == "v" }
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

// visibleRowOffset delegates row offset calculation to SelectionManager.
func (m Model) visibleRowOffset() int {
	return visibleRowOffset(m.frames, m.height, m.searchQuery, m.filterVisible)
}

// ensureSelectionVisible delegates to SelectionManager to adjust the selection
// so it falls within the visible rendered rows.
func (m *Model) ensureSelectionVisible() {
	m.SelectionManager.ensureVisible(m.frames, m.height, m.searchQuery, m.filterVisible)
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

// rootSnapshotPath delegates to ZoomNavigator to derive the canonical root path.
func (m Model) rootSnapshotPath() string {
	return m.ZoomNavigator.rootSnapshotPath(m.snapshot, m.frames)
}

// frameIndexAt delegates to the FrameAnimator package-level helper to convert
// terminal coordinates (x, y) to a frame index, accounting for UI chrome.
func (m Model) frameIndexAt(x, y int) int {
	return frameIndexAt(m.frames, x, y, m.width, m.height, m.showHelp)
}

// frameCoordToTargetRow delegates to the FrameAnimator package-level helper.
func (m Model) frameCoordToTargetRow(dataRow, availableRows int) int {
	return frameCoordToTargetRow(m.frames, dataRow, availableRows)
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
