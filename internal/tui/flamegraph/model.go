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

// snapshotNode aliases the live trie's snapshot type so the TUI consumes the
// trees SnapshotTree() returns directly. The trie contract itself (coreflamegraph.LiveTrieSource and its
// Snapshotter/Configurator halves) is defined once in the core package.
type snapshotNode = coreflamegraph.SnapshotNode

// animTickMsg advances the frame animation by one step. generation is the
// FrameAnimator generation at scheduling time; Update drops a tick whose
// generation is stale (see FrameAnimator.generation).
type animTickMsg struct {
	generation uint64
}

// flameViewCacheKey captures the View() inputs that determine the rendered
// output. When two consecutive calls produce the same key, the cached content
// string is reused instead of re-running RenderTerminalView.
//
// searchQuery is only the committed filter; searchInput and searchCursor track
// the live text input that the search footer renders while the prompt is open.
// Without them every keystroke after '/' hit the cache and the typed text stayed
// invisible until Enter.
//
// generation is Model.refreshGeneration. SetLiveTrie restarts the snapshot
// version at 0, so a new session's trie can reach the same version, frame count
// and status message as the previous session's cached render while showing
// different frame names; without the generation that render would be served
// stale whenever no View ran between the swap and the first refresh (the
// dashboard attaches a trie and loads it inside one Update). Every state change
// that invalidates in-flight refreshes (SetLiveTrie, baseline/order/metric
// resets) advances it.
//
// fieldIndex selects the toolbar's o:order(...) label. SetLiveTrie may prepend
// an unknown field order to fieldPresets and keep the index at 0, so the index
// alone is ambiguous across sessions; generation disambiguates it, and it is
// the only place fieldPresets changes. Keying on the index instead of the
// joined label keeps the cache-hit path free of a strings.Join per View.
//
// searchInput and searchCursor are only read while the search prompt is open
// (see currentViewCacheKey): the footer renders them only then.
// hasSnapshot decides whether an empty frame list renders the "snapshot has no
// visible frames" panel; clearSnapshotState drops the snapshot without touching
// lastVersion, so neither is implied by the other key fields.
type flameViewCacheKey struct {
	version       uint64
	selectedIdx   int
	width         int
	height        int
	framesLen     int
	matchCount    int
	visibleCount  int
	searchQuery   string
	searchInput   string
	searchCursor  int
	statusMessage string
	zoomPath      string
	countField    string
	heightField   string
	fieldIndex    int
	generation    uint64
	hasSnapshot   bool
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
// Bubble Tea goroutine can swap in the new state without blocking on snapshot
// or frame layout work.
type flameSnapshotReadyMsg struct {
	generation   uint64
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
// snapshot+layout work or a 1-second animation chain.
const driveWindow = 250 * time.Millisecond

type zoomState struct {
	path string
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
// SearchController. They are held in named fields and driven only through
// their methods; the collaborators never reference one another, so the Model
// is the one place that combines their state (for example applyTargetFrames,
// which re-establishes the selection and filter invariants after a layout
// swap).
//
// Receiver policy: every method on Model takes *Model, so *Model (not Model)
// is the Bubble Tea model that Init/Update/View implement - the same policy
// the stream tab's model already follows (internal/tui/eventstream). The
// mixed value/pointer receivers this type used to have worked only while
// every value happened to be addressable: a value-receiver Update calling a
// pointer-receiver mutator mutates a copy, so any non-addressable or
// later-copied Model silently lost those mutations.
type Model struct {
	// Sub-controllers — each owns a single concern.
	zoom   ZoomNavigator    // zoom path, stack, and root node management
	sel    SelectionManager // selected frame index and subtree highlight
	anim   FrameAnimator    // frame layout, ancestry index, animated transitions
	search SearchController // search query, match indices, filter-visible set

	liveTrie    coreflamegraph.LiveTrieSource
	lastVersion uint64
	snapshot    *snapshotNode
	globalTotal uint64

	// refreshInFlight is true while a background snapshot+layout job is
	// running. It coalesces flameTickMsg dispatches so we never queue more
	// than one snapshot rebuild concurrently.
	refreshInFlight bool
	// refreshGeneration identifies the snapshot state a refresh result must
	// match to be applied: the live-trie binding plus its baseline, field
	// order and metrics. SetLiveTrie and clearSnapshotState advance it so a
	// result computed for a superseded state is dropped instead of shown
	// under the new state's labels.
	refreshGeneration uint64
	// inFlightGeneration is the refreshGeneration captured by the job that
	// holds the refreshInFlight slot. Only that job's completion releases the
	// slot, so a late or duplicate completion from an older job cannot free a
	// newer job's slot and let refreshes overlap.
	inFlightGeneration uint64

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
//
// Name is the display label and is sanitised (common.Sanitize) where frames
// are built, because frame names are traced comm/syscall/path values that an
// unprivileged user controls. Path is the raw pathSeparator-joined node path:
// it is a lookup key (zoom, selection, filters) and must be sanitised by
// whoever renders it (compactFramePath).
type tuiFrame struct {
	Name        string
	Col         int
	Row         int
	Width       int
	Total       uint64
	HeightTotal uint64
	Percent     float64
	Fill        color.Color
	Depth       int
	Path        string
}

// NewModel constructs a flamegraph tab model with default state.
// The four sub-controllers (ZoomNavigator, SelectionManager,
// FrameAnimator, SearchController) are initialised here; the Model delegates
// their respective concerns to them.
//
// Like every method on Model, the constructor returns the pointer form: the
// receiver policy for this type is all-pointer so *Model is the Bubble Tea
// model (see the receiver note on the Model struct above), and a value return
// would hand back a copy whose mutations could silently detach from the model
// the program keeps.
func NewModel(liveTrie coreflamegraph.LiveTrieSource) *Model {
	m := &Model{
		zoom:      ZoomNavigator{},
		sel:       newSelectionManager(),
		anim:      newFrameAnimator(),
		search:    newSearchController(true),
		liveTrie:  liveTrie,
		viewCache: &flameViewCache{},
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

// Init returns no command and leaves the model untouched: the dashboard
// drives the flamegraph's refreshes and animation ticks through Update.
func (m *Model) Init() tea.Cmd {
	return nil
}

// Update handles incoming messages. Delegates animation ticks to FrameAnimator,
// snapshot arrivals to handleSnapshotReady, and key/mouse events to the
// appropriate handler.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case animTickMsg:
		if !m.anim.acceptsTick(msg.generation) {
			return m, nil
		}
		if !m.anim.isAnimating() {
			// Settled or snapped since the tick was scheduled.
			m.anim.stopTicks()
			return m, nil
		}
		m.tickAnimation()
		return m, m.continueAnimationCmd()
	case flameSnapshotReadyMsg:
		return m.handleSnapshotReady(msg)
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.rebuildFrames(true)
		return m, m.startAnimationCmd()
	case tea.MouseClickMsg:
		_ = m.handleMouseClick(msg)
		return m, nil
	case tea.KeyPressMsg:
		// Stamp every keypress so RefreshFromLiveTrieCmd and the
		// snapshot-ready handler can detect that the user is actively driving
		// the view and defer / unanimate accordingly.
		m.lastKeyAt = time.Now()
		if m.search.isActive() {
			return m.handleSearchInput(msg)
		}
		return m.handleKeyNavigation(msg)
	case tea.PasteMsg:
		// A bracketed paste is text for the search input and nothing else:
		// outside search mode the navigation keys are commands, which pasted
		// text must not trigger, so it is dropped.
		if m.search.isActive() {
			m.lastKeyAt = time.Now()
			m.search.handlePaste(msg)
		}
		return m, nil
	}
	return m, nil
}

// HandleRefreshCompletion consumes a background refresh result and reports
// whether msg was one. A hidden flame tab discards the result while still
// releasing the in-flight slot; applying it would start an animation whose
// ticks the dashboard does not route while another tab is active.
func (m *Model) HandleRefreshCompletion(msg tea.Msg, apply bool) (bool, tea.Cmd) {
	ready, ok := msg.(flameSnapshotReadyMsg)
	if !ok {
		return false, nil
	}
	if !apply {
		m.settleRefresh(ready)
		return true, nil
	}
	_, cmd := m.handleSnapshotReady(ready)
	return true, cmd
}

// settleRefresh records the completion of a background refresh job. It
// releases the in-flight slot when msg comes from the job holding it, and
// reports whether msg was computed for the current snapshot state and may
// therefore be applied.
func (m *Model) settleRefresh(msg flameSnapshotReadyMsg) (current bool) {
	if m.refreshInFlight && msg.generation == m.inFlightGeneration {
		m.refreshInFlight = false
	}
	return msg.generation == m.refreshGeneration
}

// invalidateRefresh advances the refresh generation so any result already
// being computed for the previous snapshot state is dropped on arrival.
func (m *Model) invalidateRefresh() {
	m.refreshGeneration++
}

// handleSearchInput processes key events while search mode is active.
// Delegates key dispatch (esc/enter/text) to SearchController, then updates
// match state and status message on the Model. It returns no command: the
// text input's cursor-blink command is dropped in handleInput because nothing
// routes blink messages back to it.
func (m *Model) handleSearchInput(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	committed, query, cancelled := m.search.handleInput(msg)
	switch {
	case cancelled:
		// ESC: clear search state and close search mode.
		m.clearSearch()
		m.recordKeyDebug(msg, true, false)
	case committed:
		// Enter: apply query, close search mode, jump to first match.
		statusMsg, jumpDir := m.search.commit(query, m.anim.currentFrames(), m.anim.currentAncestry())
		m.statusMessage = statusMsg
		m.followSearchResult(jumpDir)
		m.recordKeyDebug(msg, true, false)
	default:
		m.recordKeyDebug(msg, true, false)
	}
	return m, nil
}

// handleKeyNavigation processes navigation key events when search is not active.
// Delegates mode-toggle and zoom actions to handleModeKey, movement actions to
// handleMovementKey, then updates the subtree highlight when selection changes.
func (m *Model) handleKeyNavigation(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	prev := m.sel.selected()
	handled := m.handleModeKey(msg)
	if !handled {
		handled = m.handleMovementKey(msg)
	}
	moved := m.sel.selected() != prev
	if moved {
		m.sel.refreshSubtree(m.anim.currentFrames(), m.anim.currentAncestry())
	}
	m.recordKeyDebug(msg, handled, moved)
	return m, nil
}

// handleModeKey dispatches search, pause, zoom, and view-toggle key actions.
// Returns true when a key was handled so handleKeyNavigation can skip movement.
func (m *Model) handleModeKey(msg tea.KeyPressMsg) bool {
	switch {
	case isSearchOpenKey(msg):
		m.openSearch()
	case isNextMatchKey(msg):
		m.jumpToMatch(1)
	case isPrevMatchKey(msg):
		m.jumpToMatch(-1)
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
	frames := m.anim.currentFrames()
	navigable := m.search.navigable()
	switch {
	case isMoveShallowerKey(msg, m.keys):
		m.sel.moveVerticalWithFallback(frames, navigable, -1, 1, -1)
	case isMoveDeeperKey(msg, m.keys):
		m.sel.moveVerticalWithFallback(frames, navigable, 1, -1, 1)
	case isPrevSiblingKey(msg, m.keys):
		m.sel.moveSibling(frames, -1, navigable)
	case isNextSiblingKey(msg, m.keys):
		m.sel.moveSibling(frames, 1, navigable)
	case isJumpTopKey(msg, m.keys):
		m.sel.jumpToTop(frames, navigable)
	case isJumpRootKey(msg, m.keys):
		m.sel.jumpToRoot(frames, m.currentRootPath(), navigable)
	default:
		return false
	}
	return true
}

// handleSnapshotReady applies the result of a background snapshot+layout job.
// Discards the result if it was computed for a superseded snapshot state
// (live trie, baseline reset, field order or metric change), if viewport or
// zoom changed while the job was in flight (the next tick will dispatch a
// fresh refresh), or if the user paused after a snapshot already exists. The
// job holding the in-flight slot always releases it so subsequent ticks can
// dispatch the next refresh; any other completion cannot clear the slot.
func (m *Model) handleSnapshotReady(msg flameSnapshotReadyMsg) (tea.Model, tea.Cmd) {
	if !m.settleRefresh(msg) || msg.snapshot == nil {
		return m, nil
	}
	if msg.layoutWidth != m.width || msg.layoutHeight != m.height || msg.zoomPath != m.zoom.path() {
		return m, nil
	}
	if m.paused && m.snapshot != nil {
		return m, nil
	}

	prevPath := m.sel.selectedPath(m.anim.currentFrames())

	m.snapshot = msg.snapshot
	m.globalTotal = msg.globalTotal
	m.zoom.adoptRoot(msg.zoomRoot)
	m.lastVersion = msg.version
	// Snap directly to target frames while the user is actively pressing keys
	// — animation would just add latency on top of the work the user wants to
	// see. Animation resumes on the next refresh after the drive window
	// expires.
	animate := !m.userDriving()
	m.applyTargetFrames(msg.targetFrames, msg.ancestry, prevPath, animate)
	return m, m.startAnimationCmd()
}

// userDriving delegates to the FrameAnimator helper that checks whether the user
// pressed a key within the drive window.
func (m *Model) userDriving() bool {
	return driveWindowActive(m.lastKeyAt)
}

// SearchActive reports whether the flamegraph's search input is open and
// receiving typed text.
func (m *Model) SearchActive() bool {
	return m.search.isActive()
}

// ConsumesKey reports whether the flamegraph should handle a key press before
// dashboard- or app-level shortcuts.
func (m *Model) ConsumesKey(msg tea.KeyPressMsg) bool {
	if m.search.isActive() {
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
func (m *Model) View() tea.View {
	if !m.anim.isAnimating() && m.viewCache != nil {
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
func (m *Model) renderViewContent() string {
	extraLines := 1 // selection status line
	if m.showHelp {
		extraLines++
	}
	renderHeight := m.height - extraLines
	if renderHeight < 3 {
		renderHeight = 3
	}

	frames := m.anim.currentFrames()
	content := RenderTerminalView(RenderContext{
		Frames:             frames,
		Width:              m.width,
		Height:             renderHeight,
		SelectedIdx:        m.sel.selected(),
		SubtreeSet:         m.sel.subtree(),
		MatchSet:           m.search.matches(),
		FilterSet:          m.search.visibleSet(),
		GlobalTotal:        m.globalTotal,
		MetricLabel:        m.countFieldLabel(),
		HeightMetricActive: m.heightMetricActive(),
		IsDark:             m.isDark,
		SearchQuery:        m.search.query(),
	})
	content = replaceHeaderLine(content, m.toolbarLine())
	if m.search.isActive() {
		content = replaceFooterLine(content, m.searchFooter())
	}
	if m.snapshot != nil && len(frames) == 0 {
		content = common.Current().PanelStyle.Render(fmt.Sprintf("Flame: snapshot v%d has no visible frames", m.lastVersion))
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
// cache misses and the content is rebuilt. Any rendered input left out of the
// key is served stale from the cache, which is why the live search input value
// and cursor are included alongside the committed query, and why the refresh
// generation separates one live-trie session from the next.
func (m *Model) currentViewCacheKey() flameViewCacheKey {
	// The input value and cursor only reach the screen through the search
	// footer, so they are read only while the prompt is open. Closing the
	// prompt clears the input and flips searchActive, which changes the key;
	// reading textinput.Value() on every idle View allocated for nothing.
	var searchInput string
	var searchCursor int
	if m.search.isActive() {
		searchInput, searchCursor = m.search.inputValue(), m.search.inputCursor()
	}
	return flameViewCacheKey{
		version:       m.lastVersion,
		selectedIdx:   m.sel.selected(),
		width:         m.width,
		height:        m.height,
		framesLen:     len(m.anim.currentFrames()),
		matchCount:    len(m.search.matches()),
		visibleCount:  len(m.search.visibleSet()),
		searchQuery:   m.search.query(),
		searchInput:   searchInput,
		searchCursor:  searchCursor,
		statusMessage: m.statusMessage,
		zoomPath:      m.zoom.path(),
		countField:    m.countField,
		heightField:   m.heightField,
		fieldIndex:    m.fieldIndex,
		generation:    m.refreshGeneration,
		hasSnapshot:   m.snapshot != nil,
		searchActive:  m.search.isActive(),
		showHelp:      m.showHelp,
		paused:        m.paused,
		isDark:        m.isDark,
	}
}

// SetLiveTrie updates the data source. It invalidates any in-flight refresh,
// resets all sub-controllers, and clears snapshot state so the new trie starts
// fresh.
func (m *Model) SetLiveTrie(liveTrie coreflamegraph.LiveTrieSource) {
	// The old session's job runs against the old trie, so the new session
	// need not wait for it: drop the slot along with its result.
	m.invalidateRefresh()
	m.refreshInFlight = false
	m.liveTrie = liveTrie
	m.syncFieldPresetToTrie()
	m.syncCountFieldToTrie()
	m.syncHeightFieldToTrie()
	m.lastVersion = 0
	m.snapshot = nil
	m.globalTotal = 0
	m.zoom = ZoomNavigator{}
	m.sel = newSelectionManager()
	m.anim.reset()
	m.search.reset(false)
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
// a new snapshot was applied. The dashboard uses it for the one-off initial
// load when a live trie is attached (dashboard.Model.SetLiveTrie); periodic
// refreshes go through RefreshFromLiveTrieCmd, which does the heavy lifting on
// a background goroutine.
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
	m.zoom.resolveRoot(m.snapshot)
	m.rebuildFrames(true)
	m.lastVersion = version
	return true
}

// buildSnapshotMsg performs the CPU-heavy snapshot+layout work on a background
// goroutine. It returns a flameSnapshotReadyMsg that the Update loop consumes
// to apply the new frame layout without blocking the UI goroutine.
// Only snapshot reads are needed here, so the parameter is narrowed to
// coreflamegraph.Snapshotter rather than the full LiveTrieSource.
func buildSnapshotMsg(liveTrie coreflamegraph.Snapshotter, generation uint64, width, height int, zoomPath string) tea.Msg {
	tree, ver := liveTrie.SnapshotTree()
	if tree == nil {
		return flameSnapshotReadyMsg{generation: generation, version: ver, layoutWidth: width, layoutHeight: height, zoomPath: zoomPath}
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
		generation:   generation,
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
	m.inFlightGeneration = m.refreshGeneration
	// Capture the fields needed by the goroutine to avoid concurrent reads of
	// Model fields from outside the Bubble Tea Update goroutine.
	liveTrie, generation := m.liveTrie, m.refreshGeneration
	width, height, zoomPath := m.width, m.height, m.zoom.path()
	return func() tea.Msg {
		return buildSnapshotMsg(liveTrie, generation, width, height, zoomPath)
	}
}

// LastVersion returns the latest snapshot version loaded into the model.
func (m *Model) LastVersion() uint64 {
	return m.lastVersion
}

// HasSnapshot reports whether the flamegraph model has loaded at least one snapshot.
func (m *Model) HasSnapshot() bool {
	return m.snapshot != nil
}

// AnimationCmd returns a frame animation tick command when animation is
// active and no tick loop is live yet, so calling it while a loop runs never
// doubles the animation speed.
func (m *Model) AnimationCmd() tea.Cmd {
	return m.startAnimationCmd()
}

// Paused reports whether live refresh is paused.
func (m *Model) Paused() bool {
	return m.paused
}

// Animating reports whether a frame transition is in progress, that is
// whether the frames on screen are still interpolated towards the layout.
func (m *Model) Animating() bool {
	return m.anim.isAnimating()
}

// ResumeAnimationCmd restarts the tick loop of a running animation after a
// period in which its ticks may have been dropped, such as while the
// dashboard showed another tab. It retires the old loop first, so its tick is
// dropped if it does arrive and a lost tick does not hold the new loop back
// for tickLostAfter: there is exactly one loop afterwards while animating,
// and none (and no command) otherwise.
func (m *Model) ResumeAnimationCmd() tea.Cmd {
	m.anim.retireTicks()
	return m.startAnimationCmd()
}

// SetViewport updates model render dimensions. With animate the frames spring
// to the new layout and the returned command drives the animation (nil when a
// tick loop is already live or nothing moves); without it they snap, as for a
// hidden flame tab whose ticks the dashboard does not deliver.
func (m *Model) SetViewport(width, height int, animate bool) tea.Cmd {
	if m.width == width && m.height == height {
		return nil
	}
	m.width = width
	m.height = height
	m.rebuildFrames(animate)
	return m.startAnimationCmd()
}

// SetDarkMode sets the active color theme mode. Delegates the text input style
// update to SearchController.
func (m *Model) SetDarkMode(isDark bool) {
	m.isDark = isDark
	m.search.setDarkMode(isDark)
}

func (m *Model) rebuildFrames(animate bool) {
	prevPath := m.sel.selectedPath(m.anim.currentFrames())

	root, rootPath := m.zoom.layoutRoot(m.snapshot)
	targetFrames := buildTerminalLayoutWithPath(root, m.width, m.height, rootPath)
	if m.zoom.path() != "" {
		targetFrames = m.withZoomLineage(targetFrames)
	}
	ancestry := buildFrameAncestry(targetFrames)
	m.applyTargetFrames(targetFrames, ancestry, prevPath, animate)
}

// applyTargetFrames installs a prebuilt frame layout and ancestry index,
// optionally animating from the previous frames, then re-establishes the
// post-swap invariants across the collaborators: the selection follows
// prevPath (or its closest surviving relative), the search sets are rebuilt
// for the new indices, the selection is moved onto a navigable, on-screen
// frame, and the subtree highlight is refreshed.
func (m *Model) applyTargetFrames(targetFrames []tuiFrame, ancestry frameAncestry, prevPath string, animate bool) {
	m.anim.applyTargetFrames(targetFrames, ancestry, animate)
	frames, ancestry := m.anim.currentFrames(), m.anim.currentAncestry()
	m.sel.restoreByPath(frames, prevPath)
	m.sel.clamp(frames)
	m.search.recomputeFilterState(frames, ancestry)
	navigable := m.search.navigable()
	m.sel.ensureNavigable(frames, m.search.matches(), navigable)
	m.sel.ensureVisible(frames, m.height, navigable)
	m.sel.refreshSubtree(frames, ancestry)
}

// tickAnimation advances the frame animation by one step and keeps the
// selection and its subtree highlight valid for the interpolated frames.
func (m *Model) tickAnimation() {
	m.anim.tickAnimation()
	frames := m.anim.currentFrames()
	m.sel.clamp(frames)
	m.sel.refreshSubtree(frames, m.anim.currentAncestry())
}

// jumpToMatch moves the selection to the next (direction > 0) or previous
// search match.
func (m *Model) jumpToMatch(direction int) {
	m.sel.jumpToMatch(m.anim.currentFrames(), m.anim.currentAncestry(), m.search.matches(), direction)
}

// followSearchResult moves the selection after a query was applied: to the
// first match in direction jumpDir, or, when jumpDir is 0 (no matches or the
// filter was cleared), onto the nearest navigable frame.
func (m *Model) followSearchResult(jumpDir int) {
	m.sel.cancelWish() // applying a query is a user decision about the selection
	if jumpDir != 0 {
		m.jumpToMatch(jumpDir)
		return
	}
	m.ensureSelectionNavigable()
}

// zoomIn, zoomUndo, zoomReset and a zoom click re-root the layout on the
// user's say-so, so each cancels the selection wish first: a frame remembered
// from before the zoom is no longer the one the user is looking at.
func (m *Model) zoomIn() {
	m.sel.cancelWish()
	frames := m.anim.currentFrames()
	if len(frames) == 0 || m.snapshot == nil {
		m.statusMessage = "Zoom unavailable: no frame selected"
		return
	}
	m.clampSelection()
	selectedPath := m.sel.selectedPath(frames)
	if selectedPath == m.currentRootPath() {
		m.statusMessage = "Zoom unchanged: selected frame is current view root"
		return
	}
	if !m.zoom.descend(selectedPath, m.snapshot) {
		m.statusMessage = "Zoom failed: selected node is unavailable"
		return
	}
	m.rebuildFrames(false)
	m.statusMessage = "Zoom: " + compactFramePath(selectedPath)
}

func (m *Model) zoomUndo() {
	m.sel.cancelWish()
	if !m.zoom.undo(m.snapshot) {
		m.statusMessage = "Zoom undo unavailable"
		return
	}
	m.rebuildFrames(false)
	if m.zoom.path() == "" {
		m.statusMessage = "Zoom: root"
		return
	}
	m.statusMessage = "Zoom: " + compactFramePath(m.zoom.path())
}

// zoomReset resets the zoom to the full tree. Delegates the "already at root"
// check to ZoomNavigator.alreadyAtRoot, and the state clear to ZoomNavigator.reset.
func (m *Model) zoomReset() {
	m.sel.cancelWish()
	if m.zoom.alreadyAtRoot() {
		m.statusMessage = "Zoom already at root"
		return
	}
	m.zoom.reset()
	m.statusMessage = "Zoom reset to root"
	m.rebuildFrames(false)
}

// clampSelection delegates to SelectionManager to keep selectedIdx in bounds.
func (m *Model) clampSelection() {
	m.sel.clamp(m.anim.currentFrames())
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// continueAnimationCmd schedules the next tick of the live tick loop, or ends
// the loop once the animation has settled. Only the tick handler may use it.
func (m *Model) continueAnimationCmd() tea.Cmd {
	if !m.anim.isAnimating() {
		m.anim.stopTicks()
		return nil
	}
	return animTickCmd(m.anim.continueTicks(time.Now()))
}

// startAnimationCmd makes sure a tick loop drives the running animation. It
// returns nil when a loop is already live: that loop's pending tick picks up
// the new springs, so there is at most one loop, and a stream of snapshots or
// resizes faster than a tick never pushes the pending tick back.
func (m *Model) startAnimationCmd() tea.Cmd {
	if !m.anim.isAnimating() {
		return nil
	}
	generation, start := m.anim.startTicks(time.Now())
	if !start {
		return nil
	}
	return animTickCmd(generation)
}

func animTickCmd(generation uint64) tea.Cmd {
	return tea.Tick(animFrameDuration, func(time.Time) tea.Msg { return animTickMsg{generation: generation} })
}

// currentRootPath delegates to ZoomNavigator to return the current view root path.
func (m *Model) currentRootPath() string {
	return m.zoom.currentRootPath(m.anim.currentFrames())
}

// ensureSelectionNavigable delegates to SelectionManager to keep the selection
// on a frame that is visible under the current filter.
func (m *Model) ensureSelectionNavigable() {
	m.sel.ensureNavigable(m.anim.currentFrames(), m.search.matches(), m.search.navigable())
}

func (m *Model) recordKeyDebug(msg tea.KeyPressMsg, handled, moved bool) {
	if !flameKeyDebugEnabled {
		return
	}
	keyID := keyString(msg)
	if keyID == "" {
		keyID = fmt.Sprintf("code:%d", msg.Code)
	}
	frames := m.anim.currentFrames()
	sel := "-"
	if path := m.sel.selectedPath(frames); path != "" {
		sel = compactFramePath(path)
	}
	m.lastKeyDebug = fmt.Sprintf("dbg frames=%d idx=%d key=%q code=%d handled=%t moved=%t sel=%s", len(frames), m.sel.selected(), keyID, msg.Code, handled, moved, sel)
}

func (m *Model) handleMouseClick(msg tea.MouseClickMsg) bool {
	if msg.Button != tea.MouseLeft {
		return false
	}
	idx := m.frameIndexAt(msg.X, msg.Y)
	if idx < 0 {
		return false
	}
	m.sel.cancelWish() // a click is a user move whether or not it zooms
	clickedPath := m.anim.currentFrames()[idx].Path
	currentRoot := m.currentRootPath()
	if clickedPath == currentRoot {
		m.sel.selectFrame(m.anim.currentFrames(), m.anim.currentAncestry(), idx)
		return true
	}
	// Clicking an ancestor of the zoomed root jumps straight up to it; any
	// other frame zooms in one step.
	var zoomed bool
	if m.zoom.path() != "" && hasPathBoundaryPrefix(currentRoot, clickedPath) {
		zoomed = m.zoom.ascendTo(clickedPath, m.snapshot)
	} else {
		zoomed = m.zoom.descend(clickedPath, m.snapshot)
	}
	if !zoomed {
		return false
	}
	m.rebuildFrames(false)
	frames, ancestry := m.anim.currentFrames(), m.anim.currentAncestry()
	if !m.sel.selectFrame(frames, ancestry, m.anim.indexByPath(clickedPath)) {
		m.sel.refreshSubtree(frames, ancestry)
	}
	m.statusMessage = "Zoom: " + compactFramePath(clickedPath)
	return true
}

// frameIndexAt delegates to the renderer package-level helper to convert
// terminal coordinates (x, y) to a frame index, accounting for UI chrome. It
// returns -1 while the view shows the "no frames match filter" placeholder
// (an applied filter with an empty visible set): the frames still exist in
// the model but none is drawn, so none may be clicked. The geometry-driven
// placeholders ("terminal too narrow", ...) are handled inside frameIndexAt.
func (m *Model) frameIndexAt(x, y int) int {
	if filterActive(m.search.query()) && filterHidesAllFrames(m.search.visibleSet()) {
		return -1
	}
	return frameIndexAt(m.anim.currentFrames(), x, y, m.width, m.height, m.showHelp, m.heightMetricActive())
}

func (m *Model) withZoomLineage(frames []tuiFrame) []tuiFrame {
	return applyZoomLineage(frames, m.snapshot, m.zoom.path(), m.width)
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

	// Shift the zoomed layout down below the lineage rows; the zoom root
	// itself is dropped because the lineage re-adds it as its last row.
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
		out = append(out, lineageFrame(snapshot, parts[depth], path, depth, width, rootTotal))
	}
	return out
}

// lineageFrame builds the full-width frame of one zoom-path ancestor at row
// depth. An ancestor no longer present in snapshot gets zero totals.
func lineageFrame(snapshot *snapshotNode, name, path string, depth, width int, rootTotal uint64) tuiFrame {
	node := findNodeByPath(snapshot, path)
	total := uint64(0)
	heightTotal := uint64(0)
	if node != nil {
		total = snapshotTotal(node)
		heightTotal = snapshotHeightTotal(node)
	}
	percent := 0.0
	if rootTotal > 0 {
		percent = 100 * float64(total) / float64(rootTotal)
	}
	return tuiFrame{
		// Name is display-only and sanitised (traced comm/path frame names
		// are attacker-controlled); Path stays raw because it is the
		// lookup key for zoom, selection and filters.
		Name:        common.Sanitize(name),
		Col:         0,
		Row:         depth,
		Width:       width,
		Total:       total,
		HeightTotal: heightTotal,
		Percent:     percent,
		Fill:        terminalFrameColor(name),
		Depth:       depth,
		Path:        path,
	}
}
