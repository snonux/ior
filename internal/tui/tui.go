package tui

import (
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ior/internal/flags"
	"ior/internal/globalfilter"
	"ior/internal/parquet"
	"ior/internal/runtime"
	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	dashboardui "ior/internal/tui/dashboard"
	"ior/internal/tui/eventstream"
	tuiexport "ior/internal/tui/export"
	"ior/internal/tui/messages"
	"ior/internal/tui/pidpicker"
	"ior/internal/tui/probes"
	tracefilterui "ior/internal/tui/tracefilter"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// Screen identifies the currently active TUI screen.
type Screen int

const (
	// ScreenPIDPicker is the PID selection screen.
	ScreenPIDPicker Screen = iota
	// ScreenDashboard is the runtime dashboard screen.
	ScreenDashboard
)

type errorScreenKind uint8

const (
	errorScreenFatal errorScreenKind = iota
	errorScreenRecoverable
)

// TraceStarter starts tracing and returns when startup succeeds or fails.
// It is a type alias for runtime.TraceStarter so TUI callers need not import
// the runtime package directly.
// Long-lived tracing work should continue in background goroutines.
type TraceStarter = runtime.TraceStarter

// TraceRequest is what the TUI hands a TraceStarter for one trace session:
// its runtime bindings, the active filter and the session's shutdown
// reporter, passed explicitly rather than through context values.
// It is a type alias for runtime.TraceRequest.
type TraceRequest = runtime.TraceRequest

// ProbeManager exposes runtime probe controls to TUI layers.
// It is a type alias for runtime.ProbeManager.
type ProbeManager = runtime.ProbeManager

// RuntimePublisher is the write side of the TUI runtime contract.
// It is a type alias for runtime.RuntimePublisher; the runtime package owns
// the canonical definition so the core tracing layer can depend on it without
// importing internal/tui.
type RuntimePublisher = runtime.RuntimePublisher

// RuntimeState is the read side of the TUI runtime contract.
// It is a type alias for runtime.RuntimeState.
type RuntimeState = runtime.RuntimeState

// TraceRuntimeBindings composes RuntimePublisher and RuntimeState so a trace
// starter can both inject live data and read persistent TUI-owned state.
// It is a type alias for runtime.TraceRuntimeBindings.
type TraceRuntimeBindings = runtime.TraceRuntimeBindings

// liveFilterRegistration gives each installed live-filter setter a distinct,
// comparable identity so an older trace session can clear only its own setter.
type liveFilterRegistration struct {
	_ byte
}

// runtimeBindings is the TUI-owned concrete implementation of
// runtime.TraceRuntimeBindings. It guards all fields with a read-write mutex so
// the trace starter goroutine and the Bubble Tea update loop can safely exchange
// live data.
type runtimeBindings struct {
	mu sync.RWMutex

	// snapshotSource is the stats engine injected by the trace starter.
	snapshotSource runtime.ResettableSnapshotSource
	// streamSource is the active read-side source (may be swapped on reset).
	streamSource runtime.StreamSource
	// streamBuffer is the TUI-owned ring buffer; it always satisfies both
	// runtime.StreamSource (Len/Snapshot) and runtime.EventSink (Push).
	streamBuffer *eventstream.RingBuffer
	// streamSeq is the shared monotonic counter for stream row sequencing.
	streamSeq *eventstream.Sequencer
	// recorder handles optional parquet stream recording. It is held as the
	// runtime contract (a *parquet.Recorder in production) so tests can
	// substitute a recorder whose recordings fail.
	recorder runtime.RecordingController
	// liveTrieSource is the flamegraph trie injected by the trace starter.
	liveTrieSource runtime.LiveTrieSource
	// probeManager is the BPF probe manager injected by the trace starter.
	probeManager runtime.ProbeManager
	// liveFilterSetter, when non-nil, applies filter changes to the running
	// event loop in-place so BPF probes need not be restarted.
	liveFilterSetter       func(globalfilter.Filter)
	liveFilterRegistration *liveFilterRegistration
	// session is the generation of the newest trace session, advanced by
	// beginSession. A traceSessionBindings view publishes only while its
	// generation is still this one, so an older session that finishes setup
	// or teardown late cannot overwrite or clear the newer session's state.
	session uint64
	// filterEpoch increments on every filter change and is stored in parquet rows.
	filterEpoch atomic.Uint64
}

// newRuntimeBindings builds the TUI's bindings. Their recorder is the zero
// RecorderConfig on purpose: the shed (non-blocking) overflow mode, because the
// event loop that records also feeds the live views and must never stall
// behind the disk (the headless run asks for backpressure instead; task 4s2).
func newRuntimeBindings() *runtimeBindings {
	streamBuffer := eventstream.NewRingBuffer()
	return &runtimeBindings{
		streamSource: streamBuffer,
		streamBuffer: streamBuffer,
		streamSeq:    eventstream.NewSequencer(0),
		recorder:     parquet.NewRecorder(parquet.RecorderConfig{}),
	}
}

// StreamBuffer returns the TUI-owned ring buffer. The full EventSink (push
// plus read side) is returned because the tracing engine pushes events into
// it; the TUI itself reads through the SetEventStreamSource wiring. A nil
// buffer is returned as a nil interface, not as a typed nil: handing a
// typed-nil pointer through would defeat the caller's nil check.
func (r *runtimeBindings) StreamBuffer() runtime.EventSink {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.streamBuffer == nil {
		return nil
	}
	return r.streamBuffer
}

// Recorder returns the parquet recorder for optional stream recording,
// behind the runtime contract (the concrete recorder stays an implementation
// detail of these bindings). The field already has the interface type and is
// only ever assigned a real recorder or left nil, so no typed-nil can leak.
func (r *runtimeBindings) Recorder() runtime.RecordingController {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.recorder
}

// StreamSequencer returns the shared monotonic counter for stream row sequencing.
func (r *runtimeBindings) StreamSequencer() runtime.Sequencer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.streamSeq == nil {
		return nil
	}
	return r.streamSeq
}

// FilterEpoch returns the current filter epoch used for parquet recording.
func (r *runtimeBindings) FilterEpoch() uint64 {
	return r.filterEpoch.Load()
}

// The runtime bindings deliberately have no exported setters and so do not
// satisfy runtime.RuntimePublisher: trace sessions publish only through their
// traceSessionBindings view (see tracesession.go), whose writes are dropped
// once the session is superseded. Handing *runtimeBindings to a trace starter
// directly would bring back the clobbering that view prevents.

// installLiveFilterSetterLocked stores setter under a fresh registration and
// returns it. The caller must hold r.mu for writing.
func (r *runtimeBindings) installLiveFilterSetterLocked(setter func(globalfilter.Filter)) *liveFilterRegistration {
	registration := &liveFilterRegistration{}
	r.liveFilterSetter = setter
	r.liveFilterRegistration = registration
	return registration
}

// liveFilterUnregisterer returns the release func of one registration: it
// clears the setter only while that registration is still the installed one.
func (r *runtimeBindings) liveFilterUnregisterer(registration *liveFilterRegistration) func() {
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.liveFilterRegistration != registration {
			return
		}
		r.liveFilterSetter = nil
		r.liveFilterRegistration = nil
	}
}

// applyLiveFilter swaps the active global filter in place via the setter
// registered by the trace starter, returning true if a setter was available.
// Returning false tells the caller it must fall back to a full trace restart
// (typically because no trace is currently running).
//
// With a setter it advances the filter epoch first, so rows recorded under
// the new filter carry the new epoch. Without one it advances nothing: the
// caller's restart path advances the epoch only after it stopped the old
// session, so none of that session's rows can be stamped with the new epoch.
func (r *runtimeBindings) applyLiveFilter(filter globalfilter.Filter) bool {
	r.mu.RLock()
	setter := r.liveFilterSetter
	r.mu.RUnlock()
	if setter == nil {
		return false
	}
	r.advanceFilterEpoch()
	setter(filter)
	return true
}

// dashboardSnapshotSource returns the currently wired stats engine source.
func (r *runtimeBindings) dashboardSnapshotSource() runtime.ResettableSnapshotSource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snapshotSource
}

// eventStreamSource returns the currently active stream read source.
func (r *runtimeBindings) eventStreamSource() runtime.StreamSource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.streamSource
}

// liveTrie returns the currently wired flamegraph trie source.
func (r *runtimeBindings) liveTrie() runtime.LiveTrieSource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.liveTrieSource
}

// resetLiveTrie clears the wired flamegraph trie, if any, and returns it so
// the caller can re-bind the flamegraph view to the fresh baseline. It returns
// nil when no trie is wired yet.
func (r *runtimeBindings) resetLiveTrie() runtime.LiveTrieSource {
	trie := r.liveTrie()
	if trie != nil {
		trie.Reset()
	}
	return trie
}

// currentProbeManager returns the currently wired probe manager.
func (r *runtimeBindings) currentProbeManager() runtime.ProbeManager {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.probeManager
}

func (r *runtimeBindings) resetStreamBuffer() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.streamBuffer == nil {
		r.streamBuffer = eventstream.NewRingBuffer()
	}
	r.streamBuffer.Reset()
	r.streamSource = r.streamBuffer
}

func (r *runtimeBindings) advanceFilterEpoch() uint64 {
	return r.filterEpoch.Add(1)
}

// newRunModel builds the model RunWithTraceStarterConfig runs. It is split out
// so the production startup wiring is unit-testable: the struct literal below
// is the one path real users take, and a dropped or misnamed field there is
// silently valid Go. Without this seam, removing initialPID left the whole
// suite green while `ior -pid <n>` would open the PID picker instead of the
// dashboard and never start a trace (Init would not request one).
func newRunModel(cfg flags.Config, starter TraceStarter) *Model {
	model := newModelWithRuntimeConfig(modelStartup{
		initialPID:    cfg.PidFilter,
		filter:        filterFromConfig(cfg),
		pidFilter:     cfg.PidFilter,
		tidFilter:     cfg.TidFilter,
		exportEnabled: cfg.TUIExportEnable,
		startTrace:    starter,
	})
	model.dashboard.SetAutoResetInterval(cfg.ResetTimer)
	// Apply the configurable fast-refresh cadence from the CLI flag so the
	// stream and flame tabs honour the -tui-fast-refresh value.
	model.dashboard.SetFastRefreshInterval(cfg.TUIFastRefreshInterval)
	return model
}

// RunWithTraceStarterConfig starts the TUI with explicit runtime flags.
func RunWithTraceStarterConfig(cfg flags.Config, starter TraceStarter) error {
	return runProgram(newRunModel(cfg, starter))
}

// runTeaProgram runs a Bubble Tea program to completion. It is a variable so a
// test can substitute the one thing tea.NewProgram(...).Run() makes
// untestable: that the exported entry points report what the model was
// showing. Without a seam here that half of the error-screen fix is pinned by
// nothing - wiring tea.NewProgram directly into those entry points leaves
// every test green while a quit from the error screen exits 0 with no reason,
// which is the state the fix exists to end.
//
// The program is built by newProgram, and watchTerminationSignals owns the
// termination signals for the whole run: the first SIGTERM/SIGINT/SIGHUP
// reaches the model's quit path (recording finalised), a second one aborts a
// hung shutdown (Run then returns errShutdownForced). Bubble Tea's own handler
// is disabled because it is one-shot and skips Update, see signalQuitFilter.
var runTeaProgram = func(model *Model) (tea.Model, error) {
	return runWatchedProgram(newProgram(model), model)
}

// newProgram builds the Bubble Tea program for model with the signal filter
// installed and Bubble Tea's own signal handler disabled (the caller owns
// signals, see watchTerminationSignals). It is the one constructor for
// production and tests, so a test that drives the real event loop (with its own
// input and output) exercises exactly the wiring the binary uses. Extra options
// come after the built-in ones.
func newProgram(model tea.Model, opts ...tea.ProgramOption) *tea.Program {
	base := []tea.ProgramOption{tea.WithFilter(signalQuitFilter), tea.WithoutSignalHandler()}
	return tea.NewProgram(model, append(base, opts...)...)
}

// runProgram runs one Bubble Tea program and reports the error the model was
// still displaying when it exited. The TUI draws on the alternate screen,
// which the terminal discards on exit, so a trace that failed to start used to
// vanish without trace the moment the user left the error view: back in a
// clean shell, no rows, no message, exit status 0. Returning it makes cmd/ior
// print "Failed to run: ..." on stderr and exit non-zero, the same as the raw
// modes do for the identical failure.
//
// Every exported entry point must go through here rather than calling
// tea.NewProgram itself, which is what TestExportedEntryPointsReportTheError
// pins - testing runProgram alone leaves the entry points free to bypass it.
//
// After the program returns, an active recording is finalised as a safety net
// (finaliseRecording), so no exit path leaves an orphan ior-recording-*.tmp.
func runProgram(model *Model) error {
	final, err := runTeaProgramQuietly(model)
	if err == nil {
		err = finalModelError(final)
	}
	return finaliseRecording(model, err)
}

// runTeaProgramQuietly runs the program with the standard logger discarded.
// Bubble Tea owns the terminal for the whole run, so a stray log.Print from
// any goroutine - the model's Update or a trace running underneath it - would
// write over the rendered screen. The previous output is restored on return,
// so the "Failed to run: ..." report after the program exits is unaffected.
func runTeaProgramQuietly(model *Model) (tea.Model, error) {
	previous := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(previous)
	return runTeaProgram(model)
}

// finalModelError extracts the error a finished program's model was showing.
// A model of another type reports nothing rather than panicking: Bubble Tea
// returns whatever the last Update handed back, and a future refactor that
// swaps the returned type must not turn a clean exit into a crash.
func finalModelError(final tea.Model) error {
	model, ok := final.(*Model)
	if !ok {
		return nil
	}
	return model.lastErr
}

// NewTestFlamesModel builds the test-flames dashboard model without running the
// Bubble Tea program. It shares construction with
// RunTestFlamesWithTraceStarterConfig so in-process tests (teatest) exercise the
// exact same model wiring that `--testflames`/`--testliveflames` use.
//
// There is no attach target here: the data is seeded synthetically, so the
// model only needs to skip the PID picker. It must NOT inherit a pid filter
// from that decision — the seeded rows carry synthetic pids (2001-2004), so a
// filter of pid=1 would hide every stream row and export nothing but a CSV
// header. Any real -pid/-tid the user passed is still honoured.
//
// The raw -pid/-tid values are passed straight through: with initialPID -1
// newModelWithRuntimeConfig runs them through resolveStartupPIDFilters, the
// same helper the production path uses, which only normalises non-positive
// values to -1 here (there is no attach pid that could differ from -pid and
// clear the tid). So -pid and -tid combine here exactly as they do for a real
// `ior -pid P -tid T` startup.
func NewTestFlamesModel(cfg flags.Config, starter TraceStarter) *Model {
	model := newModelWithRuntimeConfig(modelStartup{
		initialPID:    -1,
		skipPicker:    true,
		filter:        filterFromConfig(cfg),
		pidFilter:     cfg.PidFilter,
		tidFilter:     cfg.TidFilter,
		exportEnabled: cfg.TUIExportEnable,
		startTrace:    starter,
	})
	model.dashboard.SetAutoResetInterval(cfg.ResetTimer)
	// Apply the configurable fast-refresh cadence from the CLI flag.
	model.dashboard.SetFastRefreshInterval(cfg.TUIFastRefreshInterval)
	return model
}

// RunTestFlamesWithTraceStarterConfig starts test-flames mode with explicit runtime flags.
func RunTestFlamesWithTraceStarterConfig(cfg flags.Config, starter TraceStarter) error {
	return runProgram(NewTestFlamesModel(cfg, starter))
}

// keyboardState groups keyboard event tracking and press-suppression fields.
// These fields are read and written exclusively by keys_normalize.go methods.
type keyboardState struct {
	enhancements      tea.KeyboardEnhancementsMsg
	enhancementsKnown bool
	// pressed is the set of physical keys whose press was delivered and whose
	// release has not arrived yet; see normalizeKeyEvent. Lazily allocated.
	pressed map[rune]struct{}
	// Some terminals emit release+press for a single physical key event.
	// When we fallback-handle a release as a press, suppress the immediate
	// matching press to avoid double-handling.
	suppressID    string
	suppressUntil time.Time
}

// processState groups the active PID/TID filter values. The picker return
// bookmark used to restore them after a cancelled re-selection lives in
// screenRouter.
type processState struct {
	pid int
	tid int
}

// Model is the top-level Bubble Tea model that routes between PID picker and
// dashboard. It delegates filter management to filterStack, trace lifecycle
// to traceLifecycle, and screen transitions to screenRouter.
//
// Receiver policy: every method takes *Model, so *Model (not Model) is the
// Bubble Tea model handed to tea.NewProgram - the same policy the stream
// tab's model already follows (internal/tui/eventstream). The mixed
// value/pointer receivers this type used to have worked only while every
// value happened to be addressable: the value-receiver Update called
// pointer-receiver mutators (tracer, filter stack, dashboard sub-model) on
// its local copy, so any non-addressable or later-copied Model silently
// lost those mutations.
type Model struct {
	pidPicker   pidpicker.Model
	dashboard   *dashboardui.Model
	exporter    tuiexport.Model
	probeModal  probes.Model
	filterModal tracefilterui.Model
	recordModal recordingModal
	runtime     *runtimeBindings

	keys KeyMap

	helpOverlayVisible bool

	width    int
	height   int
	quitting bool
	shutdown runtime.TraceShutdownProgress

	attaching bool
	spin      spinner.Model
	lastErr   error
	errorKind errorScreenKind

	// tracer owns trace start/stop and the active context.CancelFunc.
	tracer traceLifecycle
	// filters owns the filter chain, undo history, and label stack.
	filters filterStack
	// router owns the active screen and the pending picker return; Model
	// reads it and changes it only through its transition methods.
	router screenRouter

	proc          processState
	exportEnabled bool
	isDark        bool
	focused       bool
	// familyRun is the family attach/detach batch in flight (see
	// startFamilyBatch); it lives here, not in the probes modal, because the
	// modal is rebuilt on every open.
	familyRun familyRunState
	// bulkRun is the all-on/all-off walk in flight (see startSetAll), kept
	// here for the same reason.
	bulkRun bulkRunState

	kb keyboardState
}

// Quitting reports whether the model has begun shutting down (the user pressed
// the quit key). Exposed for in-process tests that assert terminal state via
// teatest's FinalModel.
func (m *Model) Quitting() bool {
	return m.quitting
}

// NewModel creates the top-level TUI model with default runtime flags.
// Prefer NewModelWithConfig to pass parsed CLI config explicitly.
func NewModel(initialPID int, startTrace TraceStarter) *Model {
	return NewModelWithConfig(flags.NewFlags(), initialPID, startTrace)
}

// NewModelWithConfig creates the top-level TUI model with explicit runtime flags.
func NewModelWithConfig(cfg flags.Config, initialPID int, startTrace TraceStarter) *Model {
	model := newModelWithRuntimeConfig(modelStartup{
		initialPID:    initialPID,
		filter:        filterFromConfig(cfg),
		pidFilter:     cfg.PidFilter,
		tidFilter:     cfg.TidFilter,
		exportEnabled: cfg.TUIExportEnable,
		startTrace:    startTrace,
	})
	// Seed the dashboard's auto-reset cadence from the parsed CLI flag
	// (default DefaultResetTimer; 0 disables). The dashboard's Init()
	// requests the underlying tea.Tick (through an arm message its Update
	// handles) when the dashboard becomes active.
	model.dashboard.SetAutoResetInterval(cfg.ResetTimer)
	return model
}

// modelStartup carries the startup wiring for newModelWithRuntimeConfig.
// It exists to keep the "skip the PID picker" decision separate from the
// pid filter: both used to be derived from a single initialPID argument, so
// modes that only wanted to skip the picker (test-flames) silently pinned the
// stream to pid=1 as well.
type modelStartup struct {
	// initialPID is a genuine attach target. When > 0 it both seeds the
	// pid filter and skips the picker. It clears tidFilter only when it
	// differs from pidFilter (see resolveStartupPIDFilters). Use -1 for
	// "no attach target".
	initialPID int
	// skipPicker starts on the dashboard and begins tracing immediately
	// without an attach target, for modes whose data is seeded rather than
	// attached. It has no effect on the filters.
	skipPicker bool
	// filter is the startup global filter (built from the CLI config).
	filter globalfilter.Filter
	// pidFilter/tidFilter are the CLI -pid/-tid values (-1 = no filter). A
	// positive tidFilter also skips the picker (see initialScreen).
	pidFilter int
	tidFilter int
	// exportEnabled mirrors -tuiExport.
	exportEnabled bool
	startTrace    TraceStarter
}

func newModelWithRuntimeConfig(startup modelStartup) *Model {
	common.ApplyPalette(true)

	keys := Keys
	if !startup.exportEnabled {
		keys.Export = key.NewBinding()
	}

	rt := newRuntimeBindings()
	pidFilter, tidFilter := resolveStartupPIDFilters(startup.initialPID, startup.pidFilter, startup.tidFilter)
	// Pass 0 for fastRefreshMs so the dashboard uses the package-level default
	// (200 ms). Callers that hold a flags.Config can override this via
	// SetFastRefreshInterval after construction.
	dashboard := newDashboardWithRuntime(rt, pidFilter, keys, 0)

	spin := spinner.New()
	spin.Spinner = spinner.MiniDot

	model := &Model{
		pidPicker:     pidpicker.New().SetDarkMode(true),
		dashboard:     dashboard,
		exporter:      tuiexport.NewModel(),
		probeModal:    probes.NewModel(rt.currentProbeManager()).SetDarkMode(true),
		filterModal:   tracefilterui.NewModel().SetDarkMode(true),
		recordModal:   newRecordingModal().SetDarkMode(true),
		runtime:       rt,
		keys:          keys,
		spin:          spin,
		tracer:        newTraceLifecycle(startup.startTrace),
		filters:       newFilterStack(startup.filter),
		router:        newScreenRouter(initialScreen(startup)),
		exportEnabled: startup.exportEnabled,
		isDark:        true,
		focused:       true,
	}
	model.setProcessFilters(pidFilter, tidFilter)

	// A startup that skips the picker begins tracing as soon as Update handles
	// Init's initialTraceStartMsg, so it starts in the attaching state.
	model.attaching = model.router.current() == ScreenDashboard

	return model
}

// initialScreen picks the first screen: the dashboard when startup has an
// attach target or explicitly skips the picker, otherwise the PID picker.
//
// A -tid given without -pid is an attach target as well: the thread id names
// the process to trace, so the picker would only ask for something the user
// already answered - and its PID result (handlePidSelected) discards the tid,
// turning `-tid T` into a whole-process trace of whatever was picked. The
// trace then starts with just the TID predicate, exactly as headless mode does.
func initialScreen(startup modelStartup) Screen {
	if startup.initialPID > 0 || startup.skipPicker || startup.tidFilter > 0 {
		return ScreenDashboard
	}
	return ScreenPIDPicker
}

// resolveStartupPIDFilters computes the effective pid/tid filter values from
// the startup arguments. An initialPID that differs from the configured -pid
// is a different attach target than the one -tid was given for, so it
// overrides the config PID filter and clears the TID filter. When initialPID
// is the configured -pid itself (the production `ior -pid P -tid T` path,
// where newRunModel passes cfg.PidFilter for both), the -tid is kept: it used
// to be dropped unconditionally, so the first TraceRequest covered the whole
// process instead of the one thread the user named.
func resolveStartupPIDFilters(initialPID, startupPidFilter, startupTidFilter int) (pid, tid int) {
	pid = selectedPIDFilter(startupPidFilter)
	tid = selectedPIDFilter(startupTidFilter)
	if initialPID > 0 {
		if selectedPIDFilter(initialPID) != pid {
			tid = -1
		}
		pid = selectedPIDFilter(initialPID)
	}
	return pid, tid
}

// newDashboardWithRuntime creates a dark-mode dashboard bound to the given
// runtime and pre-configured with the initial PID filter. fastRefreshMs
// controls the high-frequency tick cadence for stream and flame tabs; pass 0
// to use the package-level default (200 ms).
func newDashboardWithRuntime(rt *runtimeBindings, pidFilter int, keys KeyMap, fastRefreshMs int) *dashboardui.Model {
	dashboard := dashboardui.NewModelWithConfig(lateBoundDashboardSource{runtime: rt}, rt.eventStreamSource(), 1000, fastRefreshMs, keys)
	dashboard.SetDarkMode(true)
	dashboard.SetPidFilter(pidFilter)
	return dashboard
}

// Init initializes the active child model and requests the startup trace.
//
// Init only reads the model. Starting a trace stores its cancel func and
// shutdown reporter on the tracer, so a startup that skips the picker asks
// Update to do it through an initialTraceStartMsg (handleInitialTraceStart)
// instead of calling beginTraceCmd here. Every mutation of the model thus
// happens on Update, the one place Bubble Tea serialises them.
func (m *Model) Init() tea.Cmd {
	sizeCmd := initialWindowSizeCmd()
	if m.attachingOnDashboard() {
		return tea.Batch(sizeCmd, tea.RequestWindowSize, tea.RequestBackgroundColor, m.spin.Tick, initialTraceStartCmd)
	}
	return tea.Batch(sizeCmd, tea.RequestWindowSize, tea.RequestBackgroundColor, m.pidPicker.Init())
}

// attachingOnDashboard reports whether the dashboard is shown while a trace
// is still being attached: the startup state of a picker-skipping run and the
// state every trace restart enters until TracingStartedMsg arrives.
func (m *Model) attachingOnDashboard() bool {
	return m.router.current() == ScreenDashboard && m.attaching
}

// initialTraceStartMsg asks Update to start the trace a picker-skipping
// startup (`ior -pid N`, test-flames) begins in. Init emits it rather than
// starting the trace itself so Init stays side-effect free.
type initialTraceStartMsg struct{}

func initialTraceStartCmd() tea.Msg { return initialTraceStartMsg{} }

// handleInitialTraceStart starts the startup trace Init requested, under the
// same condition Init requested it (dashboard, attaching). A request that is
// no longer wanted is dropped: the user quit before it arrived (the quit path
// found no session to stop, so starting one now would outlive the program), or
// a session is already running (a repeated Init must not restart it).
func (m *Model) handleInitialTraceStart() (tea.Model, tea.Cmd) {
	if !m.attachingOnDashboard() || m.quitting || m.tracer.running() {
		return m, nil
	}
	return m, m.beginTraceCmd()
}

// fallbackWindowSizeMsg carries the viewport size initialWindowSizeCmd guesses
// when the terminal cannot be queried. It is a distinct type from
// tea.WindowSizeMsg so Update can tell a guess from a real size and refuse to
// let the guess win.
//
// Init batches this cmd alongside tea.RequestWindowSize, and bubbletea also
// sends a WindowSizeMsg of its own from checkResize. Both are asynchronous, so
// nothing orders them: when stdout is not a TTY the guess is
// common.EffectiveViewport's 80x24 default, and if it landed last it would
// clobber the real terminal size for the rest of the run. Every width-dependent
// rendering decision then flips with it - the dashboard's tab bar abbreviates
// below 90 columns, and syscallColumns returns 9 columns below 140 and 12
// at or above.
type fallbackWindowSizeMsg tea.WindowSizeMsg

// applyWindowSize records a viewport size and forwards it to the active model.
func (m *Model) applyWindowSize(msg tea.WindowSizeMsg) (tea.Model, tea.Cmd, bool) {
	m.width = msg.Width
	m.height = msg.Height
	// The probes modal budgets its rows from the same effective viewport View
	// renders into, so its scroll offset matches the rows actually drawn.
	m.probeModal = m.probeModal.SetSize(common.EffectiveViewport(msg.Width, msg.Height))
	next, cmd := m.updateActiveModel(msg)
	return next, cmd, true
}

func initialWindowSizeCmd() tea.Cmd {
	return func() tea.Msg {
		width, height := common.EffectiveViewport(0, 0)
		return fallbackWindowSizeMsg{Width: width, Height: height}
	}
}

// Update routes messages, transitions screens, and manages tracing startup state.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	normalizedMsg, ok := m.keyNormalizer(msg)
	if !ok {
		return m, nil
	}
	msg = normalizedMsg

	// Mouse input is positional: it only means something to what is drawn
	// under the pointer. While an overlay, modal or full-screen view covers
	// the dashboard, a click would otherwise land on the tab hidden behind it
	// (zooming the Flame tab, say) and only show up once the overlay closed.
	if isMouseMsg(msg) && m.overlayCoversScreen() {
		return m, nil
	}

	// A paste is typing, so it only means something to a text input that is on
	// screen. While the shutdown or attaching screen, the error view or the
	// help overlay covers the screens, a modal or input hidden behind must not
	// receive it (the keys they would have got are swallowed the same way).
	if _, isPaste := msg.(tea.PasteMsg); isPaste && m.textlessViewCovers() {
		return m, nil
	}

	if handled, cmd := m.dashboard.HandleFlameRefreshCompletion(msg, m.canApplyFlameRefresh()); handled {
		return m, cmd
	}
	if next, cmd, handled := m.dispatchTypedMsg(msg); handled {
		return next, cmd
	}
	if next, cmd, handled := m.dispatchAppMsg(msg); handled {
		return next, cmd
	}

	if next, cmd, handled := m.handleModalDispatch(msg); handled {
		return next, cmd
	}

	return m.updateActiveModel(msg)
}

// canApplyFlameRefresh reports whether the dashboard itself is visible and
// able to receive the animation ticks a newly applied snapshot may schedule.
// Hidden completions are still consumed by their persistent dashboard owner,
// but are discarded after releasing the matching in-flight slot.
func (m *Model) canApplyFlameRefresh() bool {
	return m.router.current() == ScreenDashboard && !m.overlayCoversScreen()
}

// overlayCoversScreen reports whether something drawn by View replaces or
// sits on top of the active screen, so that the screen behind it is not what
// the user is looking at: a view that takes no text (textlessViewCovers) or a
// modal (modalVisible). It mirrors the precedence of View, and is the single
// place that decides which input positional events (mouse) must not reach the
// hidden screen and when an async result may not be applied to it. Paste
// drops on textlessViewCovers alone, from the same helper, so a new overlay
// is added to exactly one of the two groups and both gates see it
// (TestOverlayPredicatesCoverEveryOverlayState).
func (m *Model) overlayCoversScreen() bool {
	return m.textlessViewCovers() || m.modalVisible()
}

// textlessViewCovers reports whether the shutdown or attaching screen, the
// full-screen error view or the help overlay is drawn. None of them has a text
// input; they consume keys themselves (Update gives them precedence), so a
// paste, which is a single message instead of keys, must be dropped rather
// than reach a modal or input hiding underneath.
func (m *Model) textlessViewCovers() bool {
	return m.quitting || m.attaching || m.lastErr != nil || m.helpOverlayVisible
}

// modalVisible reports whether the filter, record, probe or export modal is
// open. Modals own keys and pastes themselves, so a paste is not dropped for
// them, but the positional events and async results still must not reach
// the dashboard behind.
func (m *Model) modalVisible() bool {
	return m.filterModal.Visible() ||
		m.recordModal.Visible() ||
		m.probeModal.Visible() ||
		m.exporter.Visible()
}

// isMouseMsg reports whether msg is any pointer event: click, release,
// motion or wheel.
func isMouseMsg(msg tea.Msg) bool {
	switch msg.(type) {
	case tea.MouseClickMsg, tea.MouseReleaseMsg, tea.MouseMotionMsg, tea.MouseWheelMsg:
		return true
	}
	return false
}

// dispatchTypedMsg handles all typed message cases that require no modal check.
// Returns (model, cmd, true) when the message was consumed, or (_, _, false)
// to fall through to modal dispatch and then active-model routing.
func (m *Model) dispatchTypedMsg(msg tea.Msg) (tea.Model, tea.Cmd, bool) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		return m.applyWindowSize(msg)
	case fallbackWindowSizeMsg:
		// Only fills in a size nothing else supplied. A real WindowSizeMsg
		// already applied wins regardless of which arrived first.
		if m.width > 0 && m.height > 0 {
			return m, nil, true
		}
		return m.applyWindowSize(tea.WindowSizeMsg(msg))
	case signalQuitMsg:
		return m.handleSignalQuit()
	case tea.BackgroundColorMsg:
		m.applyTheme(msg.IsDark())
		return m, nil, true
	case tea.KeyboardEnhancementsMsg:
		m.kb.enhancements = msg
		m.kb.enhancementsKnown = true
		return m, nil, true
	case tea.FocusMsg:
		next, cmd := m.handleFocusMsg()
		return next, cmd, true
	case tea.BlurMsg:
		m.focused = false
		// SetFocused returns nil on blur but still bumps the auto-reset generation so
		// that any in-flight tick scheduled before the blur is ignored.
		m.dashboard.SetFocused(false)
		return m, nil, true
	case tea.KeyPressMsg:
		if m.quitting {
			return m.handleKeyWhileShuttingDown(msg)
		}
		if next, cmd, handled := m.handleGlobalKeyPress(msg); handled {
			return next, cmd, true
		}
		return m, nil, false
	}
	return m, nil, false
}

// dispatchAppMsg handles application-level message types (export, probe, trace,
// filter) that are not tea framework messages.
// It is called after dispatchTypedMsg returns unhandled for non-framework types.
// The work is split by area so each switch stays small: export and probe/PID
// selection messages first, then trace-lifecycle and global-filter messages.
func (m *Model) dispatchAppMsg(msg tea.Msg) (tea.Model, tea.Cmd, bool) {
	if next, cmd, handled := m.dispatchExportMsg(msg); handled {
		return next, cmd, true
	}
	if next, cmd, handled := m.dispatchSelectionMsg(msg); handled {
		return next, cmd, true
	}
	if next, cmd, handled := m.dispatchTraceMsg(msg); handled {
		return next, cmd, true
	}
	return m.dispatchFilterMsg(msg)
}

// dispatchExportMsg handles the CSV export request and its completion/failure
// results.
func (m *Model) dispatchExportMsg(msg tea.Msg) (tea.Model, tea.Cmd, bool) {
	switch msg := msg.(type) {
	case tuiexport.RequestMsg:
		// Capture the export inputs HERE, on the Update goroutine: the command
		// closure below runs on its own goroutine, and reading the live model
		// from it would race with Update/View mutations.
		source, filter, exportDir := m.dashboard.ExportStreamCSVInputs()
		return m, runExportCmd(m.exportEnabled, msg.Option, source, filter, exportDir), true
	case tuiexport.CompletedMsg:
		var cmd tea.Cmd
		m.exporter, cmd = m.exporter.Update(msg)
		return m, cmd, true
	case tuiexport.FailedMsg:
		var cmd tea.Cmd
		m.exporter, cmd = m.exporter.Update(msg)
		return m, cmd, true
	}
	return m, nil, false
}

// dispatchSelectionMsg handles probe/family/all-on-off toggles, family batch progress and
// the PID/TID picker results.
func (m *Model) dispatchSelectionMsg(msg tea.Msg) (tea.Model, tea.Cmd, bool) {
	switch msg := msg.(type) {
	case probes.ProbeToggledMsg:
		next, cmd := m.handleProbeToggledMsg(msg)
		return next, cmd, true
	case probes.FamilyBatchRequestMsg:
		return m, m.startFamilyBatch(msg), true
	case probes.SetAllRequestMsg:
		return m, m.startSetAll(msg), true
	case probes.FamilyBatchProgressMsg:
		return m, m.handleFamilyBatchProgress(msg), true
	case probes.FamilyToggledMsg:
		next, cmd := m.handleFamilyToggledMsg(msg)
		return next, cmd, true
	case PidSelectedMsg:
		next, cmd := m.handlePidSelected(msg)
		return next, cmd, true
	case TidSelectedMsg:
		next, cmd := m.handleTidSelected(msg)
		return next, cmd, true
	}
	return m, nil, false
}

// dispatchTraceMsg handles the trace-session lifecycle: initial start, the
// session-tagged start/error results, and shutdown progress.
func (m *Model) dispatchTraceMsg(msg tea.Msg) (tea.Model, tea.Cmd, bool) {
	switch msg := msg.(type) {
	case initialTraceStartMsg:
		next, cmd := m.handleInitialTraceStart()
		return next, cmd, true
	case traceSessionResultMsg:
		// A result of a session the lifecycle has since stopped or replaced
		// must not touch the model: a stale TracingStartedMsg would end the
		// new session's attaching state early and a stale error would show
		// the old session's failure against the new one.
		if !m.tracer.isCurrent(msg.session) {
			return m, nil, true
		}
		return m.dispatchAppMsg(msg.result)
	case TracingStartedMsg:
		next, cmd := m.handleTracingStarted()
		return next, cmd, true
	case TracingErrorMsg:
		m.attaching = false
		m.setError(msg.Err, errorScreenFatal)
		return m, nil, true
	case tracingShutdownProgressMsg:
		m.shutdown = msg.progress
		if msg.progress.Phase == runtime.TraceShutdownComplete {
			m.tracer.shutdownReporter = nil
			return m, tea.Quit, true
		}
		return m, m.tracer.waitForShutdownCmd(), true
	}
	return m, nil, false
}

// dispatchFilterMsg handles global-filter apply/undo requests and the
// open-in-editor request.
func (m *Model) dispatchFilterMsg(msg tea.Msg) (tea.Model, tea.Cmd, bool) {
	switch msg := msg.(type) {
	case messages.GlobalFilterRequestedMsg:
		next, cmd := m.applyGlobalFilter(msg.Filter, msg.Action)
		return next, cmd, true
	case messages.GlobalFilterUndoRequestedMsg:
		next, cmd := m.undoGlobalFilter()
		return next, cmd, true
	case messages.OpenEditorRequestedMsg:
		next, cmd := m.handleOpenEditorRequested(msg)
		return next, cmd, true
	}
	return m, nil, false
}

// handleFocusMsg restores focus and re-arms the dashboard's auto-reset tick.
func (m *Model) handleFocusMsg() (tea.Model, tea.Cmd) {
	m.focused = true
	// SetFocused returns a tea.Cmd that arms a fresh auto-reset tick
	// when focus returns (or nil if the timer is disabled). It also
	// bumps the dashboard's auto-reset generation so any tick that was
	// scheduled before the blur and is still in flight is dropped on arrival.
	focusCmd := m.dashboard.SetFocused(true)
	if m.router.current() == ScreenDashboard && !m.attaching {
		// Init() arms its own auto-reset chain (through an arm message
		// that supersedes any other live chain), so discard focusCmd here
		// to avoid two concurrently-live ticks racing the cadence.
		return m, tea.Batch(m.dashboard.Init(), m.dashboard.SnapshotCmd())
	}
	return m, focusCmd
}

// handleTracingStarted wires live sources into the dashboard once the trace
// starter confirms the trace is running.
func (m *Model) handleTracingStarted() (tea.Model, tea.Cmd) {
	m.attaching = false
	m.dashboard.SetStreamSource(m.runtime.eventStreamSource())
	m.dashboard.SetLiveTrie(m.runtime.liveTrie())
	m.dashboard.SetGlobalFilter(m.filters.current())
	// The new session's probe manager is published now, so this also gives a
	// family scope that was set while it attached its "not traced" hint.
	m.syncDashboardFilterState()
	m.rebindProbeModal()
	width, height := common.EffectiveViewport(m.width, m.height)
	next, sizeCmd := m.dashboard.Update(tea.WindowSizeMsg{Width: width, Height: height})
	m.dashboard = next.(*dashboardui.Model)
	return m, tea.Batch(sizeCmd, m.dashboard.Init(), m.dashboard.SnapshotCmd())
}

func (m *Model) keyNormalizer(msg tea.Msg) (tea.Msg, bool) {
	return m.normalizeKeyEvent(msg)
}

func (m *Model) canHandleDashboardShortcut(msg tea.KeyPressMsg) bool {
	return m.router.current() == ScreenDashboard &&
		!m.attaching &&
		m.lastErr == nil &&
		!m.filterModal.Visible() &&
		!m.exporter.Visible() &&
		!m.recordModal.Visible() &&
		!m.probeModal.Visible() &&
		!m.dashboard.BlocksGlobalShortcuts(msg)
}

func (m *Model) shouldCancelPickerToDashboard(msg tea.KeyPressMsg) bool {
	_, returning := m.router.pendingReturn()
	return m.router.current() == ScreenPIDPicker &&
		returning &&
		(isEscKey(msg) || key.Matches(msg, m.keys.Quit))
}

func (m *Model) shouldRouteQuitToEsc(msg tea.KeyPressMsg) bool {
	if m.helpOverlayVisible {
		return false
	}
	return m.router.current() == ScreenDashboard &&
		(m.filterModal.Visible() || m.exporter.Visible() || m.recordModal.Visible() || m.probeModal.Visible() || m.dashboard.BlocksGlobalShortcuts(msg))
}

// textInputFocused reports whether the screen or modal that currently receives
// keys has a focused text input. Modals sit on top of the screens, so a visible
// modal decides; otherwise the active screen does. It is only consulted for
// keys that reach handleGlobalKeyPress, which has already dealt with the error
// screen and the help overlay.
func (m *Model) textInputFocused() bool {
	switch {
	case m.attaching:
		return false
	case m.filterModal.Visible():
		return m.filterModal.TextInputFocused()
	case m.recordModal.Visible():
		return m.recordModal.TextInputFocused()
	case m.probeModal.Visible():
		return m.probeModal.TextInputFocused()
	case m.exporter.Visible():
		// The export option menu is a list, not a text input.
		return false
	}
	switch m.router.current() {
	case ScreenPIDPicker:
		return m.pidPicker.TextInputFocused()
	case ScreenDashboard:
		return m.dashboard.TextInputFocused()
	}
	return false
}

// isTypingIntoTextInput reports whether msg is printable text bound for a
// focused text input. Keys without text (ctrl+c, Esc, arrows) are never
// typing, so the global quit/cancel handling keeps working while an input has
// focus.
func (m *Model) isTypingIntoTextInput(msg tea.KeyPressMsg) bool {
	return msg.Key().Text != "" && m.textInputFocused()
}

// handleGlobalKeyPress intercepts keys that apply regardless of the active
// screen: help overlay toggle, quit, and dashboard-level shortcuts. Returns
// (model, cmd, handled); when handled is false the caller falls through to
// screen-specific routing.
func (m *Model) handleGlobalKeyPress(msg tea.KeyPressMsg) (tea.Model, tea.Cmd, bool) {
	// The full-screen error view owns its keys by construction: View renders
	// m.lastErr ahead of the help overlay, every modal and both screens, so
	// nothing else the model believes is open is on screen. Other keys still
	// reach whatever is behind it, which is pre-existing and harmless. Its
	// leaving keys are handled here, before any invisible overlay, modal or
	// picker can consume them.
	if m.lastErr != nil {
		if next, cmd, handled := m.handleErrorScreenKeyPress(msg); handled {
			return next, cmd, true
		}
	}
	if m.helpOverlayVisible {
		return m.handleHelpOverlayKeyPress(msg)
	}
	if m.isTypingIntoTextInput(msg) {
		// A focused text input owns every printable key: q and H are letters
		// of a process name, filename or search term there, not the quit and
		// help shortcuts. ctrl+c and Esc carry no text, so they still take
		// the paths below.
		return m, nil, false
	}
	if m.shouldCancelPickerToDashboard(msg) {
		next, cmd := m.cancelPickerToDashboard()
		return next, cmd, true
	}
	if key.Matches(msg, m.keys.Quit) {
		return m.handleQuitKeyPress(msg)
	}
	if isHelpOverlayOpenKey(msg) && !m.attaching && m.lastErr == nil {
		m.helpOverlayVisible = true
		return m, nil, true
	}
	if m.canHandleDashboardShortcut(msg) {
		if next, cmd, handled := m.handleDashboardShortcutKeys(msg); handled {
			return next, cmd, true
		}
	}
	return m, nil, false
}

// handleHelpOverlayKeyPress closes the help overlay on any quit/close/open
// key and consumes the event so it does not reach the underlying screen.
func (m *Model) handleHelpOverlayKeyPress(msg tea.KeyPressMsg) (tea.Model, tea.Cmd, bool) {
	if isHelpOverlayQuitKey(msg) || isHelpOverlayCloseKey(msg) || isHelpOverlayOpenKey(msg) {
		m.helpOverlayVisible = false
	}
	return m, nil, true
}

// handleQuitKeyPress handles the quit key. On the dashboard it stops the
// trace and quits; on the startup picker it quits with best-effort cleanup;
// when a modal is active the quit key is re-routed as Esc so modals close
// before the user needs to press q again.
func (m *Model) handleQuitKeyPress(msg tea.KeyPressMsg) (tea.Model, tea.Cmd, bool) {
	if m.attachingOnDashboard() {
		return m.quitWithBestEffortCleanup()
	}
	if m.canHandleDashboardShortcut(msg) {
		if err := m.stopRecordingAtQuit(); err != nil {
			m.setError(err, errorScreenRecoverable)
			return m, nil, true
		}
		return m.beginShutdown()
	}
	if m.shouldRouteQuitToEsc(msg) {
		return m.routeQuitAsEsc()
	}
	if _, returning := m.router.pendingReturn(); m.router.current() == ScreenPIDPicker && !returning {
		return m.quitFromStartupPicker()
	}
	return m, nil, true
}

// quitFromStartupPicker leaves the initial picker when there is no dashboard
// return bookmark. As with the error screen, cleanup is best effort: startup
// has no useful screen to remain on if cleanup itself fails.
func (m *Model) quitFromStartupPicker() (tea.Model, tea.Cmd, bool) {
	return m.quitWithBestEffortCleanup()
}

// handleErrorScreenKeyPress handles only the keys advertised by the error
// view. Quit always leaves the program. Esc dismisses an auxiliary recorder
// failure, but remains a quit for a fatal trace failure because there is no
// healthy dashboard to return to in that case.
func (m *Model) handleErrorScreenKeyPress(msg tea.KeyPressMsg) (tea.Model, tea.Cmd, bool) {
	if key.Matches(msg, m.keys.Quit) {
		return m.quitFromErrorScreen()
	}
	if !isEscKey(msg) {
		return m, nil, false
	}
	if m.errorKind == errorScreenRecoverable {
		return m.dismissRecoverableError()
	}
	return m.quitFromErrorScreen()
}

// dismissRecoverableError returns to the still-usable UI. A recorder failure
// may have occurred while cancelling a re-selection picker; resume that
// existing return route so its saved filters and trace restart are preserved.
func (m *Model) dismissRecoverableError() (tea.Model, tea.Cmd, bool) {
	m.clearError()
	if _, returning := m.router.pendingReturn(); m.router.current() == ScreenPIDPicker && returning {
		next, cmd := m.cancelPickerToDashboard()
		return next, cmd, true
	}
	return m, nil, true
}

// quitFromErrorScreen leaves the full-screen error view. It performs the same
// cleanup as the dashboard quit path - stop the recorder, cancel the trace
// context - but treats the recorder result as best effort: the dashboard path
// turns a recorderFinalise failure (a Stop error, or the unreported failure of
// a recording that aborted on its own) into an error screen and returns
// *without* quitting, and doing that here would swallow the key for a second
// error the user is already looking at. The displayed error stays in
// m.lastErr, which runProgram reports to the caller on exit; a recorder
// failure is joined to it rather than dropped (see quitWithBestEffortCleanup).
func (m *Model) quitFromErrorScreen() (tea.Model, tea.Cmd, bool) {
	return m.quitWithBestEffortCleanup()
}

// quitWithBestEffortCleanup stops the recorder and begins the shutdown no
// matter what the recorder says. Stop marks the failure it returns as reported
// (parquet.Recorder.TakeFailure will not hand it out again), so ignoring it
// here would make the lost recording vanish without a trace: no stream row
// (the trace is ending), no record modal, and the post-run safety net sees an
// inactive recorder. The failure is therefore kept in m.lastErr, joined to
// whatever the screen already shows, and leaves the program through
// runProgram like the signal quit's does.
func (m *Model) quitWithBestEffortCleanup() (tea.Model, tea.Cmd, bool) {
	m.keepRecordingStopFailure(m.stopRecordingAtQuit())
	return m.beginShutdown()
}

// keepRecordingStopFailure joins a recorder Stop failure (nil is a no-op) to
// m.lastErr without replacing the error already displayed. The process is
// leaving, so unlike the dashboard 'q' it cannot stay on an error screen; the
// recording the user asked for is lost, so the error must reach the exit
// status and stderr instead. Shared by the quit paths that do not stop on a
// failing recorder.
func (m *Model) keepRecordingStopFailure(err error) {
	if err != nil {
		m.lastErr = errors.Join(m.lastErr, fmt.Errorf("finalising Parquet recording: %w", err))
	}
}

func (m *Model) beginShutdown() (tea.Model, tea.Cmd, bool) {
	m.quitting = true
	m.shutdown = runtime.TraceShutdownProgress{Phase: runtime.TraceShutdownStopping}
	return m, tea.Batch(m.spin.Tick, m.tracer.stopAndWaitCmd()), true
}

func (m *Model) setError(err error, kind errorScreenKind) {
	m.lastErr = err
	m.errorKind = kind
}

func (m *Model) clearError() {
	m.lastErr = nil
	m.errorKind = errorScreenFatal
}

// routeQuitAsEsc synthesises an Esc key press and forwards it to whichever
// modal is currently visible, allowing quit to act as an intuitive close
// shortcut while a modal or sub-view is in focus.
func (m *Model) routeQuitAsEsc() (tea.Model, tea.Cmd, bool) {
	esc := tea.KeyPressMsg{Code: tea.KeyEsc}
	if m.probeModal.Visible() {
		next, cmd := m.updateProbeModal(esc)
		return next, cmd, true
	}
	if m.filterModal.Visible() {
		next, cmd := m.updateFilterModal(esc)
		return next, cmd, true
	}
	if m.recordModal.Visible() {
		next, cmd := m.updateRecordModal(esc)
		return next, cmd, true
	}
	if m.exporter.Visible() {
		next, cmd := m.updateExportModal(esc)
		return next, cmd, true
	}
	next, cmd := m.dashboard.Update(esc)
	m.dashboard = next.(*dashboardui.Model)
	return m, cmd, true
}

// handleDashboardShortcutKeys handles all dashboard-level hotkeys (export,
// record, probes, filter, undo, PID/TID reselect, auto-reset). The caller
// must verify canHandleDashboardShortcut before calling this method.
func (m *Model) handleDashboardShortcutKeys(msg tea.KeyPressMsg) (tea.Model, tea.Cmd, bool) {
	if m.exportEnabled && key.Matches(msg, m.keys.Export) {
		m.exporter = m.exporter.OpenFor(m.dashboard.StreamPaused())
		return m, nil, true
	}
	if key.Matches(msg, m.keys.Record) {
		return m.handleRecordKey()
	}
	if key.Matches(msg, m.keys.Probes) {
		width, height := common.EffectiveViewport(m.width, m.height)
		m.probeModal = m.newProbeModal().SetSize(width, height).Open()
		return m, nil, true
	}
	if key.Matches(msg, m.keys.Filter) {
		m.filterModal = m.filterModal.Open(m.filters.current())
		return m, nil, true
	}
	if key.Matches(msg, m.keys.FilterUndo) {
		next, cmd := m.undoGlobalFilter()
		return next, cmd, true
	}
	if key.Matches(msg, m.keys.NextFamily) {
		next, cmd := m.cycleFamilyScope(+1)
		return next, cmd, true
	}
	if key.Matches(msg, m.keys.PrevFamily) {
		next, cmd := m.cycleFamilyScope(-1)
		return next, cmd, true
	}
	if key.Matches(msg, m.keys.SelectPID) {
		next, cmd := m.reselectPID()
		return next, cmd, true
	}
	if key.Matches(msg, m.keys.SelectTID) {
		next, cmd := m.reselectTID()
		return next, cmd, true
	}
	if key.Matches(msg, m.keys.AutoReset) {
		next, cmd := m.cycleAutoResetInterval()
		return next, cmd, true
	}
	return m, nil, false
}

// handleRecordKey either stops an active recording or opens the record modal
// to start a new one.
func (m *Model) handleRecordKey() (tea.Model, tea.Cmd, bool) {
	if recorderActive(m.runtime.Recorder()) {
		if err := m.stopRecording(); err != nil {
			m.setError(err, errorScreenRecoverable)
		}
		return m, nil, true
	}
	m.recordModal = m.recordModal.Open(defaultParquetRecordingFilename())
	m.recordModal = m.recordModal.SetError(takePreviousRecordingFailure(m.runtime.Recorder()))
	return m, nil, true
}

// takePreviousRecordingFailure claims a failure of the previous recording
// that nobody has reported yet, wrapped for display, or returns nil. The
// event loop normally reports such a failure in the stream on the next
// event, but Start discards an untaken failure, so a recording started
// before any further event would otherwise lose it silently. TakeFailure is
// exclusive, so the failure is shown here or in the stream, never both.
func takePreviousRecordingFailure(recorder runtime.RecordingController) error {
	if recorder == nil {
		return nil
	}
	if err := recorder.TakeFailure(); err != nil {
		return fmt.Errorf("previous recording failed: %w", err)
	}
	return nil
}

// cycleAutoResetInterval advances the dashboard's auto-reset cadence to
// the next preset and re-arms the timer. The new cadence takes effect
// on the next tick; any in-flight tick from the previous cadence is
// dropped via the dashboard model's generation counter.
func (m *Model) cycleAutoResetInterval() (tea.Model, tea.Cmd) {
	next := nextAutoResetInterval(m.dashboard.AutoResetInterval())
	cmd := m.dashboard.SetAutoResetInterval(next)
	return m, cmd
}

// updateDashboardForModal keeps the dashboard behind a modal alive by
// forwarding the non-key messages it needs (ticks, spinner and async results).
// Keys and pastes belong to the modal. Mouse events never get here: Update
// drops them while any modal is visible (overlayCoversScreen), so a click
// cannot act on the tab the modal covers. A paste does get here (the modal
// dispatch runs for every message) and is reachable with a focused dashboard
// input behind the modal, so the guard is load-bearing, not just defence
// (TestPasteWhileModalCoversFocusedDashboardInputIsNotForwarded).
func (m *Model) updateDashboardForModal(msg tea.Msg) (*Model, tea.Cmd) {
	_, isKey := msg.(tea.KeyPressMsg)
	_, isPaste := msg.(tea.PasteMsg)
	if isKey || isPaste || m.router.current() != ScreenDashboard {
		return m, nil
	}
	next, cmd := m.dashboard.Update(msg)
	m.dashboard = next.(*dashboardui.Model)
	return m, cmd
}

func (m *Model) updateProbeModal(msg tea.Msg) (tea.Model, tea.Cmd) {
	m, dashboardCmd := m.updateDashboardForModal(msg)
	var cmd tea.Cmd
	m.probeModal, cmd = m.probeModal.Update(msg)
	return m, tea.Batch(dashboardCmd, cmd)
}

func (m *Model) updateFilterModal(msg tea.Msg) (tea.Model, tea.Cmd) {
	m, dashboardCmd := m.updateDashboardForModal(msg)
	wasVisible := m.filterModal.Visible()
	m.filterModal = m.filterModal.Update(msg)
	if wasVisible && !m.filterModal.Visible() {
		next, cmd := m.applyGlobalFilter(m.filterModal.Filter(), "")
		return next, tea.Batch(dashboardCmd, cmd)
	}
	return m, dashboardCmd
}

func (m *Model) updateExportModal(msg tea.Msg) (tea.Model, tea.Cmd) {
	m, dashboardCmd := m.updateDashboardForModal(msg)
	var cmd tea.Cmd
	m.exporter, cmd = m.exporter.Update(msg)
	return m, tea.Batch(dashboardCmd, cmd)
}

func (m *Model) updateRecordModal(msg tea.Msg) (tea.Model, tea.Cmd) {
	m, dashboardCmd := m.updateDashboardForModal(msg)
	var (
		path   string
		submit bool
	)
	m.recordModal, path, submit = m.recordModal.Update(msg)
	if !submit {
		return m, dashboardCmd
	}
	if err := recorderStart(m.runtime.Recorder(), path, m.syncDashboardFilterState); err != nil {
		m.recordModal = m.recordModal.SetError(err)
		return m, dashboardCmd
	}
	m.recordModal = m.recordModal.Close()
	return m, dashboardCmd
}

func (m *Model) handleModalDispatch(msg tea.Msg) (tea.Model, tea.Cmd, bool) {
	if m.quitting {
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd, true
	}
	if m.attaching {
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd, true
	}
	if m.filterModal.Visible() {
		next, cmd := m.updateFilterModal(msg)
		return next, cmd, true
	}
	if m.recordModal.Visible() {
		next, cmd := m.updateRecordModal(msg)
		return next, cmd, true
	}
	if m.probeModal.Visible() {
		next, cmd := m.updateProbeModal(msg)
		return next, cmd, true
	}
	if m.exporter.Visible() {
		next, cmd := m.updateExportModal(msg)
		return next, cmd, true
	}
	return m, nil, false
}

func (m *Model) updateActiveModel(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.router.current() {
	case ScreenPIDPicker:
		next, cmd := m.pidPicker.Update(msg)
		m.pidPicker = next.(pidpicker.Model)
		return m, cmd
	case ScreenDashboard:
		next, cmd := m.dashboard.Update(msg)
		m.dashboard = next.(*dashboardui.Model)
		return m, cmd
	default:
		return m, nil
	}
}

// handlePidSelected starts tracing the PID chosen in the picker, with no TID
// filter.
func (m *Model) handlePidSelected(msg PidSelectedMsg) (tea.Model, tea.Cmd) {
	return m.selectProcess(selectedPIDFilter(msg.Pid), -1)
}

// handleTidSelected starts tracing the TID chosen in the picker, within the
// PID the message carries or, when it carries none, the current one.
func (m *Model) handleTidSelected(msg TidSelectedMsg) (tea.Model, tea.Cmd) {
	pid := m.proc.pid
	if msg.Pid > 0 {
		pid = msg.Pid
	}
	return m.selectProcess(pid, selectedPIDFilter(msg.Tid))
}

// selectProcess is the shared body of handlePidSelected and
// handleTidSelected: it stops any running trace, resets the stream buffer,
// switches to the dashboard with the new pid/tid filters and starts a new
// trace. A recorder that fails to stop aborts the switch and surfaces a
// recoverable error, leaving the picker (and any return bookmark) as it was.
func (m *Model) selectProcess(pid, tid int) (tea.Model, tea.Cmd) {
	if err := m.stopRecording(); err != nil {
		m.setError(err, errorScreenRecoverable)
		return m, nil
	}
	// Stop before discarding the buffered rows, so the old session is told
	// to go away before its stream is reset (beginTraceCmd's stop is then a
	// no-op).
	m.tracer.stop()
	m.runtime.resetStreamBuffer()
	m.setProcessFilters(pid, tid)
	m.router.showDashboard()
	return m, m.restartTrace()
}

// reselectPID saves a return bookmark and switches to the PID picker so the
// user can choose a different process without losing dashboard state.
func (m *Model) reselectPID() (tea.Model, tea.Cmd) {
	return m.enterPicker(pidpicker.New())
}

// reselectTID saves a return bookmark and switches to the TID picker within
// the current PID so the user can narrow tracing to a specific thread.
func (m *Model) reselectTID() (tea.Model, tea.Cmd) {
	return m.enterPicker(pidpicker.NewTIDWithKeys(m.proc.pid, pidpicker.DefaultKeyMap()))
}

// enterPicker is the shared body of reselectPID and reselectTID: it stops the
// recorder and the trace, bookmarks the current pid/tid so Esc can return to
// the dashboard, resets every modal and shows picker, sized to the terminal.
// A recorder that fails to stop aborts the switch and surfaces a recoverable
// error on the dashboard, with the trace still running and no bookmark set.
func (m *Model) enterPicker(picker pidpicker.Model) (tea.Model, tea.Cmd) {
	if err := m.stopRecording(); err != nil {
		m.setError(err, errorScreenRecoverable)
		return m, nil
	}
	m.router.showPickerWithReturn(m.proc.pid, m.proc.tid)
	m.tracer.stop()
	m.attaching = false
	m.clearError()
	m.exporter = tuiexport.NewModel()
	m.probeModal = m.newProbeModal().SetSize(common.EffectiveViewport(m.width, m.height))
	m.filterModal = tracefilterui.NewModel().SetDarkMode(m.isDark)
	m.recordModal = newRecordingModal().SetDarkMode(m.isDark)
	var sizeCmd tea.Cmd
	m.pidPicker, sizeCmd = applyWindowSizeToPicker(picker.SetDarkMode(m.isDark), m.width, m.height)
	return m, tea.Batch(sizeCmd, m.pidPicker.Init())
}

func selectedPIDFilter(pid int) int {
	if pid <= 0 {
		return -1
	}
	return pid
}

// cancelPickerToDashboard restores the dashboard when the user presses Esc
// while in the picker after a reselectPID/reselectTID navigation. The return
// bookmark is only read here; showDashboard drops it once the transition
// happens, so a recorder failure leaves it in place for the next attempt.
func (m *Model) cancelPickerToDashboard() (tea.Model, tea.Cmd) {
	returnState, ok := m.router.pendingReturn()
	if !ok {
		return m, nil
	}
	if err := m.stopRecording(); err != nil {
		m.setError(err, errorScreenRecoverable)
		return m, nil
	}
	m.setProcessFilters(returnState.pidFilter, returnState.tidFilter)
	m.router.showDashboard()
	return m, m.restartTrace()
}

// restartTrace is the shared tail of every path that (re)starts tracing from
// a live model - process selection, picker cancel and the filter fallback: it
// enters the attaching state, clears any error and returns the spinner tick
// batched with the new trace's start command.
//
// It does not stop the previous session itself: beginTraceCmd owns that
// (traceLifecycle.beginCmd cancels any running session before starting the
// next), so at most one session is ever live. Callers that must quiesce the
// old session before touching state it feeds - selectProcess before
// resetStreamBuffer, the filter fallback before PrepareForTraceRestart - stop
// it explicitly first, and beginCmd's stop is then a no-op. With no tracer
// running it still starts one.
func (m *Model) restartTrace() tea.Cmd {
	m.attaching = true
	m.clearError()
	return tea.Batch(m.spin.Tick, m.beginTraceCmd())
}

// beginTraceCmd creates a tea.Cmd that starts the trace with the current
// runtime bindings and active filter. It cancels any previously running trace
// (traceLifecycle.beginCmd stops the old session first). It stores the new
// session's cancel func on the tracer, so it must only be called from Update
// (never from Init, which stays side-effect free) on the *Model Bubble Tea
// holds, so the cancel func survives to the next restart or quit.
//
// A probes modal left open across the session change follows it
// (rebindProbeModal): it would otherwise keep the old session's probe manager
// and session tag, so its toggles would hit a closed manager and their
// outcome would be dropped as stale. Right after the restart the new session
// has no manager yet, so the modal lists and toggles nothing until
// handleTracingStarted binds it to the manager the session published. No key
// path restarts while the modal is open today; this keeps it correct if one
// ever does.
func (m *Model) beginTraceCmd() tea.Cmd {
	cmd := m.tracer.beginCmd(m.runtime, m.filters.current())
	m.rebindProbeModal()
	return cmd
}

// filterFromConfig delegates to flags.BuildTraceFilter to resolve the active
// event filter from the CLI configuration fields.
func filterFromConfig(cfg flags.Config) globalfilter.Filter {
	return flags.BuildTraceFilter(cfg)
}

// setProcessFilters updates the proc pid/tid, rebinds filter process constraints,
// and synchronises the dashboard filter display.
func (m *Model) setProcessFilters(pid, tid int) {
	m.proc.pid = pid
	m.proc.tid = tid
	m.filters.rebindProcessFilters(pid, tid)
	// The notice describes a filter that was refused in favour of the one
	// showing. This changes the one showing - and restarts the trace - so the
	// notice would be left explaining a filter the user is no longer looking
	// at, in a session it never applied to.
	m.dashboard.SetFilterNotice("")
	m.syncDashboardFilterState()
}

// setGlobalFilter directly replaces the active filter, extracts the new
// PID/TID values, and synchronises the dashboard.
func (m *Model) setGlobalFilter(filter globalfilter.Filter) {
	m.filters.setGlobal(filter)
	m.proc.pid = m.filters.pidFromFilter()
	m.proc.tid = m.filters.tidFromFilter()
	m.syncDashboardFilterState()
}

// syncDashboardFilterState pushes all filter-related state (PID, global
// filter, label stack, recording status, family "not traced" hint) into the
// dashboard model so the status bar stays consistent. Every change of the
// filter on screen comes through here, which is what keeps the hint in step
// with the family scope (undo, PID/TID pick, pushed filters alike).
func (m *Model) syncDashboardFilterState() {
	m.dashboard.SetPidFilter(m.proc.pid)
	m.dashboard.SetGlobalFilter(m.filters.current())
	m.dashboard.SetFilterStack(m.filters.labelStack())
	m.dashboard.SetRecordingStatus(recorderStatus(m.runtime.Recorder()))
	m.refreshFamilyHint()
}

// refuseUnusableFilter reports whether filter is one the trace pipeline cannot
// honour, and when it is, says so instead of applying it.
//
// The check is globalfilter.ValidateTracepointFields - the same one
// setupTraceInfra runs before any BPF setup on the restart path. The live-swap
// path never restarts the trace, so nothing else on it would ever run that
// check: handing the running eventloop a comm pattern that does not fit
// MAX_PROGNAME_LENGTH - which the kernel's NUL makes one byte smaller than it
// looks - left a live-looking dashboard matching nothing at all, because
// matchString compares the pattern as a substring of a fixed-size kernel field
// that can never contain it. A refusal has to be visible or it is
// the same silence with an extra step, so this also writes the dashboard's
// filter notice: the reason on refusal, "" on every accepted filter. It is not
// the only writer - undoGlobalFilter and setProcessFilters clear it too,
// because both change the filter on screen without going through here - but it
// is the only one that ever sets a reason, and between the three the notice
// cannot outlive the filter it describes. (The family "not traced" hint is a
// separate dashboard slot that refreshFamilyHint owns; it never touches this
// notice.)
func (m *Model) refuseUnusableFilter(filter globalfilter.Filter) bool {
	err := filter.ValidateTracepointFields()
	if err == nil {
		m.dashboard.SetFilterNotice("")
		return false
	}
	m.dashboard.SetFilterNotice(fmt.Sprintf("FILTER REFUSED (%v) - keeping the previous filter", err))
	return true
}

// applyGlobalFilter pushes a new filter onto the filter stack, applies it
// in-place when possible, or falls back to a full trace restart. A filter the
// pipeline cannot honour is refused here, before it reaches the stack.
func (m *Model) applyGlobalFilter(filter globalfilter.Filter, action string) (tea.Model, tea.Cmd) {
	if m.refuseUnusableFilter(filter) {
		return m, nil
	}
	changed := m.filters.push(filter, action)
	m.setGlobalFilter(m.filters.current())
	return m.reapplyActiveFilter(changed)
}

// replaceGlobalFilter swaps the active global filter for a re-scope (e.g. the
// [/] family cycle) WITHOUT pushing onto the undo stack, then re-applies it to
// the running pipeline using the same live-swap/restart path as
// applyGlobalFilter. The stack label stays the same length across calls.
func (m *Model) replaceGlobalFilter(filter globalfilter.Filter) (tea.Model, tea.Cmd) {
	if m.refuseUnusableFilter(filter) {
		return m, nil
	}
	changed := !m.filters.current().Equal(filter)
	m.setGlobalFilter(filter)
	return m.reapplyActiveFilter(changed)
}

// reapplyActiveFilter pushes the current filter into the running pipeline,
// preferring an in-place live swap and falling back to a trace restart. It is
// the shared tail of applyGlobalFilter (push) and replaceGlobalFilter
// (setGlobal) so both routes drive the pipeline identically (DRY).
func (m *Model) reapplyActiveFilter(changed bool) (tea.Model, tea.Cmd) {
	if !changed || m.router.current() != ScreenDashboard {
		return m, nil
	}
	return m.applyFilterLiveOrRestart(m.filters.current())
}

// applyFilterLiveOrRestart hands filter to the running trace, preferring an
// in-place live swap (followed by resetAggregatesAfterLiveSwap) and falling
// back to restartTrace. It is the shared
// tail of reapplyActiveFilter and undoGlobalFilter, so every route that
// changes the active filter drives the pipeline - and resets the aggregates -
// identically.
func (m *Model) applyFilterLiveOrRestart(filter globalfilter.Filter) (tea.Model, tea.Cmd) {
	// Try the in-place swap first: hand the new filter to the running
	// eventloop via the registered setter. The BPF probes stay attached, so
	// the user no longer sees the multi-second 'Attaching tracepoints'
	// overlay on filter changes.
	if m.runtime.applyLiveFilter(filter) {
		m.clearError()
		return m, m.resetAggregatesAfterLiveSwap()
	}

	// Fallback: no trace currently running (e.g. first invocation), so
	// restart the pipeline so the new filter takes effect on the next
	// trace start. The old session is stopped - which also retires its
	// bindings view, so none of its rows is recorded from here on - before
	// the epoch advances and its aggregates are cleared; beginTraceCmd's
	// stop is then a no-op.
	m.tracer.stop()
	m.runtime.advanceFilterEpoch()
	m.dashboard.PrepareForTraceRestart()
	return m, m.restartTrace()
}

// resetAggregatesAfterLiveSwap starts a fresh baseline after an in-place
// filter swap, as a trace restart would with a new engine and trie: without
// it the Syscalls/Files/Processes tabs and the Flame tab keep every pre-swap
// event and mix it with the filtered ones that follow (apply comm~foo and the
// Processes tab still lists every other process). It must run after the
// setter, never before: resetting first would let events matched by the old
// filter land in the new baseline between the reset and the swap.
//
// The trie is reset and then re-bound so the flamegraph drops its zoom,
// selection and cached snapshot of frames that no longer exist. The stats
// reset goes through the dashboard's ResetStats, so a failed post-reset
// snapshot keeps the last good one exactly as a probe toggle or the refresh
// key do, and a refresh tick built before the swap cannot restore the
// pre-swap numbers.
func (m *Model) resetAggregatesAfterLiveSwap() tea.Cmd {
	m.dashboard.SetLiveTrie(m.runtime.resetLiveTrie())
	return m.dashboard.ResetStats()
}

// undoGlobalFilter pops the filter stack and re-applies the previous filter,
// using the same in-place swap or restart logic as applyGlobalFilter. The
// undo level is always consumed (so the label stack shrinks), but the pipeline
// is only touched when the filter really changes: a family re-scope replaces
// the active filter without pushing, so after Apply family=Network and '['
// back to all, the popped level equals the active filter, and re-applying it
// would wipe the stats, the flame trie and its zoom for nothing.
func (m *Model) undoGlobalFilter() (tea.Model, tea.Cmd) {
	before := m.filters.current()
	prev, ok := m.filters.pop()
	if !ok {
		return m, nil
	}
	// Only validated filters ever reach the stack (applyGlobalFilter refuses
	// the rest), so there is nothing to re-check here - but the filter on
	// screen is about to change, so a refusal notice describing the previous
	// one must not survive it.
	m.dashboard.SetFilterNotice("")
	m.setGlobalFilter(prev)
	if m.router.current() != ScreenDashboard || before.Equal(prev) {
		return m, nil
	}
	return m.applyFilterLiveOrRestart(prev)
}

// startRecording opens the parquet recorder at path and syncs dashboard status.
// Tests and the Model's record-modal handler call this method.
func (m *Model) startRecording(path string) error {
	return recorderStart(m.runtime.Recorder(), path, m.syncDashboardFilterState)
}

// stopRecording closes an active parquet recorder and syncs dashboard status.
// Tests and the quit/reselect paths call this method.
func (m *Model) stopRecording() error {
	return recorderStop(m.runtime.Recorder(), m.syncDashboardFilterState)
}

// stopRecordingAtQuit is stopRecording for the quit paths: it also reports a
// failure of an already dead recording that nothing has shown yet (see
// recorderFinalise).
func (m *Model) stopRecordingAtQuit() error {
	return recorderStopAtQuit(m.runtime.Recorder(), m.syncDashboardFilterState)
}

func (m *Model) applyTheme(isDark bool) {
	if m.isDark == isDark {
		return
	}
	m.isDark = isDark
	common.ApplyPalette(isDark)
	m.dashboard.SetDarkMode(isDark)
	m.pidPicker = m.pidPicker.SetDarkMode(isDark)
	m.probeModal = m.probeModal.SetDarkMode(isDark)
	m.filterModal = m.filterModal.SetDarkMode(isDark)
	m.recordModal = m.recordModal.SetDarkMode(isDark)
}

func (m *Model) windowTitle() string {
	if m.quitting {
		return "ior - shutting down"
	}
	switch m.router.current() {
	case ScreenPIDPicker:
		return "ior - select process"
	case ScreenDashboard:
		if m.proc.pid > 0 {
			return fmt.Sprintf("ior - tracing PID %d", m.proc.pid)
		}
	}
	return "ior - I/O Riot"
}

// View renders the currently active screen and startup overlay state.
func (m *Model) View() tea.View {
	title := m.windowTitle()
	if m.quitting {
		width, height := common.EffectiveViewport(m.width, m.height)
		theme := common.Current()
		line := m.shutdownView()
		return altScreenView(placeToViewport(width, height, theme.ScreenStyle.Render(theme.PanelStyle.Render(line))), title)
	}

	width, height := common.EffectiveViewport(m.width, m.height)

	if m.attaching {
		line := fmt.Sprintf("%s Attaching tracepoints...", m.spin.View())
		theme := common.Current()
		return altScreenView(placeToViewport(width, height, theme.ScreenStyle.Render(theme.PanelStyle.Render(line))), title)
	}

	if m.lastErr != nil {
		theme := common.Current()
		hint := "q / esc  quit"
		if m.errorKind == errorScreenRecoverable {
			hint = "esc  back  •  q  quit"
		}
		// Errors can echo traced or user-supplied paths; SanitizeLines keeps
		// intentional line breaks but no escape sequence.
		body := theme.ErrorStyle.Render(common.SanitizeLines(m.lastErr.Error())) + "\n\n" + theme.HelpBarStyle.Render(hint)
		return altScreenView(placeToViewport(width, height, theme.ScreenStyle.Render(body)), title)
	}
	if m.helpOverlayVisible {
		helpView := renderGlobalHelpOverlay(width, height, m.helpSections())
		return altScreenView(helpView, title)
	}

	switch m.router.current() {
	case ScreenPIDPicker:
		return m.viewPickerScreen(width, height, title)
	case ScreenDashboard:
		return m.viewDashboardScreen(width, height, title)
	default:
		return altScreenView("", title)
	}
}

func (m *Model) shutdownView() string {
	if m.shutdown.Phase == runtime.TraceShutdownReleasing {
		return fmt.Sprintf("%s Releasing remaining BPF resources...", m.spin.View())
	}
	if m.shutdown.Phase != runtime.TraceShutdownDetaching || m.shutdown.Total <= 0 {
		return fmt.Sprintf("%s Stopping trace and releasing BPF resources...", m.spin.View())
	}
	const barWidth = 28
	completed := min(m.shutdown.Completed, m.shutdown.Total)
	filled := completed * barWidth / m.shutdown.Total
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	return fmt.Sprintf("Detaching BPF probe pairs... %d/%d\n[%s]", completed, m.shutdown.Total, bar)
}

// viewPickerScreen renders the PID picker screen with optional export overlay.
func (m *Model) viewPickerScreen(width, height int, title string) tea.View {
	base := m.pidPicker.View().Content
	if m.exporter.Visible() {
		return altScreenView(placeToViewport(width, height, m.exporter.View(width, height)+"\n"+base), title)
	}
	return altScreenView(placeToViewport(width, height, base), title)
}

// viewDashboardScreen renders the dashboard screen with the appropriate modal
// overlay (filter, record, probes, export) if one is active.
func (m *Model) viewDashboardScreen(width, height int, title string) tea.View {
	base := m.dashboard.View().Content
	if m.filterModal.Visible() {
		return altScreenView(placeToViewport(width, height, m.filterModal.View(width, height)), title)
	}
	if m.recordModal.Visible() {
		return altScreenView(placeToViewport(width, height, m.recordModal.View(width, height)), title)
	}
	if m.probeModal.Visible() {
		return altScreenView(placeToViewport(width, height, m.probeModal.View(width, height)), title)
	}
	if m.exporter.Visible() {
		return altScreenView(placeToViewport(width, height, m.exporter.View(width, height)+"\n"+base), title)
	}
	return altScreenView(placeToViewport(width, height, base), title)
}

func isHelpOverlayOpenKey(msg tea.KeyPressMsg) bool {
	return msg.String() == "H"
}

func isEscKey(msg tea.KeyPressMsg) bool {
	return msg.Code == tea.KeyEsc || msg.String() == "esc"
}

func isHelpOverlayCloseKey(msg tea.KeyPressMsg) bool {
	return isEscKey(msg) || msg.String() == "?"
}

func isHelpOverlayQuitKey(msg tea.KeyPressMsg) bool {
	return msg.String() == "q"
}

// runExportCmd builds the export command for the chosen option. It takes the
// concrete export inputs (source, filter, directory) captured on the Update
// goroutine rather than a *dashboardui.Model: the closure runs on a Bubble
// Tea command goroutine, and the model's plain fields are mutated by
// Update/View with no lock. The Source itself is safe to read from any
// goroutine (Snapshot is RWMutex-guarded), so the captured inputs are the
// correct cross-goroutine boundary.
func runExportCmd(exportEnabled bool, option tuiexport.Option, source eventstream.Source, filter eventstream.Filter, exportDir string) tea.Cmd {
	return func() tea.Msg {
		if !exportEnabled {
			return tuiexport.FailedMsg{Err: fmt.Errorf("tui export is disabled by -tuiExport=false")}
		}
		switch option {
		case tuiexport.OptionCSV:
			path, err := eventstream.ExportSourceSnapshotToCSV(source, filter, exportDir, "")
			if err != nil {
				return tuiexport.FailedMsg{Err: err}
			}
			return tuiexport.CompletedMsg{Path: path}
		default:
			return tuiexport.FailedMsg{Err: fmt.Errorf("unknown export option")}
		}
	}
}

type lateBoundDashboardSource struct {
	runtime *runtimeBindings
}

// Snapshot returns a point-in-time dashboard snapshot from the underlying
// source, or (nil, nil) when no source is available. Errors are forwarded to
// the caller so they can decide how to handle a failed snapshot build.
func (s lateBoundDashboardSource) Snapshot() (*statsengine.Snapshot, error) {
	if s.runtime == nil {
		return nil, nil
	}
	source := s.runtime.dashboardSnapshotSource()
	if source == nil {
		return nil, nil
	}
	return source.Snapshot()
}

// Reset forwards to the underlying source; it is a no-op only while no source
// has been wired yet (before the trace starter publishes its stats engine).
func (s lateBoundDashboardSource) Reset() {
	if s.runtime == nil {
		return
	}
	source := s.runtime.dashboardSnapshotSource()
	if source == nil {
		return
	}
	source.Reset()
}

func placeToViewport(width, height int, content string) string {
	if width <= 0 || height <= 0 {
		return content
	}
	return lipgloss.Place(width, height, lipgloss.Left, lipgloss.Top, content)
}

// --- compile-time interface satisfaction assertions ---
//
// These blank-identifier assignments cause a build error if any concrete type
// drifts out of sync with the interface it claims to satisfy.

var (
	// *runtimeBindings provides the read side of the runtime contract. The
	// write side (RuntimePublisher) is only provided per session, by
	// traceSessionBindings (asserted in tracesession.go).
	_ runtime.RuntimeState = (*runtimeBindings)(nil)

	// lateBoundDashboardSource must satisfy the resettable snapshot-source
	// contract used by the dashboard model. It wraps the injected stats engine
	// and forwards calls through runtimeBindings so the dashboard source can
	// be wired before the actual engine is available.
	_ dashboardui.SnapshotSource       = lateBoundDashboardSource{}
	_ runtime.ResettableSnapshotSource = lateBoundDashboardSource{}
)

func altScreenView(content, title string) tea.View {
	view := tea.NewView(content)
	view.AltScreen = true
	view.ReportFocus = true
	view.MouseMode = tea.MouseModeCellMotion
	view.WindowTitle = title
	view.KeyboardEnhancements.ReportEventTypes = true
	return view
}
