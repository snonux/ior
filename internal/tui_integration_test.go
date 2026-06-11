package internal

// In-process TUI integration tests. These drive the whole Bubble Tea program
// through real key presses (via teatest) and assert on the rendered screen,
// complementing the per-component unit tests under internal/tui/... .
//
// They reuse the exact production seam used by `ior --testflames` /
// `--testliveflames`: the tuiTestFlamesStarter / tuiTestLiveFlamesStarter
// seeders feed synthetic data into the runtime bindings, and
// tui.NewTestFlamesModel builds the same dashboard model the CLI runs — minus
// program.Run(). No root and no eBPF are required, so the suite runs under
// `mage test` like any other unit test.
//
// teatest's Output() is Bubble Tea's raw, cursor-addressed terminal byte stream
// (frame-to-frame diffs, not full repaints), so substring-matching it directly
// is unreliable: a status line like "Selected: api" is split because the
// "Selected: " prefix is written once and only the changed suffix is rewritten
// on later frames. To get faithful, matchable frames we feed that byte stream
// into a charm.land/x/vt terminal emulator and assert on the reconstructed
// screen (Emulator.String()), which is what a user would actually see.
//
// Assertions target width-independent body tokens (e.g. "view:root",
// "Latency Histogram"). In --testflames mode the flamegraph trie, the stats
// engine, and the stream ring buffer are all seeded with the same synthetic
// workload (comms api/worker/ingest/batch), so every dashboard tab renders
// populated rows and the stream carries 40 buffered events. The stream view
// inherits the model's startup pid=1 filter, so its seeded rows only become
// visible once that filter is cleared.

import (
	"context"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	teatest "github.com/charmbracelet/x/exp/teatest/v2"
	"github.com/charmbracelet/x/vt"

	"ior/internal/flags"
	"ior/internal/probemanager"
	"ior/internal/runtime"
	"ior/internal/tui"
)

const (
	tuiTermWidth   = 160
	tuiTermHeight  = 48
	tuiWaitFor     = 6 * time.Second
	tuiWaitTick    = 25 * time.Millisecond
	tuiFinalWait   = 5 * time.Second
	tuiLiveWaitFor = 8 * time.Second
)

// tuiSession couples a running teatest program with a VT emulator that
// reconstructs the visible screen from the program's output stream.
type tuiSession struct {
	t   *testing.T
	tm  *teatest.TestModel
	em  *vt.Emulator
	out io.Reader
}

// tuiNewFlamesModel starts a static test-flames session (no root, no BPF).
func tuiNewFlamesModel(t *testing.T) *tuiSession {
	t.Helper()
	cfg := tuiTestConfig()
	return tuiNewSession(t, tui.NewTestFlamesModel(cfg, tuiTestFlamesStarter(cfg)))
}

// tuiNewLiveModel starts a live test-flames session whose synthetic trie is
// reshaped by a background goroutine every flags.LiveInterval (~200ms).
func tuiNewLiveModel(t *testing.T) *tuiSession {
	t.Helper()
	cfg := tuiTestConfig()
	return tuiNewSession(t, tui.NewTestFlamesModel(cfg, tuiTestLiveFlamesStarter(cfg)))
}

// tuiTestConfig returns the default CLI config with CSV export enabled so the
// export modal path is reachable.
func tuiTestConfig() flags.Config {
	cfg := flags.NewFlags()
	cfg.TUIExportEnable = true
	return cfg
}

// tuiNewPickerModel starts a session whose model begins on the PID picker
// screen. Passing initialPID=-1 to tui.NewModel selects the picker instead of
// the dashboard, so picker tests can assert the picker chrome and then select a
// PID to land on the populated dashboard seeded by tuiTestFlamesStarter.
func tuiNewPickerModel(t *testing.T) *tuiSession {
	t.Helper()
	cfg := tuiTestConfig()
	return tuiNewSession(t, tui.NewModel(-1, tuiTestFlamesStarter(cfg)))
}

// tuiFakeProbeManager is a deterministic in-test runtime.ProbeManager that
// renders a small, stable set of rows in the probes modal without any BPF.
// The real interface (internal/runtime/runtime.go) is:
//
//	States() []probemanager.ProbeState
//	Toggle(syscall string) error
//	ActiveCount() (int, int)
type tuiFakeProbeManager struct {
	states []probemanager.ProbeState
}

// tuiNewFakeProbeManager returns a fake probe manager with a couple of active
// probes so the probes modal renders non-empty rows and a "(N/N active)" title.
func tuiNewFakeProbeManager() tuiFakeProbeManager {
	return tuiFakeProbeManager{states: []probemanager.ProbeState{
		{Syscall: "read", Active: true},
		{Syscall: "write", Active: true},
		{Syscall: "openat", Active: false},
	}}
}

func (f tuiFakeProbeManager) States() []probemanager.ProbeState { return f.states }
func (f tuiFakeProbeManager) Toggle(string) error               { return nil }

// ActiveCount reports the number of active probes and the total.
func (f tuiFakeProbeManager) ActiveCount() (int, int) {
	active := 0
	for _, s := range f.states {
		if s.Active {
			active++
		}
	}
	return active, len(f.states)
}

// tuiTestFlamesStarterWithProbes behaves like tuiTestFlamesStarter (seeding the
// static flame/stats/stream sources) and additionally wires a deterministic
// fake probe manager via the runtime publisher's SetProbeManager, so pressing
// "o" opens a non-empty probes modal.
func tuiTestFlamesStarterWithProbes(cfg flags.Config) runtime.TraceStarter {
	base := tuiTestFlamesStarter(cfg)
	return func(ctx context.Context) error {
		if err := base(ctx); err != nil {
			return err
		}
		if bindings, ok := runtime.RuntimePublisherFromContext(ctx); ok {
			bindings.SetProbeManager(tuiNewFakeProbeManager())
		}
		return nil
	}
}

// tuiNewProbesModel starts a static test-flames session whose runtime also has
// a fake probe manager wired in, so the probes modal ("o") renders rows.
func tuiNewProbesModel(t *testing.T) *tuiSession {
	t.Helper()
	cfg := tuiTestConfig()
	return tuiNewSession(t, tui.NewTestFlamesModel(cfg, tuiTestFlamesStarterWithProbes(cfg)))
}

// tuiChdirTemp switches the test's working directory to a fresh temp dir (Go
// 1.24+ t.Chdir, auto-restored on cleanup) and returns it, isolating files
// written by recording/export submit tests. It returns the new directory.
func tuiChdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	return dir
}

func tuiNewSession(t *testing.T, m tui.Model) *tuiSession {
	t.Helper()
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(tuiTermWidth, tuiTermHeight))
	t.Cleanup(func() { _ = tm.Quit() })

	em := vt.NewEmulator(tuiTermWidth, tuiTermHeight)
	// Bubble Tea queries the terminal background colour (OSC 11) on startup; the
	// emulator answers via a synchronous reply pipe, so its Write blocks unless
	// someone drains the reply stream. Discard those replies in the background.
	// The goroutine is parked on a blocking Read and is reaped at process exit.
	go func() { _, _ = io.Copy(io.Discard, em) }()

	return &tuiSession{
		t:   t,
		tm:  tm,
		em:  em,
		out: tm.Output(),
	}
}

// pump feeds all currently-buffered program output into the emulator. teatest's
// output buffer drains on read, so this advances the reconstructed screen by
// whatever frames were produced since the last pump.
func (s *tuiSession) pump() {
	buf := make([]byte, 8192)
	for {
		n, err := s.out.Read(buf)
		if n > 0 {
			_, _ = s.em.Write(buf[:n])
		}
		if err != nil { // io.EOF once the buffer is drained
			return
		}
	}
}

// screen returns the current reconstructed screen as plain text.
func (s *tuiSession) screen() string {
	s.pump()
	return s.em.String()
}

// waitFor polls the reconstructed screen until every want substring is present,
// failing with the last screen on timeout.
func (s *tuiSession) waitFor(wants ...string) {
	s.t.Helper()
	deadline := time.Now().Add(tuiWaitFor)
	for {
		scr := s.screen()
		if tuiContainsAll(scr, wants...) {
			return
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("waitFor %q not met within %s.\n--- screen ---\n%s", wants, tuiWaitFor, scr)
		}
		time.Sleep(tuiWaitTick)
	}
}

func (s *tuiSession) typeStr(str string) { s.tm.Type(str) }
func (s *tuiSession) press(code rune)    { s.tm.Send(tea.KeyPressMsg{Code: code}) }
func (s *tuiSession) shiftTab()          { s.tm.Send(tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}) }

func tuiContainsAll(s string, wants ...string) bool {
	for _, w := range wants {
		if !strings.Contains(s, w) {
			return false
		}
	}
	return true
}

var tuiTotalRe = regexp.MustCompile(`total\(events\)=(\d+)`)

func (s *tuiSession) addTotals(set map[string]struct{}) {
	for _, m := range tuiTotalRe.FindAllStringSubmatch(s.screen(), -1) {
		set[m[1]] = struct{}{}
	}
}

// waitDistinctTotals polls the reconstructed screen until at least min distinct
// "total(events)=N" values have been observed (the live flamegraph's root total
// reshapes every tick) or timeout elapses, returning the set seen. It exits
// early once min is reached so the "updates are flowing" check stays fast.
func (s *tuiSession) waitDistinctTotals(min int, timeout time.Duration) map[string]struct{} {
	set := map[string]struct{}{}
	deadline := time.Now().Add(timeout)
	for {
		s.addTotals(set)
		if len(set) >= min || time.Now().After(deadline) {
			return set
		}
		time.Sleep(40 * time.Millisecond)
	}
}

// collectTotals samples distinct "total(events)=N" values over the full window
// d. Used to prove the total stays constant (<=1) while paused.
func (s *tuiSession) collectTotals(d time.Duration) map[string]struct{} {
	set := map[string]struct{}{}
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		s.addTotals(set)
		time.Sleep(40 * time.Millisecond)
	}
	return set
}

// --- Foundation -------------------------------------------------------------

func TestTUIIntegration_Launch_ShowsDashboardChrome(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root", "Selected: root", "press H for help")
}

func TestTUIIntegration_TabNav_NumberKeys(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	// Each tab is now seeded, so assert a stable column header plus a seeded
	// value rather than the old "no data" placeholders.
	steps := []struct {
		key   string
		wants []string
	}{
		{"2", []string{"Trends:", "worker/2002"}},             // Overview: top-processes line
		{"3", []string{"Syscall", "epoll_wait"}},              // Syscalls: header + seeded non-FS row
		{"4", []string{"Accesses", "Max Latency"}},            // Files: table headers
		{"5", []string{"Comm", "worker", "ingest"}},           // Processes: header + seeded comms
		{"6", []string{"Latency Histogram", "Gap Histogram"}}, // Latency+Gaps
		{"7", []string{"buffer:"}},                            // Stream chrome (rows filtered by pid=1)
		{"8", []string{"Family", "Polling"}},                  // Non-IO: header + seeded family
		{"1", []string{"view:root"}},                          // back to Flame
	}
	for _, step := range steps {
		s.typeStr(step.key)
		s.waitFor(step.wants...)
	}
}

func TestTUIIntegration_TabNav_TabAndShiftTab(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	// Start on Overview (avoids the flame tab consuming navigation keys), then
	// step forward with tab and back with shift+tab.
	s.typeStr("2")
	s.waitFor("Trends:")
	s.press(tea.KeyTab) // Overview -> Syscalls
	s.waitFor("Syscall", "epoll_wait")
	s.shiftTab() // Syscalls -> Overview
	s.waitFor("Trends:")
}

func TestTUIIntegration_HelpOverlay_Toggle(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("H")
	s.waitFor("Help", "Dashboard Tabs")
	s.press(tea.KeyEsc)
	s.waitFor("view:root") // overlay closed, flame visible again
}

func TestTUIIntegration_Quit_QExitsCleanly(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("q")
	s.tm.WaitFinished(t, teatest.WithFinalTimeout(tuiFinalWait))

	final, ok := s.tm.FinalModel(t, teatest.WithFinalTimeout(tuiFinalWait)).(tui.Model)
	if !ok {
		t.Fatalf("final model has unexpected type %T", s.tm.FinalModel(t))
	}
	if !final.Quitting() {
		t.Fatal("expected Quitting() to be true after pressing q")
	}
}

// --- Flamegraph -------------------------------------------------------------

func TestTUIIntegration_Flame_NavigateFrames(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("Selected: root")

	s.press(tea.KeyDown) // descend into first child
	s.waitFor("Selected: api")
	s.press(tea.KeyRight) // move to sibling
	s.waitFor("Selected: batch")
}

func TestTUIIntegration_Flame_ZoomInOut(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root", "Selected: root")

	s.press(tea.KeyDown) // select api
	s.waitFor("Selected: api")
	s.press(tea.KeyEnter) // zoom into api
	s.waitFor("view:root/api")
	s.press(tea.KeyBackspace) // zoom back out to root
	s.waitFor("view:root |")
}

func TestTUIIntegration_Flame_Search(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("Selected: root")

	s.typeStr("/") // open flame search
	s.waitFor("matches")
	s.typeStr("worker")
	s.press(tea.KeyEnter) // apply search
	s.waitFor(`Filter "worker"`, "matches")
}

func TestTUIIntegration_Flame_PauseResume(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("[LIVE]")

	s.press(tea.KeySpace)
	s.waitFor("[PAUSED]")
	s.press(tea.KeySpace)
	s.waitFor("[LIVE]")
}

// --- Stream (seeded ring buffer in test-flames mode) ------------------------

func TestTUIIntegration_Stream_RendersLiveChrome(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("7")
	s.waitFor("buffer:", "Comm", "Syscall")
	// The model starts with a pid=1 filter, which hides every seeded row
	// (all carry pids 2001-2004). Clear it via the stream filter modal
	// (f -> c clears all fields -> Esc applies) so the seeded rows render.
	s.typeStr("f")
	s.waitFor("j/k move")
	s.typeStr("c")
	s.press(tea.KeyEsc)
	// With the filter cleared, a seeded row (comm + syscall + path) is shown
	// alongside the unchanged "buffer:" chrome.
	s.waitFor("buffer:", "Filter: all", "batch", "/srv")
}

func TestTUIIntegration_Stream_FilterModal_OpenCancel(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("7")
	s.waitFor("buffer:")
	s.typeStr("f")
	s.waitFor("j/k move") // filter modal help line
	s.press(tea.KeyEsc)
	s.waitFor("buffer:") // modal closed, stream visible again
}

func TestTUIIntegration_Stream_ExportModal_OpenCancel(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("7")
	s.waitFor("buffer:")
	s.typeStr("e")
	s.waitFor("Export Stream CSV", "Enter confirm")
	s.press(tea.KeyEsc)
	s.waitFor("buffer:")
}

// --- Recording modal --------------------------------------------------------

func TestTUIIntegration_Recording_ModalOpenClose(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("R")
	s.waitFor("Start Parquet Recording", "Filename:")
	s.press(tea.KeyEsc)
	s.waitFor("view:root") // back to dashboard, no recording started
}

// --- Probes modal -----------------------------------------------------------

// TestTUIIntegration_ProbesModal_Smoke validates the tuiNewProbesModel helper +
// fake ProbeManager end-to-end: it opens the dashboard, presses "o", and
// asserts the probes modal renders the seeded title and a probe row.
func TestTUIIntegration_ProbesModal_Smoke(t *testing.T) {
	s := tuiNewProbesModel(t)
	s.waitFor("view:root")

	// Leave the flame tab first: on the flame tab "o" is bound to the frame
	// ordering toggle, so the probes shortcut only reaches the dashboard from a
	// non-flame tab (here Overview).
	s.typeStr("2")
	s.waitFor("Trends:")

	s.typeStr("o")
	// Title is "Probes (2/3 active)" given the fake's two active probes, and the
	// "read" row is one of the seeded rows.
	s.waitFor("Probes (2/3 active)", "read")
}

// --- Populated dashboard tabs (seeded in --testflames) ----------------------

// tuiChrome is a stable token from the persistent dashboard tab bar, which is
// rendered on every tab regardless of body height (unlike the "press H for
// help" footer hint, which tall tabs such as Overview push off-screen). The
// flame tab label is never the active selection while cycling tabs 2..8, so it
// is always present as plain "1:Flm", proving the chrome survives tab switches.
const tuiChrome = "1:Flm"

// TestTUIIntegration_AllTabs_RenderPopulatedAndKeepChrome cycles through every
// non-flame dashboard tab (2..8), asserting each renders its seeded body tokens
// while the persistent chrome line stays put, then returns to the flame tab.
func TestTUIIntegration_AllTabs_RenderPopulatedAndKeepChrome(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	tabs := []struct {
		key   string
		wants []string
	}{
		{"2", []string{"Trends:", "Top processes:", "worker/2002"}}, // Overview
		{"3", []string{"Syscall", "epoll_wait"}},                    // Syscalls
		{"4", []string{"Accesses", "Max Latency"}},                  // Files
		{"5", []string{"Comm", "worker", "ingest"}},                 // Processes
		{"6", []string{"Latency Histogram", "Gap Histogram"}},       // Latency+Gaps
		{"7", []string{"buffer:"}},                                  // Stream chrome (rows filtered by pid=1)
		{"8", []string{"Family", "Polling"}},                        // Non-IO
	}
	for _, tab := range tabs {
		s.typeStr(tab.key)
		// Each tab must render its seeded data AND keep the dashboard chrome.
		s.waitFor(append(tab.wants, tuiChrome)...)
	}

	s.typeStr("1")
	s.waitFor("view:root")
}

// TestTUIIntegration_Overview_ShowsPopulatedStats asserts the Overview tab
// renders its trends header and a seeded top-processes value.
func TestTUIIntegration_Overview_ShowsPopulatedStats(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("2")
	s.waitFor("Trends:", "Top processes:", "worker/2002")
}

// TestTUIIntegration_Latency_ShowsHistogramTotals asserts the Latency+Gaps tab
// renders both seeded histograms.
func TestTUIIntegration_Latency_ShowsHistogramTotals(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("6")
	s.waitFor("Latency Histogram", "Gap Histogram")
}

// TestTUIIntegration_NonIO_ShowsFamilyRows asserts the Non-IO tab renders its
// family header and the seeded Polling family row.
func TestTUIIntegration_NonIO_ShowsFamilyRows(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("8")
	s.waitFor("Family", "Polling")
}

// --- Syscalls tab interactions (seeded table in --testflames) ---------------
//
// The Syscalls tab (number key "3") renders a selectable table of seeded
// syscalls (write/read/close/fsync/openat/epoll_wait/getpid/poll). At the
// 160-col test width the dashboard body falls into the 8-column "compact"
// layout, so the selectable-column index runs 1..8 and column 0 is the
// "Syscall" name column. These tests drive the table's sort, column-nav,
// scroll, visualization-cycle, metric-toggle, and enter-to-filter handlers and
// assert on stable rendered tokens (the table hint line "[Row r/8 Col c/8]",
// the sort label "[sort: ...]", the bubbles/treemap headers, and the
// "filter:" status line) rather than data-dependent row ordering.

// TestTUIIntegration_Syscalls_TableRenders asserts the Syscalls tab renders its
// table header, a seeded row, and the selectable-table hint line.
func TestTUIIntegration_Syscalls_TableRenders(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("3")
	s.waitFor("Syscall", "epoll_wait", "[Row 1/8 Col 1/8]", "[sort: default]")
}

// TestTUIIntegration_Syscalls_SortToggles presses "s" then "S" on the selected
// (name) column and asserts the sort label reflects the ascending then
// descending direction. The selected column starts at 0 (Syscall), so the
// label is the stable observable; exact row order is data-dependent.
func TestTUIIntegration_Syscalls_SortToggles(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("3")
	s.waitFor("Syscall", "[sort: default]")

	s.press('s') // sort ascending on the name column
	s.waitFor("[sort: Syscall asc]")
	s.press('S') // reverse to descending
	s.waitFor("[sort: Syscall desc]")
}

// TestTUIIntegration_Syscalls_ColumnNav presses "l" (right) then "h" (left) and
// asserts the selected-column index in the table hint line moves and returns.
func TestTUIIntegration_Syscalls_ColumnNav(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("3")
	s.waitFor("[Row 1/8 Col 1/8]")

	s.press('l') // move selection one column to the right
	s.waitFor("[Row 1/8 Col 2/8]")
	s.press('h') // move back to the first column
	s.waitFor("[Row 1/8 Col 1/8]")
}

// TestTUIIntegration_Syscalls_Scroll presses "j"/"k" and PgDown/PgUp and asserts
// the selected row in the table hint line tracks the navigation, returning to
// the top row, with the table staying coherent throughout.
func TestTUIIntegration_Syscalls_Scroll(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("3")
	s.waitFor("Syscall", "[Row 1/8 Col 1/8]")

	s.press('j') // move selection down one row
	s.waitFor("[Row 2/8 Col 1/8]")
	s.press('k') // back up to the top row
	s.waitFor("[Row 1/8 Col 1/8]")

	// Paging keys clamp within the 8 seeded rows: PgDown lands on the last row,
	// PgUp returns to the first. The table header stays rendered throughout.
	s.press(tea.KeyPgDown)
	s.waitFor("Syscall", "[Row 8/8 Col 1/8]")
	s.press(tea.KeyPgUp)
	s.waitFor("Syscall", "[Row 1/8 Col 1/8]")
}

// TestTUIIntegration_Syscalls_VizCycle presses "v" to cycle the visualization
// mode table -> bubbles -> treemap -> table, asserting a mode-specific header on
// each step and the table header returning at the end.
func TestTUIIntegration_Syscalls_VizCycle(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("3")
	s.waitFor("Syscall", "epoll_wait") // table mode

	s.press('v') // table -> bubbles
	s.waitFor("Syscalls bubbles", "metric:events")
	s.press('v') // bubbles -> treemap
	s.waitFor("Syscalls treemap")
	s.press('v') // treemap -> table (header returns)
	s.waitFor("Syscall", "[Row 1/8 Col 1/8]")
}

// TestTUIIntegration_Syscalls_MetricToggle switches to bubbles mode and presses
// "b" to toggle the chart metric, asserting the metric label changes from the
// default "events" to "bytes".
func TestTUIIntegration_Syscalls_MetricToggle(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("3")
	s.waitFor("Syscall")

	s.press('v') // enter bubbles mode (default metric: events)
	s.waitFor("Syscalls bubbles", "metric:events")
	s.press('b') // toggle metric events -> bytes
	s.waitFor("Syscalls bubbles", "metric:bytes")
}

// TestTUIIntegration_Syscalls_EnterPushesFilter presses Enter on the selected
// table row and asserts the resulting global filter (shown in the dashboard
// status line) gains a "syscall~<name>" predicate for the seeded top row.
func TestTUIIntegration_Syscalls_EnterPushesFilter(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("3")
	// The model starts with a pid=1 filter; the status line shows it verbatim.
	s.waitFor("Syscall", "filter: pid=1")

	// Enter on the table's selected (top) row clones the active filter and adds a
	// syscall predicate for that row's name; "write" is the seeded top row by the
	// default count-descending order.
	s.press(tea.KeyEnter)
	s.waitFor("syscall~write")
}

// --- Live mode (--testliveflames) -------------------------------------------

func TestTUIIntegration_Live_FlamegraphUpdatesOverTime(t *testing.T) {
	s := tuiNewLiveModel(t)
	s.waitFor("total(events)=") // flame rendered
	if totals := s.waitDistinctTotals(2, tuiLiveWaitFor); len(totals) < 2 {
		t.Fatalf("expected the live flamegraph total to change over time, saw totals=%v", totals)
	}
}

func TestTUIIntegration_Live_PauseFreezesUpdates(t *testing.T) {
	s := tuiNewLiveModel(t)
	s.waitFor("total(events)=")
	if len(s.waitDistinctTotals(2, tuiLiveWaitFor)) < 2 {
		t.Fatal("expected live updates before pausing")
	}

	s.press(tea.KeySpace)
	s.waitFor("[PAUSED]")

	// Let the pause settle and discard any transitional frame, then confirm the
	// total stops changing while paused.
	time.Sleep(300 * time.Millisecond)
	s.pump()
	if frozen := s.collectTotals(800 * time.Millisecond); len(frozen) > 1 {
		t.Fatalf("expected the paused flamegraph total to stay constant, saw totals=%v", frozen)
	}
}
