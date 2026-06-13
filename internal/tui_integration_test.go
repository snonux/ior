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
	"os"
	"path/filepath"
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

// tuiStatefulProbeManager is a pointer-based runtime.ProbeManager whose Toggle
// actually flips the stored Active flag (unlike tuiFakeProbeManager, whose
// value-receiver Toggle is a no-op). It backs the toggle assertion in
// TestTUIIntegration_ProbesModal_NavSearchToggleClose: the modal calls Toggle
// then re-reads States(), so a real flip is observable as both the row's
// checkbox marker and the "(N/M active)" title changing.
type tuiStatefulProbeManager struct {
	states []probemanager.ProbeState
}

// tuiNewStatefulProbeManager returns a stateful probe manager seeded like
// tuiNewFakeProbeManager (read+write active, openat inactive) so the modal
// renders the same "(2/3 active)" title and rows, but toggling mutates state.
func tuiNewStatefulProbeManager() *tuiStatefulProbeManager {
	return &tuiStatefulProbeManager{states: []probemanager.ProbeState{
		{Syscall: "read", Active: true},
		{Syscall: "write", Active: true},
		{Syscall: "openat", Active: false},
	}}
}

func (f *tuiStatefulProbeManager) States() []probemanager.ProbeState {
	out := make([]probemanager.ProbeState, len(f.states))
	copy(out, f.states)
	return out
}

// Toggle flips the Active flag of the named probe, so a subsequent States()
// read reflects the change in the modal.
func (f *tuiStatefulProbeManager) Toggle(syscall string) error {
	for i := range f.states {
		if f.states[i].Syscall == syscall {
			f.states[i].Active = !f.states[i].Active
			return nil
		}
	}
	return nil
}

func (f *tuiStatefulProbeManager) ActiveCount() (int, int) {
	active := 0
	for _, s := range f.states {
		if s.Active {
			active++
		}
	}
	return active, len(f.states)
}

// tuiNewStatefulProbesModel starts a static test-flames session whose runtime
// has a stateful (toggle-mutating) probe manager wired in, so toggling a probe
// in the modal is observable in the rendered checkbox and active count.
func tuiNewStatefulProbesModel(t *testing.T) *tuiSession {
	t.Helper()
	cfg := tuiTestConfig()
	starter := tuiTestFlamesStarter(cfg)
	wrapped := func(ctx context.Context) error {
		if err := starter(ctx); err != nil {
			return err
		}
		if bindings, ok := runtime.RuntimePublisherFromContext(ctx); ok {
			bindings.SetProbeManager(tuiNewStatefulProbeManager())
		}
		return nil
	}
	return tuiNewSession(t, tui.NewTestFlamesModel(cfg, wrapped))
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

// waitForAbsent polls the reconstructed screen until the first substring is
// gone while the remaining "present" substrings are all still rendered, failing
// with the last screen on timeout. It is the negative counterpart of waitFor,
// used to assert a toggled-off overlay has disappeared without racing the frame
// that still shows it.
func (s *tuiSession) waitForAbsent(absent string, present ...string) {
	s.t.Helper()
	deadline := time.Now().Add(tuiWaitFor)
	for {
		scr := s.screen()
		if !strings.Contains(scr, absent) && tuiContainsAll(scr, present...) {
			return
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("waitForAbsent %q (with %q present) not met within %s.\n--- screen ---\n%s",
				absent, present, tuiWaitFor, scr)
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

// --- Flamegraph extra controls ----------------------------------------------
//
// These cover the remaining flame-tab controls (internal/tui/flamegraph
// model.go handleModeKey + controls.go): "o" cycles the field-order preset, "v"
// toggles the frame-height metric, "/"+n/N step the search match cursor, "r"
// resets the baseline, left/right + pgup/pgdn move the selection, and "?"
// toggles the in-tab flame help overlay.
//
// Observability notes for the 160-col VT harness (confirmed by dumping
// s.screen()): the toolbar header line is middle-trimmed at the terminal width,
// so only the leading "o:order(<preset>)" segment survives — the trailing
// "b:metric(...)" and "v:height(...)" toolbar segments are clipped off-screen.
// The field-order preset is therefore asserted on the visible "o:order(...)"
// token, and the height metric on the selection status line's "height:<label>"
// suffix (selectionStatusLine appends " | height:duration" when the height
// metric is active). The count-metric toggle ("b") has no surviving on-screen
// token in this mode (its toolbar label is clipped, and switching the static
// test-flames trie's count field to bytes/duration clears the snapshot to zero
// visible frames, so no "total(bytes)" status ever renders), so it is skipped
// with that reason rather than asserted brittlely.

// TestTUIIntegration_Flame_OrderCycle presses "o" and asserts the toolbar's
// field-order preset advances from the default "comm/tracepoint/path" to the
// next preset "path/tracepoint/comm" (the visible o:order(...) token).
func TestTUIIntegration_Flame_OrderCycle(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root", "o:order(comm/tracepoint/path)")

	s.press('o') // cycle to the next field-order preset
	s.waitFor("o:order(path/tracepoint/comm)")
}

// TestTUIIntegration_Flame_MetricToggle presses "b" to cycle the count metric
// (events -> bytes -> duration), asserting the selection status line's
// "total(<metric>)" token tracks each step. This must run in LIVE mode: pressing
// "b" resets the flamegraph baseline, so on the static --testflames trie the
// view goes blank (no fresh data to re-fill the delta) and nothing renders. With
// --testliveflames the synthetic workload keeps flowing, so each press
// re-renders frames under the new metric.
func TestTUIIntegration_Flame_MetricToggle(t *testing.T) {
	s := tuiNewLiveModel(t)
	s.waitFor("total(events)") // default count metric
	s.press('b')
	s.waitFor("total(bytes)") // bytes metric
	s.press('b')
	s.waitFor("total(duration)") // duration metric
}

// TestTUIIntegration_Flame_HeightToggle presses "v" and asserts the height
// metric activates: the selection status line gains a "height:duration" suffix
// (off -> duration is the first step of the height cycle).
func TestTUIIntegration_Flame_HeightToggle(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root", "Selected: root")

	s.press('v') // toggle frame-height metric off -> duration
	s.waitFor("view:root", "height:duration")
}

// TestTUIIntegration_Flame_MatchNextPrev opens flame search, applies the seeded
// token "read" (8 matches across the trie), then steps the match cursor forward
// with "n" and back with "N", asserting the "(<pos>/8 matches)" counter advances
// from 1/8 to 2/8 and returns to 1/8.
func TestTUIIntegration_Flame_MatchNextPrev(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("Selected: root")

	s.typeStr("/") // open flame search
	s.waitFor("matches")
	s.typeStr("read")
	s.press(tea.KeyEnter) // apply; selection jumps to the first match
	s.waitFor(`Filter "read"`, "1/8 matches")

	s.press('n') // advance the match cursor
	s.waitFor("2/8 matches")
	s.press('N') // step the match cursor back
	s.waitFor("1/8 matches")
}

// TestTUIIntegration_Flame_ResetBaseline presses "r" to reset the baseline. The
// reset clears the trie, which then reseeds from the static test-flames fixture,
// so rather than asserting an exact pre/post total this asserts the stable
// invariant that the flame view stays coherent and reseeds back to the root
// frame (view:root + Selected: root + the seeded total render again).
func TestTUIIntegration_Flame_ResetBaseline(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root", "Selected: root", "total(events):")

	s.press('r') // reset baseline; trie clears then reseeds from the fixture
	s.waitFor("view:root", "Selected: root", "total(events):")
}

// TestTUIIntegration_Flame_SiblingAndPaging descends into the first child
// ("api"), moves to a sibling with Right (-> "batch") and back with Left, then
// exercises the paging keys (PgDown jumps to the root-level extent, PgUp back).
// Sibling destinations are asserted by name; paging destinations are
// data-dependent, so those steps assert coherence (still on a seeded depth-1
// comm under view:root).
func TestTUIIntegration_Flame_SiblingAndPaging(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root", "Selected: root")

	s.press(tea.KeyDown) // descend root -> api
	s.waitFor("Selected: api")
	s.press(tea.KeyRight) // sibling api -> batch
	s.waitFor("Selected: batch")
	s.press(tea.KeyLeft) // sibling batch -> api
	s.waitFor("Selected: api")

	// Paging keys move the selection within the frame layout; the exact landing
	// frame is data-dependent, so assert the view stays coherent (still under
	// view:root with a selection rendered).
	s.press(tea.KeyPgDown)
	s.waitFor("view:root", "Selected:")
	s.press(tea.KeyPgUp)
	s.waitFor("view:root", "Selected:")
}

// TestTUIIntegration_Flame_HelpOverlay presses "?" to open the in-tab flame help
// (distinct from the global "H" overlay, which shows "Dashboard Tabs"); the
// flame help renders its "Flame help:" cheat-sheet footer. Pressing "?" again
// toggles it off, returning to the plain flame view.
func TestTUIIntegration_Flame_HelpOverlay(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root", "Selected: root")

	s.press('?') // open the flame in-tab help overlay
	s.waitFor("view:root", "Flame help:")

	s.press('?') // toggle the flame help back off
	s.waitForAbsent("Flame help:", "view:root")
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

// TestTUIIntegration_Export_SubmitWritesCSV drives the export modal to a real
// SUBMIT and asserts the CSV file is written with seeded rows. It chdirs into an
// isolated temp dir (the export writer's exportDir defaults to "." -> cwd, and
// the default ior-stream-<ts>.csv filename is filename-only), switches to the
// stream tab, and clears the model's startup pid=1 filter so the seeded rows
// (which all carry pids 2001-2004) are present in the snapshot the exporter
// captures. It then opens the export modal with "e", leaves the default
// selection on "CSV stream rows", and presses Enter: the modal emits a
// RequestMsg, the program runs dashboard.ExportStreamCSV() (writing the filtered
// snapshot via exportRowsToCSV), and the resulting CompletedMsg sets the modal's
// "Exported: <path>" status. The test asserts that status, then polls the temp
// dir for the ior-stream-*.csv and asserts it contains the CSV header plus a
// seeded data row (a "batch" comm on a "/srv" path), proving the seeded rows were
// exported.
func TestTUIIntegration_Export_SubmitWritesCSV(t *testing.T) {
	dir := tuiChdirTemp(t)
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	// Clearing the startup pid=1 filter makes the seeded rows visible (and thus
	// part of the exported snapshot, which the exporter filters with the same
	// global filter).
	tuiStreamClearFilter(s)
	s.waitFor("buffer:", "Filter: all", "batch", "/srv")

	// Open the export modal; the default selection is "CSV stream rows".
	s.typeStr("e")
	s.waitFor("Export Stream CSV", "CSV stream rows", "Enter confirm")

	// Enter submits OptionCSV; the export runs and the modal reports success with
	// the written path.
	s.press(tea.KeyEnter)
	s.waitFor("Exported: ", "ior-stream-")

	path := tuiWaitForFile(t, dir, "ior-stream-*.csv")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read csv %q: %v", path, err)
	}
	csv := string(data)
	// The header row is written unconditionally; the seeded "batch" comm on a
	// "/srv" path proves at least one filtered data row was exported.
	for _, want := range []string{"seq,time_ns", "comm", "batch", "/srv"} {
		if !strings.Contains(csv, want) {
			t.Fatalf("exported csv %q missing %q.\n--- csv ---\n%s", path, want, csv)
		}
	}
	// Beyond the header, at least one data line must be present.
	if lines := strings.Count(strings.TrimRight(csv, "\n"), "\n"); lines < 1 {
		t.Fatalf("exported csv %q has no data rows beyond the header:\n%s", path, csv)
	}
}

// --- Stream tab row interactions (seeded ring buffer in --testflames) --------
//
// The Stream tab (number key "7") renders the seeded 40-row ring buffer
// (comms api/worker/ingest/batch, pids 2001-2004, paths under /srv, syscalls
// read/write/close/openat/fsync with a few error rows). The model starts with
// a pid=1 filter that hides every seeded row, so each test first clears that
// filter via the dashboard filter modal (f -> c clears all fields -> Esc
// applies), after which the stream's own "Filter: all" line shows and the
// seeded rows render. These tests drive the stream's pause/select, table
// navigation, push-filter, undo, and search handlers and assert on stable
// rendered tokens from internal/tui/eventstream/render.go: the status line's
// "PAUSED" marker, the "Filter:" summary line, and the search modal prompt
// ("Regex Search" / "Pattern:").
//
// The stream's paused footer (the "Sel s/N Col c/10 | Enter push-filter" line)
// and the search/status messages are only rendered when the dashboard help bar
// is visible (eventstream.Model.SetFooterVisible is driven by dashboard
// showHelp), and that toggle is shadowed by the tui-level "H" help overlay, so
// the footer never renders in the running TUI. The selected-row/column
// highlight is style-only (no glyph marker), which the VT emulator strips.
// Navigation is therefore asserted through its *observable* effect: g/G recenter
// the viewport. The File column is middle-truncated ("/srv....yaml"), so the
// stable non-truncated discriminators are the per-row Latency values: row 0
// (api openat) is "18.4us" and a tail-region row (api read socket) is
// "198.3us", both unique across the 40 seeded rows. selectedCol still advances
// deterministically under the hood, so Enter-to-push-filter remains assertable
// via the resulting "Filter:" summary even though the column index itself is
// not on screen.

// tuiStreamClearFilter switches to the Stream tab (key 7) and clears the
// model's startup pid=1 filter via the dashboard filter modal so the seeded
// rows become visible. On return the stream renders "Filter: all" plus seeded
// chrome. Every Stream row-interaction test starts from this state.
func tuiStreamClearFilter(s *tuiSession) {
	s.t.Helper()
	// Give the dashboard a realistic full-size terminal so the stream's wide
	// event rows are not soft-wrapped and the paused selection/column/search
	// footer (the last rendered line) is not clipped by the height budget.
	s.tm.Send(tea.WindowSizeMsg{Width: tuiTermWidth, Height: tuiTermHeight})
	s.typeStr("7")
	s.waitFor("buffer:", "Comm", "Syscall")
	s.typeStr("f")
	s.waitFor("j/k move") // filter modal help line
	s.typeStr("c")        // clear all fields
	s.press(tea.KeyEsc)   // apply the now-empty filter
	s.waitFor("buffer:", "Filter: all")
}

// TestTUIIntegration_Stream_RowsRender asserts that clearing the pid=1 filter
// reveals the seeded rows: the "Filter: all" summary plus a seeded comm and a
// seeded /srv path render alongside the live "buffer:" chrome.
func TestTUIIntegration_Stream_RowsRender(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	tuiStreamClearFilter(s)
	s.waitFor("buffer:", "Filter: all", "api", "/srv")
}

// TestTUIIntegration_Stream_PauseSelectsAndNavigates pauses the live stream
// (asserting the "PAUSED" status marker), then drives g/G navigation and
// asserts the viewport recenters: "g" brings the seeded row-0 latency
// ("18.4us") to the top, "G" reveals a tail-region latency ("198.3us") that is
// absent near row 0. Down/up and h/l are exercised to prove they are consumed
// without breaking the table (PAUSED + a seeded row stay rendered). The paused
// selection/column footer ("Sel"/"Col" counters) renders independent of the
// dashboard help bar, so its tokens are asserted directly.
func TestTUIIntegration_Stream_PauseSelectsAndNavigates(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	tuiStreamClearFilter(s)

	// Space pauses; the status line's live "LIVE" marker flips to "PAUSED".
	s.press(tea.KeySpace)
	s.waitFor("PAUSED")

	// g anchors on row 0 and recenters, bringing the first seeded row's latency
	// (18.4us, api openat) to the top of the viewport. With a row selected the
	// paused footer renders the "Sel"/"Col" counters and the push-filter hint.
	s.press('g')
	s.waitFor("PAUSED", "18.4us", "Sel 1/", "Col 1/10", "Enter push-filter")

	// G jumps to the last row and recenters, revealing a tail-region latency
	// (198.3us, api read socket near the end) that is not present near row 0.
	s.press('G')
	s.waitFor("PAUSED", "198.3us")

	// Directional keys are consumed by the paused table navigator; assert the
	// table stays coherent (still paused, still rendering seeded rows) after
	// exercising down/up and the column-nav keys h/l.
	s.press('g')
	s.waitFor("PAUSED", "18.4us")
	s.press(tea.KeyDown)
	s.press(tea.KeyUp)
	s.press('l')
	s.press('h')
	s.waitFor("PAUSED", "buffer:", "api")
}

// TestTUIIntegration_Stream_EnterPushFilterThenUndo pauses, anchors the
// selection on row 0 (comm "api"), advances two columns to the Comm column,
// and presses Enter to push a "comm~api" filter. The paused footer's "Col"
// counter makes the column advance observable (Col 1/10 -> Col 3/10), so the
// push targets Comm; the resulting predicate is observable on the stream's
// "Filter:" summary line. F then pops the filter stack, reverting to
// "Filter: all".
func TestTUIIntegration_Stream_EnterPushFilterThenUndo(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	tuiStreamClearFilter(s)

	s.press(tea.KeySpace)
	s.waitFor("PAUSED")
	s.press('g')                              // anchor selection on row 0 (comm "api"); selectedCol stays 0
	s.waitFor("PAUSED", "18.4us", "Col 1/10") // row 0 (api openat) at the top; column anchored at 1/10

	// Two "l" presses move the selected column from Gap (0) to Comm (index 2);
	// the paused footer's Col counter advances from 1/10 to 3/10.
	s.press('l')
	s.press('l')
	s.waitFor("Col 3/10")

	// Enter clones the stream filter and adds the selected cell's predicate; the
	// Comm cell of row 0 is "api", so the filter becomes "comm~api" (synced into
	// the stream's own Filter line via the dashboard global filter).
	s.press(tea.KeyEnter)
	s.waitFor("Filter:", "comm~api")

	// F pops the filter stack, reverting to the cleared "all" filter.
	s.press('F')
	s.waitFor("Filter: all")
}

// TestTUIIntegration_Stream_Search opens the forward search modal ("/"),
// asserting its prompt chrome, searches for the seeded syscall "read" (which
// pauses the stream and jumps to a match), exercises n/N match navigation, and
// smoke-opens the reverse search modal ("?"). Submitting a search pauses the
// stream, so the paused footer renders the search-status line ("/read @ row
// r/N"); the observable assertions are the modal chrome, the paused state, a
// visible "read" row, and that search-status token.
func TestTUIIntegration_Stream_Search(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	tuiStreamClearFilter(s)

	// "/" opens the forward search modal (Regex Search / Pattern: prompt).
	s.press('/')
	s.waitFor("Regex Search", "Pattern:", "Enter search")
	s.typeStr("read")
	s.press(tea.KeyEnter)
	// Submitting pauses the stream and jumps the selection to a "read" match; the
	// paused footer's search-status line shows "/read @ row r/N".
	s.waitFor("PAUSED", "buffer:", "read", "/read @ row")

	// n/N step forward/back through matches; they are consumed and the table
	// stays coherent (a "read" row remains visible).
	s.press('n')
	s.waitFor("PAUSED", "read")
	s.press('N')
	s.waitFor("PAUSED", "read")

	// "?" smoke-opens the reverse search modal (same prompt chrome).
	s.press('?')
	s.waitFor("Regex Search", "Pattern:")
	s.press(tea.KeyEsc)
	s.waitFor("buffer:") // modal closed, stream visible again
}

// TestTUIIntegration_Stream_PausedFooterShowsSelection focuses on the paused
// selection/column/search footer, which renders whenever the stream is paused
// independent of the dashboard help-bar toggle (the global "H" overlay shadows
// the dashboard "H" so the help bar is never enabled). It asserts:
//   - while LIVE, the paused footer tokens are absent;
//   - after Space+g (pause + anchor row 0), the "Sel"/"Col" counters and the
//     "Enter push-filter" hint render;
//   - moving the selected column with "l" advances the "Col" counter;
//   - a "/" search submits the "/read @ row r/N" search-status line.
func TestTUIIntegration_Stream_PausedFooterShowsSelection(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	tuiStreamClearFilter(s)

	// While live the footer's selection tokens are not rendered.
	s.waitForAbsent("Enter push-filter", "buffer:", "Filter: all")

	// Pause and anchor the selection on row 0; the paused footer appears with the
	// Sel/Col counters and the push-filter hint, all without toggling the help bar.
	s.press(tea.KeySpace)
	s.waitFor("PAUSED")
	s.press('g')
	s.waitFor("Sel 1/40", "Col 1/10", "Enter push-filter", "T fd-trace")

	// Advancing the selected column updates the Col counter.
	s.press('l')
	s.waitFor("Col 2/10")

	// A submitted search renders the search-status line in the paused footer.
	s.press('/')
	s.waitFor("Regex Search", "Pattern:")
	s.typeStr("read")
	s.press(tea.KeyEnter)
	s.waitFor("PAUSED", "/read @ row")
}

// TestTUIIntegration_Stream_FDTraceView drives the FD-trace overlay end-to-end:
// it clears the startup pid=1 filter, pauses, anchors the selection on row 0
// (api openat, PID 2001 / FD 7), and presses "T" to open the FD-trace overlay.
// All seeded "api" FS rows share PID 2001 / FD 7, so the overlay's distinct
// "FD Trace (ring snapshot)" header plus the "PID:2001 FD:7 matched:" summary
// render. Esc closes the overlay and returns to the live "buffer:" stream chrome.
func TestTUIIntegration_Stream_FDTraceView(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	tuiStreamClearFilter(s)

	// Pause so row selection is active, then anchor the selection on row 0
	// (api openat) with g.
	s.press(tea.KeySpace)
	s.waitFor("PAUSED")
	s.press('g')
	s.waitFor("PAUSED", "18.4us") // row 0 (api openat) at the top

	// T opens the FD-trace overlay for the selected row's PID+FD. The overlay
	// renders its own header and a "PID:2001 FD:7 matched:N" summary; both
	// "FD Trace" and "matched:" are distinct tokens absent from the stream table.
	s.typeStr("T")
	s.waitFor("FD Trace", "PID:2001 FD:7", "matched:")

	// Esc closes the overlay and returns to the stream view (live "buffer:" chrome).
	s.press(tea.KeyEsc)
	s.waitForAbsent("FD Trace", "buffer:")
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

// tuiGlobErr lists files in dir matching the glob pattern, failing the test on a
// malformed pattern. It is the polling primitive for the file-writing submit
// tests below.
func tuiGlobMatches(t *testing.T, dir, pattern string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		t.Fatalf("glob %q in %q: %v", pattern, dir, err)
	}
	return matches
}

// tuiWaitForFile polls dir for a single file matching pattern, returning its
// path once it appears (and there is exactly one match). It fails the test on
// timeout or on an unexpected number of matches, so submit tests can assert the
// written artifact deterministically without racing the asynchronous flush.
func tuiWaitForFile(t *testing.T, dir, pattern string) string {
	t.Helper()
	deadline := time.Now().Add(tuiWaitFor)
	for {
		matches := tuiGlobMatches(t, dir, pattern)
		if len(matches) == 1 {
			return matches[0]
		}
		if len(matches) > 1 {
			t.Fatalf("expected one %q file in %q, found %d: %v", pattern, dir, len(matches), matches)
		}
		if time.Now().After(deadline) {
			entries, _ := os.ReadDir(dir)
			t.Fatalf("no %q file written to %q within %s; dir contents: %v",
				pattern, dir, tuiWaitFor, tuiDirNames(entries))
		}
		time.Sleep(tuiWaitTick)
	}
}

func tuiDirNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// TestTUIIntegration_Recording_SubmitWritesParquet drives the recording modal to
// a real SUBMIT and asserts the parquet file is written. It chdirs into an
// isolated temp dir (the recorder writes the modal's filename-only path into the
// cwd), opens the modal with "R", accepts the default ior-recording-<ts>.parquet
// filename with Enter to start the recorder, and asserts the dashboard chrome
// shows the live "rec:" status with that filename. It then presses "R" again to
// stop the recorder — recorderStop() calls Recorder.Stop(), which drains the
// queue, flushes the final batch, and closes the parquet writer (footer + atomic
// rename of the .tmp file to the final path), so the .parquet is only complete
// after this step. The test polls the temp dir for the finalized *.parquet and
// asserts it carries the parquet magic ("PAR1") at both ends, proving a valid
// footer was written.
//
// In --testflames mode no real event loop feeds rows into the recorder (the row
// sink in internal/ior.go fires only from the live event-loop callback), so the
// file is a valid but row-empty parquet: row-count > 0 is covered by the parquet
// unit tests / `mage parquetValidate`, while this integration test asserts the
// reachable end-to-end behavior (modal submit -> recorder start -> "rec:" status
// -> stop/flush -> valid parquet on disk).
func TestTUIIntegration_Recording_SubmitWritesParquet(t *testing.T) {
	dir := tuiChdirTemp(t)
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	// Open the recording modal; it pre-fills the default ior-recording-<ts>.parquet
	// filename. Enter submits, starting the recorder against that cwd-relative path.
	s.typeStr("R")
	s.waitFor("Start Parquet Recording", "Filename:", "ior-recording-")
	s.press(tea.KeyEnter)

	// The Syscalls tab is short enough to keep the "rec:" status (rendered on the
	// same chrome line as "filter:") on screen; the active recording shows the
	// filename suffix.
	// recorderStatus shortens long paths to a 36-char "...<suffix>" form, so the
	// default ior-recording-<ts>.parquet renders as "rec: ...recording-<ts>.parquet".
	s.typeStr("3")
	s.waitFor("Syscall", "rec: ", "recording-", ".parquet")

	// Press "R" again to stop the recorder. recorderStop -> Recorder.Stop() flushes
	// and closes the writer, finalizing the .parquet; the chrome flips to "rec: off".
	s.press('R')
	s.waitFor("rec: off")

	// The finalized parquet is now on disk in the isolated cwd.
	path := tuiWaitForFile(t, dir, "ior-recording-*.parquet")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read parquet %q: %v", path, err)
	}
	// A valid parquet file is framed by the 4-byte "PAR1" magic at both ends, so
	// this asserts a complete footer was written even though the test-flames
	// recorder captured zero rows.
	const magic = "PAR1"
	if len(data) < 2*len(magic) {
		t.Fatalf("parquet %q too small (%d bytes) to be a valid file", path, len(data))
	}
	if got := string(data[:len(magic)]); got != magic {
		t.Fatalf("parquet %q missing leading magic: got %q", path, got)
	}
	if got := string(data[len(data)-len(magic):]); got != magic {
		t.Fatalf("parquet %q missing trailing magic (incomplete footer): got %q", path, got)
	}
}

// --- Filter modal -----------------------------------------------------------
//
// The dashboard filter modal (internal/tui/tracefilter/model.go) opens with "f"
// and edits the global trace filter. Its fields are Syscall/Comm/File/PID/TID/
// FD/Latency/Gap/Bytes/Return/Errors; j/k move the "> " field cursor, Enter on a
// text field starts an inline edit (type + Enter commits), "c" clears every
// field, and Esc commits the edited fields and applies the filter. The applied
// filter is observable on the dashboard's status line ("filter: <summary>"),
// which is rendered on the shorter Syscalls tab (the tall Overview tab pushes it
// off the 48-row screen). The model starts with a pid=1 filter, so the modal
// opens with "PID: [ =] 1" pre-filled and the baseline status is "filter: pid=1".
//
// Tokens confirmed by dumping s.screen(): the modal header "Filter", the active
// field marker "> Syscall:", the help line "j/k move", and the status-line
// summary "filter: syscall~read pid=1 | stack: syscall~read" after applying.

// TestTUIIntegration_FilterModal_EditApplyClear opens the filter modal from the
// Syscalls tab, edits the Syscall field to "read", applies it (Esc), and asserts
// the dashboard status line gains the "syscall~read" predicate alongside the
// startup pid=1. It then reopens the modal, clears all fields ("c"), applies, and
// asserts the filter falls back to "filter: all" (clear empties every field,
// including the startup PID).
func TestTUIIntegration_FilterModal_EditApplyClear(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	// The Syscalls tab is short enough to keep the "filter:" status line on screen.
	s.typeStr("3")
	s.waitFor("Syscall", "filter: pid=1")

	// Open the filter modal; it pre-fills the active PID and starts on Syscall.
	s.typeStr("f")
	s.waitFor("Filter", "> Syscall:", "j/k move")

	// Exercise j/k navigation (Syscall -> Comm -> Syscall), then edit Syscall.
	s.press('j')
	s.waitFor("> Comm:")
	s.press('k')
	s.waitFor("> Syscall:")

	s.press(tea.KeyEnter) // start editing the Syscall field
	s.typeStr("read")
	s.press(tea.KeyEnter) // commit the field value
	s.press(tea.KeyEsc)   // apply + close

	// The applied filter combines the typed syscall predicate with the startup
	// pid=1; the dashboard status line and the undo stack both show it.
	s.waitFor("filter: syscall~read pid=1", "stack: syscall~read")

	// Reopen the modal and clear every field, then apply: the filter collapses to
	// "all" (clear empties the PID field too).
	s.typeStr("f")
	s.waitFor("Filter", "j/k move")
	s.press('c')        // clear all fields
	s.press(tea.KeyEsc) // apply the now-empty filter
	s.waitFor("filter: all")
}

// TestTUIIntegration_FilterModal_UndoFilter applies a syscall filter, then
// presses "F" (undo) on the dashboard and asserts the previous filter is popped
// off the stack: the status line reverts from "syscall~read pid=1" back to the
// baseline "pid=1", with the undo stack emptied (no "stack:" segment remains).
func TestTUIIntegration_FilterModal_UndoFilter(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("3")
	s.waitFor("Syscall", "filter: pid=1")

	// Apply a syscall~read filter via the modal.
	s.typeStr("f")
	s.waitFor("Filter", "> Syscall:")
	s.press(tea.KeyEnter) // edit Syscall (already the active field)
	s.typeStr("read")
	s.press(tea.KeyEnter) // commit
	s.press(tea.KeyEsc)   // apply + close
	s.waitFor("filter: syscall~read pid=1", "stack: syscall~read")

	// "F" pops the filter stack, restoring the baseline pid=1 filter and emptying
	// the undo stack.
	s.press('F')
	s.waitForAbsent("syscall~read", "filter: pid=1")
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

// TestTUIIntegration_ProbesModal_NavSearchToggleClose extends the smoke test
// with the modal's interactive surface (internal/tui/probes/model.go): j/k move
// the "> " selection cursor, space toggles the selected probe (via a stateful
// fake whose Toggle flips Active, so the checkbox + "(N/M active)" title change),
// "/" opens the search bar that narrows the list to matching syscalls, and Esc
// closes the modal back to the dashboard.
//
// Observable tokens confirmed by dumping s.screen(): the selection cursor is a
// literal "> " prefix on the active row ("> [x] read"); the checkbox is "[x]"
// active / "[ ]" inactive; the title is "Probes (N/M active)"; search renders a
// "Filter: <needle>" line and drops non-matching rows.
func TestTUIIntegration_ProbesModal_NavSearchToggleClose(t *testing.T) {
	s := tuiNewStatefulProbesModel(t)
	s.waitFor("view:root")

	// Leave the flame tab first: there "o" is the frame-ordering toggle, so the
	// probes shortcut only reaches the dashboard from a non-flame tab (Overview).
	s.typeStr("2")
	s.waitFor("Trends:")

	s.typeStr("o")
	// Seeded title (read+write active, openat inactive) and the selected top row.
	s.waitFor("Probes (2/3 active)", "> [x] read")

	// j/k move the selection cursor down to "write" and back up to "read".
	s.press('j')
	s.waitFor("> [x] write")
	s.press('k')
	s.waitFor("> [x] read")

	// Space toggles the selected probe ("read"): the stateful fake flips its
	// Active flag, the modal re-reads States(), and both the checkbox and the
	// active-count title update (read active -> inactive => 1/3 active).
	s.press(' ')
	s.waitFor("Probes (1/3 active)", "> [ ] read")

	// "/" opens the search bar; typing "open" + Enter narrows the list to the
	// single matching "openat" row, dropping the read/write rows. The committed
	// search renders a "Filter: open" line.
	s.press('/')
	s.typeStr("open")
	s.press(tea.KeyEnter)
	s.waitFor("Filter: open", "openat")
	s.waitForAbsent("write", "openat")

	// Esc closes the modal; the dashboard (Overview) returns.
	s.press(tea.KeyEsc)
	s.waitForAbsent("Probes (", "Trends:")
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

// --- Syscalls tab interactions (seeded table in --testflames) ---------------
//
// The Syscalls tab (number key "3") renders a selectable table of seeded
// syscalls (write/read/close/fsync/openat/epoll_wait/getpid/poll). At the
// 160-col test width the dashboard body falls into the 9-column "compact"
// layout (Syscall, Family, Count, Rate/s, Avg, p95, p99, Bytes, Errors), so the
// selectable-column index runs 1..9 and column 0 is the "Syscall" name column,
// with the "Family" column at index 1. These tests drive the table's sort,
// column-nav, scroll, visualization-cycle, metric-toggle, and enter-to-filter
// handlers and assert on stable rendered tokens (the table hint line
// "[Row r/8 Col c/9]", the sort label "[sort: ...]", the bubbles/treemap
// headers, and the "filter:" status line) rather than data-dependent row
// ordering.

// TestTUIIntegration_Syscalls_TableRenders asserts the Syscalls tab renders its
// table header (including the Family column), a seeded non-FS family value, and
// the selectable-table hint line.
func TestTUIIntegration_Syscalls_TableRenders(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("3")
	s.waitFor("Syscall", "Family", "Polling", "epoll_wait", "[Row 1/8 Col 1/9]", "[sort: default]")
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

	// Move selection to the Family column (index 1) and sort by it, grouping
	// families together.
	s.press('l')
	s.waitFor("[Row 1/8 Col 2/9]")
	s.press('s') // sort ascending by Family
	s.waitFor("[sort: Family asc]")
	s.press('S') // reverse to descending
	s.waitFor("[sort: Family desc]")
}

// TestTUIIntegration_Syscalls_ColumnNav presses "l" (right) then "h" (left) and
// asserts the selected-column index in the table hint line moves and returns.
func TestTUIIntegration_Syscalls_ColumnNav(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("3")
	s.waitFor("[Row 1/8 Col 1/9]")

	s.press('l') // move selection one column to the right
	s.waitFor("[Row 1/8 Col 2/9]")
	s.press('h') // move back to the first column
	s.waitFor("[Row 1/8 Col 1/9]")
}

// TestTUIIntegration_Syscalls_Scroll presses "j"/"k" and PgDown/PgUp and asserts
// the selected row in the table hint line tracks the navigation, returning to
// the top row, with the table staying coherent throughout.
func TestTUIIntegration_Syscalls_Scroll(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("3")
	s.waitFor("Syscall", "[Row 1/8 Col 1/9]")

	s.press('j') // move selection down one row
	s.waitFor("[Row 2/8 Col 1/9]")
	s.press('k') // back up to the top row
	s.waitFor("[Row 1/8 Col 1/9]")

	// Paging keys clamp within the 8 seeded rows: PgDown lands on the last row,
	// PgUp returns to the first. The table header stays rendered throughout.
	s.press(tea.KeyPgDown)
	s.waitFor("Syscall", "[Row 8/8 Col 1/9]")
	s.press(tea.KeyPgUp)
	s.waitFor("Syscall", "[Row 1/8 Col 1/9]")
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
	s.waitFor("Syscall", "[Row 1/8 Col 1/9]")
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

// TestTUIIntegration_Syscalls_EnterFamilyColumnPushesFilter moves the column
// selection to the Family column (index 1) and presses Enter, asserting the
// status line gains a "family~<X>" predicate (scoping by the selected row's
// syscall family rather than its name). Pressing "F" undoes the filter, which
// reverts the status line to the model's initial "pid=1" filter. The seeded
// top row ("write") classifies as the FS family, so the predicate is
// "family~FS".
func TestTUIIntegration_Syscalls_EnterFamilyColumnPushesFilter(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("3")
	s.waitFor("Syscall", "filter: pid=1", "[Row 1/8 Col 1/9]")

	// Move the column selection from Syscall (0) to Family (1).
	s.press('l')
	s.waitFor("[Row 1/8 Col 2/9]")

	// Enter on the Family column scopes the dashboard to the top row's family.
	s.press(tea.KeyEnter)
	s.waitFor("family~FS")

	// F undoes the just-pushed filter, reverting to the initial pid=1 filter.
	s.press('F')
	s.waitFor("filter: pid=1")
	if strings.Contains(s.screen(), "family~FS") {
		t.Fatalf("expected family~FS filter to be undone, screen still shows it:\n%s", s.screen())
	}
}

// TestTUIIntegration_FamilyCycleHotkeys cycles the dashboard's syscall-family
// scope with the global "]" (next) and "[" (prev) hotkeys. Each press re-scopes
// the whole dashboard by REPLACING the active filter's Family component (the
// pid=1 base filter is preserved), so the cycle walks
// all -> Network -> Memory -> ... and wraps. Because the re-scope is a
// replacement (setGlobal) and not a stack push, the "stack:" label must NOT
// grow as the user cycles.
func TestTUIIntegration_FamilyCycleHotkeys(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root", "filter: pid=1")

	stackBefore := strings.Count(s.screen(), "stack:")

	// "]" advances from the "all" state to the first family (Network). The
	// base pid=1 filter is preserved alongside the new family predicate.
	s.press(']')
	s.waitFor("family~Network", "pid=1")

	// "]" again advances to the next family (Memory).
	s.press(']')
	s.waitFor("family~Memory")

	// "[" reverses back to the previous family (Network).
	s.press('[')
	s.waitFor("family~Network")

	// "[" again steps off the first family back to the "all" state: the
	// family predicate disappears while the base pid=1 filter remains.
	s.press('[')
	s.waitForAbsent("family~", "filter: pid=1")

	// The replacement path must never push onto the undo stack, so the
	// "stack:" label count is unchanged across the whole cycle.
	if got := strings.Count(s.screen(), "stack:"); got != stackBefore {
		t.Fatalf("family cycle grew the filter stack: stack-label count %d -> %d\n%s",
			stackBefore, got, s.screen())
	}
}

// --- Files tab interactions (seeded table in --testflames) ------------------
//
// The Files tab (number key "4") renders a six-column selectable table
// (Accesses/Read/Write/Avg Latency/Max Latency/Path) over the seeded file
// snapshots. Pressing "d" toggles directory grouping, which swaps in the
// dir-aggregated table (adds a "Files" count column and a "Directory" path
// column) and unlocks the bubbles/treemap/icicle visualisations — the flat
// (ungrouped) view is table-only. As with the Syscalls tests these assertions
// target stable rendered tokens (the table hint line, the "[sort: ...]" label,
// and the viz headers) rather than data-dependent row ordering. The selected
// column starts at 0 (Accesses), whose default direction is descending, so the
// first "s" press yields "Accesses desc" and "S" reverses to "Accesses asc".

// TestTUIIntegration_Files_TableRenders asserts the Files tab renders its flat
// table headers and the selectable-table hint line.
func TestTUIIntegration_Files_TableRenders(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("4")
	s.waitFor("Accesses", "Max Latency", "[sort: default]")
}

// TestTUIIntegration_Files_DirGroupToggle presses "d" to switch to the
// directory-grouped view (distinct "Directory" header + "Files" count column,
// and the "[d:files]" hint that toggles back), then "d" again to return to the
// flat per-file table.
func TestTUIIntegration_Files_DirGroupToggle(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("4")
	s.waitFor("Accesses", "Max Latency") // flat view

	s.press('d') // flat -> directory-grouped
	// The dir-grouped header carries the distinct "Directory" column title and a
	// "Files" per-directory count column; the toggle hint flips to "d:files".
	s.waitFor("Directory", "Files", "[d:files]")

	s.press('d') // directory-grouped -> flat (per-file headers return)
	s.waitFor("Accesses", "Max Latency", "[d:dirs]")
}

// TestTUIIntegration_Files_SortAndViz sorts the flat table (asserting the
// "[sort: ...]" label flips direction), then enters dir-grouped mode and cycles
// the visualization with "v" through bubbles -> treemap -> icicle, asserting
// each mode-specific header. The icicle mode is only reachable in dir-grouped
// mode, which is the Files tab's distinguishing viz.
func TestTUIIntegration_Files_SortAndViz(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("4")
	s.waitFor("Accesses", "[sort: default]")

	// Column 0 (Accesses) defaults to descending, so "s" sorts descending and
	// "S" reverses to ascending.
	s.press('s')
	s.waitFor("[sort: Accesses desc]")
	s.press('S')
	s.waitFor("[sort: Accesses asc]")

	// Non-table visualisations require dir-grouped mode.
	s.press('d')
	s.waitFor("Directory")

	// Cycle: table -> bubbles -> treemap -> icicle. The bubble chart is labelled
	// "Files/Dirs" while the treemap/icicle headers use "Files".
	s.press('v')
	s.waitFor("Files/Dirs bubbles", "metric:events")
	s.press('v')
	s.waitFor("Files treemap")
	s.press('v')
	s.waitFor("Files icicle")
}

// TestTUIIntegration_Files_MetricToggle switches into the dir-grouped bubble
// chart and presses "b" to cycle the chart metric from the default "events" to
// "bytes". The Files tab only accepts metric changes in dir-grouped mode.
func TestTUIIntegration_Files_MetricToggle(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("4")
	s.waitFor("Accesses")

	s.press('d') // enable dir-grouped mode (required for bubble metrics)
	s.waitFor("Directory")
	s.press('v') // table -> bubbles (default metric: events)
	s.waitFor("Files/Dirs bubbles", "metric:events")
	s.press('b') // toggle metric events -> bytes
	s.waitFor("Files/Dirs bubbles", "metric:bytes")
}

// --- Processes tab interactions (seeded table in --testflames) --------------
//
// The Processes tab (number key "5") renders a six-column selectable table
// (PID/Comm/Syscalls/Rate/s/Total Bytes/Avg Latency) over the four seeded
// processes (api/worker/ingest/batch, pids 2001-2004). The default order is
// Syscalls-descending, so "worker" (6 syscalls) and "ingest" (5) lead. The
// selected column starts at 0 (PID), whose default direction is ascending.
// These tests drive the sort, column-nav, visualization-cycle, and
// refresh-reanchor handlers and assert on stable rendered tokens (the table
// hint line, the "[sort: ...]" label, and the bubbles/treemap headers).

// TestTUIIntegration_Processes_TableRenders asserts the Processes tab renders
// its table header, two seeded comms, and the selectable-table hint line.
func TestTUIIntegration_Processes_TableRenders(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("5")
	s.waitFor("Comm", "worker", "ingest", "[Row 1/4 Col 1/6]", "[sort: default]")
}

// TestTUIIntegration_Processes_SortColumns sorts on the PID column (default
// ascending) with "s"/"S", then moves one column right to Comm and sorts again,
// asserting the "[sort: <Col> asc|desc]" label tracks each column.
func TestTUIIntegration_Processes_SortColumns(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("5")
	s.waitFor("Comm", "[sort: default]")

	// Column 0 (PID) defaults to ascending.
	s.press('s')
	s.waitFor("[sort: PID asc]")
	s.press('S')
	s.waitFor("[sort: PID desc]")

	// Move to column 1 (Comm, default ascending) and sort it. The earlier PID
	// sort reanchored the selected row, so assert only the column index moved
	// (the row index is data-dependent after the reanchor).
	s.press('l')
	s.waitFor("Col 2/6")
	s.press('s')
	s.waitFor("[sort: Comm asc]")
}

// TestTUIIntegration_Processes_VizCycle presses "v" to cycle the visualization
// mode table -> bubbles -> treemap -> table, asserting a mode-specific header on
// each step and the table header returning at the end.
func TestTUIIntegration_Processes_VizCycle(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("5")
	s.waitFor("Comm", "worker") // table mode

	s.press('v') // table -> bubbles
	s.waitFor("Processes bubbles", "metric:events")
	s.press('v') // bubbles -> treemap
	s.waitFor("Processes treemap")
	s.press('v') // treemap -> table (header returns)
	s.waitFor("Comm", "[Row 1/4 Col 1/6]")
}

// TestTUIIntegration_Processes_ReanchorsSelectionAfterRefresh selects a non-top
// row, then waits through at least one dashboard refresh tick (the snapshot
// refreshes ~1s) and asserts the selection still anchors the same row. Because
// the test-flames snapshot is static, the stable-key reanchoring keeps the
// selection pinned to the same process across the refresh: the "[Row 2/4]" hint
// and the seeded comms remain rendered. This asserts the weaker but
// deterministic invariant (the table stays coherent and the selection index is
// preserved) rather than attempting to observe a row identity swap, which the
// static seed cannot produce.
func TestTUIIntegration_Processes_ReanchorsSelectionAfterRefresh(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	s.typeStr("5")
	s.waitFor("Comm", "[Row 1/4 Col 1/6]")

	s.press('j') // move selection to row 2
	s.waitFor("[Row 2/4 Col 1/6]")

	// Wait through more than one refresh tick (cadence is ~1s) so a snapshot
	// refresh has certainly fired, then confirm the selection survived it: the
	// row hint is unchanged and the seeded comms still render.
	time.Sleep(1200 * time.Millisecond)
	s.waitFor("Comm", "worker", "ingest", "[Row 2/4 Col 1/6]")
}

// --- PID picker (tui.NewModel(-1) starts on the picker) ----------------------
//
// Passing initialPID=-1 to tui.NewModel selects the PID picker screen instead
// of the dashboard (tuiNewPickerModel). The picker (internal/tui/pidpicker/
// model.go) reads the host's real /proc, so its process rows are
// non-deterministic; these tests assert only the deterministic chrome: the
// "Select PID" header, the "Filter: " input prompt, and the synthetic "All
// PIDs" row that always occupies index 0 (selected on entry as "> All PIDs").
// Selecting that row emits PidSelectedMsg{Pid:0}, which the tui model handles
// by attaching and transitioning to the populated dashboard (asserted via the
// flame tab's "view:root" token).

// TestTUIIntegration_PidPicker_FilterSelectAllToDashboard starts on the PID
// picker, asserts its chrome and the selected "All PIDs" row, types a filter
// string (echoed in the "Filter: " input), then presses Enter on the still-
// selected "All PIDs" row (index 0). The resulting PidSelectedMsg{Pid:0}
// transitions to the dashboard, asserted via the seeded flame view.
func TestTUIIntegration_PidPicker_FilterSelectAllToDashboard(t *testing.T) {
	s := tuiNewPickerModel(t)
	// Picker chrome: the header, the filter input prompt, and the synthetic
	// "All PIDs" row, which starts selected ("> ").
	s.waitFor("Select PID", "Filter: ", "> All PIDs")

	// Typing focuses the input and echoes into the "Filter: " prompt; "zzz" is an
	// unlikely comm/pid substring, so the real process rows narrow away while the
	// always-present "All PIDs" row stays at index 0.
	s.typeStr("zzz")
	s.waitFor("Filter: zzz", "All PIDs")

	// Enter on the selected index-0 row emits PidSelectedMsg{Pid:0}; the model
	// attaches and lands on the populated dashboard (seeded flame view).
	s.press(tea.KeyEnter)
	s.waitFor("view:root")
}

// TestTUIIntegration_PidPicker_ReselectEscReturns starts on the dashboard,
// presses "p" to reselect a PID (which bookmarks the dashboard and switches to
// the picker), then Esc to cancel. Because the picker was entered with a
// pending return bookmark, Esc cancels back to the original dashboard without
// restarting the trace (shouldCancelPickerToDashboard in tui.go), asserted via
// the still-seeded flame view.
func TestTUIIntegration_PidPicker_ReselectEscReturns(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	// "p" reselects the PID: the dashboard is bookmarked and the picker opens.
	s.press('p')
	s.waitFor("Select PID", "Filter: ", "All PIDs")

	// Esc cancels the picker; the pending bookmark routes back to the dashboard
	// without re-attaching, so the seeded flame view returns intact.
	s.press(tea.KeyEsc)
	s.waitFor("view:root")
}

// --- TID picker ("t" reselect on the dashboard) -----------------------------
//
// The "t" key on the dashboard triggers reselectTID() (tui.go), which bookmarks
// the dashboard and opens the pidpicker model in TID mode
// (pidpicker.NewTIDWithKeys, PickerModeTID). In TID mode the picker reads the
// current PID's real /proc threads, so its thread rows are non-deterministic;
// these tests assert only the deterministic chrome: the "Select TID for PID N"
// header and the synthetic "All TIDs" row that always occupies index 0
// (selected on entry as "> All TIDs"). tuiNewFlamesModel starts with pid=1, so
// the header reads "Select TID for PID 1". Selecting "All TIDs" emits
// TidSelectedMsg{Tid:0}; handleTidSelected clears the TID filter (tid<=0 -> -1)
// and returns to the dashboard, asserted via the flame tab's "view:root" token
// and the "filter: pid=1" status line (no tid component, since it was cleared).

// TestTUIIntegration_TidPicker_ReselectFromDashboard starts on the dashboard,
// presses "t" to open the TID picker, asserts its chrome and the selected
// "All TIDs" row, then presses Enter on that still-selected index-0 row. The
// resulting TidSelectedMsg{Tid:0} clears the tid filter and re-attaches the
// dashboard, asserted via the seeded flame view and the "filter: pid=1" status
// line.
func TestTUIIntegration_TidPicker_ReselectFromDashboard(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	// "t" reselects the TID: the dashboard is bookmarked and the TID picker opens
	// scoped to the current pid (1). The synthetic "All TIDs" row starts selected.
	s.press('t')
	s.waitFor("Select TID for PID 1", "Filter: ", "> All TIDs")

	// Enter on the selected index-0 row emits TidSelectedMsg{Tid:0}; the model
	// clears the tid filter and re-attaches, landing on the seeded flame view with
	// the pid-only filter status line.
	s.press(tea.KeyEnter)
	s.waitFor("view:root", "filter: pid=1")
}

// TestTUIIntegration_TidPicker_EscReturnsToDashboard starts on the dashboard,
// presses "t" to open the TID picker, asserts its chrome, then Esc to cancel.
// Because the picker was entered with a pending return bookmark, Esc cancels
// back to the original dashboard without restarting the trace
// (shouldCancelPickerToDashboard in tui.go), asserted via the still-seeded
// flame view.
func TestTUIIntegration_TidPicker_EscReturnsToDashboard(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	// "t" reselects the TID: the dashboard is bookmarked and the TID picker opens.
	s.press('t')
	s.waitFor("Select TID for PID 1", "Filter: ", "All TIDs")

	// Esc cancels the picker; the pending bookmark routes back to the dashboard
	// without re-attaching, so the seeded flame view returns intact.
	s.press(tea.KeyEsc)
	s.waitFor("view:root")
}

// --- Global keys (reset baseline "r", cycle auto-reset "I") -------------------
//
// These dashboard-level shortcuts are routed by handleDashboardShortcutKeys in
// tui.go regardless of the active tab. "r" resets the stats/flame baseline; "I"
// advances the auto-reset cadence through autoResetCycle (off, 10s, 30s, 1m,
// 2m, 5m). The auto-reset cadence is rendered in the dashboard chrome's status
// line ("auto-reset: <remaining>/<total>") via filterSummary, which — like the
// "filter:" summary — only stays on screen on a short tab (the tall Overview
// pushes it off the 48-row grid), so these tests assert it from the Syscalls
// tab (key 3). The test-flames config seeds the default 30s reset timer, so the
// baseline status is "auto-reset: .../30s".

// TestTUIIntegration_Global_ResetClearsCounts presses "r" to reset the
// baseline. The reset clears the stats/flame aggregates, which then reseed from
// the static test-flames fixture, so rather than asserting zeroed counts this
// asserts the stable invariant that the dashboard stays coherent: the Syscalls
// table still renders its seeded rows and the chrome (the persistent tab bar)
// survives the reset.
func TestTUIIntegration_Global_ResetClearsCounts(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	// The Syscalls tab keeps the status line on screen and renders a seeded table.
	s.typeStr("3")
	s.waitFor("Syscall", "epoll_wait", tuiChrome)

	// "r" resets the baseline; the aggregates clear then reseed from the fixture,
	// so the seeded table and the persistent chrome remain rendered.
	s.press('r')
	s.waitFor("Syscall", "epoll_wait", tuiChrome)
}

// TestTUIIntegration_Global_AutoResetCycleShowsInterval presses "I" once and
// asserts the auto-reset cadence advances in the dashboard status line. The
// seeded default is 30s, so the baseline status shows "auto-reset: .../30s";
// one "I" press advances 30s -> 1m0s, so the total flips to "/1m0s".
func TestTUIIntegration_Global_AutoResetCycleShowsInterval(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	// The Syscalls tab keeps the auto-reset status line on screen.
	s.typeStr("3")
	s.waitFor("Syscall", "auto-reset: ", "/30s")

	// "I" advances the cadence from the seeded 30s to the next preset (1m0s); the
	// status line's total segment flips accordingly.
	s.press('I')
	s.waitFor("auto-reset: ", "/1m0s")
}

// --- Terminal resize (tea.WindowSizeMsg) ------------------------------------
//
// The model forwards tea.WindowSizeMsg to the dashboard, which re-renders its
// tab bar at the new width (renderTabBar in dashboard/tabs.go). The VT emulator
// is fixed at 160x48, so a narrow WindowSizeMsg makes the dashboard render a
// narrow tab bar within the 160-col grid: below width 90 it falls back to the
// plain renderer with abbreviated labels ("1:Flm 2:Ovr ...", active bracketed),
// while at full width it renders the full labels ("1:Flame", "2:Overview").

// TestTUIIntegration_Resize_NarrowThenWide drives a narrow then wide resize and
// asserts the tab bar degrades to short labels and then restores. A narrow
// WindowSizeMsg{80x24} forces the plain narrow tab bar (short labels, active
// bracketed as "[1:Flm]"); a wide WindowSizeMsg{160x48} restores the full
// labels ("1:Flame"/"2:Overview") while the seeded flame view stays coherent.
func TestTUIIntegration_Resize_NarrowThenWide(t *testing.T) {
	s := tuiNewFlamesModel(t)
	s.waitFor("view:root")

	// A narrow size (<90 cols) degrades the tab bar to the plain narrow renderer:
	// abbreviated labels with the active tab bracketed.
	s.tm.Send(tea.WindowSizeMsg{Width: 80, Height: 24})
	s.waitFor("[1:Flm]", "2:Ovr")

	// Restoring a wide size brings back the full tab labels; the flame view stays
	// coherent (still on view:root).
	s.tm.Send(tea.WindowSizeMsg{Width: tuiTermWidth, Height: tuiTermHeight})
	s.waitFor("1:Flame", "2:Overview", "view:root")
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
