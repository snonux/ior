package dashboard

import (
	"errors"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/messages"
)

// gatedSource is a SnapshotSource whose Snapshot blocks until released, so a
// test can hold a build "in flight" and watch what the UI goroutine does in
// the meantime. Unlike fakeSnapshotSource it is safe to call from the
// goroutines the test starts to play the role of Bubble Tea's command runner.
type gatedSource struct {
	mu      sync.Mutex
	calls   int
	resets  int
	snap    *statsengine.Snapshot
	err     error
	entered chan struct{}
	release chan struct{}
}

func newGatedSource(snap *statsengine.Snapshot) *gatedSource {
	return &gatedSource{
		snap:    snap,
		entered: make(chan struct{}, 8),
		release: make(chan struct{}),
	}
}

func (g *gatedSource) Snapshot() (*statsengine.Snapshot, error) {
	g.mu.Lock()
	g.calls++
	snap, err := g.snap, g.err
	g.mu.Unlock()
	g.entered <- struct{}{}
	<-g.release
	return snap, err
}

func (g *gatedSource) Reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.resets++
}

func (g *gatedSource) resetCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.resets
}

func (g *gatedSource) callCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

// runAsync runs cmd on its own goroutine, as Bubble Tea does, and delivers
// its message on the returned channel.
func runAsync(cmd tea.Cmd) <-chan tea.Msg {
	out := make(chan tea.Msg, 1)
	go func() { out <- cmd() }()
	return out
}

func awaitMsg(t *testing.T, ch <-chan tea.Msg) tea.Msg {
	t.Helper()
	select {
	case msg := <-ch:
		return msg
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the command result")
		return nil
	}
}

func awaitEntered(t *testing.T, g *gatedSource) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Snapshot to be called")
	}
}

// updateWithTimeout runs m.Update and fails instead of hanging when Update
// blocks, which is what a synchronous snapshot build behind a held gate does.
func updateWithTimeout(t *testing.T, m *Model, msg tea.Msg) tea.Cmd {
	t.Helper()
	done := make(chan tea.Cmd, 1)
	go func() {
		_, cmd := m.Update(msg)
		done <- cmd
	}()
	select {
	case cmd := <-done:
		return cmd
	case <-time.After(5 * time.Second):
		t.Fatal("Update blocked: the snapshot is being built on the UI goroutine")
		return nil
	}
}

// statsCmdsOf returns the commands of a refresh tick's batch that build a
// snapshot, told apart from the re-arming tick by running nothing: the tick
// is the first command (refreshCmd) and the snapshot builder, if present,
// the second.
func statsCmdsOf(t *testing.T, cmd tea.Cmd) []tea.Cmd {
	t.Helper()
	if cmd == nil {
		t.Fatal("expected a command from the refresh tick")
	}
	batch, ok := cmd().(tea.BatchMsg)
	if !ok {
		// A single surviving command is the re-arming tick: no snapshot
		// request was made. (cmd() above ran it, which is fine for a tick.)
		return nil
	}
	if len(batch) != 2 {
		t.Fatalf("expected the re-arm tick and one snapshot command, got %d commands", len(batch))
	}
	return batch[1:]
}

// TestRefreshTickBuildsTheSnapshotOffTheUpdatePath is the regression test for
// the dashboard building its stats snapshot on the UI goroutine: Update must
// return while Snapshot is still running, the snapshot must be built by the
// returned command, and the result must reach the model as a StatsTickMsg.
func TestRefreshTickBuildsTheSnapshotOffTheUpdatePath(t *testing.T) {
	snap := &statsengine.Snapshot{TotalSyscalls: 42}
	src := newGatedSource(snap)
	m := NewModelWithConfig(src, nil, 100, 200, common.DefaultKeyMap())

	cmd := updateWithTimeout(t, m, refreshTickMsg{})
	if got := src.callCount(); got != 0 {
		t.Fatalf("Update called Snapshot %d times; it must only return a command", got)
	}

	// Run the snapshot command the way Bubble Tea would, on its own
	// goroutine, and keep it blocked inside Snapshot.
	cmds := statsCmdsOf(t, cmd)
	if len(cmds) != 1 {
		t.Fatalf("expected one snapshot command, got %d", len(cmds))
	}
	result := runAsync(cmds[0])
	awaitEntered(t, src)

	// The UI goroutine stays responsive while the build is in flight.
	updateWithTimeout(t, m, tea.WindowSizeMsg{Width: 120, Height: 40})

	close(src.release)
	tick, ok := awaitMsg(t, result).(messages.StatsTickMsg)
	if !ok || tick.Snap != snap || tick.Err != nil || tick.Generation != m.statsGen {
		t.Fatalf("expected a current-generation tick carrying the snapshot, got %+v", tick)
	}
	updateWithTimeout(t, m, tick)
	if got := m.LatestSnapshot(); got != snap {
		t.Fatalf("expected the built snapshot to be applied, got %+v", got)
	}
}

// TestRefreshStatsCmdSkipsWhileTheBuildIsRunning: a build slower than the
// refresh cadence must not stack overlapping builds, and the busy flag must
// be released when the build ends, success or failure.
func TestRefreshStatsCmdSkipsWhileTheBuildIsRunning(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"success", nil},
		{"failure", errors.New("snapshot build failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := newGatedSource(&statsengine.Snapshot{})
			src.err = tc.err
			m := NewModelWithConfig(src, nil, 100, 200, common.DefaultKeyMap())

			first := m.refreshStatsCmd()
			if first == nil {
				t.Fatal("expected the first refresh to build a snapshot")
			}
			result := runAsync(first)
			awaitEntered(t, src)

			if skipped := m.refreshStatsCmd(); skipped != nil {
				t.Fatal("a refresh was requested while the previous build is still running")
			}
			if got := src.callCount(); got != 1 {
				t.Fatalf("expected the single in-flight build, got %d Snapshot calls", got)
			}

			close(src.release)
			awaitMsg(t, result)
			// The flag is released by the command when its build ends, so
			// even a result that is never delivered cannot wedge refreshing.
			if m.refreshStatsCmd() == nil {
				t.Fatal("expected refreshing to resume once the build finished")
			}
		})
	}
}

// TestRefreshBuiltBeforeAResetIsDropped: a snapshot request made before a
// reset and delivered after it carries the old generation and must not put
// the pre-reset numbers back over the post-reset snapshot.
func TestRefreshBuiltBeforeAResetIsDropped(t *testing.T) {
	pre := &statsengine.Snapshot{TotalSyscalls: 99}
	src := newGatedSource(pre)
	m := NewModelWithConfig(src, nil, 100, 200, common.DefaultKeyMap())
	m.activeTab = TabOverview

	result := runAsync(m.refreshStatsCmd())
	awaitEntered(t, src)

	// The reset builds its post-reset snapshot synchronously, so release the
	// gate for it; the in-flight build completes straight after.
	close(src.release)
	old := awaitMsg(t, result).(messages.StatsTickMsg)
	postReset := &statsengine.Snapshot{TotalSyscalls: 0}
	src.mu.Lock()
	src.snap = postReset
	src.mu.Unlock()
	m.ResetStats()
	if got := m.LatestSnapshot(); got != postReset {
		t.Fatalf("precondition: expected the post-reset snapshot, got %+v", got)
	}

	updateWithTimeout(t, m, old)
	if got := m.LatestSnapshot(); got != postReset {
		t.Fatalf("a refresh requested before the reset restored the old numbers: %+v", got)
	}
}

// TestSnapshotCmdAndBaselineResetBuildWhenRun: SnapshotCmd and the baseline
// reset key build their snapshot in the command, not while the model handles
// the request; the reset itself (engine clear, generation bump) still
// happens at once so older ticks are dropped.
func TestSnapshotCmdAndBaselineResetBuildWhenRun(t *testing.T) {
	src := newGatedSource(&statsengine.Snapshot{TotalSyscalls: 5})
	close(src.release) // builds may finish immediately
	m := NewModelWithConfig(src, nil, 100, 200, common.DefaultKeyMap())

	cmd := m.SnapshotCmd()
	if got := src.callCount(); got != 0 {
		t.Fatalf("SnapshotCmd built the snapshot eagerly (%d calls)", got)
	}
	if tick, ok := cmd().(messages.StatsTickMsg); !ok || tick.Snap == nil || tick.Generation != m.statsGen {
		t.Fatalf("expected a current-generation snapshot tick, got %#v", tick)
	}

	genBefore := m.statsGen
	calls := src.callCount()
	reset := m.resetBaselineCmd()
	if m.statsGen != genBefore+1 || src.resets != 1 {
		t.Fatalf("the reset must bump the generation and clear the engine at once: gen %d resets %d", m.statsGen, src.resets)
	}
	if got := src.callCount(); got != calls {
		t.Fatalf("resetBaselineCmd built the snapshot eagerly (%d new calls)", got-calls)
	}
	if tick, ok := reset().(messages.StatsTickMsg); !ok || tick.Generation != m.statsGen {
		t.Fatalf("expected a tick of the new generation, got %#v", tick)
	}
}

// captureCmdCases lists the commands that build a snapshot off the UI
// goroutine, each created by a function that must capture the engine and the
// stats generation at creation time (on the UI goroutine) and not read them
// from the model when the command runs.
var captureCmdCases = []struct {
	name string
	make func(m *Model) tea.Cmd
}{
	{"statsTickCmd", func(m *Model) tea.Cmd { return m.statsTickCmd() }},
	{"SnapshotCmd", func(m *Model) tea.Cmd { return m.SnapshotCmd() }},
	{"refreshStatsCmd", func(m *Model) tea.Cmd { return m.refreshStatsCmd() }},
	{"resetBaselineCmd", func(m *Model) tea.Cmd { return m.resetBaselineCmd() }},
}

// TestStatsCmdsCaptureGenerationAndEngineWhenCreated pins the capture-at-
// creation contract across a reset: a command made at generation N and run
// after a reset (generation N+1, and here even after the model's engine was
// swapped) must still build from the engine it was made with, label its tick
// with generation N, and have that tick dropped by handleStatsTick. A command
// that read m.statsGen / m.engine when it ran would label the stale snapshot
// as current and let it overwrite the post-reset numbers.
func TestStatsCmdsCaptureGenerationAndEngineWhenCreated(t *testing.T) {
	for _, tc := range captureCmdCases {
		t.Run(tc.name, func(t *testing.T) {
			oldSnap := &statsengine.Snapshot{TotalSyscalls: 99}
			src := newGatedSource(oldSnap)
			close(src.release) // builds finish immediately
			m := NewModelWithConfig(src, nil, 100, 200, common.DefaultKeyMap())

			cmd := tc.make(m)
			if cmd == nil {
				t.Fatal("expected a command")
			}
			// Read after creation: resetBaselineCmd bumps the generation
			// itself before it returns the command.
			madeAt := m.statsGen

			// Reset after the command was made, then point the model at a
			// different engine: neither may leak into the old command.
			other := newGatedSource(&statsengine.Snapshot{TotalSyscalls: 1})
			close(other.release)
			postReset := &statsengine.Snapshot{TotalSyscalls: 0}
			src.mu.Lock()
			src.snap = postReset
			src.mu.Unlock()
			m.ResetStats()
			m.engine = other
			if m.statsGen == madeAt {
				t.Fatal("precondition: the reset must advance the generation")
			}
			post := m.LatestSnapshot()

			tick, ok := cmd().(messages.StatsTickMsg)
			if !ok {
				t.Fatalf("expected a StatsTickMsg, got %#v", tick)
			}
			if tick.Generation != madeAt {
				t.Fatalf("tick labelled generation %d, want the creation-time %d (model is at %d)",
					tick.Generation, madeAt, m.statsGen)
			}
			if other.callCount() != 0 {
				t.Fatal("the command read the model's engine when it ran instead of the captured one")
			}
			m.handleStatsTick(tick)
			if got := m.LatestSnapshot(); got != post {
				t.Fatalf("a pre-reset command's tick replaced the post-reset snapshot: %+v", got)
			}
		})
	}
}

// TestStatsCmdRunningDuringAResetIsDropped is the -race friendly variant: the
// command runs on its own goroutine, held inside Snapshot, while the UI
// goroutine resets the stats (writing statsGen and m.engine). The command
// touches only what it captured, so the race detector stays quiet, and its
// tick is dropped on arrival.
func TestStatsCmdRunningDuringAResetIsDropped(t *testing.T) {
	for _, tc := range captureCmdCases {
		t.Run(tc.name, func(t *testing.T) {
			src := newGatedSource(&statsengine.Snapshot{TotalSyscalls: 99})
			m := NewModelWithConfig(src, nil, 100, 200, common.DefaultKeyMap())
			m.activeTab = TabOverview

			cmd := tc.make(m)
			madeAt := m.statsGen
			result := runAsync(cmd)
			awaitEntered(t, src)

			// The reset's own post-reset build goes through the same gated
			// source, so it needs a second release: let both through.
			postReset := &statsengine.Snapshot{TotalSyscalls: 0}
			src.mu.Lock()
			src.snap = postReset
			src.mu.Unlock()
			resetsBefore := src.resetCount()
			go func() {
				// Release the in-flight build only after the reset has
				// run, so the two genuinely overlap.
				awaitResetAfter(src, resetsBefore)
				close(src.release)
			}()
			m.ResetStats()
			m.engine = nil

			tick := awaitMsg(t, result).(messages.StatsTickMsg)
			if tick.Generation != madeAt {
				t.Fatalf("tick labelled generation %d, want %d", tick.Generation, madeAt)
			}
			m.handleStatsTick(tick)
			if got := m.LatestSnapshot(); got != postReset {
				t.Fatalf("the in-flight pre-reset build replaced the post-reset snapshot: %+v", got)
			}
		})
	}
}

// awaitResetAfter blocks until src.Reset has been called more than before
// times.
func awaitResetAfter(g *gatedSource, before int) {
	for g.resetCount() <= before {
		time.Sleep(time.Millisecond)
	}
}
