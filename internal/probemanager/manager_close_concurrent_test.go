package probemanager

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// destroyGate is a fake-link Destroy hook that holds every caller until want
// destroys are in flight at once. It models the RCU grace period a real
// tracepoint link destroy waits for: a serial detach can never get want calls
// in flight, so the gate times out, records it, and the test fails; a
// concurrent detach releases everybody at once.
type destroyGate struct {
	want    int
	timeout time.Duration

	mu       sync.Mutex
	inflight int
	maxSeen  int
	reached  chan struct{}
	closed   bool // reached is closed; inflight may return to want, so close once
	timedOut bool
}

func newDestroyGate(want int) *destroyGate {
	return &destroyGate{want: want, timeout: time.Second, reached: make(chan struct{})}
}

func (g *destroyGate) hook() {
	g.mu.Lock()
	g.inflight++
	g.maxSeen = max(g.maxSeen, g.inflight)
	if g.inflight == g.want && !g.closed {
		g.closed = true
		close(g.reached)
	}
	g.mu.Unlock()

	select {
	case <-g.reached:
	case <-time.After(g.timeout):
		g.mu.Lock()
		g.timedOut = true
		g.mu.Unlock()
	}

	g.mu.Lock()
	g.inflight--
	g.mu.Unlock()
}

func (g *destroyGate) result() (maxSeen int, timedOut bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.maxSeen, g.timedOut
}

// newGatedManager registers n syscalls "sc0".."scN-1", attaches all of them
// and returns the manager with every link's Destroy wired to hook. The links
// are returned so tests can inspect destroy counts.
func newGatedManager(t *testing.T, n int, hook func()) (*Manager, []*fakeLink) {
	t.Helper()
	attacher := &fakeAttacher{programs: map[string]*fakeProgram{}, errs: map[string]error{}}
	var links []*fakeLink
	var tps []string
	for i := range n {
		enter := &fakeLink{onDestroy: hook}
		exit := &fakeLink{onDestroy: hook}
		links = append(links, enter, exit)
		attacher.programs[fmt.Sprintf("handle_sys_enter_sc%d", i)] = &fakeProgram{link: enter}
		attacher.programs[fmt.Sprintf("handle_sys_exit_sc%d", i)] = &fakeProgram{link: exit}
		tps = append(tps, fmt.Sprintf("sys_enter_sc%d", i), fmt.Sprintf("sys_exit_sc%d", i))
	}
	mgr := NewManager(attacher)
	if err := mgr.AttachAll(nil, tps, nil); err != nil {
		t.Fatalf("AttachAll: %v", err)
	}
	return mgr, links
}

// TestManagerCloseDestroysAllLinksConcurrently is the task zr2 regression: with
// 20 links every Destroy must be in flight at the same time, otherwise the
// per-link grace periods add up (7.5s for the real default set).
func TestManagerCloseDestroysAllLinksConcurrently(t *testing.T) {
	gate := newDestroyGate(20)
	mgr, links := newGatedManager(t, 10, nil)
	for _, l := range links {
		l.onDestroy = gate.hook
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if maxSeen, timedOut := gate.result(); timedOut || maxSeen != 20 {
		t.Fatalf("destroys were not concurrent: max in flight = %d (want 20), timedOut = %v", maxSeen, timedOut)
	}
	for i, l := range links {
		if got := l.destroyCalls(); got != 1 {
			t.Fatalf("link %d destroy calls = %d, want exactly 1", i, got)
		}
	}
}

// TestManagerDetachDestroysPairConcurrently covers the single-probe path used by
// the TUI toggle: enter and exit links must overlap their grace periods too.
func TestManagerDetachDestroysPairConcurrently(t *testing.T) {
	gate := newDestroyGate(2)
	mgr, links := newGatedManager(t, 1, nil)
	for _, l := range links {
		l.onDestroy = gate.hook
	}
	if err := mgr.Detach("sc0"); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if maxSeen, timedOut := gate.result(); timedOut || maxSeen != 2 {
		t.Fatalf("pair destroy was serial: max in flight = %d, timedOut = %v", maxSeen, timedOut)
	}
}

// TestManagerCloseProgressIsSerializedAndMonotonic pins the exact-progress
// contract under concurrency: (0,total) first, then 1..total strictly in
// order, never two callbacks at once.
func TestManagerCloseProgressIsSerializedAndMonotonic(t *testing.T) {
	const pairs = 40
	mgr, _ := newGatedManager(t, pairs, nil)
	// One inactive registered probe: it must not count towards total.
	mgr.Register("idle", TracepointPair{Enter: "sys_enter_idle", Exit: "sys_exit_idle"})

	var (
		mu      sync.Mutex
		running bool
		seen    []int
		totals  = map[int]bool{}
		overlap bool
	)
	err := mgr.CloseWithProgress(func(completed, total int) {
		mu.Lock()
		if running {
			overlap = true
		}
		running = true
		seen = append(seen, completed)
		totals[total] = true
		mu.Unlock()

		time.Sleep(50 * time.Microsecond) // widen the window for a racy caller

		mu.Lock()
		running = false
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("CloseWithProgress: %v", err)
	}
	if overlap {
		t.Fatal("progress callbacks overlapped")
	}
	if len(seen) != pairs+1 {
		t.Fatalf("got %d progress updates, want %d", len(seen), pairs+1)
	}
	for i, got := range seen {
		if got != i {
			t.Fatalf("progress[%d] = %d, want %d (sequence %v)", i, got, i, seen)
		}
	}
	if len(totals) != 1 || !totals[pairs] {
		t.Fatalf("totals = %v, want only %d", totals, pairs)
	}
}

// TestManagerCloseAttemptsEveryEntryDespiteErrors: one failing destroy must not
// stop the others, and Close still reports the error.
func TestManagerCloseAttemptsEveryEntryDespiteErrors(t *testing.T) {
	mgr, links := newGatedManager(t, 8, nil)
	boom := errors.New("destroy failed")
	links[3].err = boom
	links[10].err = boom

	err := mgr.Close()
	if !errors.Is(err, boom) {
		t.Fatalf("Close error = %v, want %v", err, boom)
	}
	for i, l := range links {
		if got := l.destroyCalls(); got != 1 {
			t.Fatalf("link %d destroy calls = %d, want 1", i, got)
		}
	}
	if active, _ := mgr.ActiveCount(); active != 0 {
		t.Fatalf("active = %d after Close, want 0", active)
	}
}

// TestDetachAllHonoursConcurrencyLimit: the bound protects against exhausting
// the thread/pids budget, so it must hold while still allowing full use of it.
func TestDetachAllHonoursConcurrencyLimit(t *testing.T) {
	const limit = 3
	gate := newDestroyGate(2 * limit) // a pair per entry, limit entries at once
	mgr, links := newGatedManager(t, 12, nil)
	for _, l := range links {
		l.onDestroy = gate.hook
	}
	entries, ok := mgr.snapshotAndMarkClosed()
	if !ok {
		t.Fatal("manager already closed")
	}
	if err := mgr.detachAll(entries, len(entries), nil, limit); err != nil {
		t.Fatalf("detachAll: %v", err)
	}
	maxSeen, timedOut := gate.result()
	if timedOut || maxSeen != 2*limit {
		t.Fatalf("max links in flight = %d (timedOut %v), want exactly %d", maxSeen, timedOut, 2*limit)
	}
}

// TestManagerCloseReturnsFirstErrorBySyscallName pins the documented "first
// error" contract: with two failing syscalls Close must always return the one
// that sorts first by name, not whichever the random map iteration or the
// goroutine scheduling produced. Repeated because a random order would only
// fail some of the time.
func TestManagerCloseReturnsFirstErrorBySyscallName(t *testing.T) {
	errFirst := errors.New("sc3 destroy failed")
	errSecond := errors.New("sc7 destroy failed")
	for range 20 {
		mgr, links := newGatedManager(t, 10, nil)
		links[2*3].err = errFirst    // sc3 enter
		links[2*7+1].err = errSecond // sc7 exit
		if err := mgr.Close(); err != errFirst {
			t.Fatalf("Close error = %v, want %v", err, errFirst)
		}
	}
}
