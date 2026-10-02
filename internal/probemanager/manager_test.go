package probemanager

import (
	"errors"
	"fmt"
	"ior/internal/tracepoints"
	"os"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeLink stands for the links one fakeProgram hands out: the program
// returns the same fakeLink at every attach and counts the attach on it
// (handedOut), so a test can still name "the enter link" before anything is
// attached. A fakeLink a test passes to the manager itself counts as one link.
//
// It holds the manager to the contract of Link, as the real link would with a
// use after free: every link handed out may be destroyed once, also when that
// Destroy returns err. A Destroy beyond that is recorded as a violation, and
// TestMain fails the run over any (linkViolations; violations, when set,
// takes them instead, for the test of the fake itself).
type fakeLink struct {
	mu         sync.Mutex
	handedOut  int
	destroyed  int
	err        error
	onDestroy  func()
	violations *violationLog
}

func (l *fakeLink) Destroy() error {
	l.mu.Lock()
	l.destroyed++
	if l.destroyed > max(l.handedOut, 1) {
		l.violationLog().add(fmt.Sprintf("Destroy call %d on a fake link handed out %d times\n%s",
			l.destroyed, l.handedOut, debug.Stack()))
	}
	onDestroy := l.onDestroy
	l.mu.Unlock()

	if onDestroy != nil {
		onDestroy()
	}
	return l.err
}

func (l *fakeLink) violationLog() *violationLog {
	if l.violations != nil {
		return l.violations
	}
	return &linkViolations
}

// attach counts one more link handed out by a program.
func (l *fakeLink) attach() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.handedOut++
}

func (l *fakeLink) destroyCalls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.destroyed
}

// live returns how many of the links handed out were not destroyed: the
// programs this fake has attached to its tracepoint right now.
func (l *fakeLink) live() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.handedOut - l.destroyed
}

// violationLog collects the breaches of the Link contract the fake links saw.
type violationLog struct {
	mu      sync.Mutex
	entries []string
}

func (v *violationLog) add(entry string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.entries = append(v.entries, entry)
}

func (v *violationLog) all() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return slices.Clone(v.entries)
}

// linkViolations is where every fake link of the package reports, whichever
// test made it; the stack in each entry names the test.
var linkViolations violationLog

// TestMain fails the run when any test destroyed a fake link twice. The check
// sits here rather than in each test because most tests build their links as
// plain literals, and a double Destroy is wrong in every one of them.
func TestMain(m *testing.M) {
	code := m.Run()
	if found := linkViolations.all(); len(found) > 0 {
		fmt.Fprintf(os.Stderr, "FAIL: %d violations of the Link contract (Destroy is final):\n%s\n",
			len(found), strings.Join(found, "\n"))
		code = 1
	}
	os.Exit(code)
}

// TestFakeLinkRecordsASecondDestroy pins the fake itself: one Destroy per
// link handed out is fine, whatever it returns, and the next one is recorded.
func TestFakeLinkRecordsASecondDestroy(t *testing.T) {
	var log violationLog
	link := &fakeLink{err: errors.New("busy"), violations: &log}
	prog := &fakeProgram{link: link}
	for range 2 {
		if _, err := prog.AttachTracepoint("syscalls", "sys_enter_read"); err != nil {
			t.Fatalf("AttachTracepoint: %v", err)
		}
		_ = link.Destroy()
	}
	if len(log.all()) != 0 || link.live() != 0 {
		t.Fatalf("violations %v, live %d after two attaches and two destroys; want none and 0", log.all(), link.live())
	}
	_ = link.Destroy()
	if len(log.all()) != 1 {
		t.Fatalf("%d violations after a destroy of a link that is gone, want 1", len(log.all()))
	}

	direct := &fakeLink{violations: &log}
	_ = direct.Destroy()
	_ = direct.Destroy()
	if len(log.all()) != 2 {
		t.Fatalf("%d violations, want a second one for a link no program handed out", len(log.all()))
	}
}

type fakeProgram struct {
	mu         sync.Mutex
	tracepoint string
	attachs    int
	link       *fakeLink
	err        error
	onAttach   func()
}

func (p *fakeProgram) AttachTracepoint(_, name string) (Link, error) {
	p.mu.Lock()
	p.tracepoint = name
	p.attachs++
	onAttach := p.onAttach
	p.mu.Unlock()

	if onAttach != nil {
		onAttach()
	}
	if p.err != nil {
		return nil, p.err
	}
	p.mu.Lock()
	if p.link == nil {
		p.link = &fakeLink{}
	}
	link := p.link
	p.mu.Unlock()
	link.attach()
	return link, nil
}

func (p *fakeProgram) attachCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.attachs
}

type fakeAttacher struct {
	programs map[string]*fakeProgram
	errs     map[string]error
}

func (a *fakeAttacher) GetProgram(name string) (Program, error) {
	if err, ok := a.errs[name]; ok {
		return nil, err
	}
	p, ok := a.programs[name]
	if !ok {
		return nil, errors.New("missing program")
	}
	return p, nil
}

func TestManagerAttachAllToggleAndCounts(t *testing.T) {
	attacher := &fakeAttacher{
		programs: map[string]*fakeProgram{
			"handle_sys_enter_read":  {},
			"handle_sys_exit_read":   {},
			"handle_sys_enter_write": {},
			"handle_sys_exit_write":  {},
		},
		errs: map[string]error{},
	}
	mgr := NewManager(attacher)

	err := mgr.AttachAll(func(tp string) bool { return tp == "sys_enter_read" || tp == "sys_exit_read" }, []string{
		"sys_enter_read", "sys_exit_read", "sys_enter_write", "sys_exit_write",
	}, nil)
	if err != nil {
		t.Fatalf("AttachAll returned error: %v", err)
	}

	active, total := mgr.ActiveCount()
	if active != 1 || total != 2 {
		t.Fatalf("unexpected counts active=%d total=%d", active, total)
	}

	states := mgr.States()
	if len(states) != 2 {
		t.Fatalf("expected 2 states, got %d", len(states))
	}
	if states[0].Syscall != "read" || !states[0].Active {
		t.Fatalf("expected read active first, got %+v", states[0])
	}
	if states[1].Syscall != "write" || states[1].Active {
		t.Fatalf("expected write inactive second, got %+v", states[1])
	}

	if err := mgr.Toggle("write"); err != nil {
		t.Fatalf("Toggle(write) returned error: %v", err)
	}
	active, total = mgr.ActiveCount()
	if active != 2 || total != 2 {
		t.Fatalf("unexpected counts after toggle active=%d total=%d", active, total)
	}
}

func TestManagerAttachAllWithDimensionSelectorAttachesOnlyEnabledSyscalls(t *testing.T) {
	attacher := &fakeAttacher{
		programs: map[string]*fakeProgram{
			"handle_sys_enter_openat": {},
			"handle_sys_exit_openat":  {},
			"handle_sys_enter_write":  {},
			"handle_sys_exit_write":   {},
		},
		errs: map[string]error{},
	}
	mgr := NewManager(attacher)
	selector, err := tracepoints.ParseSelectorWithDimensions("", "", tracepoints.DimensionSelectorConfig{
		TraceSyscalls: "openat",
	})
	if err != nil {
		t.Fatalf("build selector: %v", err)
	}

	err = mgr.AttachAll(selector.ShouldAttach, []string{
		"sys_enter_openat", "sys_exit_openat",
		"sys_enter_write", "sys_exit_write",
	}, nil)
	if err != nil {
		t.Fatalf("AttachAll returned error: %v", err)
	}

	if got := attacher.programs["handle_sys_enter_openat"].attachCalls(); got != 1 {
		t.Fatalf("openat enter attach calls = %d, want 1", got)
	}
	if got := attacher.programs["handle_sys_exit_openat"].attachCalls(); got != 1 {
		t.Fatalf("openat exit attach calls = %d, want 1", got)
	}
	if got := attacher.programs["handle_sys_enter_write"].attachCalls(); got != 0 {
		t.Fatalf("write enter attach calls = %d, want 0", got)
	}
	if got := attacher.programs["handle_sys_exit_write"].attachCalls(); got != 0 {
		t.Fatalf("write exit attach calls = %d, want 0", got)
	}
}

// closeFixture is a manager with one registered syscall, close, whose two
// fake programs hand out one fake link each. The tests of the manager's
// locking below share it: they park one call inside a fake (blocker) and
// watch what a second call does meanwhile.
type closeFixture struct {
	mgr                 *Manager
	enterProg, exitProg *fakeProgram
	enter, exit         *fakeLink
}

// newCloseFixture registers close, and attaches it too when attached.
func newCloseFixture(t *testing.T, attached bool) *closeFixture {
	t.Helper()
	f := &closeFixture{enter: &fakeLink{}, exit: &fakeLink{}}
	f.enterProg, f.exitProg = &fakeProgram{link: f.enter}, &fakeProgram{link: f.exit}
	f.mgr = NewManager(&fakeAttacher{
		programs: map[string]*fakeProgram{
			"handle_sys_enter_close": f.enterProg,
			"handle_sys_exit_close":  f.exitProg,
		},
		errs: map[string]error{},
	})
	if !attached {
		f.mgr.Register("close", TracepointPair{Enter: "sys_enter_close", Exit: "sys_exit_close"})
		return f
	}
	if err := f.mgr.AttachAll(nil, []string{"sys_enter_close", "sys_exit_close"}, nil); err != nil {
		t.Fatalf("AttachAll returned error: %v", err)
	}
	return f
}

// assertAttachCalls checks how often each program was asked to attach.
func (f *closeFixture) assertAttachCalls(t *testing.T, enter, exit int) {
	t.Helper()
	if got := f.enterProg.attachCalls(); got != enter {
		t.Fatalf("enter attach ran %d times, want %d", got, enter)
	}
	if got := f.exitProg.attachCalls(); got != exit {
		t.Fatalf("exit attach ran %d times, want %d", got, exit)
	}
}

// assertDestroyCalls checks how often each link was destroyed.
func (f *closeFixture) assertDestroyCalls(t *testing.T, enter, exit int) {
	t.Helper()
	if got := f.enter.destroyCalls(); got != enter {
		t.Fatalf("enter link destroy calls = %d, want %d", got, enter)
	}
	if got := f.exit.destroyCalls(); got != exit {
		t.Fatalf("exit link destroy calls = %d, want %d", got, exit)
	}
}

// blocker parks the calls of a fake: hook, set as a fakeProgram's onAttach or
// a fakeLink's onDestroy, returns only after release.
type blocker struct {
	once    sync.Once
	started chan struct{}
	gate    chan struct{}
}

func newBlocker() *blocker {
	return &blocker{started: make(chan struct{}), gate: make(chan struct{})}
}

func (b *blocker) hook() {
	b.once.Do(func() { close(b.started) })
	<-b.gate
}

// awaitStarted returns once a call is parked in hook, and fails the test with
// notStarted when none arrives within a second.
func (b *blocker) awaitStarted(t *testing.T, notStarted string) {
	t.Helper()
	select {
	case <-b.started:
	case <-time.After(time.Second):
		t.Fatal(notStarted)
	}
}

// release lets the parked call, and every later one, go on.
func (b *blocker) release() {
	close(b.gate)
}

// goErr runs call on a goroutine of its own and returns the channel its error
// arrives on.
func goErr(call func() error) <-chan error {
	result := make(chan error, 1)
	go func() { result <- call() }()
	return result
}

// assertStillRunning fails the test with early when the call behind result
// returns within 50ms: it is expected to wait for something the test holds.
func assertStillRunning(t *testing.T, result <-chan error, early string) {
	t.Helper()
	select {
	case err := <-result:
		t.Fatalf("%s: %v", early, err)
	case <-time.After(50 * time.Millisecond):
	}
}

// closeBegun starts CloseWithProgress on a goroutine of its own and returns
// the channel of its error once it made its first report, (0, total): the
// manager is marked closed by then.
func closeBegun(t *testing.T, mgr *Manager) <-chan error {
	t.Helper()
	begun := make(chan struct{})
	var once sync.Once
	result := goErr(func() error {
		return mgr.CloseWithProgress(func(completed, _ int) {
			if completed == 0 {
				once.Do(func() { close(begun) })
			}
		})
	})
	select {
	case <-begun:
	case <-time.After(time.Second):
		t.Fatal("close did not begin")
	}
	return result
}

func TestManagerAttachSerializesConcurrentCalls(t *testing.T) {
	f := newCloseFixture(t, false)
	enterAttach := newBlocker()
	f.enterProg.onAttach = enterAttach.hook

	first := goErr(func() error { return f.mgr.Attach("close") })
	enterAttach.awaitStarted(t, "first attach did not start")

	// Goroutine 1 is now blocked inside AttachTracepoint for the enter probe.
	// Enter has been called exactly once; exit has not been called yet because
	// attachPair calls enter then exit sequentially.  These assertions are safe
	// without any sleep: the blocker's started channel being closed is a
	// happens-before edge that makes the attach-count writes visible here.
	f.assertAttachCalls(t, 1, 0)

	// Start a second concurrent Attach.  It will acquire m.mu briefly then
	// block on entry.attachMu (held by goroutine 1) before it can reach
	// AttachTracepoint.  The final count assertions below confirm it never ran
	// a second attach.
	second := goErr(func() error { return f.mgr.Attach("close") })
	enterAttach.release()

	if err := <-first; err != nil {
		t.Fatalf("first Attach returned error: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("second Attach returned error: %v", err)
	}
	f.assertAttachCalls(t, 1, 1)
	if !f.mgr.IsActive("close") {
		t.Fatalf("expected probe to remain active after concurrent attach calls")
	}
}

func TestManagerAttachWaitsForDetachBeforeReturning(t *testing.T) {
	f := newCloseFixture(t, true)
	enterDestroy := newBlocker()
	f.enter.onDestroy = enterDestroy.hook

	detach := goErr(func() error { return f.mgr.Detach("close") })
	enterDestroy.awaitStarted(t, "detach did not start destroying the enter link")

	attach := goErr(func() error { return f.mgr.Attach("close") })
	assertStillRunning(t, attach, "Attach returned before Detach completed")
	enterDestroy.release()

	if err := <-detach; err != nil {
		t.Fatalf("Detach returned error: %v", err)
	}
	if err := <-attach; err != nil {
		t.Fatalf("Attach returned error: %v", err)
	}
	f.assertAttachCalls(t, 2, 2)
	f.assertDestroyCalls(t, 1, 1)
	if !f.mgr.IsActive("close") {
		t.Fatalf("expected probe to be active after detach followed by attach")
	}
}

// TestManagerCloseWaitsForDetachAndDoesNotDoubleDestroy: a Close that starts
// while a Detach is destroying the pair waits for it and destroys nothing
// itself. Its progress counts that pair all the same (pairEntry): the Detach
// has taken the links off the entry, but the entry is active until the Detach
// commits, and the active pairs are what Close counts. A total taken from the
// links still on the entries would be 0 here, and the progress bar of the
// teardown would end before the last tracepoint is detached.
func TestManagerCloseWaitsForDetachAndDoesNotDoubleDestroy(t *testing.T) {
	f := newCloseFixture(t, true)
	enterDestroy := newBlocker()
	f.enter.onDestroy = enterDestroy.hook

	detach := goErr(func() error { return f.mgr.Detach("close") })
	enterDestroy.awaitStarted(t, "detach did not start destroying the enter link")

	// Written by Close's goroutines one at a time, and read only after Close
	// has returned.
	var progress [][2]int
	closed := goErr(func() error {
		return f.mgr.CloseWithProgress(func(completed, total int) {
			progress = append(progress, [2]int{completed, total})
		})
	})
	assertStillRunning(t, closed, "Close returned before Detach completed")
	enterDestroy.release()

	if err := <-detach; err != nil {
		t.Fatalf("Detach returned error: %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if want := [][2]int{{0, 1}, {1, 1}}; !slices.Equal(progress, want) {
		t.Fatalf("Close reported progress %v, want %v: the pair being detached counts", progress, want)
	}
	f.assertDestroyCalls(t, 1, 1)
	if f.mgr.IsActive("close") {
		t.Fatalf("expected probe to be inactive after Close")
	}
}

func TestManagerCloseWaitsForBlockedAttachCleanup(t *testing.T) {
	f := newCloseFixture(t, false)
	enterAttach := newBlocker()
	f.enterProg.onAttach = enterAttach.hook

	attach := goErr(func() error { return f.mgr.Attach("close") })
	enterAttach.awaitStarted(t, "attach did not reach the blocked module call")

	closed := closeBegun(t, f.mgr)
	assertStillRunning(t, closed, "CloseWithProgress returned before blocked attach cleanup")
	enterAttach.release()

	if err := <-attach; err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("Attach error = %v, want closed manager", err)
	}
	if err := <-closed; err != nil {
		t.Fatalf("CloseWithProgress returned error: %v", err)
	}
	f.assertDestroyCalls(t, 1, 1)
}

func TestManagerCloseAllowsReentrantCloseDuringDestroy(t *testing.T) {
	mgr := &Manager{probes: make(map[string]*probeEntry)}
	reentrantErr := make(chan error, 1)
	enter := &fakeLink{onDestroy: func() { reentrantErr <- mgr.Close() }}
	mgr.probes["close"] = &probeEntry{
		syscall:   "close",
		enterLink: enter,
		active:    true,
	}

	closeErr := make(chan error, 1)
	go func() { closeErr <- mgr.Close() }()
	select {
	case err := <-closeErr:
		if err != nil {
			t.Fatalf("outer Close returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("re-entrant Close deadlocked during link destruction")
	}
	if err := <-reentrantErr; err != nil {
		t.Fatalf("re-entrant Close returned error: %v", err)
	}
	if got := enter.destroyCalls(); got != 1 {
		t.Fatalf("enter link destroy calls = %d, want 1", got)
	}
}

func TestManagerDetachDestroysLinks(t *testing.T) {
	enter := &fakeLink{}
	exit := &fakeLink{}
	attacher := &fakeAttacher{
		programs: map[string]*fakeProgram{
			"handle_sys_enter_close": {link: enter},
			"handle_sys_exit_close":  {link: exit},
		},
		errs: map[string]error{},
	}
	mgr := NewManager(attacher)
	if err := mgr.AttachAll(nil, []string{"sys_enter_close", "sys_exit_close"}, nil); err != nil {
		t.Fatalf("AttachAll returned error: %v", err)
	}
	if err := mgr.Detach("close"); err != nil {
		t.Fatalf("Detach returned error: %v", err)
	}
	if enter.destroyed != 1 || exit.destroyed != 1 {
		t.Fatalf("expected both links destroyed once, got enter=%d exit=%d", enter.destroyed, exit.destroyed)
	}
}

// TestManagerDetachFailureLeavesTheProbeInactiveWithItsError: a Destroy that
// reports an error is final like any other (Link), so the probe is off and
// the error stays on it (final_destroy_test.go has the whole contract).
func TestManagerDetachFailureLeavesTheProbeInactiveWithItsError(t *testing.T) {
	enter := &fakeLink{err: errors.New("destroy failed")}
	exit := &fakeLink{}
	attacher := &fakeAttacher{
		programs: map[string]*fakeProgram{
			"handle_sys_enter_close": {link: enter},
			"handle_sys_exit_close":  {link: exit},
		},
		errs: map[string]error{},
	}
	mgr := NewManager(attacher)
	if err := mgr.AttachAll(nil, []string{"sys_enter_close", "sys_exit_close"}, nil); err != nil {
		t.Fatalf("AttachAll returned error: %v", err)
	}

	err := mgr.Detach("close")
	if err == nil {
		t.Fatalf("expected detach error")
	}
	states := mgr.States()
	if len(states) != 1 {
		t.Fatalf("expected one state, got %+v", states)
	}
	if states[0].Active {
		t.Fatalf("expected the probe to be inactive although one destroy reported an error")
	}
	if states[0].Error == "" {
		t.Fatalf("expected error to be recorded after detach failure")
	}
	if enter.destroyCalls() != 1 || exit.destroyCalls() != 1 {
		t.Fatalf("expected both links destroyed once, got enter=%d exit=%d", enter.destroyCalls(), exit.destroyCalls())
	}
}

func TestManagerClosePreventsFurtherOperations(t *testing.T) {
	attacher := &fakeAttacher{
		programs: map[string]*fakeProgram{
			"handle_sys_enter_open": {},
			"handle_sys_exit_open":  {},
		},
		errs: map[string]error{},
	}
	mgr := NewManager(attacher)
	if err := mgr.AttachAll(nil, []string{"sys_enter_open", "sys_exit_open"}, nil); err != nil {
		t.Fatalf("AttachAll returned error: %v", err)
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if err := mgr.Toggle("open"); err == nil {
		t.Fatalf("expected Toggle to fail after Close")
	}
}

func TestManagerAttachAllReturnsProgramError(t *testing.T) {
	attacher := &fakeAttacher{
		programs: map[string]*fakeProgram{},
		errs: map[string]error{
			"handle_sys_enter_read": errors.New("boom"),
		},
	}
	mgr := NewManager(attacher)
	err := mgr.AttachAll(nil, []string{"sys_enter_read", "sys_exit_read"}, nil)
	if err == nil {
		t.Fatalf("expected attach error")
	}
	states := mgr.States()
	if len(states) != 1 || states[0].Error == "" {
		t.Fatalf("expected state to capture attach error, got %+v", states)
	}
}

// When onAttachError is supplied, AttachAll should report each per-syscall
// failure through the callback and continue attaching the remaining probes.
// This is the path that lets a binary built on a newer kernel run on an older
// one where some tracepoints don't exist.
func TestManagerAttachAllWarnAndContinue(t *testing.T) {
	attacher := &fakeAttacher{
		programs: map[string]*fakeProgram{
			"handle_sys_enter_write": {},
			"handle_sys_exit_write":  {},
		},
		errs: map[string]error{
			"handle_sys_enter_read": errors.New("no such tracepoint"),
		},
	}
	mgr := NewManager(attacher)

	var warned []string
	warn := func(syscall string, err error) {
		warned = append(warned, syscall+":"+err.Error())
	}
	err := mgr.AttachAll(nil, []string{
		"sys_enter_read", "sys_exit_read",
		"sys_enter_write", "sys_exit_write",
	}, warn)
	if err != nil {
		t.Fatalf("AttachAll returned error despite warn callback: %v", err)
	}
	if len(warned) != 1 {
		t.Fatalf("expected exactly 1 warning, got %d (%v)", len(warned), warned)
	}
	if !strings.Contains(warned[0], "read") || !strings.Contains(warned[0], "no such tracepoint") {
		t.Fatalf("unexpected warning text: %q", warned[0])
	}
	active, total := mgr.ActiveCount()
	if active != 1 || total != 2 {
		t.Fatalf("expected write attached and read skipped, got active=%d total=%d", active, total)
	}
}

func TestManagerAttachAllPicksUpNewTracepointsOnLaterCall(t *testing.T) {
	attacher := &fakeAttacher{
		programs: map[string]*fakeProgram{
			"handle_sys_enter_read":  {},
			"handle_sys_exit_read":   {},
			"handle_sys_enter_write": {},
			"handle_sys_exit_write":  {},
		},
		errs: map[string]error{},
	}
	mgr := NewManager(attacher)

	if err := mgr.AttachAll(nil, []string{"sys_enter_read", "sys_exit_read"}, nil); err != nil {
		t.Fatalf("AttachAll(read) returned error: %v", err)
	}
	states := mgr.States()
	if len(states) != 1 || states[0].Syscall != "read" {
		t.Fatalf("expected only read after first call, got %+v", states)
	}

	if err := mgr.AttachAll(nil, []string{"sys_enter_read", "sys_exit_read", "sys_enter_write", "sys_exit_write"}, nil); err != nil {
		t.Fatalf("AttachAll(read+write) returned error: %v", err)
	}
	states = mgr.States()
	if len(states) != 2 {
		t.Fatalf("expected new syscall to appear after second call, got %+v", states)
	}
	if states[0].Syscall != "read" || states[1].Syscall != "write" {
		t.Fatalf("unexpected syscall ordering/content: %+v", states)
	}
}

func TestManagerIsActiveReflectsCurrentState(t *testing.T) {
	attacher := &fakeAttacher{
		programs: map[string]*fakeProgram{
			"handle_sys_enter_read": {},
			"handle_sys_exit_read":  {},
		},
		errs: map[string]error{},
	}
	mgr := NewManager(attacher)
	if err := mgr.AttachAll(nil, []string{"sys_enter_read", "sys_exit_read"}, nil); err != nil {
		t.Fatalf("AttachAll returned error: %v", err)
	}
	if !mgr.IsActive("read") {
		t.Fatalf("expected read to be active")
	}
	if err := mgr.Detach("read"); err != nil {
		t.Fatalf("Detach returned error: %v", err)
	}
	if mgr.IsActive("read") {
		t.Fatalf("expected read to be inactive after detach")
	}
	if mgr.IsActive("does_not_exist") {
		t.Fatalf("expected unknown syscall to be inactive")
	}
}

func TestAttachReturnsCleanupErrorsWhenManagerClosesMidAttach(t *testing.T) {
	enterDestroyErr := errors.New("enter cleanup failed")
	exitDestroyErr := errors.New("exit cleanup failed")
	f := newCloseFixture(t, false)
	f.enter.err, f.exit.err = enterDestroyErr, exitDestroyErr
	exitAttach := newBlocker()
	f.exitProg.onAttach = exitAttach.hook

	attach := goErr(func() error { return f.mgr.Attach("close") })
	exitAttach.awaitStarted(t, "attach did not reach the exit tracepoint")

	closed := closeBegun(t, f.mgr)
	assertStillRunning(t, closed, "CloseWithProgress returned before the in-flight attach could roll back")
	exitAttach.release()

	err := <-attach
	if err == nil {
		t.Fatalf("expected attach error when manager closes mid-attach")
	}
	if !strings.Contains(err.Error(), "probe manager is closed") {
		t.Fatalf("expected close error in attach result, got %v", err)
	}
	if !errors.Is(err, enterDestroyErr) {
		t.Fatalf("expected joined enter cleanup error, got %v", err)
	}
	if !errors.Is(err, exitDestroyErr) {
		t.Fatalf("expected joined exit cleanup error, got %v", err)
	}
	f.assertDestroyCalls(t, 1, 1)
	if err := <-closed; err != nil {
		t.Fatalf("CloseWithProgress returned error: %v", err)
	}
}

// TestAttachPairReturnsCleanupErrorWhenExitAttachFails: an enter link whose
// destroy reports an error after the exit attach failed is gone like any
// destroyed link (Link), so attachPair returns both errors and no link.
// Handed back, as task z13 first had it, the manager kept the link and
// destroyed it a second time (final_destroy_test.go has the manager's side).
func TestAttachPairReturnsCleanupErrorWhenExitAttachFails(t *testing.T) {
	enterDestroyErr := errors.New("enter cleanup failed")
	exitAttachErr := errors.New("exit attach failed")
	enter := &fakeLink{err: enterDestroyErr}

	attacher := &fakeAttacher{
		programs: map[string]*fakeProgram{
			"handle_sys_enter_close": {link: enter},
			"handle_sys_exit_close":  {err: exitAttachErr},
		},
		errs: map[string]error{},
	}

	enterLink, exitLink, err := attachPair(attacher, "sys_enter_close", "sys_exit_close")
	if err == nil {
		t.Fatalf("expected attachPair error")
	}
	if enterLink != nil || exitLink != nil {
		t.Fatalf("expected failed attachPair to return no link, got enter=%v exit=%v", enterLink, exitLink)
	}
	if !errors.Is(err, exitAttachErr) {
		t.Fatalf("expected exit attach error in result, got %v", err)
	}
	if !errors.Is(err, enterDestroyErr) {
		t.Fatalf("expected enter cleanup error in result, got %v", err)
	}
	if enter.destroyed != 1 {
		t.Fatalf("expected enter link cleanup to run once, got %d", enter.destroyed)
	}
}

// TestAttachPairReturnsNoLinkWhenItsCleanupSucceeds is the ordinary failure:
// the enter link is destroyed again, and the attach error comes back alone.
func TestAttachPairReturnsNoLinkWhenItsCleanupSucceeds(t *testing.T) {
	exitAttachErr := errors.New("exit attach failed")
	enter := &fakeLink{}
	attacher := &fakeAttacher{
		programs: map[string]*fakeProgram{
			"handle_sys_enter_close": {link: enter},
			"handle_sys_exit_close":  {err: exitAttachErr},
		},
		errs: map[string]error{},
	}

	enterLink, exitLink, err := attachPair(attacher, "sys_enter_close", "sys_exit_close")
	if !errors.Is(err, exitAttachErr) {
		t.Fatalf("expected exit attach error in result, got %v", err)
	}
	if enterLink != nil || exitLink != nil {
		t.Fatalf("expected no links after a successful cleanup, got enter=%v exit=%v", enterLink, exitLink)
	}
	if enter.destroyed != 1 {
		t.Fatalf("expected enter link cleanup to run once, got %d", enter.destroyed)
	}
}

// closeUpdate is one progress report of CloseWithProgress, with the number of
// Destroy calls the test's links had seen when it was made.
type closeUpdate struct {
	completed int
	total     int
	destroyed int
}

// twoActivePairsAndAnInactiveOne returns a manager holding links as the
// enter and exit links of two active pairs, first and second, beside a
// registered probe without a link.
func twoActivePairsAndAnInactiveOne(links []*fakeLink) *Manager {
	return &Manager{probes: map[string]*probeEntry{
		"first": {
			syscall:   "first",
			enterLink: links[0],
			exitLink:  links[1],
			active:    true,
		},
		"second": {
			syscall:   "second",
			enterLink: links[2],
			exitLink:  links[3],
			active:    true,
		},
		"inactive": {syscall: "inactive"},
	}}
}

// closeRecordingDestroys closes mgr and returns its progress reports, each
// with the Destroy calls links had seen by then, and the error of the close.
func closeRecordingDestroys(mgr *Manager, links []*fakeLink) ([]closeUpdate, error) {
	var updates []closeUpdate
	err := mgr.CloseWithProgress(func(completed, total int) {
		destroyed := 0
		for _, link := range links {
			destroyed += link.destroyCalls()
		}
		updates = append(updates, closeUpdate{completed: completed, total: total, destroyed: destroyed})
	})
	return updates, err
}

func TestManagerCloseWithProgressCountsActivePairsAndContinuesAfterError(t *testing.T) {
	firstEnterErr := errors.New("first enter detach failed")
	links := []*fakeLink{
		{err: firstEnterErr}, {}, {}, {},
	}
	updates, err := closeRecordingDestroys(twoActivePairsAndAnInactiveOne(links), links)
	if !errors.Is(err, firstEnterErr) {
		t.Fatalf("CloseWithProgress() error = %v, want %v", err, firstEnterErr)
	}
	// Entries detach concurrently, so a progress update may already see links
	// of a pair that has not been counted yet. What must hold is that a pair is
	// only counted after both its links are destroyed: destroyed is at least
	// 2*completed, and exactly 0 before anything was reported and 4 at the end.
	want := []closeUpdate{
		{completed: 0, total: 2, destroyed: 0},
		{completed: 1, total: 2},
		{completed: 2, total: 2, destroyed: 4},
	}
	if len(updates) != len(want) {
		t.Fatalf("progress updates = %+v, want %+v", updates, want)
	}
	for i := range want {
		got := updates[i]
		if got.completed != want[i].completed || got.total != want[i].total {
			t.Fatalf("progress[%d] = %+v, want %+v", i, got, want[i])
		}
		if got.destroyed < 2*got.completed || (i != 1 && got.destroyed != want[i].destroyed) {
			t.Fatalf("progress[%d] = %+v, want destroyed >= %d (exactly %d for i != 1)", i, got, 2*got.completed, want[i].destroyed)
		}
	}
	for i, link := range links {
		if got := link.destroyCalls(); got != 1 {
			t.Fatalf("link %d destroy calls = %d, want 1", i, got)
		}
	}
}
