package probemanager

import (
	"errors"
	"ior/internal/tracepoints"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeLink struct {
	mu        sync.Mutex
	destroyed int
	err       error
	onDestroy func()
}

func (l *fakeLink) Destroy() error {
	l.mu.Lock()
	l.destroyed++
	onDestroy := l.onDestroy
	l.mu.Unlock()

	if onDestroy != nil {
		onDestroy()
	}
	return l.err
}

func (l *fakeLink) destroyCalls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.destroyed
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
	if p.link == nil {
		p.link = &fakeLink{}
	}
	return p.link, nil
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

func TestManagerAttachSerializesConcurrentCalls(t *testing.T) {
	enterBlocked := make(chan struct{})
	releaseEnter := make(chan struct{})
	enter := &fakeProgram{link: &fakeLink{}}
	var enteredOnce sync.Once
	enter.onAttach = func() {
		enteredOnce.Do(func() { close(enterBlocked) })
		<-releaseEnter
	}
	exit := &fakeProgram{link: &fakeLink{}}
	attacher := &fakeAttacher{
		programs: map[string]*fakeProgram{
			"handle_sys_enter_close": enter,
			"handle_sys_exit_close":  exit,
		},
		errs: map[string]error{},
	}
	mgr := NewManager(attacher)
	mgr.Register("close", TracepointPair{Enter: "sys_enter_close", Exit: "sys_exit_close"})

	errCh1 := make(chan error, 1)
	go func() {
		errCh1 <- mgr.Attach("close")
	}()

	select {
	case <-enterBlocked:
	case <-time.After(time.Second):
		t.Fatal("first attach did not start")
	}

	// Goroutine 1 is now blocked inside AttachTracepoint for the enter probe.
	// Enter has been called exactly once; exit has not been called yet because
	// attachPair calls enter then exit sequentially.  These assertions are safe
	// without any sleep: enterBlocked being closed is a happens-before edge that
	// makes the attach-count writes visible here.
	if got := enter.attachCalls(); got != 1 {
		t.Fatalf("expected enter attach to be in flight (called once), got %d", got)
	}
	if got := exit.attachCalls(); got != 0 {
		t.Fatalf("expected exit attach to not have started while enter is blocked, got %d", got)
	}

	// Start a second concurrent Attach.  It will acquire m.mu briefly then
	// block on entry.attachMu (held by goroutine 1) before it can reach
	// AttachTracepoint.  The final count assertions below confirm it never ran
	// a second attach.
	errCh2 := make(chan error, 1)
	go func() {
		errCh2 <- mgr.Attach("close")
	}()

	close(releaseEnter)

	if err := <-errCh1; err != nil {
		t.Fatalf("first Attach returned error: %v", err)
	}
	if err := <-errCh2; err != nil {
		t.Fatalf("second Attach returned error: %v", err)
	}
	if got := enter.attachCalls(); got != 1 {
		t.Fatalf("expected enter attach to run once, got %d", got)
	}
	if got := exit.attachCalls(); got != 1 {
		t.Fatalf("expected exit attach to run once, got %d", got)
	}
	if !mgr.IsActive("close") {
		t.Fatalf("expected probe to remain active after concurrent attach calls")
	}
}

func TestManagerAttachWaitsForDetachBeforeReturning(t *testing.T) {
	enterDestroyStarted := make(chan struct{})
	releaseDestroy := make(chan struct{})
	var enterDestroyOnce sync.Once
	enter := &fakeLink{}
	enter.onDestroy = func() {
		enterDestroyOnce.Do(func() { close(enterDestroyStarted) })
		<-releaseDestroy
	}
	exit := &fakeLink{}
	enterProg := &fakeProgram{link: enter}
	exitProg := &fakeProgram{link: exit}
	attacher := &fakeAttacher{
		programs: map[string]*fakeProgram{
			"handle_sys_enter_close": enterProg,
			"handle_sys_exit_close":  exitProg,
		},
		errs: map[string]error{},
	}
	mgr := NewManager(attacher)
	if err := mgr.AttachAll(nil, []string{"sys_enter_close", "sys_exit_close"}, nil); err != nil {
		t.Fatalf("AttachAll returned error: %v", err)
	}

	detachErrCh := make(chan error, 1)
	go func() {
		detachErrCh <- mgr.Detach("close")
	}()

	select {
	case <-enterDestroyStarted:
	case <-time.After(time.Second):
		t.Fatal("detach did not start destroying the enter link")
	}

	attachErrCh := make(chan error, 1)
	go func() {
		attachErrCh <- mgr.Attach("close")
	}()

	select {
	case err := <-attachErrCh:
		t.Fatalf("Attach returned before Detach completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseDestroy)

	if err := <-detachErrCh; err != nil {
		t.Fatalf("Detach returned error: %v", err)
	}
	if err := <-attachErrCh; err != nil {
		t.Fatalf("Attach returned error: %v", err)
	}
	if got := enterProg.attachCalls(); got != 2 {
		t.Fatalf("expected enter attach to run twice, got %d", got)
	}
	if got := exitProg.attachCalls(); got != 2 {
		t.Fatalf("expected exit attach to run twice, got %d", got)
	}
	if got := enter.destroyCalls(); got != 1 {
		t.Fatalf("expected enter link to be destroyed once, got %d", got)
	}
	if got := exit.destroyCalls(); got != 1 {
		t.Fatalf("expected exit link to be destroyed once, got %d", got)
	}
	if !mgr.IsActive("close") {
		t.Fatalf("expected probe to be active after detach followed by attach")
	}
}

func TestManagerCloseWaitsForDetachAndDoesNotDoubleDestroy(t *testing.T) {
	enterDestroyStarted := make(chan struct{})
	releaseDestroy := make(chan struct{})
	var enterDestroyOnce sync.Once
	enter := &fakeLink{}
	enter.onDestroy = func() {
		enterDestroyOnce.Do(func() { close(enterDestroyStarted) })
		<-releaseDestroy
	}
	exit := &fakeLink{}
	enterProg := &fakeProgram{link: enter}
	exitProg := &fakeProgram{link: exit}
	attacher := &fakeAttacher{
		programs: map[string]*fakeProgram{
			"handle_sys_enter_close": enterProg,
			"handle_sys_exit_close":  exitProg,
		},
		errs: map[string]error{},
	}
	mgr := NewManager(attacher)
	if err := mgr.AttachAll(nil, []string{"sys_enter_close", "sys_exit_close"}, nil); err != nil {
		t.Fatalf("AttachAll returned error: %v", err)
	}

	detachErrCh := make(chan error, 1)
	go func() {
		detachErrCh <- mgr.Detach("close")
	}()

	select {
	case <-enterDestroyStarted:
	case <-time.After(time.Second):
		t.Fatal("detach did not start destroying the enter link")
	}

	closeErrCh := make(chan error, 1)
	go func() {
		closeErrCh <- mgr.Close()
	}()

	select {
	case err := <-closeErrCh:
		t.Fatalf("Close returned before Detach completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseDestroy)

	if err := <-detachErrCh; err != nil {
		t.Fatalf("Detach returned error: %v", err)
	}
	if err := <-closeErrCh; err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if got := enter.destroyCalls(); got != 1 {
		t.Fatalf("expected enter link to be destroyed once, got %d", got)
	}
	if got := exit.destroyCalls(); got != 1 {
		t.Fatalf("expected exit link to be destroyed once, got %d", got)
	}
	if mgr.IsActive("close") {
		t.Fatalf("expected probe to be inactive after Close")
	}
}

func TestManagerCloseWaitsForBlockedAttachCleanup(t *testing.T) {
	attachStarted := make(chan struct{})
	releaseAttach := make(chan struct{})
	enter := &fakeLink{}
	exit := &fakeLink{}
	enterProgram := &fakeProgram{link: enter}
	var startOnce sync.Once
	enterProgram.onAttach = func() {
		startOnce.Do(func() { close(attachStarted) })
		<-releaseAttach
	}
	mgr := NewManager(&fakeAttacher{
		programs: map[string]*fakeProgram{
			"handle_sys_enter_close": enterProgram,
			"handle_sys_exit_close":  {link: exit},
		},
		errs: map[string]error{},
	})
	mgr.Register("close", TracepointPair{Enter: "sys_enter_close", Exit: "sys_exit_close"})

	attachErr := make(chan error, 1)
	go func() { attachErr <- mgr.Attach("close") }()
	select {
	case <-attachStarted:
	case <-time.After(time.Second):
		t.Fatal("attach did not reach the blocked module call")
	}

	closeStarted := make(chan struct{})
	closeErr := make(chan error, 1)
	go func() {
		closeErr <- mgr.CloseWithProgress(func(completed, total int) {
			if completed == 0 {
				select {
				case <-closeStarted:
				default:
					close(closeStarted)
				}
			}
		})
	}()
	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		t.Fatal("close did not begin")
	}
	select {
	case err := <-closeErr:
		t.Fatalf("CloseWithProgress returned before blocked attach cleanup: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseAttach)
	if err := <-attachErr; err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("Attach error = %v, want closed manager", err)
	}
	if err := <-closeErr; err != nil {
		t.Fatalf("CloseWithProgress returned error: %v", err)
	}
	if got := enter.destroyCalls(); got != 1 {
		t.Fatalf("enter link destroy calls = %d, want 1", got)
	}
	if got := exit.destroyCalls(); got != 1 {
		t.Fatalf("exit link destroy calls = %d, want 1", got)
	}
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

func TestManagerDetachFailureKeepsActiveStateForUndetachedLink(t *testing.T) {
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
	if !states[0].Active {
		t.Fatalf("expected probe to remain active when one link failed to detach")
	}
	if states[0].Error == "" {
		t.Fatalf("expected error to be recorded after detach failure")
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
	enter := &fakeLink{err: enterDestroyErr}
	exit := &fakeLink{err: exitDestroyErr}
	exitAttachStarted := make(chan struct{})
	allowAttachReturn := make(chan struct{})

	attacher := &fakeAttacher{
		programs: map[string]*fakeProgram{
			"handle_sys_enter_close": {link: enter},
			"handle_sys_exit_close":  {link: exit},
		},
		errs: map[string]error{},
	}
	mgr := NewManager(attacher)
	attacher.programs["handle_sys_exit_close"].onAttach = func() {
		close(exitAttachStarted)
		<-allowAttachReturn
	}
	mgr.Register("close", TracepointPair{Enter: "sys_enter_close", Exit: "sys_exit_close"})

	attachErr := make(chan error, 1)
	go func() { attachErr <- mgr.Attach("close") }()
	<-exitAttachStarted

	closed := make(chan struct{})
	closeErr := make(chan error, 1)
	go func() {
		closeErr <- mgr.CloseWithProgress(func(completed, _ int) {
			if completed == 0 {
				select {
				case <-closed:
				default:
					close(closed)
				}
			}
		})
	}()
	<-closed
	select {
	case err := <-closeErr:
		t.Fatalf("CloseWithProgress returned before the in-flight attach could roll back: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(allowAttachReturn)

	err := <-attachErr
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
	if enter.destroyed != 1 || exit.destroyed != 1 {
		t.Fatalf("expected both cleanup destroys to run once, got enter=%d exit=%d", enter.destroyed, exit.destroyed)
	}
	if err := <-closeErr; err != nil {
		t.Fatalf("CloseWithProgress returned error: %v", err)
	}
}

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
		t.Fatalf("expected failed attachPair to return nil links, got enter=%v exit=%v", enterLink, exitLink)
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

func TestManagerCloseWithProgressCountsActivePairsAndContinuesAfterError(t *testing.T) {
	firstEnterErr := errors.New("first enter detach failed")
	links := []*fakeLink{
		{err: firstEnterErr}, {}, {}, {},
	}
	mgr := &Manager{probes: map[string]*probeEntry{
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

	type update struct {
		completed int
		total     int
		destroyed int
	}
	var updates []update
	err := mgr.CloseWithProgress(func(completed, total int) {
		destroyed := 0
		for _, link := range links {
			destroyed += link.destroyCalls()
		}
		updates = append(updates, update{completed: completed, total: total, destroyed: destroyed})
	})

	if !errors.Is(err, firstEnterErr) {
		t.Fatalf("CloseWithProgress() error = %v, want %v", err, firstEnterErr)
	}
	// Entries detach concurrently, so a progress update may already see links
	// of a pair that has not been counted yet. What must hold is that a pair is
	// only counted after both its links are destroyed: destroyed is at least
	// 2*completed, and exactly 0 before anything was reported and 4 at the end.
	want := []update{
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
