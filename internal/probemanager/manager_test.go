package probemanager

import (
	"errors"
	"strings"
	"testing"
)

type fakeLink struct {
	destroyed int
	err       error
}

func (l *fakeLink) Destroy() error {
	l.destroyed++
	return l.err
}

type fakeProgram struct {
	tracepoint string
	link       *fakeLink
	err        error
	onAttach   func()
}

func (p *fakeProgram) AttachTracepoint(_, name string) (Link, error) {
	p.tracepoint = name
	if p.onAttach != nil {
		p.onAttach()
	}
	if p.err != nil {
		return nil, p.err
	}
	if p.link == nil {
		p.link = &fakeLink{}
	}
	return p.link, nil
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
	})
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
	if err := mgr.AttachAll(nil, []string{"sys_enter_close", "sys_exit_close"}); err != nil {
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
	if err := mgr.AttachAll(nil, []string{"sys_enter_close", "sys_exit_close"}); err != nil {
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
	if err := mgr.AttachAll(nil, []string{"sys_enter_open", "sys_exit_open"}); err != nil {
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
	err := mgr.AttachAll(nil, []string{"sys_enter_read", "sys_exit_read"})
	if err == nil {
		t.Fatalf("expected attach error")
	}
	states := mgr.States()
	if len(states) != 1 || states[0].Error == "" {
		t.Fatalf("expected state to capture attach error, got %+v", states)
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

	if err := mgr.AttachAll(nil, []string{"sys_enter_read", "sys_exit_read"}); err != nil {
		t.Fatalf("AttachAll(read) returned error: %v", err)
	}
	states := mgr.States()
	if len(states) != 1 || states[0].Syscall != "read" {
		t.Fatalf("expected only read after first call, got %+v", states)
	}

	if err := mgr.AttachAll(nil, []string{"sys_enter_read", "sys_exit_read", "sys_enter_write", "sys_exit_write"}); err != nil {
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
	if err := mgr.AttachAll(nil, []string{"sys_enter_read", "sys_exit_read"}); err != nil {
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

	attacher := &fakeAttacher{
		programs: map[string]*fakeProgram{
			"handle_sys_enter_close": {link: enter},
			"handle_sys_exit_close":  {link: exit},
		},
		errs: map[string]error{},
	}
	mgr := NewManager(attacher)
	attacher.programs["handle_sys_exit_close"].onAttach = func() {
		if err := mgr.Close(); err != nil {
			t.Fatalf("Close returned error during attach hook: %v", err)
		}
	}
	mgr.Register("close", TracepointPair{Enter: "sys_enter_close", Exit: "sys_exit_close"})

	err := mgr.Attach("close")
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
