package probemanager

import (
	"errors"
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
}

func (p *fakeProgram) AttachTracepoint(_, name string) (Link, error) {
	p.tracepoint = name
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
