package internal

import (
	"errors"
	"strings"
	"testing"
)

type fakeTracepointProgram struct {
	attachCalls int
	attachErr   error
}

type fakeTracepointLink struct{}

func (fakeTracepointLink) Destroy() error { return nil }

func (p *fakeTracepointProgram) attachTracepoint(_, _ string) (tracepointLink, error) {
	p.attachCalls++
	if p.attachErr != nil {
		return nil, p.attachErr
	}
	return fakeTracepointLink{}, nil
}

type fakeTracepointModule struct {
	getProgramCalls []string
	getProgramErrs  map[string]error
	programs        map[string]*fakeTracepointProgram
}

func (m *fakeTracepointModule) getProgram(progName string) (tracepointProgram, error) {
	m.getProgramCalls = append(m.getProgramCalls, progName)
	if err, ok := m.getProgramErrs[progName]; ok {
		return nil, err
	}
	if prog, ok := m.programs[progName]; ok {
		return prog, nil
	}
	return nil, errors.New("missing program")
}

func TestAttachTracepointsWithSkipsFilteredTracepoints(t *testing.T) {
	module := &fakeTracepointModule{
		programs: map[string]*fakeTracepointProgram{
			"handle_sys_enter_read":  {},
			"handle_sys_enter_write": {},
		},
		getProgramErrs: map[string]error{},
	}

	err := attachTracepointsWith(module, func(tracepoint string) bool {
		return tracepoint == "sys_enter_read"
	}, []string{"sys_enter_read", "sys_enter_write"}, false)
	if err != nil {
		t.Fatalf("attachTracepointsWith returned error: %v", err)
	}

	if len(module.getProgramCalls) != 1 || module.getProgramCalls[0] != "handle_sys_enter_read" {
		t.Fatalf("getProgram calls = %v, want only handle_sys_enter_read", module.getProgramCalls)
	}

	if module.programs["handle_sys_enter_read"].attachCalls != 1 {
		t.Fatalf("read attach calls = %d, want 1", module.programs["handle_sys_enter_read"].attachCalls)
	}
	if module.programs["handle_sys_enter_write"].attachCalls != 0 {
		t.Fatalf("write attach calls = %d, want 0", module.programs["handle_sys_enter_write"].attachCalls)
	}
}

func TestAttachTracepointsWithReturnsErrorWhenProgramMissing(t *testing.T) {
	module := &fakeTracepointModule{
		programs: map[string]*fakeTracepointProgram{},
		getProgramErrs: map[string]error{
			"handle_sys_enter_read": errors.New("not found"),
		},
	}

	err := attachTracepointsWith(module, func(string) bool { return true }, []string{"sys_enter_read"}, false)
	if err == nil {
		t.Fatal("attachTracepointsWith returned nil error, want non-nil")
	}
	if !strings.Contains(err.Error(), "handle_sys_enter_read") {
		t.Fatalf("error %q does not mention handle_sys_enter_read", err)
	}
}

func TestAttachTracepointsWithAttachFailureContinues(t *testing.T) {
	module := &fakeTracepointModule{
		programs: map[string]*fakeTracepointProgram{
			"handle_sys_enter_read":  {attachErr: errors.New("no tracepoint")},
			"handle_sys_enter_write": {},
		},
		getProgramErrs: map[string]error{},
	}

	err := attachTracepointsWith(module, func(string) bool { return true }, []string{"sys_enter_read", "sys_enter_write"}, false)
	if err != nil {
		t.Fatalf("attachTracepointsWith returned error: %v", err)
	}

	if module.programs["handle_sys_enter_read"].attachCalls != 1 {
		t.Fatalf("read attach calls = %d, want 1", module.programs["handle_sys_enter_read"].attachCalls)
	}
	if module.programs["handle_sys_enter_write"].attachCalls != 1 {
		t.Fatalf("write attach calls = %d, want 1", module.programs["handle_sys_enter_write"].attachCalls)
	}
}
