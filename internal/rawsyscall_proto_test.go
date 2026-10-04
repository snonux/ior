package internal

import (
	"errors"
	"slices"
	"testing"

	"ior/internal/probemanager"
)

// Tests of the raw syscall prototype's userspace half (task 703). The BPF
// half is exercised by hand on a live kernel (docs/raw-tracepoint-design.md);
// these pin what decides whether a run is touched at all.

func TestParseRawSyscallMode(t *testing.T) {
	for _, tc := range []struct {
		value   string
		want    rawSyscallMode
		wantErr bool
	}{
		{"", rawSyscallOff, false},
		{"0", rawSyscallOff, false},
		{"tailcall", rawSyscallMode{dispatch: rawDispatchTailCall}, false},
		{"switch", rawSyscallMode{dispatch: rawDispatchSwitch}, false},
		{"fentry", rawSyscallMode{dispatch: rawDispatchFentry}, false},
		{"tailcall-probe", rawSyscallMode{dispatch: rawDispatchTailCall, probeRegs: true}, false},
		{"switch-probe", rawSyscallMode{dispatch: rawDispatchSwitch, probeRegs: true}, false},
		{"fentry-probe", rawSyscallOff, true},
		{"1", rawSyscallOff, true},
		{"-probe", rawSyscallOff, true},
		{"tailcall-probe-probe", rawSyscallOff, true},
	} {
		got, err := parseRawSyscallMode(tc.value)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("parseRawSyscallMode(%q) = %+v, %v; want %+v, error %v",
				tc.value, got, err, tc.want, tc.wantErr)
		}
	}
}

// Off, the prototype must not change the selection nor load a program: that
// is what keeps a run without IOR_RAW_SYSCALLS exactly as before.
func TestRawSyscallPrototypeOffChangesNothing(t *testing.T) {
	if progs := rawSyscallPrograms(rawSyscallOff); progs != nil {
		t.Fatalf("programs to load when off: %v", progs)
	}
	calls := 0
	should := func(string) bool { calls++; return true }
	got, selected := rawSyscallSelection(rawSyscallOff, should)
	if selected != nil || !got("sys_enter_read") || calls != 1 {
		t.Fatalf("selection off: selected %v, filter not passed through (calls %d)", selected, calls)
	}
	release, traced := attachRawSyscallPrototype(&fakeProbeAttacher{}, rawSyscallOff, nil, bpfSetupLog{})
	release()
	if traced {
		t.Fatal("prototype off reported traced syscalls")
	}
}

func TestRawSyscallSelectionTakesItsSyscallsFromTheManager(t *testing.T) {
	mode := rawSyscallMode{dispatch: rawDispatchTailCall}
	should := func(tp string) bool { return tp == "sys_exit_write" || tp == "sys_enter_openat" }
	managed, selected := rawSyscallSelection(mode, should)
	if len(selected) != 1 || selected[0].name != "write" {
		t.Fatalf("selected = %+v, want write only", selected)
	}
	for tp, want := range map[string]bool{
		"sys_enter_write": false, "sys_exit_write": false, "sys_enter_read": false,
		"sys_enter_openat": true, "sys_exit_close": false,
	} {
		if got := managed(tp); got != want {
			t.Errorf("managed(%q) = %v, want %v", tp, got, want)
		}
	}
	all, selectedAll := rawSyscallSelection(mode, nil)
	if len(selectedAll) != len(rawSyscalls) || all("sys_enter_read") || !all("sys_enter_close") {
		t.Fatalf("nil filter: selected %d, read managed %v", len(selectedAll), all("sys_enter_read"))
	}
}

func TestRawSyscallProgramsPerVariant(t *testing.T) {
	tail := rawSyscallPrograms(rawSyscallMode{dispatch: rawDispatchTailCall})
	want := []string{"ior_raw_sys_enter_tail", "ior_raw_sys_exit_tail",
		"ior_raw_enter_read", "ior_raw_exit_read", "ior_raw_enter_write", "ior_raw_exit_write"}
	if !slices.Equal(tail, want) {
		t.Errorf("tailcall programs = %v, want %v", tail, want)
	}
	sw := rawSyscallPrograms(rawSyscallMode{dispatch: rawDispatchSwitch, probeRegs: true})
	if !slices.Equal(sw, []string{"ior_raw_sys_enter_switch", "ior_raw_sys_exit_switch"}) {
		t.Errorf("switch programs = %v", sw)
	}
	fe := rawSyscallPrograms(rawSyscallMode{dispatch: rawDispatchFentry})
	wantFE := []string{"ior_fentry_read", "ior_fexit_read", "ior_fentry_write", "ior_fexit_write"}
	if !slices.Equal(fe, wantFE) {
		t.Errorf("fentry programs = %v, want %v", fe, wantFE)
	}
}

func TestUsesRawDispatchers(t *testing.T) {
	if !(rawSyscallMode{dispatch: rawDispatchTailCall}).usesRawDispatchers() ||
		!(rawSyscallMode{dispatch: rawDispatchSwitch}).usesRawDispatchers() ||
		(rawSyscallMode{dispatch: rawDispatchFentry}).usesRawDispatchers() ||
		rawSyscallOff.usesRawDispatchers() {
		t.Fatal("usesRawDispatchers mismatch")
	}
}

// fakeRawProgram is a raw-tracepoint program with a file descriptor.
type fakeRawProgram struct {
	rawProbeProgram
	fd       int
	autoload bool
}

func (p *fakeRawProgram) SetAutoload(autoload bool) error { p.autoload = autoload; return nil }
func (p *fakeRawProgram) FileDescriptor() int             { return p.fd }

// fakeRawModule is a rawSyscallModule that hands out one fakeRawProgram per
// name (fds from 100 in order of first request) and records every write.
type fakeRawModule struct {
	progs   map[string]*fakeRawProgram
	order   []string
	slots   map[string]map[uint32]uint32
	globals map[string]uint32
	slotErr error
}

func newFakeRawModule() *fakeRawModule {
	return &fakeRawModule{progs: map[string]*fakeRawProgram{},
		slots: map[string]map[uint32]uint32{}, globals: map[string]uint32{}}
}

func (m *fakeRawModule) GetProgram(name string) (probemanager.Program, error) {
	if p, ok := m.progs[name]; ok {
		return p, nil
	}
	p := &fakeRawProgram{fd: 100 + len(m.progs)}
	p.link = &fakeProbeLink{}
	m.progs[name] = p
	m.order = append(m.order, name)
	return p, nil
}

func (m *fakeRawModule) setRawSyscallGlobal(name string, value uint32) error {
	m.globals[name] = value
	return nil
}

func (m *fakeRawModule) setRawSyscallSlot(table string, nr, value uint32) error {
	if m.slotErr != nil {
		return m.slotErr
	}
	if m.slots[table] == nil {
		m.slots[table] = map[uint32]uint32{}
	}
	m.slots[table][nr] = value
	return nil
}

func TestTailCallPrototypeFillsBothTablesAndAttachesTheDispatchers(t *testing.T) {
	module := newFakeRawModule()
	mode := rawSyscallMode{dispatch: rawDispatchTailCall}
	release, traced := attachRawSyscallPrototype(module, mode, rawSyscalls[1:], bpfSetupLog{})
	if !traced {
		t.Fatal("tail-call prototype with write selected reported nothing traced")
	}
	enterFD := uint32(module.progs["ior_raw_enter_write"].fd)
	exitFD := uint32(module.progs["ior_raw_exit_write"].fd)
	if module.slots["ior_raw_enter_progs"][1] != enterFD || module.slots["ior_raw_exit_progs"][1] != exitFD {
		t.Fatalf("slots = %v, want write's handlers (%d, %d) at 1", module.slots, enterFD, exitFD)
	}
	if _, ok := module.slots["ior_raw_enter_progs"][0]; ok {
		t.Fatal("read's slot filled although only write was selected")
	}
	for name, tp := range map[string]string{"ior_raw_sys_enter_tail": "sys_enter", "ior_raw_sys_exit_tail": "sys_exit"} {
		if got := module.progs[name].rawName; got != tp {
			t.Errorf("%s attached to %q, want %q", name, got, tp)
		}
	}
	release()
	release()
	for _, name := range []string{"ior_raw_sys_enter_tail", "ior_raw_sys_exit_tail"} {
		if n := module.progs[name].link.(*fakeProbeLink).destroyCount(); n != 1 {
			t.Errorf("%s destroyed %d times, want 1", name, n)
		}
	}
}

func TestSwitchPrototypeEnablesItsSlotsAndFailsClosed(t *testing.T) {
	module := newFakeRawModule()
	mode := rawSyscallMode{dispatch: rawDispatchSwitch}
	release, traced := attachRawSyscallPrototype(module, mode, rawSyscalls, bpfSetupLog{})
	release()
	if !traced || module.slots["ior_raw_traced"][0] != 1 || module.slots["ior_raw_traced"][1] != 1 {
		t.Fatalf("switch: traced %v, slots %v", traced, module.slots)
	}
	failing := newFakeRawModule()
	failing.slotErr = errors.New("boom")
	var warned []any
	log := bpfSetupLog{warn: func(args ...any) { warned = append(warned, args...) }}
	release, traced = attachRawSyscallPrototype(failing, mode, rawSyscalls, log)
	release()
	if traced || len(warned) != 1 || len(failing.progs) != 0 {
		t.Fatalf("failed slot write: traced %v, warnings %v, programs touched %v", traced, warned, failing.order)
	}
}

func TestLoadRawSyscallProgramsSwitchesOnExactlyTheVariantsPrograms(t *testing.T) {
	off := newFakeRawModule()
	if err := loadRawSyscallPrograms(off, rawSyscallOff); err != nil || len(off.progs) != 0 || len(off.globals) != 0 {
		t.Fatalf("off: err %v, programs %v, globals %v", err, off.order, off.globals)
	}
	module := newFakeRawModule()
	mode := rawSyscallMode{dispatch: rawDispatchSwitch, probeRegs: true}
	if err := loadRawSyscallPrograms(module, mode); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(module.order, rawSyscallPrograms(mode)) {
		t.Fatalf("programs = %v, want %v", module.order, rawSyscallPrograms(mode))
	}
	for name, prog := range module.progs {
		if !prog.autoload {
			t.Errorf("%s not switched to load", name)
		}
	}
	if module.globals["IOR_RAW_PROBE_REGS"] != 1 {
		t.Fatalf("globals = %v, want IOR_RAW_PROBE_REGS=1", module.globals)
	}
	fe := newFakeRawModule()
	feMode := rawSyscallMode{dispatch: rawDispatchFentry}
	if err := loadRawSyscallPrograms(fe, feMode); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fe.order, rawSyscallPrograms(feMode)) || fe.globals["IOR_RAW_PROBE_REGS"] != 0 {
		t.Fatalf("fentry load: programs %v globals %v", fe.order, fe.globals)
	}
}

// fakeFentryProgram records AttachGeneric listing names for the fentry tests.
type fakeFentryProgram struct {
	fakeRawProgram
	listAs     string
	failAttach bool
}

func (p *fakeFentryProgram) AttachGeneric(listAs string) (probemanager.Link, error) {
	p.listAs = listAs
	if p.failAttach || p.err != nil {
		if p.err != nil {
			return nil, p.err
		}
		return nil, errors.New("attach refused")
	}
	if p.link == nil {
		p.link = &fakeProbeLink{}
	}
	return p.link, nil
}

// fakeFentryModule hands out fakeFentryProgram values that implement
// genericAttachProgram.
type fakeFentryModule struct {
	progs map[string]*fakeFentryProgram
	order []string
}

func newFakeFentryModule() *fakeFentryModule {
	return &fakeFentryModule{progs: map[string]*fakeFentryProgram{}}
}

func (m *fakeFentryModule) GetProgram(name string) (probemanager.Program, error) {
	if p, ok := m.progs[name]; ok {
		return p, nil
	}
	p := &fakeFentryProgram{}
	p.fd = 100 + len(m.progs)
	p.link = &fakeProbeLink{}
	m.progs[name] = p
	m.order = append(m.order, name)
	return p, nil
}

func (m *fakeFentryModule) setRawSyscallGlobal(string, uint32) error { return nil }
func (m *fakeFentryModule) setRawSyscallSlot(string, uint32, uint32) error {
	return errors.New("fentry has no dispatch slots")
}

func TestFentryPrototypeAttachesSelectedPairsUnderClassicNames(t *testing.T) {
	module := newFakeFentryModule()
	mode := rawSyscallMode{dispatch: rawDispatchFentry}
	release, traced := attachRawSyscallPrototype(module, mode, rawSyscalls[1:], bpfSetupLog{})
	if !traced {
		t.Fatal("fentry with write selected reported nothing traced")
	}
	want := map[string]string{
		"ior_fentry_write": "sys_enter_write",
		"ior_fexit_write":  "sys_exit_write",
	}
	for prog, listAs := range want {
		if got := module.progs[prog].listAs; got != listAs {
			t.Errorf("%s listed as %q, want %q", prog, got, listAs)
		}
	}
	if _, ok := module.progs["ior_fentry_read"]; ok {
		t.Fatal("read's fentry attached although only write was selected")
	}
	release()
	release()
	for prog := range want {
		if n := module.progs[prog].link.(*fakeProbeLink).destroyCount(); n != 1 {
			t.Errorf("%s destroyed %d times, want 1", prog, n)
		}
	}
}

func TestFentryPrototypeAttachesNothingWithAnEmptySelection(t *testing.T) {
	module := newFakeFentryModule()
	release, traced := attachRawSyscallPrototype(module, rawSyscallMode{dispatch: rawDispatchFentry}, nil, bpfSetupLog{})
	release()
	if traced || len(module.progs) != 0 {
		t.Fatalf("empty selection: traced %v, programs %v", traced, module.order)
	}
}

func TestFentryPrototypeReleasesAHalfAttachedPair(t *testing.T) {
	t.Run("exit fails after enter", func(t *testing.T) {
		module := newFakeFentryModule()
		enter, _ := module.GetProgram("ior_fentry_write")
		exit, _ := module.GetProgram("ior_fexit_write")
		exit.(*fakeFentryProgram).failAttach = true
		var warned []any
		log := bpfSetupLog{warn: func(args ...any) { warned = append(warned, args...) }}
		release, traced := attachRawSyscallPrototype(module, rawSyscallMode{dispatch: rawDispatchFentry},
			rawSyscalls[1:], log)
		release()
		if traced {
			t.Fatal("half-attached write counted as traced")
		}
		if n := enter.(*fakeFentryProgram).link.(*fakeProbeLink).destroyCount(); n != 1 {
			t.Fatalf("successful enter destroyed %d times, want 1", n)
		}
		if exit.(*fakeFentryProgram).listAs != "sys_exit_write" || len(warned) == 0 {
			t.Fatalf("listAs %q warnings %v", exit.(*fakeFentryProgram).listAs, warned)
		}
	})
	t.Run("enter fails before exit", func(t *testing.T) {
		module := newFakeFentryModule()
		enter, _ := module.GetProgram("ior_fentry_write")
		enter.(*fakeFentryProgram).failAttach = true
		release, traced := attachRawSyscallPrototype(module, rawSyscallMode{dispatch: rawDispatchFentry},
			rawSyscalls[1:], bpfSetupLog{warn: func(...any) {}})
		release()
		if traced {
			t.Fatal("half-attached write counted as traced")
		}
		// Exit must never have been asked for: attachPair-style ordering.
		if _, ok := module.progs["ior_fexit_write"]; ok {
			t.Fatal("exit side attached after enter failed")
		}
	})
	t.Run("one full pair kept beside a half-failed one", func(t *testing.T) {
		module := newFakeFentryModule()
		_, _ = module.GetProgram("ior_fentry_read")
		readExit, _ := module.GetProgram("ior_fexit_read")
		readExit.(*fakeFentryProgram).failAttach = true
		release, traced := attachRawSyscallPrototype(module, rawSyscallMode{dispatch: rawDispatchFentry},
			rawSyscalls, bpfSetupLog{warn: func(...any) {}})
		if !traced {
			t.Fatal("write's full pair should keep traced true")
		}
		// read's enter must already have been released with the failed pair.
		if n := module.progs["ior_fentry_read"].link.(*fakeProbeLink).destroyCount(); n != 1 {
			t.Fatalf("failed read's enter destroyed %d times before outer release, want 1", n)
		}
		release()
		for _, prog := range []string{"ior_fentry_write", "ior_fexit_write"} {
			if n := module.progs[prog].link.(*fakeProbeLink).destroyCount(); n != 1 {
				t.Errorf("%s destroyed %d times, want 1", prog, n)
			}
		}
	})
}

func TestFentryPrototypeRejectsAProgramWithoutAttachGeneric(t *testing.T) {
	// fakeRawModule's programs do not implement genericAttachProgram.
	module := newFakeRawModule()
	var warned []any
	log := bpfSetupLog{warn: func(args ...any) { warned = append(warned, args...) }}
	release, traced := attachRawSyscallPrototype(module, rawSyscallMode{dispatch: rawDispatchFentry},
		rawSyscalls[:1], log)
	release()
	if traced || len(warned) == 0 {
		t.Fatalf("non-generic program: traced %v, warnings %v", traced, warned)
	}
}
