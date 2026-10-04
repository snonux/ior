package internal

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"unsafe"

	"ior/internal/probemanager"
)

// The raw/fentry syscall dispatch PROTOTYPE of tasks 703 and g23: read and
// write traced through one raw_syscalls:sys_enter/sys_exit pair, or through
// fentry/fexit on __x64_sys_{read,write}, instead of their classic
// syscalls:sys_{enter,exit}_{read,write} tracepoints. BPF side and
// rationale: internal/c/rawsyscall.c; design, measurements and the plan for
// the real thing: docs/raw-tracepoint-design.md.
//
// It is off unless IOR_RAW_SYSCALLS names a variant, and a run without it is
// untouched: the prototype's programs sit in "?" sections, which libbpf does
// not load unless their autoload is switched on here. With it, read and
// write leave the probe manager (they are neither registered as attached
// nor offered in the probes modal; a prototype limitation) and are traced by
// the chosen backend (raw dispatchers, or per-syscall fentry/fexit links).

// rawSyscallEnv selects the prototype: "tailcall" or "switch" (see
// rawsyscall.c for the two raw dispatch variants), each optionally with
// "-probe", which reads the registers with probe reads where the kernel
// would allow direct loads (IOR_RAW_PROBE_REGS, what el8 would pay); or
// "fentry" (task g23: trampolines on __x64_sys_{read,write}, no "-probe").
// Unset, empty or "0" leaves it off.
const rawSyscallEnv = "IOR_RAW_SYSCALLS"

// rawSyscallMode is a prototype variant; the zero value is "off".
type rawSyscallMode struct {
	dispatch  string // "", rawDispatchTailCall, rawDispatchSwitch or rawDispatchFentry
	probeRegs bool
}

const (
	rawDispatchTailCall = "tailcall"
	rawDispatchSwitch   = "switch"
	rawDispatchFentry   = "fentry"
	rawProbeRegsSuffix  = "-probe"
)

var rawSyscallOff = rawSyscallMode{}

// usesRawDispatchers reports whether mode attaches the raw_syscalls
// sys_enter/sys_exit pair. fentry does not: it keeps the classic
// handle_restart_sigreturn probe (attachRestartSigreturnProbe).
func (m rawSyscallMode) usesRawDispatchers() bool {
	return m.dispatch == rawDispatchTailCall || m.dispatch == rawDispatchSwitch
}

// parseRawSyscallMode reads a value of rawSyscallEnv. An unknown value is
// an error and leaves the prototype off.
func parseRawSyscallMode(value string) (rawSyscallMode, error) {
	if value == "" || value == "0" {
		return rawSyscallOff, nil
	}
	dispatch, probe := strings.CutSuffix(value, rawProbeRegsSuffix)
	switch dispatch {
	case rawDispatchTailCall, rawDispatchSwitch:
		return rawSyscallMode{dispatch: dispatch, probeRegs: probe}, nil
	case rawDispatchFentry:
		if probe {
			return rawSyscallOff, fmt.Errorf("%s=%q: fentry has no %s variant; the prototype stays off",
				rawSyscallEnv, value, rawProbeRegsSuffix)
		}
		return rawSyscallMode{dispatch: rawDispatchFentry}, nil
	}
	return rawSyscallOff, fmt.Errorf("%s=%q: want %s, %s or %s, the first two optionally with %s; the prototype stays off",
		rawSyscallEnv, value, rawDispatchTailCall, rawDispatchSwitch, rawDispatchFentry, rawProbeRegsSuffix)
}

// rawSyscallModeFromEnv is the run's prototype variant. It is read once:
// the load stage (which programs to load) and the attach stage (which ones
// to attach) must agree, and the warning for a bad value is given once.
var rawSyscallModeFromEnv = sync.OnceValues(func() (rawSyscallMode, error) {
	return parseRawSyscallMode(os.Getenv(rawSyscallEnv))
})

// rawSyscall is one syscall the prototype can trace: its x86_64 number (the
// slot of the raw dispatch tables), the raw tail-call targets, and the
// fentry/fexit program names.
type rawSyscall struct {
	name       string
	nr         uint32
	enterProg  string
	exitProg   string
	fenterProg string
	fexitProg  string
}

// rawSyscalls are the prototype's syscalls; the numbers are x86_64's.
var rawSyscalls = []rawSyscall{
	{name: "read", nr: 0, enterProg: "ior_raw_enter_read", exitProg: "ior_raw_exit_read",
		fenterProg: "ior_fentry_read", fexitProg: "ior_fexit_read"},
	{name: "write", nr: 1, enterProg: "ior_raw_enter_write", exitProg: "ior_raw_exit_write",
		fenterProg: "ior_fentry_write", fexitProg: "ior_fexit_write"},
}

// rawSyscallTracedByPrototype reports whether the prototype is on and
// syscall is one of its (read/write) names. It does not ask whether that
// syscall was selected or attached: an unselected or failed attach emits
// no record anyway, and the active-probe row filter
// (configureEventLoopOutput) only needs "the probe manager does not own
// this name". Tightening it to the attached set would need state the
// prototype does not keep today.
func rawSyscallTracedByPrototype(syscall string) bool {
	if mode, _ := rawSyscallModeFromEnv(); mode == rawSyscallOff {
		return false
	}
	for _, sc := range rawSyscalls {
		if sc.name == syscall {
			return true
		}
	}
	return false
}

// rawDispatchers returns the enter and exit dispatcher programs of a raw
// mode. It panics for fentry, which has none.
func rawDispatchers(mode rawSyscallMode) (enter, exit string) {
	switch mode.dispatch {
	case rawDispatchSwitch:
		return "ior_raw_sys_enter_switch", "ior_raw_sys_exit_switch"
	case rawDispatchTailCall:
		return "ior_raw_sys_enter_tail", "ior_raw_sys_exit_tail"
	}
	panic("rawDispatchers called for a mode without raw dispatchers")
}

// rawSyscallPrograms returns every program mode has to load.
func rawSyscallPrograms(mode rawSyscallMode) []string {
	if mode == rawSyscallOff {
		return nil
	}
	if mode.dispatch == rawDispatchFentry {
		progs := make([]string, 0, 2*len(rawSyscalls))
		for _, sc := range rawSyscalls {
			progs = append(progs, sc.fenterProg, sc.fexitProg)
		}
		return progs
	}
	enter, exit := rawDispatchers(mode)
	progs := []string{enter, exit}
	if mode.dispatch == rawDispatchTailCall {
		for _, sc := range rawSyscalls {
			progs = append(progs, sc.enterProg, sc.exitProg)
		}
	}
	return progs
}

// rawSyscallProgram is what the prototype needs of a program beyond
// attaching it: switching its load on, and its fd for a tail-call table.
type rawSyscallProgram interface {
	SetAutoload(autoload bool) error
	FileDescriptor() int
}

// rawSyscallModule is what the prototype needs of the module beyond
// resolving programs: setting a u32 global before the load, and writing one
// u32 slot of a dispatch table after it.
type rawSyscallModule interface {
	probemanager.Attacher
	setRawSyscallGlobal(name string, value uint32) error
	setRawSyscallSlot(mapName string, nr, value uint32) error
}

// SetAutoload makes libbpfTracepointProgram a rawSyscallProgram; it must be
// called before the object is loaded.
func (p libbpfTracepointProgram) SetAutoload(autoload bool) error {
	return p.prog.SetAutoload(autoload)
}

// FileDescriptor makes libbpfTracepointProgram a rawSyscallProgram.
func (p libbpfTracepointProgram) FileDescriptor() int {
	return p.prog.FileDescriptor()
}

// setRawSyscallGlobal makes libbpfTracepointModule a rawSyscallModule.
func (m libbpfTracepointModule) setRawSyscallGlobal(name string, value uint32) error {
	return m.module.InitGlobalVariable(name, value)
}

// setRawSyscallSlot makes libbpfTracepointModule a rawSyscallModule.
func (m libbpfTracepointModule) setRawSyscallSlot(mapName string, nr, value uint32) error {
	table, err := m.module.GetMap(mapName)
	if err != nil {
		return err
	}
	return table.Update(unsafe.Pointer(&nr), unsafe.Pointer(&value))
}

// enableRawSyscallPrograms switches the autoload of the run's prototype
// programs on and sets IOR_RAW_PROBE_REGS for a "-probe" variant; it runs
// between opening and loading the object. Off, it does nothing; a bad
// variable is a warning and leaves it off.
func enableRawSyscallPrograms(module rawSyscallModule, warn func(args ...any)) error {
	mode, err := rawSyscallModeFromEnv()
	if err != nil {
		warn(err.Error())
	}
	return loadRawSyscallPrograms(module, mode)
}

// loadRawSyscallPrograms is enableRawSyscallPrograms for a given mode.
func loadRawSyscallPrograms(module rawSyscallModule, mode rawSyscallMode) error {
	if mode.probeRegs {
		if err := module.setRawSyscallGlobal("IOR_RAW_PROBE_REGS", 1); err != nil {
			return fmt.Errorf("set IOR_RAW_PROBE_REGS: %w", err)
		}
	}
	for _, name := range rawSyscallPrograms(mode) {
		prog, err := module.GetProgram(name)
		if err != nil {
			return err
		}
		loadable, ok := prog.(rawSyscallProgram)
		if !ok {
			return fmt.Errorf("program %s cannot be switched to load", name)
		}
		if err := loadable.SetAutoload(true); err != nil {
			return fmt.Errorf("autoload %s: %w", name, err)
		}
	}
	return nil
}

// rawSyscallSelection splits shouldAttach for the prototype: the returned
// filter is shouldAttach without the prototype's syscalls, which the probe
// manager then leaves alone, and selected lists those of them shouldAttach
// chose. Off, shouldAttach is returned unchanged and selected is empty.
func rawSyscallSelection(mode rawSyscallMode, shouldAttach func(string) bool) (func(string) bool, []rawSyscall) {
	if mode == rawSyscallOff {
		return shouldAttach, nil
	}
	wants := func(tp string) bool { return shouldAttach == nil || shouldAttach(tp) }
	raw := map[string]bool{}
	var selected []rawSyscall
	for _, sc := range rawSyscalls {
		enter, exit := "sys_enter_"+sc.name, "sys_exit_"+sc.name
		raw[enter], raw[exit] = true, true
		if wants(enter) || wants(exit) {
			selected = append(selected, sc)
		}
	}
	return func(tp string) bool { return !raw[tp] && wants(tp) }, selected
}

// attachRawSyscallPrototype attaches mode's backend for selected. It returns
// the release closure and whether at least one selected syscall is traced
// through it, which counts as an attached probe for the headless guard.
//
// Raw modes fill the dispatch tables and attach the two dispatchers (also
// with nothing selected: that measures what an untraced syscall costs once
// they are there). fentry attaches one enter and one exit trampoline per
// selected syscall and attaches nothing with an empty selection.
func attachRawSyscallPrototype(attacher probemanager.Attacher, mode rawSyscallMode, selected []rawSyscall,
	log bpfSetupLog) (func(), bool) {
	module, ok := attacher.(rawSyscallModule)
	if mode == rawSyscallOff || !ok {
		return func() {}, false
	}
	log = log.withDefaults()
	if mode.dispatch == rawDispatchFentry {
		return attachFentrySyscallPrototype(attacher, selected, log)
	}
	for _, sc := range selected {
		if err := fillRawSyscallSlots(module, mode, sc); err != nil {
			log.warn(fmt.Sprintf("raw syscall prototype: %s: %v", sc.name, err))
			return func() {}, false
		}
	}
	enter, exit := rawDispatchers(mode)
	attached := 0
	attach := func(prog, tp string) func() {
		return attachHandProbe(attacher, prog, "raw "+tp, log,
			func(p probemanager.Program) (probemanager.Link, error) {
				raw, ok := p.(probemanager.RawTracepointProgram)
				if !ok {
					return nil, errors.New("program cannot attach as a raw tracepoint")
				}
				link, err := raw.AttachRawTracepoint(tp)
				if err == nil {
					attached++
				}
				return link, err
			})
	}
	release := releaseConcurrently(attach(enter, "sys_enter"), attach(exit, "sys_exit"))
	return release, attached == 2 && len(selected) > 0
}

// attachFentrySyscallPrototype attaches the fentry/fexit trampolines of
// selected. Each syscall is all-or-nothing: if either side fails, the other
// is destroyed and the syscall is skipped with a warning (a half pair would
// leave unpaired enters or exits). The run counts as tracing when at least
// one full pair attached. Links are listed under the classic sys_enter_/
// sys_exit_ names so the restart-fold skip counter finds them.
func attachFentrySyscallPrototype(attacher probemanager.Attacher, selected []rawSyscall,
	log bpfSetupLog) (func(), bool) {
	releases := make([]func(), 0, 2*len(selected))
	traced := 0
	for _, sc := range selected {
		// Enter first; only attach exit when enter stuck. That matches
		// probemanager.attachPair and never leaves a lone exit live while
		// enter's failure is still being handled.
		enterRel, enterOK := attachFentrySide(attacher, sc.fenterProg, "sys_enter_"+sc.name,
			"fentry __x64_sys_"+sc.name, log)
		if !enterOK {
			enterRel()
			continue
		}
		exitRel, exitOK := attachFentrySide(attacher, sc.fexitProg, "sys_exit_"+sc.name,
			"fexit __x64_sys_"+sc.name, log)
		if !exitOK {
			enterRel()
			exitRel()
			log.warn(fmt.Sprintf("fentry prototype: %s: exit side failed; enter released", sc.name))
			continue
		}
		releases = append(releases, enterRel, exitRel)
		traced++
	}
	return releaseConcurrently(releases...), traced > 0
}

// attachFentrySide attaches one fentry/fexit program listed as listAs.
// ok is false when the program was missing, could not AttachGeneric, or
// attachHandProbe warned and returned a no-op; the returned release is then
// safe to call either way.
func attachFentrySide(attacher probemanager.Attacher, prog, listAs, label string, log bpfSetupLog) (func(), bool) {
	var attached bool
	release := attachHandProbe(attacher, prog, label, log,
		func(p probemanager.Program) (probemanager.Link, error) {
			gen, ok := p.(genericAttachProgram)
			if !ok {
				return nil, errors.New("program cannot attach as fentry/fexit")
			}
			link, err := gen.AttachGeneric(listAs)
			if err == nil {
				attached = true
			}
			return link, err
		})
	return release, attached
}

// genericAttachProgram is a program that attaches from its SEC() name
// (fentry/fexit): libbpfTracepointProgram.AttachGeneric. listAs is the
// classic tracepoint name the link is listed under.
type genericAttachProgram interface {
	AttachGeneric(listAs string) (probemanager.Link, error)
}

// fillRawSyscallSlots enables sc in mode's dispatch tables: its two handler
// programs in the tail-call tables, or a 1 in the switch's enable table.
func fillRawSyscallSlots(module rawSyscallModule, mode rawSyscallMode, sc rawSyscall) error {
	if mode.dispatch == rawDispatchSwitch {
		return module.setRawSyscallSlot("ior_raw_traced", sc.nr, 1)
	}
	for _, slot := range []struct{ table, program string }{
		{"ior_raw_enter_progs", sc.enterProg}, {"ior_raw_exit_progs", sc.exitProg},
	} {
		prog, err := module.GetProgram(slot.program)
		if err != nil {
			return err
		}
		withFD, ok := prog.(rawSyscallProgram)
		if !ok {
			return fmt.Errorf("program %s has no file descriptor", slot.program)
		}
		if err := module.setRawSyscallSlot(slot.table, sc.nr, uint32(withFD.FileDescriptor())); err != nil {
			return fmt.Errorf("%s[%d]: %w", slot.table, sc.nr, err)
		}
	}
	return nil
}
