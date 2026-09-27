package internal

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"ior/internal/flags"
)

// runnerDeps bundles all injectable function dependencies used by the mode
// registry and its handlers. Using a struct instead of package-level vars
// allows tests to substitute individual functions without mutating global
// state (Dependency Inversion Principle).
type runnerDeps struct {
	// getEUID returns the effective user ID of the calling process.
	// Overridden in tests to simulate root or non-root execution.
	getEUID func() int

	// runTrace executes a headless plain/flamegraph trace (no TUI).
	runTrace func(flags.Config) error

	// runParquet executes a headless Parquet recording run (no TUI).
	runParquet func(flags.Config) error

	// runTraceWithContext drives a BPF trace with a parent context, started
	// signal channel, event-loop configurator, and the TUI setup hooks. Used
	// by the TUI starter.
	runTraceWithContext traceRunFunc

	// runTUI launches the interactive TUI backed by a live BPF trace.
	// Injected by the cmd layer through Run's TUIRunners argument so that the
	// core package never imports the TUI layer.
	runTUI TUIRunFunc

	// runTUITestFlames launches the TUI seeded with static synthetic flame data.
	runTUITestFlames TUIRunFunc

	// runTUITestLiveFlames launches the TUI fed by a live synthetic flame goroutine.
	runTUITestLiveFlames TUIRunFunc
}

// productionRunnerDeps returns the production function set, completed with
// the TUI launchers the cmd layer injected. It rejects a TUIRunners with any
// nil field up front, so an omitted launcher is reported at startup instead of
// panicking only once its mode is selected.
func productionRunnerDeps(tui TUIRunners) (runnerDeps, error) {
	var missing []string
	for _, r := range []struct {
		name string
		fn   TUIRunFunc
	}{
		{"Trace", tui.Trace},
		{"TestFlames", tui.TestFlames},
		{"TestLiveFlames", tui.TestLiveFlames},
	} {
		if r.fn == nil {
			missing = append(missing, r.name)
		}
	}
	if len(missing) > 0 {
		return runnerDeps{}, fmt.Errorf("internal: TUIRunners missing %s — this is a bug", strings.Join(missing, ", "))
	}
	return runnerDeps{
		getEUID:              os.Geteuid,
		runTrace:             runTrace,
		runParquet:           runHeadlessParquet,
		runTraceWithContext:  runTraceWithContext,
		runTUI:               tui.Trace,
		runTUITestFlames:     tui.TestFlames,
		runTUITestLiveFlames: tui.TestLiveFlames,
	}, nil
}

// modeSelector is one command-line flag that selects an execution mode.
// Selectors are the unit of mutual exclusivity: at most one may be set per run,
// whether they belong to different handlers (-parquet vs -plain) or to the same
// one (-plain vs -flamegraph).
type modeSelector struct {
	// flag is the flag as it appears in error messages, e.g. "-plain".
	flag string
	// isSet reports whether cfg selects this flag.
	isSet func(flags.Config) bool
}

// modeHandler describes a single execution mode for the ior binary.
// Each mode declares the flags that select it (selectors), enforces its own
// invariants (validate), and runs (run). Exclusivity between modes is not a
// handler concern: the registry enforces it once, over every handler's
// selectors, so adding a mode never means editing the others.
type modeHandler interface {
	// selectors lists the flags that select this mode. A handler with no
	// selectors is the default mode, chosen when no selector is set; a
	// registry has exactly one.
	selectors() []modeSelector
	// validate returns an error if cfg is invalid for this mode. It is called
	// only for the selected handler, after the exclusivity check, so it only
	// checks this mode's own constraints. It runs before any root-privilege
	// gate: the gate is the first statement of each trace-requiring
	// handler's run(), not part of validate().
	validate(cfg flags.Config) error
	// run executes the mode using the supplied config.
	run(cfg flags.Config, deps runnerDeps) error
}

// modeRegistry is the set of modeHandlers paired with the injectable
// function dependencies they share. Storing deps on the registry (rather than
// as package-level vars) lets Run and tests construct isolated registries
// without mutating global state.
type modeRegistry struct {
	handlers []modeHandler
	deps     runnerDeps
}

// newModeRegistry constructs a registry with the standard handlers and the
// provided dependencies. Because at most one selector may be set, handler
// order does not decide which mode runs; it only fixes the order in which
// conflicting flags are listed in the error message.
func newModeRegistry(deps runnerDeps) modeRegistry {
	return modeRegistry{
		handlers: []modeHandler{
			&testFlamesModeHandler{},
			&testLiveFlamesModeHandler{},
			&headlessParquetModeHandler{},
			&plainTraceModeHandler{},
			&tuiModeHandler{},
		},
		deps: deps,
	}
}

// modeConflictError reports that more than one mode-selecting flag was set.
type modeConflictError struct {
	// flags lists the conflicting flags in registry order.
	flags []string
}

func (e *modeConflictError) Error() string {
	last := len(e.flags) - 1
	if last < 1 {
		return fmt.Sprintf("internal: mode conflict with %d flag(s) — this is a bug", len(e.flags))
	}
	return strings.Join(e.flags[:last], ", ") + " and " + e.flags[last] + " are mutually exclusive"
}

// dispatch resolves the single mode cfg selects, then runs its handler.
func (reg modeRegistry) dispatch(cfg flags.Config) error {
	h, err := reg.resolve(cfg)
	if err != nil {
		return err
	}
	return h.run(cfg, reg.deps)
}

// validate runs every mode-combination check without running any mode.
func (reg modeRegistry) validate(cfg flags.Config) error {
	_, err := reg.resolve(cfg)
	return err
}

// resolve returns the handler cfg selects. It is the one place that enforces
// mode exclusivity: every set selector across all handlers is counted, and
// more than one is rejected with a *modeConflictError naming all of them.
// With exactly one mode chosen, only that handler's own validate runs.
func (reg modeRegistry) resolve(cfg flags.Config) (modeHandler, error) {
	var (
		selected   modeHandler
		defaultH   modeHandler
		setFlags   []string
		numDefault int
	)
	for _, h := range reg.handlers {
		sels := h.selectors()
		if len(sels) == 0 {
			defaultH = h
			numDefault++
			continue
		}
		for _, s := range sels {
			if s.isSet(cfg) {
				setFlags = append(setFlags, s.flag)
				selected = h
			}
		}
	}
	if numDefault != 1 {
		return nil, fmt.Errorf("internal: mode registry has %d default handlers, want 1 — this is a bug", numDefault)
	}
	if len(setFlags) > 1 {
		return nil, &modeConflictError{flags: setFlags}
	}
	if selected == nil {
		selected = defaultH
	}
	if err := selected.validate(cfg); err != nil {
		return nil, err
	}
	return selected, nil
}

// --- testFlamesModeHandler ---

// testFlamesModeHandler runs the TUI seeded with static synthetic flame data
// so the flamegraph tab can be exercised without a live BPF trace.
type testFlamesModeHandler struct{}

func (h *testFlamesModeHandler) selectors() []modeSelector {
	return []modeSelector{{flag: "-testflames", isSet: func(cfg flags.Config) bool { return cfg.TestFlames }}}
}

func (h *testFlamesModeHandler) validate(flags.Config) error { return nil }

func (h *testFlamesModeHandler) run(cfg flags.Config, deps runnerDeps) error {
	return deps.runTUITestFlames(cfg, tuiTestFlamesStarter(cfg))
}

// --- testLiveFlamesModeHandler ---

// testLiveFlamesModeHandler runs the TUI fed by a goroutine that continuously
// updates a synthetic live-flame trie so the flamegraph tab animates without
// requiring a real BPF trace.
type testLiveFlamesModeHandler struct{}

func (h *testLiveFlamesModeHandler) selectors() []modeSelector {
	return []modeSelector{{flag: "-testliveflames", isSet: func(cfg flags.Config) bool { return cfg.TestLiveFlames }}}
}

func (h *testLiveFlamesModeHandler) validate(flags.Config) error { return nil }

func (h *testLiveFlamesModeHandler) run(cfg flags.Config, deps runnerDeps) error {
	return deps.runTUITestLiveFlames(cfg, tuiTestLiveFlamesStarter(cfg))
}

// --- headlessParquetModeHandler ---

// headlessParquetModeHandler streams all traced syscall events directly to a
// Parquet file without starting the TUI.
type headlessParquetModeHandler struct{}

func (h *headlessParquetModeHandler) selectors() []modeSelector {
	return []modeSelector{{flag: "-parquet", isSet: isHeadlessParquetMode}}
}

// validate rejects content filters: the headless recording captures a clean
// event stream scoped at most by -pid.
func (h *headlessParquetModeHandler) validate(cfg flags.Config) error {
	if hasHeadlessParquetContentFilters(cfg) {
		return errors.New("-parquet cannot be combined with content filters (-comm, -path, -tid)")
	}
	return nil
}

func (h *headlessParquetModeHandler) run(cfg flags.Config, deps runnerDeps) error {
	if deps.getEUID() != 0 {
		return errRootPrivilegesRequired
	}
	return deps.runParquet(cfg)
}

// --- plainTraceModeHandler ---

// plainTraceModeHandler runs a headless BPF trace that writes CSV rows to
// stdout (plain mode) or a compressed flamegraph file (-flamegraph), without
// starting the TUI. Its two selectors are mutually exclusive with each other
// like any other pair of selectors.
type plainTraceModeHandler struct{}

func (h *plainTraceModeHandler) selectors() []modeSelector {
	return []modeSelector{
		{flag: "-plain", isSet: func(cfg flags.Config) bool { return cfg.PlainMode }},
		{flag: "-flamegraph", isSet: func(cfg flags.Config) bool { return cfg.FlamegraphOutput }},
	}
}

func (h *plainTraceModeHandler) validate(flags.Config) error { return nil }

func (h *plainTraceModeHandler) run(cfg flags.Config, deps runnerDeps) error {
	if deps.getEUID() != 0 {
		return errRootPrivilegesRequired
	}
	return deps.runTrace(cfg)
}

// --- tuiModeHandler ---

// tuiModeHandler is the default mode that launches the full interactive TUI
// dashboard backed by a live BPF trace. It has no selectors, so it runs
// whenever no other mode's flag is set.
type tuiModeHandler struct{}

func (h *tuiModeHandler) selectors() []modeSelector { return nil }

func (h *tuiModeHandler) validate(flags.Config) error { return nil }

func (h *tuiModeHandler) run(cfg flags.Config, deps runnerDeps) error {
	if deps.getEUID() != 0 {
		return errRootPrivilegesRequired
	}
	return deps.runTUI(cfg, tuiTraceStarterFromRunTrace(cfg, deps.runTraceWithContext))
}
