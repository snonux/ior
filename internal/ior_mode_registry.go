package internal

import (
	"context"
	"errors"
	"os"

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
	// signal channel, and event-loop configurator. Used by the TUI starter.
	runTraceWithContext func(context.Context, flags.Config, chan<- struct{}, func(*eventLoop)) error

	// runTUI launches the interactive TUI backed by a live BPF trace.
	// Injected at startup via SetTUIRunners so that the core package never
	// imports the TUI layer.
	runTUI tuiRunFunc

	// runTUITestFlames launches the TUI seeded with static synthetic flame data.
	runTUITestFlames tuiRunFunc

	// runTUITestLiveFlames launches the TUI fed by a live synthetic flame goroutine.
	runTUITestLiveFlames tuiRunFunc
}

// defaultRunnerDeps returns the production function set.
func defaultRunnerDeps() runnerDeps {
	return runnerDeps{
		getEUID:             os.Geteuid,
		runTrace:            runTrace,
		runParquet:          runHeadlessParquet,
		runTraceWithContext: runTraceWithContext,
		// TUI runners are nil until SetTUIRunners is called from cmd/ior/main.go.
	}
}

// modeHandler describes a single execution mode for the ior binary.
// Each mode knows how to recognise itself (match), enforce its
// invariants (validate), and run (run). The registry evaluates
// handlers in registration order — the first matching handler wins.
type modeHandler interface {
	// match returns true when this handler should own the run.
	match(cfg flags.Config) bool
	// validate returns an error if the config is invalid for this mode.
	// It is called only after the root-privilege check has been skipped
	// (pre-root modes are checked first and return early before requiring root).
	validate(cfg flags.Config) error
	// run executes the mode using the supplied config.
	run(cfg flags.Config, deps runnerDeps) error
}

// modeRegistry is an ordered list of modeHandlers paired with the
// injectable function dependencies they share. Storing deps on the registry
// (rather than as package-level vars) lets tests construct isolated
// registries without mutating global state.
type modeRegistry struct {
	handlers []modeHandler
	deps     runnerDeps
}

// newModeRegistry constructs a registry with the standard handler order and
// the provided dependencies.
// Modes are evaluated first-match-wins, so more specific modes (e.g.,
// testFlames) must be registered before more general ones (e.g., TUI default).
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

// defaultRegistry is the canonical ordered registry used at runtime.
var defaultRegistry = newModeRegistry(defaultRunnerDeps())

// dispatch validates cross-mode constraints, requires root when necessary,
// then delegates to the first matching handler in the registry.
func (reg modeRegistry) dispatch(cfg flags.Config) error {
	if err := reg.validate(cfg); err != nil {
		return err
	}
	for _, h := range reg.handlers {
		if h.match(cfg) {
			return h.run(cfg, reg.deps)
		}
	}
	// Registry must always include a catch-all (tuiModeHandler matches everything).
	return errors.New("internal: no mode handler matched — this is a bug")
}

// validate runs cross-mode constraint checks across all handlers in the
// registry. Handlers that do not match are still checked for rejected
// combination errors (e.g., parquet + plain is rejected regardless of which
// handler ultimately runs).
func (reg modeRegistry) validate(cfg flags.Config) error {
	for _, h := range reg.handlers {
		if err := h.validate(cfg); err != nil {
			return err
		}
	}
	return nil
}

// --- testFlamesModeHandler ---

// testFlamesModeHandler runs the TUI seeded with static synthetic flame data
// so the flamegraph tab can be exercised without a live BPF trace.
type testFlamesModeHandler struct{}

func (h *testFlamesModeHandler) match(cfg flags.Config) bool {
	return cfg.TestFlames
}

func (h *testFlamesModeHandler) validate(cfg flags.Config) error {
	if !cfg.TestFlames {
		return nil
	}
	if cfg.PlainMode {
		return errors.New("--testflames cannot be combined with -plain")
	}
	if cfg.FlamegraphOutput {
		return errors.New("--testflames cannot be combined with -flamegraph")
	}
	if isHeadlessParquetMode(cfg) {
		return errors.New("--testflames cannot be combined with -parquet")
	}
	if cfg.TestLiveFlames {
		return errors.New("--testflames and --testliveflames are mutually exclusive")
	}
	return nil
}

func (h *testFlamesModeHandler) run(cfg flags.Config, deps runnerDeps) error {
	return deps.runTUITestFlames(cfg, tuiTestFlamesStarter(cfg))
}

// --- testLiveFlamesModeHandler ---

// testLiveFlamesModeHandler runs the TUI fed by a goroutine that continuously
// updates a synthetic live-flame trie so the flamegraph tab animates without
// requiring a real BPF trace.
type testLiveFlamesModeHandler struct{}

func (h *testLiveFlamesModeHandler) match(cfg flags.Config) bool {
	return cfg.TestLiveFlames
}

func (h *testLiveFlamesModeHandler) validate(cfg flags.Config) error {
	if !cfg.TestLiveFlames {
		return nil
	}
	if cfg.PlainMode {
		return errors.New("--testliveflames cannot be combined with -plain")
	}
	if cfg.FlamegraphOutput {
		return errors.New("--testliveflames cannot be combined with -flamegraph")
	}
	// No need to check parquet+testliveflames here — parquet handler validates
	// the reverse (parquet cannot be combined with testliveflames).
	return nil
}

func (h *testLiveFlamesModeHandler) run(cfg flags.Config, deps runnerDeps) error {
	return deps.runTUITestLiveFlames(cfg, tuiTestLiveFlamesStarter(cfg))
}

// --- headlessParquetModeHandler ---

// headlessParquetModeHandler streams all traced syscall events directly to a
// Parquet file without starting the TUI.
type headlessParquetModeHandler struct{}

func (h *headlessParquetModeHandler) match(cfg flags.Config) bool {
	return isHeadlessParquetMode(cfg)
}

func (h *headlessParquetModeHandler) validate(cfg flags.Config) error {
	if !isHeadlessParquetMode(cfg) {
		return nil
	}
	// Test-flame modes cannot be combined with headless Parquet because both
	// require exclusive control over the event source.
	if cfg.TestFlames {
		return errors.New("--testflames cannot be combined with -parquet")
	}
	if cfg.TestLiveFlames {
		return errors.New("--testliveflames cannot be combined with -parquet")
	}
	if cfg.PlainMode {
		return errors.New("-parquet and -plain are mutually exclusive")
	}
	if cfg.FlamegraphOutput {
		return errors.New("-parquet and -flamegraph are mutually exclusive")
	}
	if hasHeadlessParquetContentFilters(cfg) {
		return errors.New("-parquet cannot be combined with content filters (-comm, -path, -pid, -tid)")
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
// starting the TUI.
type plainTraceModeHandler struct{}

func (h *plainTraceModeHandler) match(cfg flags.Config) bool {
	return cfg.PlainMode || cfg.FlamegraphOutput
}

func (h *plainTraceModeHandler) validate(cfg flags.Config) error {
	if cfg.PlainMode && cfg.FlamegraphOutput {
		return errors.New("-plain and -flamegraph are mutually exclusive")
	}
	return nil
}

func (h *plainTraceModeHandler) run(cfg flags.Config, deps runnerDeps) error {
	if deps.getEUID() != 0 {
		return errRootPrivilegesRequired
	}
	return deps.runTrace(cfg)
}

// --- tuiModeHandler ---

// tuiModeHandler is the catch-all default that launches the full interactive
// TUI dashboard backed by a live BPF trace. It matches every config that no
// earlier handler claimed.
type tuiModeHandler struct{}

func (h *tuiModeHandler) match(_ flags.Config) bool {
	return true // catch-all default
}

func (h *tuiModeHandler) validate(_ flags.Config) error {
	return nil
}

func (h *tuiModeHandler) run(cfg flags.Config, deps runnerDeps) error {
	if deps.getEUID() != 0 {
		return errRootPrivilegesRequired
	}
	return deps.runTUI(cfg, tuiTraceStarterFromRunTrace(cfg, deps.runTraceWithContext))
}
