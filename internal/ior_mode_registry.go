package internal

import (
	"errors"

	"ior/internal/flags"
)

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
	run(cfg flags.Config) error
}

// modeRegistry is an ordered list of modeHandlers.
// dispatchRun and validateRunConfig iterate through it.
type modeRegistry []modeHandler

// defaultRegistry is the canonical ordered registry used at runtime.
// Modes are evaluated first-match-wins, so more specific modes (e.g.,
// testFlames) are registered before more general ones (e.g., TUI default).
var defaultRegistry = modeRegistry{
	&testFlamesModeHandler{},
	&testLiveFlamesModeHandler{},
	&headlessParquetModeHandler{},
	&plainTraceModeHandler{},
	&tuiModeHandler{},
}

// dispatch validates cross-mode constraints, requires root when necessary,
// then delegates to the first matching handler in the registry.
func (reg modeRegistry) dispatch(cfg flags.Config) error {
	if err := reg.validate(cfg); err != nil {
		return err
	}
	for _, h := range reg {
		if h.match(cfg) {
			return h.run(cfg)
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
	for _, h := range reg {
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

func (h *testFlamesModeHandler) run(cfg flags.Config) error {
	return runTUITestFlamesFn(cfg, tuiTestFlamesStarter(cfg))
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

func (h *testLiveFlamesModeHandler) run(cfg flags.Config) error {
	return runTUITestLiveFlamesFn(cfg, tuiTestLiveFlamesStarter(cfg))
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

func (h *headlessParquetModeHandler) run(cfg flags.Config) error {
	if getEUID() != 0 {
		return errRootPrivilegesRequired
	}
	return runParquetFn(cfg)
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

func (h *plainTraceModeHandler) run(cfg flags.Config) error {
	if getEUID() != 0 {
		return errRootPrivilegesRequired
	}
	return runTraceFn(cfg)
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

func (h *tuiModeHandler) run(cfg flags.Config) error {
	if getEUID() != 0 {
		return errRootPrivilegesRequired
	}
	return runTUIFn(cfg, tuiTraceStarterFromRunTrace(cfg, runTraceWithContextFn))
}
