package internal

import (
	"errors"
	"strings"
	"testing"

	"ior/internal/flags"
	"ior/internal/runtime"
)

// modeFlag is one mode-selecting command-line flag together with the config
// mutation that sets it, in the registry's order.
type modeFlag struct {
	name string
	set  func(*flags.Config)
}

// allModeFlags lists every mode-selecting flag in registry order, which is the
// order a conflict error names them in.
func allModeFlags() []modeFlag {
	return []modeFlag{
		{"--testflames", func(c *flags.Config) { c.TestFlames = true }},
		{"--testliveflames", func(c *flags.Config) { c.TestLiveFlames = true }},
		{"-parquet", func(c *flags.Config) { c.ParquetPath = "trace.parquet" }},
		{"-plain", func(c *flags.Config) { c.PlainMode = true }},
		{"-flamegraph", func(c *flags.Config) { c.FlamegraphOutput = true }},
	}
}

// failingDeps returns deps whose every runner fails the test, for checks that
// must be rejected before any mode runs.
func failingDeps(t *testing.T) runnerDeps {
	t.Helper()
	fail := func(what string) { t.Errorf("%s must not run for a rejected config", what) }
	deps := stubDeps()
	deps.runTrace = func(flags.Config) error { fail("runTrace"); return nil }
	deps.runParquet = func(flags.Config) error { fail("runParquet"); return nil }
	deps.runTUI = func(flags.Config, runtime.TraceStarter) error { fail("runTUI"); return nil }
	deps.runTUITestFlames = func(flags.Config, runtime.TraceStarter) error { fail("runTUITestFlames"); return nil }
	deps.runTUITestLiveFlames = func(flags.Config, runtime.TraceStarter) error { fail("runTUITestLiveFlames"); return nil }
	return deps
}

// TestModeRegistryRejectsEveryConflictingPair covers all pairs of mode flags,
// including the two flags owned by the same handler (-plain, -flamegraph).
// Each must be rejected by the single exclusivity check with an error naming
// both flags, and no runner may be called.
func TestModeRegistryRejectsEveryConflictingPair(t *testing.T) {
	mf := allModeFlags()
	pairs := 0
	for i := range mf {
		for j := i + 1; j < len(mf); j++ {
			a, b := mf[i], mf[j]
			pairs++
			t.Run(a.name+"+"+b.name, func(t *testing.T) {
				var cfg flags.Config
				a.set(&cfg)
				b.set(&cfg)

				err := dispatchRunWithDeps(cfg, failingDeps(t))
				want := a.name + " and " + b.name + " are mutually exclusive"
				if err == nil || err.Error() != want {
					t.Fatalf("dispatch error = %v, want %q", err, want)
				}
				var conflict *modeConflictError
				if !errors.As(err, &conflict) {
					t.Fatalf("error %T is not a *modeConflictError", err)
				}
				if got := strings.Join(conflict.flags, ","); got != a.name+","+b.name {
					t.Fatalf("conflict flags = %q, want %q", got, a.name+","+b.name)
				}
				if verr := validateRunConfig(cfg); verr == nil || verr.Error() != want {
					t.Fatalf("validateRunConfig error = %v, want %q", verr, want)
				}
			})
		}
	}
	if want := len(mf) * (len(mf) - 1) / 2; pairs != want {
		t.Fatalf("covered %d pairs, want %d", pairs, want)
	}
}

// TestModeRegistryConflictNamesEveryFlag checks that more than two conflicting
// flags are all reported, not just the first pair found.
func TestModeRegistryConflictNamesEveryFlag(t *testing.T) {
	var cfg flags.Config
	names := make([]string, 0, len(allModeFlags()))
	for _, f := range allModeFlags() {
		f.set(&cfg)
		names = append(names, f.name)
	}
	err := dispatchRunWithDeps(cfg, failingDeps(t))
	want := "--testflames, --testliveflames, -parquet, -plain and -flamegraph are mutually exclusive"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
	var conflict *modeConflictError
	if !errors.As(err, &conflict) || strings.Join(conflict.flags, ",") != strings.Join(names, ",") {
		t.Fatalf("conflict = %+v, want flags %v", conflict, names)
	}
}

// TestModeRegistryAcceptsEachSingleMode dispatches every valid mode choice
// (each flag alone, and none for the TUI default) and checks that exactly the
// expected runner is called.
func TestModeRegistryAcceptsEachSingleMode(t *testing.T) {
	cases := []struct {
		name   string
		set    func(*flags.Config)
		runner string
	}{
		{"default TUI", func(*flags.Config) {}, "runTUI"},
		{"--testflames", func(c *flags.Config) { c.TestFlames = true }, "runTUITestFlames"},
		{"--testliveflames", func(c *flags.Config) { c.TestLiveFlames = true }, "runTUITestLiveFlames"},
		{"-parquet", func(c *flags.Config) { c.ParquetPath = "trace.parquet" }, "runParquet"},
		{"-parquet with -pid", func(c *flags.Config) { c.ParquetPath = "trace.parquet"; c.PidFilter = 42 }, "runParquet"},
		{"-plain", func(c *flags.Config) { c.PlainMode = true }, "runTrace"},
		{"-flamegraph", func(c *flags.Config) { c.FlamegraphOutput = true }, "runTrace"},
		// Content filters constrain only -parquet; other modes accept them.
		{"-plain with -comm", func(c *flags.Config) { c.PlainMode = true; c.CommFilter = "nginx" }, "runTrace"},
		{"default TUI with -path", func(c *flags.Config) { c.PathFilter = "/tmp" }, "runTUI"},
		// A blank -parquet value does not select parquet mode.
		{"blank -parquet with -plain", func(c *flags.Config) { c.ParquetPath = "  "; c.PlainMode = true }, "runTrace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var called []string
			record := func(name string) { called = append(called, name) }
			deps := stubDeps()
			deps.runTrace = func(flags.Config) error { record("runTrace"); return nil }
			deps.runParquet = func(flags.Config) error { record("runParquet"); return nil }
			deps.runTUI = func(flags.Config, runtime.TraceStarter) error { record("runTUI"); return nil }
			deps.runTUITestFlames = func(flags.Config, runtime.TraceStarter) error { record("runTUITestFlames"); return nil }
			deps.runTUITestLiveFlames = func(flags.Config, runtime.TraceStarter) error { record("runTUITestLiveFlames"); return nil }

			var cfg flags.Config
			tc.set(&cfg)
			if err := validateRunConfig(cfg); err != nil {
				t.Fatalf("validateRunConfig: %v", err)
			}
			if err := dispatchRunWithDeps(cfg, deps); err != nil {
				t.Fatalf("dispatch: %v", err)
			}
			if len(called) != 1 || called[0] != tc.runner {
				t.Fatalf("runners called = %v, want [%s]", called, tc.runner)
			}
		})
	}
}

// TestModeRegistryChecksOwnConstraintsAfterExclusivity checks that a mode's
// own constraint (parquet's content-filter ban) is still enforced, and that a
// flag conflict is reported ahead of it.
func TestModeRegistryChecksOwnConstraintsAfterExclusivity(t *testing.T) {
	cfg := flags.Config{ParquetPath: "trace.parquet", TidFilter: 7}
	err := dispatchRunWithDeps(cfg, failingDeps(t))
	if err == nil || err.Error() != "-parquet cannot be combined with content filters (-comm, -path, -tid)" {
		t.Fatalf("error = %v, want content-filter rejection", err)
	}

	cfg.PlainMode = true
	err = dispatchRunWithDeps(cfg, failingDeps(t))
	var conflict *modeConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want the mode conflict reported first", err)
	}
}

// extraModeHandler is a test-only mode used to show that a new handler gets
// exclusivity against every existing mode without any of them changing. It is
// selected by an otherwise-unused sentinel -duration value.
type extraModeHandler struct{ ran *bool }

func (h *extraModeHandler) selectors() []modeSelector {
	return []modeSelector{{flag: "-extra", isSet: func(cfg flags.Config) bool { return cfg.Duration == 4242 }}}
}

func (h *extraModeHandler) validate(flags.Config) error { return nil }

func (h *extraModeHandler) run(flags.Config, runnerDeps) error {
	*h.ran = true
	return nil
}

// TestModeRegistryNewHandlerIsExclusiveWithoutEditingOthers registers an
// extra mode and checks it both runs on its own and conflicts with every
// existing mode flag.
func TestModeRegistryNewHandlerIsExclusiveWithoutEditingOthers(t *testing.T) {
	ran := false
	reg := newModeRegistry(failingDeps(t))
	reg.handlers = append([]modeHandler{&extraModeHandler{ran: &ran}}, reg.handlers...)

	if err := reg.dispatch(flags.Config{Duration: 4242}); err != nil || !ran {
		t.Fatalf("extra mode alone: err=%v ran=%v, want it to run", err, ran)
	}
	for _, f := range allModeFlags() {
		cfg := flags.Config{Duration: 4242}
		f.set(&cfg)
		want := "-extra and " + f.name + " are mutually exclusive"
		if err := reg.validate(cfg); err == nil || err.Error() != want {
			t.Errorf("extra with %s: error = %v, want %q", f.name, err, want)
		}
	}
}

// TestModeRegistryRequiresExactlyOneDefault guards the registry invariant that
// one selector-less handler supplies the default mode.
func TestModeRegistryRequiresExactlyOneDefault(t *testing.T) {
	reg := newModeRegistry(failingDeps(t))
	reg.handlers = append(reg.handlers, &tuiModeHandler{})
	if err := reg.validate(flags.Config{}); err == nil || !strings.Contains(err.Error(), "2 default handlers") {
		t.Fatalf("two defaults: error = %v, want registry bug error", err)
	}

	reg.handlers = reg.handlers[:len(reg.handlers)-2]
	if err := reg.validate(flags.Config{}); err == nil || !strings.Contains(err.Error(), "0 default handlers") {
		t.Fatalf("no default: error = %v, want registry bug error", err)
	}
}
