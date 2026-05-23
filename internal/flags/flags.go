package flags

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"ior/internal/collapse"
	appconfig "ior/internal/config"
	"ior/internal/globalfilter"
	"ior/internal/tracepoints"
	"ior/internal/types"
)

// Config captures runtime configuration parsed from CLI flags.
type Config struct {
	// PidFilter restricts tracing to the given process ID; -1 means no filter.
	PidFilter int
	// TidFilter restricts tracing to the given thread ID; -1 means no filter.
	TidFilter int
	// EventMapSize controls the BPF ring-buffer map size for kernel events.
	EventMapSize int
	// CommFilter is a command-name substring filter applied at the CLI level.
	CommFilter string
	// PathFilter is a file-path substring filter applied at the CLI level.
	PathFilter string
	// PprofEnable turns on pprof profiling endpoints during the trace run.
	PprofEnable bool
	// Duration is the maximum tracing duration in seconds.
	Duration int

	// TracepointSelector holds the compiled include/exclude regexes that
	// decide which BPF tracepoints to attach. The selection logic lives in
	// tracepoints.Selector.ShouldAttach rather than on Config itself.
	TracepointSelector tracepoints.Selector

	// PlainMode disables the TUI and writes raw CSV rows to stdout.
	PlainMode bool
	// FlamegraphOutput writes aggregated .ior.zst output for offline workflows.
	FlamegraphOutput bool
	// ParquetPath is the file path for writing all traced syscall rows to
	// Parquet in headless mode; empty string disables Parquet output.
	ParquetPath string
	// OutputName is the base name used for .ior.zst trace output files.
	OutputName string
	// TestFlames runs the TUI with static synthetic flamegraph data for
	// keyboard-navigation testing without a live BPF trace.
	TestFlames bool
	// TestLiveFlames runs the TUI with continuously-updating synthetic
	// flamegraph data for live keyboard-navigation testing.
	TestLiveFlames bool
	// LiveInterval is the refresh interval for the synthetic live flamegraph
	// used when TestLiveFlames is active.
	LiveInterval time.Duration
	// TUIFastRefreshInterval is the high-frequency refresh cadence for the TUI
	// flamegraph and stream tabs. A value of 0 disables high-frequency refresh,
	// falling back to the standard Bubble Tea tick rate.
	TUIFastRefreshInterval time.Duration
	// TUIExportEnable allows the TUI to write CSV snapshot export files.
	TUIExportEnable bool
	// CollapsedFields lists the event fields used as flamegraph collapse keys.
	CollapsedFields []string
	// CountField is the event field used as the numeric weight in flamegraph
	// collapse aggregation.
	CountField string
	// GlobalFilter is the structured event filter applied across all dashboards
	// and output modes; takes precedence over the individual CLI filter flags.
	// Use BuildTraceFilter(cfg) to obtain a resolved globalfilter.Filter.
	GlobalFilter globalfilter.Filter
	// ResetTimer is the interval at which aggregate dashboard state (flamegraph
	// trie and stats engine) is automatically cleared; 0 disables auto-reset.
	ResetTimer time.Duration
	// SyscallFamilySamplingRates controls in-kernel syscall sampling by family.
	// Rate semantics: 0 aggregate-only, 1 emit every event, N>1 emit 1-in-N events.
	SyscallFamilySamplingRates map[types.SyscallFamily]uint32
	// SyscallSamplingRates controls in-kernel syscall sampling by syscall name.
	// Keys use syscall names (for example "futex"), not tracepoint names.
	// Rate semantics: 0 aggregate-only, 1 emit every event, N>1 emit 1-in-N events.
	SyscallSamplingRates map[string]uint32

	// ShowVersion prints the banner plus version and exits without running.
	ShowVersion bool
}

// IsRawOutputMode reports whether the config selects a headless output path
// (-plain, -flamegraph, or headless -parquet) that lacks a TUI aggregate
// sink. In these modes, aggregate-only sampling (rate 0) would silently
// suppress ring-buffer events, so callers should promote default aggregate-
// only rates to 1.
func (f Config) IsRawOutputMode() bool {
	return f.PlainMode || f.FlamegraphOutput || strings.TrimSpace(f.ParquetPath) != ""
}

// DefaultResetTimer is the default cadence for the dashboard's auto-reset
// timer. It periodically clears aggregate state (live flamegraph trie and
// stats engine) — the same effect as pressing `r` — to prevent unbounded
// growth during long traces. A value of 0 disables auto-reset entirely.
const DefaultResetTimer = 30 * time.Second

// NewFlags returns a configuration instance initialized with project defaults.
func NewFlags() Config {
	return Config{
		PidFilter:                  -1,
		TidFilter:                  -1,
		EventMapSize:               appconfig.DefaultEventMapSize,
		Duration:                   900,
		LiveInterval:               200 * time.Millisecond,
		TUIFastRefreshInterval:     250 * time.Millisecond,
		TUIExportEnable:            true,
		CollapsedFields:            []string{"comm", "tracepoint", "path"},
		CountField:                 "count",
		ResetTimer:                 DefaultResetTimer,
		SyscallFamilySamplingRates: make(map[types.SyscallFamily]uint32),
		SyscallSamplingRates:       make(map[string]uint32),
	}
}

// GetPidFilter returns the active process filter.
func (f Config) GetPidFilter() int {
	return f.PidFilter
}

// GetTidFilter returns the active thread filter.
func (f Config) GetTidFilter() int {
	return f.TidFilter
}

// GetTUIExportEnable reports whether TUI CSV export is enabled.
func (f Config) GetTUIExportEnable() bool {
	return f.TUIExportEnable
}

// Clone returns a deep copy of the Config, duplicating all slice and filter
// fields so that modifications to the copy do not affect the original.
func (f Config) Clone() Config {
	out := f
	out.TracepointSelector = f.TracepointSelector.Clone()
	out.CollapsedFields = slices.Clone(f.CollapsedFields)
	out.GlobalFilter = f.GlobalFilter.Clone()
	out.SyscallFamilySamplingRates = cloneFamilySamplingRates(f.SyscallFamilySamplingRates)
	out.SyscallSamplingRates = cloneSyscallSamplingRates(f.SyscallSamplingRates)
	return out
}

// Parse parses CLI flags from os.Args and returns the resulting Config.
// It uses the global flag.CommandLine set, so it must be called once at
// program startup before any other flag parsing occurs.
func Parse() (Config, error) {
	return parseFromFlagSet(flag.CommandLine, os.Args[1:])
}

// parseFromFlagSet parses flags into a new Config using the provided FlagSet
// and argument list. It is factored out of Parse to allow tests to inject a
// fresh FlagSet and custom argument slices without touching global state.
func parseFromFlagSet(fs *flag.FlagSet, args []string) (Config, error) {
	cfg := NewFlags()
	tpsAttach, tpsExclude, fields, familySampling, syscallSampling, dims := registerFlags(fs, &cfg)

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if err := resolvePostParseFields(&cfg, tpsAttach, tpsExclude, fields, dims); err != nil {
		return Config{}, err
	}
	if err := resolveSamplingRates(&cfg, familySampling, syscallSampling); err != nil {
		return Config{}, err
	}
	if err := validateConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// registerFlags binds all CLI flags to cfg and returns the string pointers for
// fields that require post-parse resolution (tracepoint regexes, collapse fields).
func registerFlags(fs *flag.FlagSet, cfg *Config) (tpsAttach, tpsExclude, fields, familySampling, syscallSampling *string, dims *tracepoints.DimensionSelectorConfig) {
	validFields := collapse.ValidFields()
	validCounts := collapse.ValidCountFields()
	dimensionCfg := &tracepoints.DimensionSelectorConfig{}

	fs.IntVar(&cfg.PidFilter, "pid", cfg.PidFilter, "Filter for processes ID")
	fs.IntVar(&cfg.TidFilter, "tid", cfg.TidFilter, "Filter for thread ID")
	fs.IntVar(&cfg.EventMapSize, "mapSize", cfg.EventMapSize, "BPF FD event ring buffer map size")
	fs.IntVar(&cfg.Duration, "duration", cfg.Duration, "Probe duration in seconds")

	fs.StringVar(&cfg.CommFilter, "comm", "", "Command to filter for")
	fs.StringVar(&cfg.PathFilter, "path", "", "Path to filter for")
	fs.BoolVar(&cfg.PprofEnable, "pprof", false, "Enable profiling")

	tpsAttach = fs.String("tps", "", "Comma separated list regexes for tracepoints to load")
	tpsExclude = fs.String("tpsExclude", "", "Comma separated list regexes for tracepoints to exclude")
	fs.StringVar(&dimensionCfg.TraceFamilies, "trace-families", "",
		"Comma separated syscall families to attach (for example FS,Time,Network)")
	fs.StringVar(&dimensionCfg.TraceKinds, "trace-kinds", "",
		"Comma separated tracepoint kinds to attach (for example fd,open,sleep,epoll-ctl)")
	fs.StringVar(&dimensionCfg.TraceSyscalls, "trace-syscalls", "",
		"Comma separated syscall names to attach (for example openat,read,nanosleep)")
	fs.StringVar(&dimensionCfg.NoTraceFamilies, "no-trace-families", "",
		"Comma separated syscall families to exclude from attachment")
	fs.StringVar(&dimensionCfg.NoTraceKinds, "no-trace-kinds", "",
		"Comma separated tracepoint kinds to exclude from attachment")
	fs.StringVar(&dimensionCfg.NoTraceSyscalls, "no-trace-syscalls", "",
		"Comma separated syscall names to exclude from attachment")

	fs.BoolVar(&cfg.PlainMode, "plain", false, "Enable plain CSV output mode (disable TUI)")
	fs.BoolVar(&cfg.FlamegraphOutput, "flamegraph", false, "Write aggregated .ior.zst output for trace/integration workflows")
	fs.StringVar(&cfg.ParquetPath, "parquet", cfg.ParquetPath, "Write traced syscall rows directly to a parquet file in headless mode (skip the TUI; compatible with -pid; incompatible with -plain, -flamegraph, --testflames, --testliveflames, and other content filters)")
	fs.StringVar(&cfg.OutputName, "name", cfg.OutputName, "Base name for .ior.zst trace output files")
	fs.BoolVar(&cfg.TestFlames, "testflames", false, "Run TUI with static synthetic flamegraph data for keyboard-navigation testing")
	fs.BoolVar(&cfg.TestLiveFlames, "testliveflames", false, "Run TUI with continuously-updating synthetic flamegraph data for live keyboard-navigation testing")
	fs.DurationVar(&cfg.LiveInterval, "live-interval", cfg.LiveInterval, "Synthetic live flamegraph refresh interval for --testliveflames")
	fs.DurationVar(&cfg.TUIFastRefreshInterval, "tui-fast-refresh", cfg.TUIFastRefreshInterval,
		"High-frequency refresh interval for TUI flamegraph and stream tabs (0 = disable high-frequency refresh)")
	fs.BoolVar(&cfg.TUIExportEnable, "tuiExport", cfg.TUIExportEnable, "Enable TUI CSV snapshot export files (separate from Parquet recording)")
	fs.DurationVar(&cfg.ResetTimer, "resetTimer", cfg.ResetTimer,
		"Auto-reset interval for aggregate dashboard state (flamegraph trie + stats engine); set to 0 to disable")
	familySampling = fs.String("syscall-sampling-families", "",
		"Per-family sampling rates, for example \"Time=100,Misc=0\" (0=aggregate-only, 1=all, N=1-in-N)")
	syscallSampling = fs.String("syscall-sampling-syscalls", "",
		"Per-syscall sampling rates, for example \"futex=0,clock_gettime=200\" (overrides family rates)")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "Print version banner and exit")
	fields = fs.String("fields", "",
		fmt.Sprintf("Comma separated list of fields to collapse, valid are: %v", validFields))
	fs.StringVar(&cfg.CountField, "count", cfg.CountField,
		fmt.Sprintf("Count field to collapse, valid are: %v", validCounts))
	return tpsAttach, tpsExclude, fields, familySampling, syscallSampling, dimensionCfg
}

// resolvePostParseFields compiles the tracepoint selector and collapse field
// list from the raw string flags that cannot be bound directly to cfg fields.
func resolvePostParseFields(cfg *Config, tpsAttach, tpsExclude, fields *string, dims *tracepoints.DimensionSelectorConfig) error {
	// Parse the tracepoint include/exclude regex lists into a Selector.
	// The Selector owns all matching logic; Config is purely a data carrier.
	if dims == nil {
		dims = &tracepoints.DimensionSelectorConfig{}
	}
	sel, err := tracepoints.ParseSelectorWithDimensions(*tpsAttach, *tpsExclude, *dims)
	if err != nil {
		return err
	}
	cfg.TracepointSelector = sel

	// Keep this list empty by default.
	// As of February 23, 2026, open_by_handle_at and name_to_handle_at were
	// re-evaluated on newer kernels and do not require CO-RE-based exclusions.
	// If future kernels regress, add targeted exclusions here.
	if *fields == "" {
		cfg.CollapsedFields = []string{"comm", "tracepoint", "path"}
	} else {
		cfg.CollapsedFields = strings.Split(*fields, ",")
	}

	for _, field := range cfg.CollapsedFields {
		if !collapse.IsValidField(field) {
			return fmt.Errorf("invalid field for collapse: %s", field)
		}
	}
	if !collapse.IsValidCountField(cfg.CountField) {
		return fmt.Errorf("invalid count field: %s", cfg.CountField)
	}
	return nil
}

func resolveSamplingRates(cfg *Config, familySampling, syscallSampling *string) error {
	familyRates, err := parseFamilySamplingRates(*familySampling)
	if err != nil {
		return err
	}
	syscallRates, err := parseSyscallSamplingRates(*syscallSampling)
	if err != nil {
		return err
	}
	cfg.SyscallFamilySamplingRates = familyRates
	cfg.SyscallSamplingRates = mergeSyscallSamplingRates(syscallRates)
	// In raw output modes (-plain, -flamegraph, headless -parquet) there is
	// no aggregate sink, so aggregate-only defaults (rate 0) would silently
	// suppress ring-buffer events. Promote those defaults to rate 1 unless
	// the user explicitly requested rate 0 via -syscall-sampling-syscalls.
	if cfg.IsRawOutputMode() {
		promoteAggregateOnlyForRawOutput(cfg.SyscallSamplingRates, syscallRates)
	}
	return nil
}

// validateConfig checks numeric/duration bounds that cannot be enforced by the
// flag package itself and returns a descriptive error on the first violation.
func validateConfig(cfg Config) error {
	// A zero or negative duration would cause the trace context to cancel
	// immediately, capturing no events. Require at least one second.
	if cfg.Duration <= 0 {
		return fmt.Errorf("invalid duration: %d (must be > 0)", cfg.Duration)
	}
	// A negative reset timer would imply auto-resets in the past, which is
	// nonsensical. 0 disables, anything positive enables.
	if cfg.ResetTimer < 0 {
		return fmt.Errorf("invalid resetTimer: %s (must be >= 0; 0 disables)", cfg.ResetTimer)
	}
	// A non-positive mapSize would wrap to a huge uint32 when cast in
	// resizeBPFMaps, causing libbpf to fail with a confusing "map too large"
	// error. Reject it here with a clear diagnostic instead.
	if cfg.EventMapSize <= 0 {
		return fmt.Errorf("invalid mapSize: %d (must be > 0)", cfg.EventMapSize)
	}
	return nil
}
