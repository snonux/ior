package flags

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"ior/internal/collapse"
	appconfig "ior/internal/config"
	"ior/internal/globalfilter"
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

	// TracepointsToAttach is the list of compiled regexes that select which
	// tracepoints to load; an empty list means attach all tracepoints.
	TracepointsToAttach []*regexp.Regexp
	// TracepointsToExclude is the list of compiled regexes that suppress
	// specific tracepoints even when they match TracepointsToAttach.
	TracepointsToExclude []*regexp.Regexp

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
	// TUIExportEnable allows the TUI to write CSV snapshot export files.
	TUIExportEnable bool
	// CollapsedFields lists the event fields used as flamegraph collapse keys.
	CollapsedFields []string
	// CountField is the event field used as the numeric weight in flamegraph
	// collapse aggregation.
	CountField string
	// GlobalFilter is the structured event filter applied across all dashboards
	// and output modes; takes precedence over the individual CLI filter flags.
	GlobalFilter globalfilter.Filter
	// ResetTimer is the interval at which aggregate dashboard state (flamegraph
	// trie and stats engine) is automatically cleared; 0 disables auto-reset.
	ResetTimer time.Duration

	// ShowVersion prints the banner plus version and exits without running.
	ShowVersion bool
}

// DefaultResetTimer is the default cadence for the dashboard's auto-reset
// timer. It periodically clears aggregate state (live flamegraph trie and
// stats engine) — the same effect as pressing `r` — to prevent unbounded
// growth during long traces. A value of 0 disables auto-reset entirely.
const DefaultResetTimer = 30 * time.Second

// NewFlags returns a configuration instance initialized with project defaults.
func NewFlags() Config {
	return Config{
		PidFilter:       -1,
		TidFilter:       -1,
		EventMapSize:    appconfig.DefaultEventMapSize,
		Duration:        900,
		LiveInterval:    200 * time.Millisecond,
		TUIExportEnable: true,
		CollapsedFields: []string{"comm", "tracepoint", "path"},
		CountField:      "count",
		ResetTimer:      DefaultResetTimer,
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
	out.TracepointsToAttach = slices.Clone(f.TracepointsToAttach)
	out.TracepointsToExclude = slices.Clone(f.TracepointsToExclude)
	out.CollapsedFields = slices.Clone(f.CollapsedFields)
	out.GlobalFilter = f.GlobalFilter.Clone()
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
	validFields := collapse.ValidFields()
	validCounts := collapse.ValidCountFields()

	fs.IntVar(&cfg.PidFilter, "pid", cfg.PidFilter, "Filter for processes ID")
	fs.IntVar(&cfg.TidFilter, "tid", cfg.TidFilter, "Filter for thread ID")
	fs.IntVar(&cfg.EventMapSize, "mapSize", cfg.EventMapSize, "BPF FD event ring buffer map size")
	fs.IntVar(&cfg.Duration, "duration", cfg.Duration, "Probe duration in seconds")

	fs.StringVar(&cfg.CommFilter, "comm", "", "Command to filter for")
	fs.StringVar(&cfg.PathFilter, "path", "", "Path to filter for")

	fs.BoolVar(&cfg.PprofEnable, "pprof", false, "Enable profiling")

	tracepointsToAttach := fs.String("tps", "", "Comma separated list regexes for tracepoints to load")
	tracepointsToExclude := fs.String("tpsExclude", "", "Comma separated list regexes for tracepoints to exclude")

	fs.BoolVar(&cfg.PlainMode, "plain", false, "Enable plain CSV output mode (disable TUI)")
	fs.BoolVar(&cfg.FlamegraphOutput, "flamegraph", false, "Write aggregated .ior.zst output for trace/integration workflows")
	fs.StringVar(&cfg.ParquetPath, "parquet", cfg.ParquetPath, "Write all traced syscall rows directly to a parquet file in headless mode (skip the TUI; incompatible with -plain, -flamegraph, --testflames, --testliveflames, and content filters)")
	fs.StringVar(&cfg.OutputName, "name", cfg.OutputName, "Base name for .ior.zst trace output files")
	fs.BoolVar(&cfg.TestFlames, "testflames", false, "Run TUI with static synthetic flamegraph data for keyboard-navigation testing")
	fs.BoolVar(&cfg.TestLiveFlames, "testliveflames", false, "Run TUI with continuously-updating synthetic flamegraph data for live keyboard-navigation testing")
	fs.DurationVar(&cfg.LiveInterval, "live-interval", cfg.LiveInterval, "Synthetic live flamegraph refresh interval for --testliveflames")
	fs.BoolVar(&cfg.TUIExportEnable, "tuiExport", cfg.TUIExportEnable, "Enable TUI CSV snapshot export files (separate from Parquet recording)")
	fs.DurationVar(&cfg.ResetTimer, "resetTimer", cfg.ResetTimer,
		"Auto-reset interval for aggregate dashboard state (flamegraph trie + stats engine); set to 0 to disable")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "Print version banner and exit")
	fields := fs.String("fields", "",
		fmt.Sprintf("Comma separated list of fields to collapse, valid are: %v", validFields))
	fs.StringVar(&cfg.CountField, "count", cfg.CountField,
		fmt.Sprintf("Count field to collapse, valid are: %v", validCounts))

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	var err error
	cfg.TracepointsToAttach, err = extractTracepointFlags(*tracepointsToAttach)
	if err != nil {
		return Config{}, err
	}
	cfg.TracepointsToExclude, err = extractTracepointFlags(*tracepointsToExclude)
	if err != nil {
		return Config{}, err
	}

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
			return Config{}, fmt.Errorf("invalid field for collapse: %s", field)
		}
	}

	if !collapse.IsValidCountField(cfg.CountField) {
		return Config{}, fmt.Errorf("invalid count field: %s", cfg.CountField)
	}

	// A zero or negative duration would cause the trace context to cancel
	// immediately, capturing no events. Require at least one second.
	if cfg.Duration <= 0 {
		return Config{}, fmt.Errorf("invalid duration: %d (must be > 0)", cfg.Duration)
	}

	// A negative reset timer would imply auto-resets in the past, which is
	// nonsensical. 0 disables, anything positive enables.
	if cfg.ResetTimer < 0 {
		return Config{}, fmt.Errorf("invalid resetTimer: %s (must be >= 0; 0 disables)", cfg.ResetTimer)
	}

	// A non-positive mapSize would wrap to a huge uint32 when cast in
	// resizeBPFMaps, causing libbpf to fail with a confusing "map too large"
	// error. Reject it here with a clear diagnostic instead.
	if cfg.EventMapSize <= 0 {
		return Config{}, fmt.Errorf("invalid mapSize: %d (must be > 0)", cfg.EventMapSize)
	}

	return cfg, nil
}

func extractTracepointFlags(tracepoints string) (regexes []*regexp.Regexp, err error) {
	if len(tracepoints) == 0 {
		return regexes, nil
	}
	for _, name := range strings.Split(tracepoints, ",") {
		re, err := regexp.Compile(name)
		if err != nil {
			return nil, fmt.Errorf("unable to compile regex %q: %w", name, err)
		}
		regexes = append(regexes, re)
	}
	return regexes, nil
}

// TraceFilter builds a globalfilter.Filter from the config's filter fields.
// If GlobalFilter is already active, it is returned as-is. Otherwise,
// individual CLI-level filters (CommFilter, PathFilter, PidFilter, TidFilter)
// are merged into a new filter.
func (cfg Config) TraceFilter() globalfilter.Filter {
	filter := cfg.GlobalFilter.Clone()
	if filter.IsActive() {
		return filter
	}
	if cfg.CommFilter != "" {
		filter.Comm = &globalfilter.StringFilter{Pattern: cfg.CommFilter}
	}
	if cfg.PathFilter != "" {
		filter.File = &globalfilter.StringFilter{Pattern: cfg.PathFilter}
	}
	if cfg.PidFilter > 0 {
		filter.PID = globalfilter.NewEqFilter(int64(cfg.PidFilter))
	}
	if cfg.TidFilter > 0 {
		filter.TID = globalfilter.NewEqFilter(int64(cfg.TidFilter))
	}
	return filter
}

// ShouldIAttachTracepoint reports whether the given tracepoint name passes the
// attach/exclude regex filters. Exclusions are checked first; if the name
// matches any exclude pattern it is rejected regardless of the attach list.
// When the attach list is empty, all non-excluded tracepoints are accepted.
func (f Config) ShouldIAttachTracepoint(tracepointName string) bool {
	for _, re := range f.TracepointsToExclude {
		if re.MatchString(tracepointName) {
			return false
		}
	}
	if len(f.TracepointsToAttach) == 0 {
		return true
	}
	for _, re := range f.TracepointsToAttach {
		if re.MatchString(tracepointName) {
			return true
		}
	}

	return false
}
