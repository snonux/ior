package flags

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"ior/internal/collapse"
	appconfig "ior/internal/config"
	"ior/internal/csvlist"
	"ior/internal/globalfilter"
	"ior/internal/textsafe"
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

	// PlainMode disables the TUI and writes CSV rows to stdout.
	PlainMode bool
	// EscapeMode (-escape) decides when -plain escapes control and
	// invisible characters in traced text: auto (only when stdout is a
	// terminal), always (also through pipes such as `| less -R`) or never.
	EscapeMode textsafe.EscapeMode
	// FlamegraphOutput writes aggregated .ior.zst output for offline workflows.
	FlamegraphOutput bool
	// ParquetPath is the file path for writing all traced syscall rows to
	// Parquet in headless mode; empty string disables Parquet output.
	ParquetPath string
	// OutputName is the base name (never a path) used for .ior.zst trace output
	// files, which always land in the working directory.
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
	// SyscallSamplingRates holds only the rates the user set explicitly via
	// -syscall-sampling-syscalls, keyed by syscall name (for example "futex"),
	// not tracepoint name. Rate semantics: 0 aggregate-only, 1 emit every
	// event, N>1 emit 1-in-N events.
	SyscallSamplingRates map[string]uint32
	// DefaultSyscallSamplingRates holds the built-in per-syscall defaults
	// (futex*, clock_gettime: aggregate-only, or 1 in raw output modes). It is
	// separate from SyscallSamplingRates so that precedence is
	// default < SyscallFamilySamplingRates < SyscallSamplingRates: an explicit
	// family rate must beat a built-in default.
	DefaultSyscallSamplingRates map[string]uint32

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
		PidFilter:                   -1,
		TidFilter:                   -1,
		EventMapSize:                appconfig.DefaultEventMapSize,
		Duration:                    900,
		LiveInterval:                200 * time.Millisecond,
		TUIFastRefreshInterval:      250 * time.Millisecond,
		TUIExportEnable:             true,
		EscapeMode:                  textsafe.EscapeAuto,
		CollapsedFields:             collapse.DefaultFields(),
		CountField:                  collapse.DefaultCountField(),
		ResetTimer:                  DefaultResetTimer,
		SyscallFamilySamplingRates:  make(map[types.SyscallFamily]uint32),
		SyscallSamplingRates:        make(map[string]uint32),
		DefaultSyscallSamplingRates: make(map[string]uint32),
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
	out.DefaultSyscallSamplingRates = cloneSyscallSamplingRates(f.DefaultSyscallSamplingRates)
	return out
}

// LibbpfDebugEnv is the environment variable that re-enables libbpf's INFO and
// DEBUG output for the headless modes (internal.libbpfDebugEnv reads it). It is
// not a flag, so the usage epilogue is where -h users can discover it.
const LibbpfDebugEnv = "IOR_LIBBPF_DEBUG"

// setUsage makes -h/-help print the flag defaults followed by the environment
// variables ior reads, which the flag package cannot list by itself.
func setUsage(fs *flag.FlagSet) {
	fs.Usage = func() {
		// Best effort like the flag package's own default usage: a closed
		// stderr must not turn -h into a failure.
		_, _ = fmt.Fprintf(fs.Output(), "Usage of %s:\n", fs.Name())
		fs.PrintDefaults()
		_, _ = fmt.Fprintf(fs.Output(), "\nEnvironment:\n  %s=1\n    \tPrint libbpf's INFO and DEBUG output (about 23k lines on every start) to stderr in the\n    \theadless modes; by default only libbpf warnings are shown. 0, false, no and off keep it\n    \toff. Ignored by the TUI, whose screen owns stderr.\n", LibbpfDebugEnv)
	}
}

// Parse parses CLI flags from os.Args and returns the resulting Config.
// It uses the global flag.CommandLine set, so it must be called once at
// program startup before any other flag parsing occurs.
func Parse() (Config, error) {
	return parseFromFlagSet(flag.CommandLine, os.Args[1:])
}

// ParseArgs parses args (without the program name) into a Config using a
// private FlagSet, leaving the global flag.CommandLine untouched. It lets
// tests outside this package build a Config through the real CLI resolution
// path instead of hand-assembling maps that production never produces.
func ParseArgs(args []string) (Config, error) {
	fs := flag.NewFlagSet("ior", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return parseFromFlagSet(fs, args)
}

// parseFromFlagSet parses flags into a new Config using the provided FlagSet
// and argument list. It is factored out of Parse to allow tests to inject a
// fresh FlagSet and custom argument slices without touching global state.
func parseFromFlagSet(fs *flag.FlagSet, args []string) (Config, error) {
	cfg := NewFlags()
	tpsAttach, tpsExclude, fields, familySampling, syscallSampling, dims := registerFlags(fs, &cfg)
	setUsage(fs)

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
// fields that require post-parse resolution (tracepoint regexes, collapse fields,
// sampling rates, and the tracepoint dimension selectors). Registration is
// split by concern into the register*Flags helpers below; the order does not
// matter because the flag package sorts the help output by name.
func registerFlags(fs *flag.FlagSet, cfg *Config) (tpsAttach, tpsExclude, fields, familySampling, syscallSampling *string, dims *tracepoints.DimensionSelectorConfig) {
	// Families and kinds enumerate their full valid sets in the help text
	// (audit domain-06 D2); syscall names are too numerous to list.
	validFamilies := syscallFamilyNames()

	registerFilterFlags(fs, cfg)
	tpsAttach, tpsExclude, dims = registerTraceSelectionFlags(fs, validFamilies)
	registerOutputFlags(fs, cfg)
	familySampling, syscallSampling = registerSamplingFlags(fs, validFamilies)
	fields = registerCollapseFlags(fs, cfg)
	return tpsAttach, tpsExclude, fields, familySampling, syscallSampling, dims
}

// syscallFamilyNames lists every syscall family name for the help texts.
func syscallFamilyNames() []string {
	families := types.AllSyscallFamilies()
	names := make([]string, 0, len(families))
	for _, family := range families {
		names = append(names, string(family))
	}
	return names
}

// registerFilterFlags binds the process/comm/path filters and the basic probe
// settings (map size, duration, pprof).
func registerFilterFlags(fs *flag.FlagSet, cfg *Config) {
	fs.IntVar(&cfg.PidFilter, "pid", cfg.PidFilter, "Filter for processes ID (a headless -plain/-flamegraph/-parquet run stops when this process exits)")
	fs.IntVar(&cfg.TidFilter, "tid", cfg.TidFilter, "Filter for thread ID")
	fs.IntVar(&cfg.EventMapSize, "mapSize", cfg.EventMapSize, "BPF event ring buffer size in bytes (non-swappable kernel memory; libbpf rounds it up to a power-of-two multiple of the page size; larger absorbs consumer stalls without dropping events)")
	fs.IntVar(&cfg.Duration, "duration", cfg.Duration, "Probe duration in seconds")

	fs.StringVar(&cfg.CommFilter, "comm", "", "Command to filter for")
	fs.StringVar(&cfg.PathFilter, "path", "", "Path to filter for")
	fs.BoolVar(&cfg.PprofEnable, "pprof", false, "Enable profiling")
}

// registerTraceSelectionFlags binds the tracepoint regex lists and the
// family/kind/syscall attach selectors. The regex lists stay raw strings
// because they are compiled into a Selector after parsing.
func registerTraceSelectionFlags(fs *flag.FlagSet, validFamilies []string) (tpsAttach, tpsExclude *string, dims *tracepoints.DimensionSelectorConfig) {
	validKinds := tracepoints.KnownKinds()
	dimensionCfg := &tracepoints.DimensionSelectorConfig{}

	tpsAttach = fs.String("tps", "", "Comma separated list of regexes for tracepoints to load; they match tracepoint names such as sys_enter_openat, so use -tps openat, not '^openat$' (whitespace around each regex and empty entries are ignored; a regex cannot contain a comma)")
	tpsExclude = fs.String("tpsExclude", "", "Comma separated list of regexes for tracepoints to exclude (whitespace around each regex and empty entries are ignored; a regex cannot contain a comma)")
	fs.StringVar(&dimensionCfg.TraceFamilies, "trace-families", "",
		"Comma separated syscall families to attach; default attaches the FS family only (valid: "+strings.Join(validFamilies, ",")+")")
	fs.StringVar(&dimensionCfg.TraceKinds, "trace-kinds", "",
		"Comma separated tracepoint kinds to attach (valid: "+strings.Join(validKinds, ",")+")")
	fs.StringVar(&dimensionCfg.TraceSyscalls, "trace-syscalls", "",
		"Comma separated syscall names to attach (for example openat,read,nanosleep)")
	fs.StringVar(&dimensionCfg.NoTraceFamilies, "no-trace-families", "",
		"Comma separated syscall families to exclude from attachment (valid: "+strings.Join(validFamilies, ",")+")")
	fs.StringVar(&dimensionCfg.NoTraceKinds, "no-trace-kinds", "",
		"Comma separated tracepoint kinds to exclude from attachment (valid: "+strings.Join(validKinds, ",")+")")
	fs.StringVar(&dimensionCfg.NoTraceSyscalls, "no-trace-syscalls", "",
		"Comma separated syscall names to exclude from attachment")
	return tpsAttach, tpsExclude, dimensionCfg
}

// registerOutputFlags binds the output-mode flags (plain CSV, flamegraph,
// parquet, synthetic flame test modes) and the TUI timing/export settings.
func registerOutputFlags(fs *flag.FlagSet, cfg *Config) {
	fs.BoolVar(&cfg.PlainMode, "plain", false, "Enable plain CSV output mode (disable TUI); control and invisible characters in traced text are escaped (\\x1b, \\u202e) as selected by -escape")
	fs.Var(&cfg.EscapeMode, "escape", "When -plain escapes control and invisible characters in traced text (`mode`): auto (only when stdout is a terminal; a pipe such as | less -R, | grep or | tee gets raw bytes), always, or never")
	fs.BoolVar(&cfg.FlamegraphOutput, "flamegraph", false, "Write aggregated .ior.zst output for trace/integration workflows")
	fs.StringVar(&cfg.ParquetPath, "parquet", cfg.ParquetPath, "Write traced syscall rows directly to a parquet file in headless mode, replacing an existing file at that path (skip the TUI; compatible with -pid; incompatible with -plain, -flamegraph, -testflames, -testliveflames, and other content filters)")
	fs.StringVar(&cfg.OutputName, "name", cfg.OutputName, "Base name (no '/') for .ior.zst trace output files, written to the working directory as <hostname>-<name>-<timestamp>.ior.zst")
	fs.BoolVar(&cfg.TestFlames, "testflames", false, "Run TUI with static synthetic flamegraph data for keyboard-navigation testing")
	fs.BoolVar(&cfg.TestLiveFlames, "testliveflames", false, "Run TUI with continuously-updating synthetic flamegraph data for live keyboard-navigation testing")
	fs.DurationVar(&cfg.LiveInterval, "live-interval", cfg.LiveInterval, "Synthetic live flamegraph refresh interval for -testliveflames")
	fs.DurationVar(&cfg.TUIFastRefreshInterval, "tui-fast-refresh", cfg.TUIFastRefreshInterval,
		"High-frequency refresh interval for TUI flamegraph and stream tabs (0 = fall back to the built-in 200ms flame/stream tick, not to the slower dashboard cadence)")
	fs.BoolVar(&cfg.TUIExportEnable, "tuiExport", cfg.TUIExportEnable, "Enable TUI stream CSV export (e and stream-tab x/X/E shortcuts plus their hints; separate from Parquet recording)")
	fs.DurationVar(&cfg.ResetTimer, "resetTimer", cfg.ResetTimer,
		"Auto-reset interval for aggregate dashboard state (flamegraph trie + stats engine); set to 0 to disable")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "Print version banner and exit")
}

// registerSamplingFlags binds the per-family and per-syscall sampling rate
// lists, which are resolved into cfg after parsing.
func registerSamplingFlags(fs *flag.FlagSet, validFamilies []string) (familySampling, syscallSampling *string) {
	familySampling = fs.String("syscall-sampling-families", "",
		"Per-family sampling rates as name=rate, for example \"Time=100,Misc=0\" (0=aggregate-only, 1=all, N=1-in-N; family rate 0 is promoted to 1 in raw output modes -plain/-flamegraph/-parquet which have no aggregate sink; valid families: "+strings.Join(validFamilies, ",")+")")
	syscallSampling = fs.String("syscall-sampling-syscalls", "",
		"Per-syscall sampling rates as name=rate, for example \"futex=0,clock_gettime=200\" (overrides family rates, which in turn override the built-in aggregate-only defaults of futex* and clock_gettime)")
	return familySampling, syscallSampling
}

// registerCollapseFlags binds the collapse field list (resolved after parsing)
// and the collapse count field.
func registerCollapseFlags(fs *flag.FlagSet, cfg *Config) (fields *string) {
	validFields := collapse.ValidFields()
	validCounts := collapse.ValidCountFields()
	fields = fs.String("fields", "",
		fmt.Sprintf("Comma separated list of fields to collapse, valid are: %v", validFields))
	fs.StringVar(&cfg.CountField, "count", cfg.CountField,
		fmt.Sprintf("Count field to collapse, valid are: %v", validCounts))
	return fields
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
	// A blank or comma-only -fields value falls back to the defaults, like an
	// unset flag; padding around entries ("path, comm") is ignored.
	if cfg.CollapsedFields = csvlist.Split(*fields); len(cfg.CollapsedFields) == 0 {
		cfg.CollapsedFields = collapse.DefaultFields()
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
	cfg.SyscallSamplingRates = syscallRates
	// Built-in defaults stay in their own map (see Config.DefaultSyscallSamplingRates)
	// and are promoted to rate 1 in raw output modes, which have no aggregate
	// sink; explicit -syscall-sampling-syscalls rates are never promoted.
	cfg.DefaultSyscallSamplingRates = resolveDefaultSyscallSamplingRates(cfg.IsRawOutputMode())
	return nil
}

// maxEventMapSize is the largest -mapSize (bytes) accepted: 2 GiB, the
// biggest power of two that fits the uint32 max_entries of a BPF map, so
// libbpf's round-up in bpf_map__set_max_entries can never overflow.
const maxEventMapSize int64 = 1 << 31

// maxDurationSeconds is the largest -duration (in seconds) that still fits in
// a time.Duration (int64 nanoseconds), roughly 292 years. It is typed int64
// so the constant also compiles where int is 32 bits wide.
const maxDurationSeconds int64 = math.MaxInt64 / int64(time.Second)

// validateConfig checks numeric/duration bounds that cannot be enforced by the
// flag package itself and returns a descriptive error on the first violation.
func validateConfig(cfg Config) error {
	// A zero or negative duration would cause the trace context to cancel
	// immediately, capturing no events. Require at least one second. The
	// upper bound matters just as much: setupTraceContext converts the
	// seconds with time.Duration(cfg.Duration)*time.Second, and anything
	// above maxDurationSeconds overflows int64 nanoseconds into a negative
	// (already expired) timeout, so the trace would silently end at once
	// with exit 0.
	if cfg.Duration <= 0 || int64(cfg.Duration) > maxDurationSeconds {
		return fmt.Errorf("invalid duration: %d (must be between 1 and %d seconds)",
			cfg.Duration, maxDurationSeconds)
	}
	// A negative reset timer would imply auto-resets in the past, which is
	// nonsensical. 0 disables, anything positive enables.
	if cfg.ResetTimer < 0 {
		return fmt.Errorf("invalid resetTimer: %s (must be >= 0; 0 disables)", cfg.ResetTimer)
	}
	// A non-positive mapSize would wrap to a huge uint32 when cast in
	// resizeBPFMaps, causing libbpf to fail with a confusing "map too large"
	// error. Reject it here with a clear diagnostic instead. The upper bound
	// is the largest power of two a uint32 holds (the biggest ring buffer
	// libbpf can round up to); anything above would wrap in the same cast.
	if cfg.EventMapSize <= 0 || int64(cfg.EventMapSize) > maxEventMapSize {
		return fmt.Errorf("invalid mapSize: %d (must be between 1 and %d bytes)",
			cfg.EventMapSize, maxEventMapSize)
	}
	// A -pid/-tid of 0 matches only the idle task, and any negative value
	// other than the -1 "no filter" sentinel wraps to a huge uint32 BPF
	// global that no real TGID/TID can ever equal — both produce a silently
	// empty trace, so reject them with a clear startup error.
	if err := validateProcessID("pid", cfg.PidFilter); err != nil {
		return err
	}
	if err := validateProcessID("tid", cfg.TidFilter); err != nil {
		return err
	}
	// A -tps/-tpsExclude/-trace-* selection that matches no traceable syscall
	// attaches nothing and produces an empty trace for the whole -duration,
	// so name it at startup. The runtime guard for headless runs (see
	// attachRequiredTraceProbes) also covers a kernel that lacks the
	// tracepoints; this one additionally protects the TUI, where zero probes
	// is otherwise only a warning, and needs no root or BPF load to fire.
	if err := validateTracepointSelection(cfg.TracepointSelector, tracepoints.List); err != nil {
		return err
	}
	// A -comm/-path pattern longer than the fixed-size kernel event field it
	// is matched against can never be found in anything the tracepoint gates
	// see, so it is another silently empty trace - the same class as the
	// checks above. setupTraceInfra rejects it too, but only after the TUI is
	// already up, where it arrives as TracingErrorMsg and takes over the
	// screen; refusing it here means the user gets the reason on stderr with
	// a non-zero exit, before any terminal is taken over at all.
	return BuildTraceFilter(cfg).ValidateTracepointFields()
}

// validateTracepointSelection fails when sel attaches none of tpNames, the
// tracepoints this build can trace. A selector that has no restrictions at
// all (the zero value of a hand-built Config) attaches everything and passes.
// The message names the flags because the selector itself is a compiled form
// the user never typed. -tps/-tpsExclude regexes match tracepoint names
// (sys_enter_openat), so an anchored syscall name such as "^openat$" matches
// nothing; when it would match the name without its sys_enter_/sys_exit_
// prefix the message says so, because that is the likely typo.
func validateTracepointSelection(sel tracepoints.Selector, tpNames []string) error {
	for _, name := range tpNames {
		if sel.ShouldAttach(name) {
			return nil
		}
	}
	msg := fmt.Sprintf("the -tps/-tpsExclude/-trace-* selection matches none of the %d traceable syscall tracepoints, so the trace would stay empty", len(tpNames))
	if matchesBareSyscallName(sel, tpNames) {
		msg += "; -tps patterns match tracepoint names such as sys_enter_openat, not bare syscall names, so try -tps openat (without ^ and $ anchors)"
	}
	return errors.New(msg)
}

// matchesBareSyscallName reports whether the -tps/-tpsExclude regexes of sel
// would select at least one tracepoint if they were matched against the
// syscall name without its sys_enter_/sys_exit_ prefix. Only the regex lists
// are consulted: the -trace-* family/dimension allowlist is keyed by bare
// names already, so it cannot cause this particular mistake.
func matchesBareSyscallName(sel tracepoints.Selector, tpNames []string) bool {
	if len(sel.Attach) == 0 {
		return false
	}
	bareMatches := func(res []*regexp.Regexp, bare string) bool {
		for _, re := range res {
			if re.MatchString(bare) {
				return true
			}
		}
		return false
	}
	for _, name := range tpNames {
		bare, ok := tracepoints.SyscallNameFromTracepoint(name)
		if ok && bareMatches(sel.Attach, bare) && !bareMatches(sel.Exclude, bare) {
			return true
		}
	}
	return false
}

// fallbackPidMax is used when /proc/sys/kernel/pid_max cannot be read (for
// example in a container without /proc mounted); 4194304 is the maximum
// pid_max on 64-bit Linux.
const fallbackPidMax = 4194304

// pidMaxFn is swapped in tests to pin the validation bound deterministically.
var pidMaxFn = defaultPidMax

func defaultPidMax() int {
	data, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		return fallbackPidMax
	}
	if max, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && max > 0 {
		return max
	}
	return fallbackPidMax
}

// validateProcessID rejects -pid/-tid values outside {-1} ∪ [1, pid_max]:
// -1 means "no filter", and any other value must be a real process/thread ID.
func validateProcessID(name string, value int) error {
	if value == -1 {
		return nil
	}
	if max := pidMaxFn(); value < 1 || value > max {
		return fmt.Errorf("invalid %s: %d (must be -1 for no filter or an ID in [1, %d])", name, value, max)
	}
	return nil
}
