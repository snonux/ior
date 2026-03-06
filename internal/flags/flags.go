package flags

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	current  atomic.Pointer[Flags]
	once     sync.Once
	parseErr error
)

func init() {
	defaults := NewFlags()
	current.Store(&defaults)
}

var (
	validCollapsedFields = []string{
		"path",
		"comm",
		"tracepoint",
		"pid",
		"tid",
		"flags",
	}

	validCollapsedCounts = []string{
		"count",
		"duration",
		"durationToPrev",
		"bytes",
	}
)

type Flags struct {
	PidFilter    int
	TidFilter    int
	EventMapSize int
	CommFilter   string
	PathFilter   string
	PprofEnable  bool
	Duration     int

	// Tracepints flags
	TracepointsToAttach  []*regexp.Regexp
	TracepointsToExclude []*regexp.Regexp

	// Output/runtime flags
	PlainMode       bool
	TestFlames      bool
	TestLiveFlames  bool
	LiveInterval    time.Duration
	TUIExportEnable bool
	CollapsedFields []string
	CountField      string
}

// NewFlags returns a configuration instance initialized with project defaults.
func NewFlags() Flags {
	return Flags{
		PidFilter:       -1,
		TidFilter:       -1,
		EventMapSize:    4096 * 16,
		Duration:        900,
		LiveInterval:    200 * time.Millisecond,
		TUIExportEnable: true,
		CollapsedFields: []string{"comm", "tracepoint", "path"},
		CountField:      "count",
	}
}

// GetPidFilter returns the active process filter.
func (f Flags) GetPidFilter() int {
	return f.PidFilter
}

// GetTidFilter returns the active thread filter.
func (f Flags) GetTidFilter() int {
	return f.TidFilter
}

// GetTUIExportEnable reports whether TUI CSV export is enabled.
func (f Flags) GetTUIExportEnable() bool {
	return f.TUIExportEnable
}

func (f Flags) clone() Flags {
	out := f
	out.TracepointsToAttach = slices.Clone(f.TracepointsToAttach)
	out.TracepointsToExclude = slices.Clone(f.TracepointsToExclude)
	out.CollapsedFields = slices.Clone(f.CollapsedFields)
	return out
}

func Get() Flags {
	cfg := current.Load()
	if cfg == nil {
		return NewFlags()
	}
	return cfg.clone()
}

func setCurrent(cfg Flags) {
	snapshot := cfg.clone()
	current.Store(&snapshot)
}

func updateCurrent(update func(*Flags)) {
	for {
		old := current.Load()
		next := NewFlags()
		if old != nil {
			next = old.clone()
		}
		update(&next)
		snapshot := next.clone()
		if current.CompareAndSwap(old, &snapshot) {
			return
		}
	}
}

// SetPidFilter updates the active PID filter used for subsequent tracing runs.
func SetPidFilter(pid int) {
	updateCurrent(func(cfg *Flags) {
		cfg.PidFilter = pid
	})
}

// SetTidFilter updates the active TID filter used for subsequent tracing runs.
func SetTidFilter(tid int) {
	updateCurrent(func(cfg *Flags) {
		cfg.TidFilter = tid
	})
}

// SetTUIExportEnable toggles TUI snapshot export file writing.
func SetTUIExportEnable(enabled bool) {
	updateCurrent(func(cfg *Flags) {
		cfg.TUIExportEnable = enabled
	})
}

func Parse() error {
	once.Do(func() {
		parseErr = parse()
	})
	return parseErr
}

func parse() error {
	cfg := NewFlags()

	flag.IntVar(&cfg.PidFilter, "pid", cfg.PidFilter, "Filter for processes ID")
	flag.IntVar(&cfg.TidFilter, "tid", cfg.TidFilter, "Filter for thread ID")
	flag.IntVar(&cfg.EventMapSize, "mapSize", cfg.EventMapSize, "BPF FD event ring buffer map size")
	flag.IntVar(&cfg.Duration, "duration", cfg.Duration, "Probe duration in seconds")

	flag.StringVar(&cfg.CommFilter, "comm", "", "Command to filter for")
	flag.StringVar(&cfg.PathFilter, "path", "", "Path to filter for")

	flag.BoolVar(&cfg.PprofEnable, "pprof", false, "Enable profiling")

	tracepointsToAttach := flag.String("tps", "", "Comma separated list regexes for tracepoints to load")
	tracepointsToExclude := flag.String("tpsExclude", "", "Comma separated list regexes for tracepoints to exclude")

	flag.BoolVar(&cfg.PlainMode, "plain", false, "Enable plain CSV output mode (disable TUI)")
	flag.BoolVar(&cfg.TestFlames, "testflames", false, "Run TUI with static synthetic flamegraph data for keyboard-navigation testing")
	flag.BoolVar(&cfg.TestLiveFlames, "testliveflames", false, "Run TUI with continuously-updating synthetic flamegraph data for live keyboard-navigation testing")
	flag.DurationVar(&cfg.LiveInterval, "live-interval", cfg.LiveInterval, "Synthetic live flamegraph refresh interval for --testliveflames")
	flag.BoolVar(&cfg.TUIExportEnable, "tuiExport", cfg.TUIExportEnable, "Enable writing TUI snapshot export files")
	fields := flag.String("fields", "",
		fmt.Sprintf("Comma separated list of fields to collapse, valid are: %v", validCollapsedFields))
	flag.StringVar(&cfg.CountField, "count", cfg.CountField,
		fmt.Sprintf("Count field to collapse, valid are: %v", validCollapsedCounts))
	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		return err
	}

	var err error
	cfg.TracepointsToAttach, err = extractTracepointFlags(*tracepointsToAttach)
	if err != nil {
		return err
	}
	cfg.TracepointsToExclude, err = extractTracepointFlags(*tracepointsToExclude)
	if err != nil {
		return err
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
		if !slices.Contains(validCollapsedFields, field) {
			return fmt.Errorf("invalid field for collapse: %s", field)
		}
	}

	if !slices.Contains(validCollapsedCounts, cfg.CountField) {
		return fmt.Errorf("invalid count field: %s", cfg.CountField)
	}

	setCurrent(cfg)
	return nil
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

func (flags Flags) ShouldIAttachTracepoint(tracepointName string) bool {
	for _, re := range flags.TracepointsToExclude {
		if re.MatchString(tracepointName) {
			return false
		}
	}
	if len(flags.TracepointsToAttach) == 0 {
		return true
	}
	for _, re := range flags.TracepointsToAttach {
		if re.MatchString(tracepointName) {
			return true
		}
	}

	return false
}
