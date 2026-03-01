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

	bpf "github.com/aquasecurity/libbpfgo"
)

var (
	singleton = Flags{
		TUIExportEnable: true,
	}
	once            sync.Once
	parseErr        error
	pidFilter       atomic.Int64
	tidFilter       atomic.Int64
	tuiExportEnable atomic.Bool
)

func init() {
	pidFilter.Store(-1)
	tidFilter.Store(-1)
	tuiExportEnable.Store(true)
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

	// Flamegraph flags
	PlainMode        bool
	FlamegraphEnable bool
	LiveFlamegraph   bool
	LiveInterval     time.Duration
	FlamegraphName   string
	TUIExportEnable  bool

	// To convert ior data into native SVG format
	IorDataFile     string
	CollapsedFields []string
	CountField      string
}

func Get() Flags {
	out := singleton
	out.PidFilter = int(pidFilter.Load())
	out.TidFilter = int(tidFilter.Load())
	out.TUIExportEnable = tuiExportEnable.Load()
	return out
}

// SetPidFilter updates the active PID filter used for subsequent tracing runs.
func SetPidFilter(pid int) {
	pidFilter.Store(int64(pid))
}

// SetTidFilter updates the active TID filter used for subsequent tracing runs.
func SetTidFilter(tid int) {
	tidFilter.Store(int64(tid))
}

// SetTUIExportEnable toggles TUI snapshot export file writing.
func SetTUIExportEnable(enabled bool) {
	tuiExportEnable.Store(enabled)
}

func Parse() error {
	once.Do(func() {
		parseErr = parse()
	})
	return parseErr
}

func parse() error {
	flag.IntVar(&singleton.PidFilter, "pid", -1, "Filter for processes ID")
	flag.IntVar(&singleton.TidFilter, "tid", -1, "Filter for thread ID")
	flag.IntVar(&singleton.EventMapSize, "mapSize", 4096*16, "BPF FD event ring buffer map size")
	flag.IntVar(&singleton.Duration, "duration", 60, "Probe duration in seconds")

	flag.StringVar(&singleton.CommFilter, "comm", "", "Command to filter for")
	flag.StringVar(&singleton.PathFilter, "path", "", "Path to filter for")

	flag.BoolVar(&singleton.PprofEnable, "pprof", false, "Enable profiling")

	tracepointsToAttach := flag.String("tps", "", "Comma separated list regexes for tracepoints to load")
	tracepointsToExclude := flag.String("tpsExclude", "", "Comma separated list regexes for tracepoints to exclude")

	flag.BoolVar(&singleton.PlainMode, "plain", false, "Enable plain CSV output mode (disable TUI)")
	flag.BoolVar(&singleton.FlamegraphEnable, "flamegraph", false, "Enable flamegraph builder")
	flag.BoolVar(&singleton.LiveFlamegraph, "live", false, "Enable live flamegraph mode")
	flag.DurationVar(&singleton.LiveInterval, "live-interval", 200*time.Millisecond, "Live flamegraph refresh interval")
	flag.StringVar(&singleton.FlamegraphName, "name", "default", "Name of the flamegraph, used to generate the SVG file")
	flag.BoolVar(&singleton.TUIExportEnable, "tuiExport", true, "Enable writing TUI snapshot export files")

	flag.StringVar(&singleton.IorDataFile, "ior", "", "IOR data file to convert into native SVG flamegraph")
	fields := flag.String("fields", "",
		fmt.Sprintf("Comma separated list of fields to collapse, valid are: %v", validCollapsedFields))
	flag.StringVar(&singleton.CountField, "count", "count",
		fmt.Sprintf("Count field to collapse, valid are: %v", validCollapsedCounts))
	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		return err
	}
	pidFilter.Store(int64(singleton.PidFilter))
	tidFilter.Store(int64(singleton.TidFilter))
	tuiExportEnable.Store(singleton.TUIExportEnable)

	var err error
	singleton.TracepointsToAttach, err = extractTracepointFlags(*tracepointsToAttach)
	if err != nil {
		return err
	}
	singleton.TracepointsToExclude, err = extractTracepointFlags(*tracepointsToExclude)
	if err != nil {
		return err
	}

	// Keep this list empty by default.
	// As of February 23, 2026, open_by_handle_at and name_to_handle_at were
	// re-evaluated on newer kernels and do not require CO-RE-based exclusions.
	// If future kernels regress, add targeted exclusions here.

	if *fields == "" {
		singleton.CollapsedFields = []string{"comm", "path", "tracepoint"}
	} else {
		singleton.CollapsedFields = strings.Split(*fields, ",")
	}

	for _, field := range singleton.CollapsedFields {
		if !slices.Contains(validCollapsedFields, field) {
			return fmt.Errorf("invalid field for collapse: %s", field)
		}
	}

	if !slices.Contains(validCollapsedCounts, singleton.CountField) {
		return fmt.Errorf("invalid count field: %s", singleton.CountField)
	}

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

func (flags Flags) SetBPF(bpfModule *bpf.Module) error {
	// Ignore `ior` process itself from the filter
	if err := bpfModule.InitGlobalVariable("IOR_PID_FILTER", uint32(os.Getpid())); err != nil {
		return fmt.Errorf("unable set IOR_PID_FILTER: %w", err)
	}

	if err := bpfModule.InitGlobalVariable("PID_FILTER", uint32(flags.PidFilter)); err != nil {
		return fmt.Errorf("unable to set up PID_FILTER global variable: %w", err)
	}

	if err := bpfModule.InitGlobalVariable("TID_FILTER", uint32(flags.TidFilter)); err != nil {
		return fmt.Errorf("unable to set up TID_FILTER global variable: %w", err)
	}

	return nil
}

func (flags Flags) ResizeBPFMaps(bpfModule *bpf.Module) error {
	if err := resizeBPFMap(bpfModule, "event_map", uint32(flags.EventMapSize)); err != nil {
		return fmt.Errorf("event_map: %w", err)
	}
	return nil
}

func resizeBPFMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap(name)
	if err != nil {
		return err
	}

	if err = m.SetMaxEntries(size); err != nil {
		return err
	}

	if actual := m.MaxEntries(); actual != size {
		return fmt.Errorf("map resize to %d failed, expected %v, actual %v", size, size, actual)
	}

	return nil
}
