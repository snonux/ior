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

	bpf "github.com/aquasecurity/libbpfgo"
)

var (
	singleton = Flags{
		TUIExportEnable: true,
	}
	once      sync.Once
	pidFilter atomic.Int64
)

const flamegraphToolDefault = "$HOME/git/FlameGraph/flamegraph.pl"

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
	FlamegraphName   string
	TUIExportEnable  bool

	// To convert ior data into collapsed format
	IorDataFile     string
	CollapsedFields []string
	CountField      string

	// To generate the Flamegraph SVGs
	FlamegraphTool string
}

func Get() Flags {
	out := singleton
	out.PidFilter = int(pidFilter.Load())
	return out
}

// SetPidFilter updates the active PID filter used for subsequent tracing runs.
func SetPidFilter(pid int) {
	pidFilter.Store(int64(pid))
}

// SetTUIExportEnable toggles TUI snapshot export file writing.
func SetTUIExportEnable(enabled bool) {
	singleton.TUIExportEnable = enabled
}

func Parse() {
	once.Do(func() {
		parse()
	})
}

func parse() {
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
	flag.StringVar(&singleton.FlamegraphName, "name", "default", "Name of the flamegraph, used to generate the SVG file")
	flag.BoolVar(&singleton.TUIExportEnable, "tuiExport", true, "Enable writing TUI snapshot export files")

	flag.StringVar(&singleton.IorDataFile, "ior", "", "IOR data file to convert into collapsed format")
	fields := flag.String("fields", "",
		fmt.Sprintf("Comma separated list of fields to collapse, valid are: %v", validCollapsedFields))
	flag.StringVar(&singleton.CountField, "count", "count",
		fmt.Sprintf("Count field to collaps, valid are: %v", validCollapsedCounts))

	// https://github.com/brendangregg/FlameGraph
	flag.StringVar(&singleton.FlamegraphTool, "flamegraphTool",
		"", "Path to the flamegraph tool (e.g. flamegraph.pl or inferno-flamegraph)")
	flag.Parse()
	pidFilter.Store(int64(singleton.PidFilter))

	if singleton.FlamegraphTool == "" {
		singleton.FlamegraphTool = flamegraphToolDefault
	}

	singleton.TracepointsToAttach = extractTracepointFlags(*tracepointsToAttach)
	singleton.TracepointsToExclude = extractTracepointFlags(*tracepointsToExclude)

	// Keep this list empty by default.
	// As of February 23, 2026, open_by_handle_at and name_to_handle_at were
	// re-evaluated on newer kernels and do not require CO-RE-based exclusions.
	// If future kernels regress, add targeted exclusions here.

	if *fields == "" {
		singleton.CollapsedFields = []string{"pid", "path", "tracepoint"}
	} else {
		singleton.CollapsedFields = strings.Split(*fields, ",")
	}

	for _, field := range singleton.CollapsedFields {
		if !slices.Contains(validCollapsedFields, field) {
			fmt.Println("Invalid field for collapse:", field)
			os.Exit(2)
		}
	}

	if !slices.Contains(validCollapsedCounts, singleton.CountField) {
		fmt.Println("Invalid count field:", singleton.CountField)
		os.Exit(2)
	}
}

func extractTracepointFlags(tracepoints string) (regexes []*regexp.Regexp) {
	if len(tracepoints) == 0 {
		return regexes
	}
	for _, name := range strings.Split(tracepoints, ",") {
		re, err := regexp.Compile(name)
		if err != nil {
			fmt.Println("Unable to compile regex", name, ": ", err)
			os.Exit(2)
		}
		regexes = append(regexes, re)
	}
	return regexes
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
