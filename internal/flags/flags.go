package flags

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"

	bpf "github.com/aquasecurity/libbpfgo"
)

var singleton Flags
var once sync.Once

var validCollapsedFields = []string{
	"path",
	"comm",
	"tracepoint",
	"pid",
	"tid",
	"count",
	"duration",
	"durationToPrev",
	"bytes",
}

func Get() Flags {
	return singleton
}

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
	FlamegraphEnable bool
	FlamegraphName   string

	// To convert ior data into collapsed format
	IorDataFile     string
	CollapsedFields []string
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

	flag.BoolVar(&singleton.FlamegraphEnable, "flamegraph", false, "Enable flamegraph builder")
	flag.StringVar(&singleton.FlamegraphName, "name", "foo", "Name of the flamegraph data output")

	flag.StringVar(&singleton.IorDataFile, "ior", "", "IOR data file to convert into collapsed format")
	fields := flag.String("fields", "",
		fmt.Sprintf("Comma separated list of fields to collapse, valid are: %v", validCollapsedFields))
	flag.Parse()

	singleton.TracepointsToAttach = extractTracepointFlags(*tracepointsToAttach)
	singleton.TracepointsToExclude = extractTracepointFlags(*tracepointsToExclude)

	if *fields == "" {
		singleton.CollapsedFields = []string{"path", "tracepoint", "count"}
	} else {
		singleton.CollapsedFields = strings.Split(*fields, ",")
	}

	for _, field := range singleton.CollapsedFields {
		if !slices.Contains(validCollapsedFields, field) {
			fmt.Println("Invalid field for collapse:", field)
			os.Exit(2)
		}
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
			fmt.Println("Not attaching", tracepointName, "as excluded")
			return false
		}
	}
	if len(flags.TracepointsToAttach) == 0 {
		fmt.Println("Attaching", tracepointName, "as none are explicitly incluced")
		return true
	}
	for _, re := range flags.TracepointsToAttach {
		if re.MatchString(tracepointName) {
			fmt.Println("Attaching", tracepointName, "as included")
			return true
		}
	}

	fmt.Println("Not attaching", tracepointName, "as not includedd")
	return false
}

func (flags Flags) SetBPF(bpfModule *bpf.Module) error {
	// Ignore `ior` process itself from the filter
	if err := bpfModule.InitGlobalVariable("IOR_PID_FILTER", uint32(os.Getpid())); err != nil {
		return fmt.Errorf("unable set IOR_PID_FILTER: %w", err)
	}

	fmt.Println("Setting PID_FILTER to", flags.PidFilter)
	if err := bpfModule.InitGlobalVariable("PID_FILTER", uint32(flags.PidFilter)); err != nil {
		return fmt.Errorf("unable to set up PID_FILTER global variable: %w", err)
	}

	fmt.Println("Setting TID_FILTER to", flags.TidFilter)
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
