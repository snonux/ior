package flags

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	bpf "github.com/aquasecurity/libbpfgo"
)

type Flags struct {
	PidFilter            int
	TidFilter            int
	EventMapSize         int
	CommFilter           string
	PathFilter           string
	PprofEnable          bool
	FlamegraphEnable     bool
	Duration             int
	TracepointsToAttach  []*regexp.Regexp
	TracepointsToExclude []*regexp.Regexp
}

func New() (flags Flags) {
	flag.IntVar(&flags.PidFilter, "pid", -1, "Filter for processes ID")
	flag.IntVar(&flags.TidFilter, "tid", -1, "Filter for thread ID")
	flag.IntVar(&flags.EventMapSize, "mapSize", 4096*16, "BPF FD event ring buffer map size")
	flag.IntVar(&flags.Duration, "duration", 60, "Probe duration in seconds")

	flag.StringVar(&flags.CommFilter, "comm", "", "Command to filter for")
	flag.StringVar(&flags.PathFilter, "path", "", "Path to filter for")

	flag.BoolVar(&flags.PprofEnable, "pprof", false, "Enable profiling")
	flag.BoolVar(&flags.FlamegraphEnable, "flamegraph", false, "Enable flamegraph builder")

	tracepointsToAttach := flag.String("tps", "", "Comma separated list regexes for tracepoints to load")
	tracepointsToExclude := flag.String("tpsExclude", "", "Comma separated list regexes for tracepoints to exclude")
	flag.Parse()

	flags.TracepointsToAttach = extractTracepointFlags(tracepointsToAttach)
	flags.TracepointsToExclude = extractTracepointFlags(tracepointsToExclude)

	return flags
}

func extractTracepointFlags(tracepoints *string) (regexes []*regexp.Regexp) {
	for _, name := range strings.Split(*tracepoints, ",") {
		re, err := regexp.Compile(name)
		if err != nil {
			fmt.Println("Unable to compile regex", name, ": ", err)
			os.Exit(2)
		}
		regexes = append(regexes, re)
	}
	return regexes
}

func (flags Flags) AttachTracepoint(tracepointName string) bool {
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
