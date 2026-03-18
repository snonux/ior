package probemanager

import "strings"

const (
	sysEnterPrefix = "sys_enter_"
	sysExitPrefix  = "sys_exit_"
)

// TracepointPair holds enter/exit tracepoint names for one syscall.
type TracepointPair struct {
	Enter string
	Exit  string
}

// GroupTracepoints groups syscall tracepoint names by base syscall name.
// Input names must be in sys_enter_<name> / sys_exit_<name> format.
func GroupTracepoints(names []string) map[string]TracepointPair {
	out := make(map[string]TracepointPair, len(names)/2)
	for _, name := range names {
		base, isEnter, ok := parseSyscallTracepoint(name)
		if !ok {
			continue
		}

		pair := out[base]
		if isEnter {
			pair.Enter = name
		} else {
			pair.Exit = name
		}
		out[base] = pair
	}
	return out
}

func parseSyscallTracepoint(name string) (base string, isEnter bool, ok bool) {
	if after, found := strings.CutPrefix(name, sysEnterPrefix); found {
		if after == "" {
			return "", false, false
		}
		return after, true, true
	}
	if after, found := strings.CutPrefix(name, sysExitPrefix); found {
		if after == "" {
			return "", false, false
		}
		return after, false, true
	}
	return "", false, false
}
