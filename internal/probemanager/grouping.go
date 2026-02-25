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
	if strings.HasPrefix(name, sysEnterPrefix) {
		base = strings.TrimPrefix(name, sysEnterPrefix)
		if base == "" {
			return "", false, false
		}
		return base, true, true
	}
	if strings.HasPrefix(name, sysExitPrefix) {
		base = strings.TrimPrefix(name, sysExitPrefix)
		if base == "" {
			return "", false, false
		}
		return base, false, true
	}
	return "", false, false
}
