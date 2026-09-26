package tracepoints

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// Selector holds compiled include and exclude regexes for choosing which
// tracepoints to attach at BPF probe registration time. It is the single
// authoritative home for tracepoint-selection logic, keeping that concern
// out of the top-level flags.Config.
type Selector struct {
	// Attach is the list of compiled regexes that select which tracepoints to
	// load. An empty list means "attach all non-excluded tracepoints".
	Attach []*regexp.Regexp
	// Exclude is the list of compiled regexes that suppress specific
	// tracepoints even when they match the Attach list.
	Exclude []*regexp.Regexp
	// Syscalls optionally restricts attach to an explicit syscall allowlist.
	// Keys are bare syscall names (for example "openat", not "sys_enter_openat").
	// When RestrictSyscalls is true, only entries in this map are attached.
	Syscalls map[string]struct{}
	// RestrictSyscalls gates whether Syscalls should be enforced.
	RestrictSyscalls bool
}

// ParseSelector parses the comma-separated regex strings for the -tps and
// -tpsExclude CLI flags into a Selector. Each entry is whitespace-trimmed and
// empty entries are ignored, so "read, write," selects exactly "read" and
// "write". A string with no non-blank entries leaves the corresponding list
// nil (i.e. "match all" for Attach, "exclude nothing" for Exclude). An error
// is returned if any regex fails to compile.
func ParseSelector(attach, exclude string) (Selector, error) {
	attachRegexes, err := parseRegexList(attach)
	if err != nil {
		return Selector{}, err
	}
	excludeRegexes, err := parseRegexList(exclude)
	if err != nil {
		return Selector{}, err
	}
	return Selector{Attach: attachRegexes, Exclude: excludeRegexes}, nil
}

// parseRegexList splits a comma-separated string of regex patterns and
// compiles each one. Entries are split with splitCSV, the same helper the
// -trace-* dimension flags use: surrounding whitespace is trimmed and blank
// entries are dropped. That matters because an empty regex matches every
// name, so a stray trailing comma ("read,") would otherwise attach — or with
// -tpsExclude, suppress — every tracepoint, and a space after a comma
// ("read, write") would compile " write", which never matches. Returns nil
// (not an error) when no non-blank entry remains.
func parseRegexList(patterns string) ([]*regexp.Regexp, error) {
	entries, provided := splitCSV(patterns)
	if !provided {
		return nil, nil
	}
	regexes := make([]*regexp.Regexp, 0, len(entries))
	for _, pattern := range entries {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("unable to compile regex %q: %w", pattern, err)
		}
		regexes = append(regexes, re)
	}
	return regexes, nil
}

// ShouldAttach reports whether the given tracepoint name passes the
// selector's attach/exclude regex filters. Exclusions are checked first; if
// the name matches any exclude pattern it is rejected regardless of the attach
// list. When the attach list is empty, all non-excluded tracepoints are
// accepted.
func (s Selector) ShouldAttach(tracepointName string) bool {
	for _, re := range s.Exclude {
		if re.MatchString(tracepointName) {
			return false
		}
	}
	if len(s.Attach) == 0 {
		if !s.RestrictSyscalls {
			return true
		}
		syscall, ok := SyscallNameFromTracepoint(tracepointName)
		if !ok {
			return false
		}
		_, allowed := s.Syscalls[syscall]
		return allowed
	}
	for _, re := range s.Attach {
		if re.MatchString(tracepointName) {
			if !s.RestrictSyscalls {
				return true
			}
			syscall, ok := SyscallNameFromTracepoint(tracepointName)
			if !ok {
				return false
			}
			_, allowed := s.Syscalls[syscall]
			return allowed
		}
	}
	return false
}

// Clone returns a deep copy of the Selector so that modifications to the
// copy's slices do not affect the original.
func (s Selector) Clone() Selector {
	return Selector{
		Attach:           slices.Clone(s.Attach),
		Exclude:          slices.Clone(s.Exclude),
		Syscalls:         maps.Clone(s.Syscalls),
		RestrictSyscalls: s.RestrictSyscalls,
	}
}

// SyscallNameFromTracepoint returns the bare syscall name for a tracepoint
// (for example "openat" from "sys_enter_openat").
func SyscallNameFromTracepoint(tracepointName string) (string, bool) {
	switch {
	case strings.HasPrefix(tracepointName, "sys_enter_"):
		return strings.TrimPrefix(tracepointName, "sys_enter_"), true
	case strings.HasPrefix(tracepointName, "sys_exit_"):
		return strings.TrimPrefix(tracepointName, "sys_exit_"), true
	default:
		return "", false
	}
}
