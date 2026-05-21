package tracepoints

import (
	"fmt"
	"sort"
	"strings"

	"ior/internal/types"
)

// DimensionSelectorConfig holds attach-time syscall-dimension selection inputs.
// Each field accepts comma-separated values.
type DimensionSelectorConfig struct {
	TraceFamilies   string
	TraceKinds      string
	TraceSyscalls   string
	NoTraceFamilies string
	NoTraceKinds    string
	NoTraceSyscalls string
}

// ParseSelectorWithDimensions compiles regex-based attach/exclude filters and
// applies attach-time syscall dimension gating.
func ParseSelectorWithDimensions(attach, exclude string, dims DimensionSelectorConfig) (Selector, error) {
	sel, err := ParseSelector(attach, exclude)
	if err != nil {
		return Selector{}, err
	}

	allow, err := buildAllowedSyscalls(dims)
	if err != nil {
		return Selector{}, err
	}
	sel.RestrictSyscalls = true
	sel.Syscalls = allow
	return sel, nil
}

func buildAllowedSyscalls(dims DimensionSelectorConfig) (map[string]struct{}, error) {
	knownSyscalls := allKnownSyscalls()
	knownKinds := allKnownKinds()

	includeFamilies, familyFilterProvided, err := parseFamiliesCSV(dims.TraceFamilies)
	if err != nil {
		return nil, err
	}
	includeKinds, kindFilterProvided, err := parseKindsCSV(dims.TraceKinds, knownKinds)
	if err != nil {
		return nil, err
	}
	includeSyscalls, syscallFilterProvided, err := parseSyscallsCSV(dims.TraceSyscalls, knownSyscalls)
	if err != nil {
		return nil, err
	}

	allow := make(map[string]struct{})
	hasPositive := familyFilterProvided || kindFilterProvided || syscallFilterProvided
	if hasPositive {
		for syscall, family := range syscallFamilies {
			if _, ok := includeFamilies[family]; ok {
				allow[syscall] = struct{}{}
			}
		}
		for syscall, kind := range syscallKinds {
			if _, ok := includeKinds[kind]; ok {
				allow[syscall] = struct{}{}
			}
		}
		for syscall := range includeSyscalls {
			allow[syscall] = struct{}{}
		}
	} else {
		// Backward compatibility default: keep existing file-I/O coverage on and
		// leave newly-expanded non-IO families disabled unless explicitly opted in.
		for syscall, family := range syscallFamilies {
			if family == string(types.FamilyFS) {
				allow[syscall] = struct{}{}
			}
		}
	}

	excludeFamilies, _, err := parseFamiliesCSV(dims.NoTraceFamilies)
	if err != nil {
		return nil, err
	}
	excludeKinds, _, err := parseKindsCSV(dims.NoTraceKinds, knownKinds)
	if err != nil {
		return nil, err
	}
	excludeSyscalls, _, err := parseSyscallsCSV(dims.NoTraceSyscalls, knownSyscalls)
	if err != nil {
		return nil, err
	}

	for syscall := range allow {
		if _, ok := excludeSyscalls[syscall]; ok {
			delete(allow, syscall)
			continue
		}
		if family, ok := syscallFamilies[syscall]; ok {
			if _, excluded := excludeFamilies[family]; excluded {
				delete(allow, syscall)
				continue
			}
		}
		if kind, ok := syscallKinds[syscall]; ok {
			if _, excluded := excludeKinds[kind]; excluded {
				delete(allow, syscall)
			}
		}
	}

	return allow, nil
}

func parseFamiliesCSV(raw string) (map[string]struct{}, bool, error) {
	values, provided := splitCSV(raw)
	if !provided {
		return map[string]struct{}{}, false, nil
	}
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		family, ok := types.ParseSyscallFamily(value)
		if !ok {
			return nil, false, fmt.Errorf("invalid syscall family in trace selector: %q", value)
		}
		out[string(family)] = struct{}{}
	}
	return out, true, nil
}

func parseKindsCSV(raw string, knownKinds map[string]struct{}) (map[string]struct{}, bool, error) {
	values, provided := splitCSV(raw)
	if !provided {
		return map[string]struct{}{}, false, nil
	}
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		kind := normalizeKind(value)
		if _, ok := knownKinds[kind]; !ok {
			return nil, false, fmt.Errorf("invalid syscall kind in trace selector: %q", value)
		}
		out[kind] = struct{}{}
	}
	return out, true, nil
}

func parseSyscallsCSV(raw string, knownSyscalls map[string]struct{}) (map[string]struct{}, bool, error) {
	values, provided := splitCSV(raw)
	if !provided {
		return map[string]struct{}{}, false, nil
	}
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		syscall := strings.ToLower(strings.TrimSpace(value))
		if _, ok := knownSyscalls[syscall]; !ok {
			return nil, false, fmt.Errorf("invalid syscall in trace selector: %q", value)
		}
		out[syscall] = struct{}{}
	}
	return out, true, nil
}

func splitCSV(raw string) ([]string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		values = append(values, part)
	}
	if len(values) == 0 {
		return nil, false
	}
	return values, true
}

func normalizeKind(raw string) string {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	normalized = strings.ReplaceAll(normalized, "_", "-")
	return normalized
}

func allKnownSyscalls() map[string]struct{} {
	out := make(map[string]struct{}, len(syscallFamilies))
	for syscall := range syscallFamilies {
		out[syscall] = struct{}{}
	}
	return out
}

func allKnownKinds() map[string]struct{} {
	out := make(map[string]struct{})
	for _, kind := range syscallKinds {
		if kind == "" {
			continue
		}
		out[kind] = struct{}{}
	}
	return out
}

// KnownKinds returns the sorted, normalized attach-time kind names accepted by
// -trace-kinds and -no-trace-kinds.
func KnownKinds() []string {
	kindSet := allKnownKinds()
	kinds := make([]string, 0, len(kindSet))
	for kind := range kindSet {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
}
