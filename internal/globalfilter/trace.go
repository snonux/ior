package globalfilter

import (
	"fmt"
	"strings"

	"ior/internal/event"
	"ior/internal/types"
)

// ValidateTracepointFields checks string filters that are applied against
// fixed-size kernel event fields before pair reconstruction.
func (f Filter) ValidateTracepointFields() error {
	if err := validateTraceStringFilter("comm", f.Comm, types.MAX_PROGNAME_LENGTH); err != nil {
		return err
	}
	if err := validateTraceStringFilter("path", f.File, types.MAX_FILENAME_LENGTH); err != nil {
		return err
	}
	return nil
}

// UsesCommFilter reports whether the filter needs command-name matching.
func (f Filter) UsesCommFilter() bool {
	return hasStringPattern(f.Comm)
}

// MatchPair reports whether a completed syscall pair satisfies the filter.
func (f Filter) MatchPair(pair *event.Pair) bool {
	if pair == nil {
		return false
	}
	return f.Matches(pairCandidate{pair: pair})
}

// MatchOpenEvent applies the subset of the filter that can be evaluated on raw
// open events before exit pairing.
func (f Filter) MatchOpenEvent(ev *types.OpenEvent) bool {
	if ev == nil {
		return false
	}
	if !matchString(f.Comm, types.StringValue(ev.Comm[:])) {
		return false
	}
	return matchString(f.File, types.StringValue(ev.Filename[:]))
}

// MatchPathEvent applies the path-related subset of the filter to raw path events.
func (f Filter) MatchPathEvent(ev *types.PathEvent) bool {
	if ev == nil {
		return false
	}
	return matchString(f.File, types.StringValue(ev.Pathname[:]))
}

// MatchNameEvent applies the path-related subset of the filter to raw rename-like events.
func (f Filter) MatchNameEvent(ev *types.NameEvent) bool {
	if ev == nil {
		return false
	}
	if !hasStringPattern(f.File) {
		return true
	}
	return matchString(f.File, types.StringValue(ev.Oldname[:])) ||
		matchString(f.File, types.StringValue(ev.Newname[:]))
}

func hasStringPattern(filter *StringFilter) bool {
	return filter != nil && strings.TrimSpace(filter.Pattern) != ""
}

func validateTraceStringFilter(name string, filter *StringFilter, maxLen int) error {
	if !hasStringPattern(filter) {
		return nil
	}
	pattern := strings.TrimSpace(filter.Pattern)
	if len(pattern) > maxLen {
		return fmt.Errorf("%s filter max size is %d (got %d)", name, maxLen, len(pattern))
	}
	return nil
}
