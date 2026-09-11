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
//
// The file dimension is either-name-aware by construction: a rename-like
// pair carries its source path in Pair.Oldname, and Matches accepts it as a
// second legitimate value of the file dimension (see Candidate.OldFileValue).
// That is what makes this checkpoint agree with the raw enter filter these
// pairs already passed - MatchNameEvent matches oldname OR newname, while
// Pair.File.Name() reports only the newname - so a `-path <oldname>` filter
// keeps the rows it legitimately selected instead of dropping them at the
// first full checkpoint. There is no separate "either-name" variant of this
// method any more: the widening used to be re-chosen per call site
// (MatchPair vs MatchPairEitherName), and stages picking the narrow one is
// exactly how rows counted in one stage went missing in another.
func (f Filter) MatchPair(pair *event.Pair) bool {
	if pair == nil {
		return false
	}
	return f.Matches(pairCandidate{pair: pair})
}

// MatchOpenEvent applies the subset of the filter that can be evaluated on raw
// open events before exit pairing.
func (f Filter) MatchOpenEvent(ev *types.OpenEvent) bool {
	if !f.MatchOpenEventComm(ev) {
		return false
	}
	return matchString(f.File, types.StringValue(ev.Filename[:]))
}

// MatchOpenEventComm is MatchOpenEvent without the file dimension, for the one
// case where the file dimension cannot yet be answered: an open whose sys_enter
// filename read faulted arrives with an empty payload name and only recovers it
// at sys_exit. See matchRawOpenEvent (internal/eventloop_kinds.go) - the file
// dimension is deferred to the exit checkpoint there, never dropped.
func (f Filter) MatchOpenEventComm(ev *types.OpenEvent) bool {
	if ev == nil {
		return false
	}
	return matchString(f.Comm, types.StringValue(ev.Comm[:]))
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
	// Measure what the matcher actually compares, not what the user typed:
	// trimAnchors drops the `^`/`$` syntax so an anchored pattern is judged on
	// the text that has to fit the kernel field. See trimAnchors.
	pattern, _, _ := trimAnchors(strings.TrimSpace(filter.Pattern))
	if len(pattern) > maxLen {
		return fmt.Errorf("%s filter max size is %d (got %d)", name, maxLen, len(pattern))
	}
	return nil
}
