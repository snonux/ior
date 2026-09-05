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

// MatchPairEitherName is MatchPair for the rename-like (name-carrying) kinds:
// every dimension is applied exactly as MatchPair applies it, except that the
// file dimension is satisfied when *either* the new path (Pair.File.Name()) or
// the captured source path (Pair.Oldname) matches.
//
// That asymmetry is not a licence to be lax, it is what makes the pair filter
// agree with the raw enter filter these kinds are already subjected to:
// MatchNameEvent matches oldname OR newname, while oldnameNewnameFile.Name()
// reports only the newname. A plain MatchPair here would therefore drop every
// row a `-path <oldname>` filter legitimately selected — the reason the name
// kinds used to skip the pair filter altogether and, with it, every numeric and
// metadata dimension. Widening only the file dimension closes that gap without
// re-introducing the false negatives.
//
// The second evaluation is reached only when the first one failed and a file
// pattern is actually set, so the common paths cost the same as MatchPair.
func (f Filter) MatchPairEitherName(pair *event.Pair) bool {
	if pair == nil {
		return false
	}
	candidate := pairCandidate{pair: pair}
	if f.Matches(candidate) {
		return true
	}
	if !hasStringPattern(f.File) || pair.Oldname == "" {
		return false
	}
	return f.Matches(oldnameCandidate{pairCandidate: candidate})
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
	pattern := strings.TrimSpace(filter.Pattern)
	if len(pattern) > maxLen {
		return fmt.Errorf("%s filter max size is %d (got %d)", name, maxLen, len(pattern))
	}
	return nil
}

// eitherNameCandidate reports oldName as the file dimension of an arbitrary
// candidate, leaving every other dimension to the wrapped value.
type eitherNameCandidate struct {
	Candidate
	oldName string
}

func (c eitherNameCandidate) FileValue() string {
	return c.oldName
}

// MatchesEitherName is Matches with the same file-dimension widening that
// MatchPairEitherName applies to a Pair, for candidates that carry a rename
// source path of their own (streamrow.Row, whose FileValue is the newname).
//
// The Stream tab and its CSV export filter rows rather than pairs, so without
// this they would re-narrow the either-name contract that the event loop and
// the dashboard ingest stage already honour: a `-path <oldname>` filter would
// count a rename row in the aggregates while hiding it from the row list it is
// supposed to correspond to. oldName is empty for every non-rename row, in
// which case this is exactly Matches.
func (f Filter) MatchesEitherName(candidate Candidate, oldName string) bool {
	if f.Matches(candidate) {
		return true
	}
	if !hasStringPattern(f.File) || oldName == "" {
		return false
	}
	return f.Matches(eitherNameCandidate{Candidate: candidate, oldName: oldName})
}
