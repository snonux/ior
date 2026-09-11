package globalfilter

import (
	"strings"
	"testing"

	"ior/internal/types"
)

func TestValidateTracepointFieldsRejectsOversizedPatterns(t *testing.T) {
	tooLongComm := strings.Repeat("a", types.MAX_PROGNAME_LENGTH+1)
	if err := (Filter{Comm: &StringFilter{Pattern: tooLongComm}}).ValidateTracepointFields(); err == nil {
		t.Fatalf("expected oversized comm pattern to fail validation")
	}

	tooLongPath := strings.Repeat("b", types.MAX_FILENAME_LENGTH+1)
	if err := (Filter{File: &StringFilter{Pattern: tooLongPath}}).ValidateTracepointFields(); err == nil {
		t.Fatalf("expected oversized path pattern to fail validation")
	}
}

func TestTracepointHelpersMatchRawEvents(t *testing.T) {
	filter := Filter{
		Comm: &StringFilter{Pattern: "^nginx"},
		File: &StringFilter{Pattern: "access.log$"},
	}

	open := &types.OpenEvent{}
	copy(open.Comm[:], "nginx-worker")
	copy(open.Filename[:], "/var/log/nginx/access.log")
	if !filter.MatchOpenEvent(open) {
		t.Fatalf("expected open event to match comm and file filters")
	}

	path := &types.PathEvent{}
	copy(path.Pathname[:], "/var/log/nginx/access.log")
	if !filter.MatchPathEvent(path) {
		t.Fatalf("expected path event to match file filter")
	}

	name := &types.NameEvent{}
	copy(name.Oldname[:], "/tmp/old.log")
	copy(name.Newname[:], "/var/log/nginx/access.log")
	if !filter.MatchNameEvent(name) {
		t.Fatalf("expected rename event to match file filter via newname")
	}
}

// TestMatchOpenEventCommDropsOnlyTheFileDimension pins the split MatchOpenEvent
// was refactored into. matchRawOpenEvent (internal/eventloop_kinds.go) uses the
// comm-only form for an open whose sys_enter filename read faulted: its real
// path arrives a moment later as a fixup control record, so judging the file
// dimension on the empty payload name would answer it with "no name, no match"
// and drop the event before the recovery could be applied. The comm dimension
// must keep biting, and this must be the *only* difference from MatchOpenEvent.
func TestMatchOpenEventCommDropsOnlyTheFileDimension(t *testing.T) {
	filter := Filter{
		Comm: &StringFilter{Pattern: "ioworkload"},
		File: &StringFilter{Pattern: "locale-archive"},
	}
	emptyName := &types.OpenEvent{}
	copy(emptyName.Comm[:], "ioworkload")
	if filter.MatchOpenEvent(emptyName) {
		t.Error("MatchOpenEvent must not match an empty filename against a -path pattern")
	}
	if !filter.MatchOpenEventComm(emptyName) {
		t.Error("MatchOpenEventComm must accept a matching comm regardless of the filename")
	}

	wrongComm := &types.OpenEvent{}
	copy(wrongComm.Comm[:], "someoneelse")
	if filter.MatchOpenEventComm(wrongComm) {
		t.Error("MatchOpenEventComm must still apply the comm dimension")
	}

	if filter.MatchOpenEventComm(nil) {
		t.Error("MatchOpenEventComm(nil) must not match")
	}
}

// TestValidateTracepointFieldsMeasuresTheMatchedTextNotTheAnchors pins the
// agreement between the length check and the matcher.
//
// The anchors are syntax: matchString strips `^`/`$` before comparing, and the
// filter modal advertises `^exact$` as the way to match exactly. Measuring the
// raw pattern rejected `^` plus the longest possible comm plus `$` - the
// documented way to exact-match it.
//
// The boundary is one byte below the buffer size, because the kernel
// NUL-terminates what it writes: MAX_PROGNAME_LENGTH is 16, so 15 bytes is the
// longest comm that can ever arrive and a 16-byte pattern is unmatchable. That
// case is the one the anchor fix nearly let through - unanchored it was always
// wrongly accepted, and trimming the anchors would have started accepting the
// anchored form too.
//
// This only became user-visible when the TUI started validating live filter
// swaps (task l3); before that an over-long pattern failed the trace outright.
func TestValidateTracepointFieldsMeasuresTheMatchedTextNotTheAnchors(t *testing.T) {
	longestComm := strings.Repeat("a", types.MAX_PROGNAME_LENGTH-1)

	anchored := Filter{Comm: &StringFilter{Pattern: "^" + longestComm + "$"}}
	if err := anchored.ValidateTracepointFields(); err != nil {
		t.Errorf("anchored exact match on the longest possible comm was rejected: %v", err)
	}
	// And it really does match, so rejecting it cost a working filter.
	if !matchString(anchored.Comm, longestComm) {
		t.Errorf("%q does not match %q; the premise of this test is wrong", anchored.Comm.Pattern, longestComm)
	}

	// A pattern the width of the whole buffer cannot match anything, anchored
	// or not: the NUL takes the last byte.
	bufferWidth := strings.Repeat("a", types.MAX_PROGNAME_LENGTH)
	for _, pattern := range []string{bufferWidth, "^" + bufferWidth + "$"} {
		f := Filter{Comm: &StringFilter{Pattern: pattern}}
		if err := f.ValidateTracepointFields(); err == nil {
			t.Errorf("pattern %q is as wide as the whole comm buffer and can never match, but was accepted", pattern)
		}
	}

	// The validator normalises case the way matchString does, so a pattern
	// whose lowered form fits is not rejected on its raw length. U+212A lowers
	// to a single-byte "k".
	kelvin := Filter{Comm: &StringFilter{Pattern: strings.Repeat("\u212A", 6)}}
	if err := kelvin.ValidateTracepointFields(); err != nil {
		t.Errorf("a pattern whose lowered form is 6 bytes was rejected on its raw length: %v", err)
	}
}
