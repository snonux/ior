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
// raw pattern rejected `^` plus a 15-character comm plus `$` as 17 characters
// for a 16-byte field - the documented way to exact-match the longest comm
// Linux allows, since TASK_COMM_LEN includes the NUL.
//
// This only became user-visible when the TUI started validating live filter
// swaps (task l3); before that the check ran solely on a trace restart.
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

	// The anchors buy no extra room for the text itself.
	tooLong := Filter{Comm: &StringFilter{Pattern: "^" + strings.Repeat("a", types.MAX_PROGNAME_LENGTH+1) + "$"}}
	if err := tooLong.ValidateTracepointFields(); err == nil {
		t.Error("an over-long pattern was accepted because it was anchored")
	}
}
