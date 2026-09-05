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
