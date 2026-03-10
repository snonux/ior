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
