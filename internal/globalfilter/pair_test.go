package globalfilter

import (
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

func samplePair() *event.Pair {
	return &event.Pair{
		EnterEv:        &types.RetEvent{TraceId: types.SYS_ENTER_READ, Pid: 1234, Tid: 1235},
		ExitEv:         &types.RetEvent{TraceId: types.SYS_EXIT_READ, Pid: 1234, Tid: 1235, Ret: -1},
		Comm:           "nginx",
		File:           file.NewFd(7, "/var/log/access.log", 0),
		Duration:       1_500_000,
		DurationToPrev: 12_000,
		Bytes:          4_096,
	}
}

func TestMatchPairMatchesAllSupportedFields(t *testing.T) {
	filter := Filter{
		Syscall:    &StringFilter{Pattern: "rea"},
		Comm:       &StringFilter{Pattern: "NGI"},
		File:       &StringFilter{Pattern: "access"},
		PID:        &NumericFilter{Op: OpEq, Value: 1234},
		TID:        &NumericFilter{Op: OpEq, Value: 1235},
		FD:         &NumericFilter{Op: OpEq, Value: 7},
		LatencyNs:  &NumericFilter{Op: OpGt, Value: 1_000_000},
		GapNs:      &NumericFilter{Op: OpLte, Value: 12_000},
		Bytes:      &NumericFilter{Op: OpLt, Value: 8_192},
		RetVal:     &NumericFilter{Op: OpEq, Value: -1},
		ErrorsOnly: true,
	}
	if !MatchPair(filter, samplePair()) {
		t.Fatalf("expected full filter to match pair")
	}
}

func TestMatchPairRejectsMismatchesAndMissingFD(t *testing.T) {
	pair := samplePair()
	if MatchPair(Filter{Syscall: &StringFilter{Pattern: "write"}}, pair) {
		t.Fatalf("expected syscall mismatch to reject pair")
	}
	if MatchPair(Filter{FD: &NumericFilter{Op: OpEq, Value: 99}}, pair) {
		t.Fatalf("expected fd mismatch to reject pair")
	}

	pair.File = nil
	if MatchPair(Filter{FD: &NumericFilter{Op: OpEq, Value: 7}}, pair) {
		t.Fatalf("expected missing fd to reject pair")
	}
}

// TestMatchPairSeesRetOnKindSpecificExits guards the ret-carrier fix at the
// filter layer: accept/pipe/socketpair/eventfd exits decode into their own
// event structs rather than *types.RetEvent, so `ret`/errors-only filters used
// to see ret=0 and silently drop every failing call of those syscalls.
func TestMatchPairSeesRetOnKindSpecificExits(t *testing.T) {
	tests := []struct {
		name  string
		enter event.Event
		exit  event.Event
		ret   int64
	}{
		{
			name:  "accept",
			enter: &types.AcceptEvent{TraceId: types.SYS_ENTER_ACCEPT, Pid: 1234, Tid: 1235},
			exit:  &types.AcceptEvent{TraceId: types.SYS_EXIT_ACCEPT, Pid: 1234, Tid: 1235, Ret: -11},
			ret:   -11,
		},
		{
			name:  "pipe",
			enter: &types.PipeEvent{TraceId: types.SYS_ENTER_PIPE, Pid: 1234, Tid: 1235},
			exit:  &types.PipeEvent{TraceId: types.SYS_EXIT_PIPE, Pid: 1234, Tid: 1235, Ret: -24},
			ret:   -24,
		},
		{
			name:  "socketpair",
			enter: &types.SocketpairEvent{TraceId: types.SYS_ENTER_SOCKETPAIR, Pid: 1234, Tid: 1235},
			exit:  &types.SocketpairEvent{TraceId: types.SYS_EXIT_SOCKETPAIR, Pid: 1234, Tid: 1235, Ret: -93},
			ret:   -93,
		},
		{
			name:  "eventfd2",
			enter: &types.EventfdEvent{TraceId: types.SYS_ENTER_EVENTFD2, Pid: 1234, Tid: 1235},
			exit:  &types.EventfdEvent{TraceId: types.SYS_EXIT_EVENTFD2, Pid: 1234, Tid: 1235, Ret: -24},
			ret:   -24,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pair := &event.Pair{EnterEv: tt.enter, ExitEv: tt.exit, Comm: "srv"}
			if !MatchPair(Filter{ErrorsOnly: true}, pair) {
				t.Fatalf("errors-only filter did not match failing %s pair", tt.name)
			}
			if !MatchPair(Filter{RetVal: &NumericFilter{Op: OpEq, Value: tt.ret}}, pair) {
				t.Fatalf("ret == %d filter did not match %s pair", tt.ret, tt.name)
			}
		})
	}
}

// renamePair models what handleNameExit builds: File.Name() is the newname and
// the source path only reaches the filter through Pair.Oldname.
func renamePair() *event.Pair {
	return &event.Pair{
		EnterEv:  &types.RetEvent{TraceId: types.SYS_ENTER_RENAME, Pid: 1234, Tid: 1235},
		ExitEv:   &types.RetEvent{TraceId: types.SYS_EXIT_RENAME, Pid: 1234, Tid: 1235, Ret: 0},
		Comm:     "mv",
		File:     file.NewOldnameNewname([]byte("/tmp/old.txt"), []byte("/tmp/new.txt")),
		Oldname:  "/tmp/old.txt",
		Duration: 1_500_000,
	}
}

// TestMatchPairEitherNameWidensOnlyTheFileDimension pins the rename-kind
// filter contract: the file dimension follows MatchNameEvent and matches
// oldname OR newname, while every other dimension stays exactly as strict as
// MatchPair. Before this existed the name kinds skipped the pair filter
// entirely, so none of the numeric dimensions reached their rows at all.
func TestMatchPairEitherNameWidensOnlyTheFileDimension(t *testing.T) {
	pair := renamePair()

	if !(Filter{File: &StringFilter{Pattern: "/tmp/new.txt"}}).MatchPairEitherName(pair) {
		t.Fatalf("expected a newname match to be accepted")
	}
	if !(Filter{File: &StringFilter{Pattern: "/tmp/old.txt"}}).MatchPairEitherName(pair) {
		t.Fatalf("expected an oldname match to be accepted")
	}
	if (Filter{File: &StringFilter{Pattern: "/tmp/other.txt"}}).MatchPairEitherName(pair) {
		t.Fatalf("expected a path matching neither name to be rejected")
	}
	// MatchPair alone is the false negative this method exists to avoid.
	if MatchPair(Filter{File: &StringFilter{Pattern: "/tmp/old.txt"}}, pair) {
		t.Fatalf("sanity: plain MatchPair is not supposed to see the oldname")
	}

	// Every other dimension keeps MatchPair's strictness, including when the
	// file dimension was satisfied by the oldname.
	strict := Filter{
		File:      &StringFilter{Pattern: "/tmp/old.txt"},
		LatencyNs: &NumericFilter{Op: OpGt, Value: 2_000_000},
	}
	if strict.MatchPairEitherName(pair) {
		t.Fatalf("expected an oldname match to still be subject to -latency")
	}
	for name, filter := range map[string]Filter{
		"syscall":     {Syscall: &StringFilter{Pattern: "unlink"}},
		"comm":        {Comm: &StringFilter{Pattern: "cat"}},
		"pid":         {PID: &NumericFilter{Op: OpGt, Value: 99999}},
		"tid":         {TID: &NumericFilter{Op: OpNeq, Value: 1235}},
		"bytes":       {Bytes: &NumericFilter{Op: OpGte, Value: 1}},
		"ret":         {RetVal: &NumericFilter{Op: OpEq, Value: -1}},
		"errors-only": {ErrorsOnly: true},
	} {
		if filter.MatchPairEitherName(pair) {
			t.Fatalf("expected the %s dimension to reject the rename pair", name)
		}
	}

	if (Filter{}).MatchPairEitherName(nil) {
		t.Fatalf("expected a nil pair to be rejected")
	}
}

// stubCandidate is a minimal Candidate for exercising MatchesEitherName
// directly, without depending on any concrete row type.
type stubCandidate struct {
	syscall string
	file    string
	latency uint64
}

func (c stubCandidate) SyscallValue() string { return c.syscall }
func (c stubCandidate) FamilyValue() string  { return "FS" }
func (c stubCandidate) CommValue() string    { return "mv" }
func (c stubCandidate) FileValue() string    { return c.file }
func (c stubCandidate) PIDValue() uint32     { return 1 }
func (c stubCandidate) TIDValue() uint32     { return 1 }
func (c stubCandidate) FDValue() int32       { return -1 }
func (c stubCandidate) LatencyValue() uint64 { return c.latency }
func (c stubCandidate) GapValue() uint64     { return 0 }
func (c stubCandidate) BytesValue() uint64   { return 0 }
func (c stubCandidate) ReturnValue() int64   { return 0 }
func (c stubCandidate) ErrorValue() bool     { return false }

// TestMatchesEitherNameWidensOnlyTheFileDimension is the Candidate-level
// counterpart of TestMatchPairEitherNameWidensOnlyTheFileDimension. The Stream
// tab and its CSV export filter rows rather than pairs, so this path needs its
// own guard: it is the one shared by both of those call sites.
func TestMatchesEitherNameWidensOnlyTheFileDimension(t *testing.T) {
	row := stubCandidate{syscall: "renameat2", file: "/tmp/new.txt", latency: 1_000_000}
	const oldName = "/tmp/old.txt"

	if !(Filter{File: &StringFilter{Pattern: "/tmp/new.txt"}}).MatchesEitherName(row, oldName) {
		t.Fatal("expected a newname match to be accepted")
	}
	if !(Filter{File: &StringFilter{Pattern: "/tmp/old.txt"}}).MatchesEitherName(row, oldName) {
		t.Fatal("expected an oldname match to be accepted")
	}
	if (Filter{File: &StringFilter{Pattern: "/tmp/other.txt"}}).MatchesEitherName(row, oldName) {
		t.Fatal("expected a pattern matching neither name to be rejected")
	}

	// An empty oldName must not widen anything: a row with no rename source
	// behaves exactly like plain Matches.
	if (Filter{File: &StringFilter{Pattern: "/tmp/old.txt"}}).MatchesEitherName(row, "") {
		t.Fatal("an absent oldname must not satisfy the file dimension")
	}

	// The widening must not become a bypass for any other dimension.
	strict := Filter{
		File:    &StringFilter{Pattern: "/tmp/old.txt"},
		Syscall: &StringFilter{Pattern: "openat"},
	}
	if strict.MatchesEitherName(row, oldName) {
		t.Fatal("expected an oldname match to still be subject to -syscall")
	}
	slow := Filter{
		File:      &StringFilter{Pattern: "/tmp/old.txt"},
		LatencyNs: &NumericFilter{Op: OpGt, Value: 2_000_000},
	}
	if slow.MatchesEitherName(row, oldName) {
		t.Fatal("expected an oldname match to still be subject to -latency")
	}
}
