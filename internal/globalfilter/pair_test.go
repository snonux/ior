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

func TestMatchPairErrorsOnlyUsesTheErrnoReturnWindow(t *testing.T) {
	pair := samplePair()
	retEvent := pair.ExitEv.(*types.RetEvent)

	retEvent.Ret = -4096
	if MatchPair(Filter{ErrorsOnly: true}, pair) {
		t.Fatal("errors-only filter matched -4096 outside the errno window")
	}

	retEvent.Ret = -4095
	if !MatchPair(Filter{ErrorsOnly: true}, pair) {
		t.Fatal("errors-only filter rejected -4095 at the errno boundary")
	}
}

// TestMatchPairErrorsOnlyRejectsKernelRestartCodes covers task aq2: a call a
// signal interrupted exits with -512/-513/-514/-516, which user space never
// sees, so errors-only must not show it; a ret filter still matches the raw
// value so the row can be found explicitly.
func TestMatchPairErrorsOnlyRejectsKernelRestartCodes(t *testing.T) {
	pair := samplePair()
	retEvent := pair.ExitEv.(*types.RetEvent)
	for _, ret := range []int64{-512, -513, -514, -516} {
		retEvent.Ret = ret
		if MatchPair(Filter{ErrorsOnly: true}, pair) {
			t.Errorf("errors-only filter matched restart code %d", ret)
		}
		if !MatchPair(Filter{RetVal: &NumericFilter{Op: OpEq, Value: ret}}, pair) {
			t.Errorf("ret == %d filter did not match the raw restart code", ret)
		}
	}
	for _, ret := range []int64{-4, -511, -515} {
		retEvent.Ret = ret
		if !MatchPair(Filter{ErrorsOnly: true}, pair) {
			t.Errorf("errors-only filter rejected real errno %d", ret)
		}
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

// TestMatchPairSeesTheRenameOldname pins the rename-kind filter contract:
// the file dimension of plain MatchPair matches oldname OR newname - the same
// rule the raw enter filter MatchNameEvent applies - while every other
// dimension stays exactly as strict as before. There is no separate
// either-name variant of MatchPair any more: the widening lives inside
// Matches (Candidate.OldFileValue), and the per-stage variants were how one
// stage silently disagreed with another.
func TestMatchPairSeesTheRenameOldname(t *testing.T) {
	pair := renamePair()

	if !(Filter{File: &StringFilter{Pattern: "/tmp/new.txt"}}).MatchPair(pair) {
		t.Fatalf("expected a newname match to be accepted")
	}
	if !(Filter{File: &StringFilter{Pattern: "/tmp/old.txt"}}).MatchPair(pair) {
		t.Fatalf("expected an oldname match to be accepted")
	}
	if (Filter{File: &StringFilter{Pattern: "/tmp/other.txt"}}).MatchPair(pair) {
		t.Fatalf("expected a path matching neither name to be rejected")
	}

	// Every other dimension keeps its strictness, including when the file
	// dimension was satisfied by the oldname.
	strict := Filter{
		File:      &StringFilter{Pattern: "/tmp/old.txt"},
		LatencyNs: &NumericFilter{Op: OpGt, Value: 2_000_000},
	}
	if strict.MatchPair(pair) {
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
		if filter.MatchPair(pair) {
			t.Fatalf("expected the %s dimension to reject the rename pair", name)
		}
	}

	if (Filter{}).MatchPair(nil) {
		t.Fatalf("expected a nil pair to be rejected")
	}
}

// stubCandidate is a minimal Candidate for exercising Matches directly,
// without depending on any concrete row type. oldFile models the rename
// source path a real candidate reports through OldFileValue; it is empty for
// every single-name candidate.
type stubCandidate struct {
	syscall string
	file    string
	oldFile string
	latency uint64
}

func (c stubCandidate) SyscallValue() string { return c.syscall }
func (c stubCandidate) FamilyValue() string  { return "FS" }
func (c stubCandidate) CommValue() string    { return "mv" }
func (c stubCandidate) FileValue() string    { return c.file }
func (c stubCandidate) OldFileValue() string { return c.oldFile }
func (c stubCandidate) PIDValue() uint32     { return 1 }
func (c stubCandidate) TIDValue() uint32     { return 1 }
func (c stubCandidate) FDValue() int32       { return -1 }
func (c stubCandidate) LatencyValue() uint64 { return c.latency }
func (c stubCandidate) GapValue() uint64     { return 0 }
func (c stubCandidate) BytesValue() uint64   { return 0 }
func (c stubCandidate) ReturnValue() int64   { return 0 }
func (c stubCandidate) ErrorValue() bool     { return false }

// TestMatchesSeesTheCandidateOldName is the Candidate-level counterpart of
// TestMatchPairSeesTheRenameOldname. The Stream tab and its CSV export filter
// rows rather than pairs, and they call plain Matches - so the widening has to
// come from the candidate itself (OldFileValue), not from a call-site variant.
func TestMatchesSeesTheCandidateOldName(t *testing.T) {
	row := stubCandidate{syscall: "renameat2", file: "/tmp/new.txt", oldFile: "/tmp/old.txt", latency: 1_000_000}
	singleName := stubCandidate{syscall: "renameat2", file: "/tmp/new.txt", latency: 1_000_000}

	if !(&Filter{File: &StringFilter{Pattern: "/tmp/new.txt"}}).Matches(row) {
		t.Fatal("expected a newname match to be accepted")
	}
	if !(&Filter{File: &StringFilter{Pattern: "/tmp/old.txt"}}).Matches(row) {
		t.Fatal("expected an oldname match to be accepted")
	}
	if (&Filter{File: &StringFilter{Pattern: "/tmp/other.txt"}}).Matches(row) {
		t.Fatal("expected a pattern matching neither name to be rejected")
	}

	// An empty OldFileValue must not widen anything: a row with no rename
	// source behaves exactly like a single-name candidate. The degenerate
	// anchored pattern "^$" is the sharp case - it matches the empty string,
	// so an absent oldname satisfying it would let `-path '^$'` keep every
	// single-name row instead of only the genuinely empty-path ones.
	if (&Filter{File: &StringFilter{Pattern: "/tmp/old.txt"}}).Matches(singleName) {
		t.Fatal("an absent oldname must not satisfy the file dimension")
	}
	if !(&Filter{File: &StringFilter{Pattern: "^$"}}).Matches(stubCandidate{syscall: "read", file: ""}) {
		t.Fatal("an empty-path row must satisfy -path '^$'")
	}
	if (&Filter{File: &StringFilter{Pattern: "^$"}}).Matches(singleName) {
		t.Fatal("an absent oldname must not satisfy -path '^$'")
	}
	if (&Filter{File: &StringFilter{Pattern: "^$"}}).Matches(row) {
		t.Fatal("a non-empty oldname must not satisfy -path '^$'")
	}

	// The widening must not become a bypass for any other dimension.
	strict := Filter{
		File:    &StringFilter{Pattern: "/tmp/old.txt"},
		Syscall: &StringFilter{Pattern: "openat"},
	}
	if strict.Matches(row) {
		t.Fatal("expected an oldname match to still be subject to -syscall")
	}
	slow := Filter{
		File:      &StringFilter{Pattern: "/tmp/old.txt"},
		LatencyNs: &NumericFilter{Op: OpGt, Value: 2_000_000},
	}
	if slow.Matches(row) {
		t.Fatal("expected an oldname match to still be subject to -latency")
	}
}
