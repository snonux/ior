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
