package probemanager

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"ior/internal/types"
)

// newFamilyTestManager registers read/write (FS), socket/connect (Network)
// and nanosleep (Time) and attaches only read. connect has no exit program,
// so attaching it always fails, as a tracepoint missing on an older kernel.
func newFamilyTestManager(t *testing.T) *Manager {
	t.Helper()
	programs := map[string]*fakeProgram{}
	for _, syscall := range []string{"read", "write", "socket", "connect", "nanosleep"} {
		programs["handle_sys_enter_"+syscall] = &fakeProgram{}
		if syscall != "connect" {
			programs["handle_sys_exit_"+syscall] = &fakeProgram{}
		}
	}
	mgr := NewManager(&fakeAttacher{programs: programs, errs: map[string]error{}})
	var tps []string
	for _, syscall := range []string{"read", "write", "socket", "connect", "nanosleep"} {
		tps = append(tps, "sys_enter_"+syscall, "sys_exit_"+syscall)
	}
	onlyRead := func(tp string) bool { return strings.HasSuffix(tp, "_read") }
	if err := mgr.AttachAll(onlyRead, tps, nil); err != nil {
		t.Fatalf("AttachAll: %v", err)
	}
	return mgr
}

// familyCount returns the FamilyStates entry of family.
func familyCount(t *testing.T, mgr *Manager, family types.SyscallFamily) FamilyState {
	t.Helper()
	for _, state := range FamilyStates(mgr.States()) {
		if state.Family == family {
			return state
		}
	}
	t.Fatalf("family %s missing from FamilyStates", family)
	return FamilyState{}
}

func TestAttachFamilyReportsPerSyscallErrorsAndProgress(t *testing.T) {
	mgr := newFamilyTestManager(t)
	var progress [][2]int
	result, err := mgr.AttachFamily(context.Background(), types.FamilyNetwork, func(done, total int) {
		progress = append(progress, [2]int{done, total})
	})
	if err != nil {
		t.Fatalf("AttachFamily: %v", err)
	}
	if result.Total != 2 || result.Changed != 1 {
		t.Fatalf("result = %+v, want Total 2 Changed 1", result)
	}
	if len(result.Errors) != 1 || result.Errors[0].Syscall != "connect" {
		t.Fatalf("errors = %+v, want exactly connect", result.Errors)
	}
	if err := result.Err(); err == nil || !strings.HasPrefix(err.Error(), "connect: ") {
		t.Fatalf("Err() = %v, want a connect-prefixed error", err)
	}
	if want := [][2]int{{0, 2}, {1, 2}, {2, 2}}; !slices.Equal(progress, want) {
		t.Fatalf("progress = %v, want %v", progress, want)
	}
	if got := familyCount(t, mgr, types.FamilyNetwork); got.Active != 1 || got.Total != 2 {
		t.Fatalf("Network = %+v, want 1/2", got)
	}
	// Other families are untouched: the batch is scoped to the family.
	if got := familyCount(t, mgr, types.FamilyTime); got.Active != 0 || got.Total != 1 {
		t.Fatalf("Time = %+v, want 0/1", got)
	}
}

func TestDetachFamilyOnlyTouchesActiveProbes(t *testing.T) {
	mgr := newFamilyTestManager(t)
	result, err := mgr.DetachFamily(context.Background(), types.FamilyFS, nil)
	if err != nil {
		t.Fatalf("DetachFamily: %v", err)
	}
	// write is already detached, so only read counts.
	if result.Total != 1 || result.Changed != 1 || result.Err() != nil {
		t.Fatalf("result = %+v, want Total 1 Changed 1 no errors", result)
	}
	if active, _ := mgr.ActiveCount(); active != 0 {
		t.Fatalf("active = %d, want 0", active)
	}
	// A second detach has nothing left to do.
	result, err = mgr.DetachFamily(context.Background(), types.FamilyFS, nil)
	if err != nil || result.Total != 0 || result.Changed != 0 {
		t.Fatalf("second detach = %+v, %v; want an empty result", result, err)
	}
}

func TestBatchOnEmptyOrUnknownFamilyIsANoop(t *testing.T) {
	mgr := newFamilyTestManager(t)
	calls := 0
	result, err := mgr.AttachFamily(context.Background(), types.FamilyAIO, func(done, total int) {
		calls++
		if done != 0 || total != 0 {
			t.Fatalf("progress (%d, %d), want (0, 0)", done, total)
		}
	})
	if err != nil || result.Total != 0 || calls != 1 {
		t.Fatalf("result = %+v err = %v calls = %d; want empty result, one progress call", result, err, calls)
	}
	result, err = mgr.AttachFamily(context.Background(), types.SyscallFamily("Bogus"), nil)
	if err != nil || result.Total != 0 {
		t.Fatalf("unknown family = %+v, %v; want an empty result", result, err)
	}
}

func TestBatchRejectsNilManagerAndPredicate(t *testing.T) {
	var nilMgr *Manager
	if _, err := nilMgr.AttachFamily(context.Background(), types.FamilyFS, nil); err == nil {
		t.Fatal("nil manager AttachFamily: want error")
	}
	if _, err := newFamilyTestManager(t).DetachMatching(context.Background(), nil, nil); err == nil {
		t.Fatal("nil predicate: want error")
	}
}

func TestAttachMatchingOnClosedManagerReportsEachSyscall(t *testing.T) {
	mgr := newFamilyTestManager(t)
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	result, err := mgr.AttachMatching(context.Background(), func(string) bool { return true }, nil)
	if err != nil {
		t.Fatalf("AttachMatching: %v", err)
	}
	// Close deactivated all five probes; every attach fails as closed.
	if result.Total != 5 || result.Changed != 0 || len(result.Errors) != 5 {
		t.Fatalf("result = %+v, want 5 failures", result)
	}
	for _, e := range result.Errors {
		if e.Err == nil || !strings.Contains(e.Err.Error(), "closed") {
			t.Fatalf("error for %s = %v, want closed", e.Syscall, e.Err)
		}
	}
}

func TestFamilyStatesListsEveryFamilyInDisplayOrder(t *testing.T) {
	states := []ProbeState{
		{Syscall: "openat", Active: true},
		{Syscall: "read"},
		{Syscall: "socket", Active: true},
		{Syscall: "not_a_syscall", Active: true}, // unknown -> Misc
	}
	got := FamilyStates(states)
	if len(got) != len(types.AllSyscallFamilies()) {
		t.Fatalf("len = %d, want %d", len(got), len(types.AllSyscallFamilies()))
	}
	want := map[types.SyscallFamily][2]int{
		types.FamilyFS: {1, 2}, types.FamilyNetwork: {1, 1}, types.FamilyMisc: {1, 1},
	}
	for i, state := range got {
		if state.Family != types.AllSyscallFamilies()[i] {
			t.Fatalf("entry %d = %s, want display order", i, state.Family)
		}
		if counts := want[state.Family]; state.Active != counts[0] || state.Total != counts[1] {
			t.Fatalf("%s = %d/%d, want %d/%d", state.Family, state.Active, state.Total, counts[0], counts[1])
		}
	}
}

func TestBatchResultErrIsNilWithoutErrors(t *testing.T) {
	if err := (BatchResult{Total: 3, Changed: 3}).Err(); err != nil {
		t.Fatalf("Err() = %v, want nil", err)
	}
	sentinel := errors.New("boom")
	err := BatchResult{Errors: []SyscallError{{Syscall: "x", Err: sentinel}}}.Err()
	if !errors.Is(err, sentinel) {
		t.Fatalf("Err() = %v, want to wrap the syscall error", err)
	}
}

// TestFamilyBatchStopsBetweenProbesWhenCancelled: the TUI cancels a batch
// when its trace session ends. Cancelling from the progress callback after
// the first probe must leave the remaining probes untouched and return the
// partial result with the context's error.
func TestFamilyBatchStopsBetweenProbesWhenCancelled(t *testing.T) {
	mgr := newFamilyTestManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := mgr.AttachMatching(ctx, func(s string) bool { return s != "read" }, func(done, _ int) {
		if done == 1 {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	// Sorted batch: connect (fails, no exit program), nanosleep, socket, write.
	if result.Total != 4 || result.Changed != 0 || len(result.Errors) != 1 || result.Errors[0].Syscall != "connect" {
		t.Fatalf("result = %+v, want only connect visited out of 4", result)
	}
	for _, family := range []types.SyscallFamily{types.FamilyTime, types.FamilyNetwork} {
		if got := familyCount(t, mgr, family).Active; got != 0 {
			t.Fatalf("%s has %d active probes after the cancelled batch, want 0", family, got)
		}
	}
}

// TestFamilyBatchWithCancelledContextChangesNothing: a batch whose session
// already ended must not touch a single probe (negative case of the above).
func TestFamilyBatchWithCancelledContextChangesNothing(t *testing.T) {
	mgr := newFamilyTestManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := mgr.DetachFamily(ctx, types.FamilyFS, nil)
	if !errors.Is(err, context.Canceled) || result.Total != 1 || result.Changed != 0 || len(result.Errors) != 0 {
		t.Fatalf("result = %+v err = %v, want an untouched batch of 1 and context.Canceled", result, err)
	}
	if got := familyCount(t, mgr, types.FamilyFS).Active; got != 1 {
		t.Fatalf("FS active = %d, want read still attached", got)
	}
}
