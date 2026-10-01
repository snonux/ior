package probes

import (
	"context"
	"errors"
	"testing"

	"ior/internal/probemanager"
	"ior/internal/types"
)

// drainRun follows run r the way the TUI does (next, then Next of every
// progress message) and returns the progress updates and the result.
func drainRun(t *testing.T, r *familyBatchRun) ([]FamilyBatchProgressMsg, FamilyToggledMsg) {
	t.Helper()
	var progress []FamilyBatchProgressMsg
	next := r.next
	for range 10 {
		switch msg := next().(type) {
		case FamilyBatchProgressMsg:
			progress = append(progress, msg)
			next = msg.Next()
		case FamilyToggledMsg:
			return progress, msg
		default:
			t.Fatalf("unexpected batch message %T", msg)
		}
	}
	t.Fatal("batch did not finish")
	return nil, FamilyToggledMsg{}
}

// TestBatchResultWaitsForPendingProgress forces the ordering behind the old
// flake (task gs2): the batch has finished, with its last progress update
// still unread, before the TUI asks for the next message, so both channels
// are ready. execute runs synchronously here, so every iteration hits that
// state. next must still deliver the latest update first and the result
// last; the old plain select dropped the update in about half of the
// iterations, so a few hundred of them fail it with certainty.
func TestBatchResultWaitsForPendingProgress(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name         string
		ctx          context.Context
		family       types.SyscallFamily
		attach       bool
		failAttach   map[string]bool
		wantProgress [][2]int // only the latest update survives: report coalesces
		wantChanged  int
		wantErrors   int
		wantErr      error
	}{
		{name: "attach", ctx: context.Background(), family: types.FamilyNetwork, attach: true,
			wantProgress: [][2]int{{2, 2}}, wantChanged: 2},
		{name: "attach with a failing probe", ctx: context.Background(), family: types.FamilyNetwork, attach: true,
			failAttach: map[string]bool{"connect": true}, wantProgress: [][2]int{{2, 2}}, wantChanged: 1, wantErrors: 1},
		{name: "detach", ctx: context.Background(), family: types.FamilyFS,
			wantProgress: [][2]int{{1, 1}}, wantChanged: 1},
		{name: "empty family", ctx: context.Background(), family: types.FamilyAIO, attach: true,
			wantProgress: [][2]int{{0, 0}}},
		// A cancelled batch reports nothing: the result comes alone.
		{name: "cancelled", ctx: cancelled, family: types.FamilyNetwork, attach: true,
			wantErr: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := range 300 {
				fm := familyTestManager()
				fm.failAttach = tt.failAttach
				r := newFamilyBatchRun(9, tt.family, tt.attach)
				r.execute(tt.ctx, ctxManager{fm})
				progress, done := drainRun(t, r)
				checkProgress(t, i, progress, tt.wantProgress, tt.family, tt.attach)
				if done.Run != 9 || done.Family != tt.family || done.Attach != tt.attach {
					t.Fatalf("iteration %d: result %+v, want run 9 of %s", i, done, tt.family)
				}
				if !errors.Is(done.Err, tt.wantErr) || done.Result.Changed != tt.wantChanged || len(done.Result.Errors) != tt.wantErrors {
					t.Fatalf("iteration %d: result %+v err %v, want %d changed, %d errors, err %v",
						i, done.Result, done.Err, tt.wantChanged, tt.wantErrors, tt.wantErr)
				}
			}
		})
	}
}

// checkProgress compares the progress updates of iteration i with want
// (completed, total pairs) and checks they belong to the expected batch.
func checkProgress(t *testing.T, i int, got []FamilyBatchProgressMsg, want [][2]int, family types.SyscallFamily, attach bool) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("iteration %d: %d progress updates %+v, want %v", i, len(got), got, want)
	}
	for n, msg := range got {
		if msg.Run != 9 || msg.Family != family || msg.Attach != attach ||
			msg.Completed != want[n][0] || msg.Total != want[n][1] {
			t.Fatalf("iteration %d: progress %d = %+v, want %v of run 9 %s", i, n, msg, want[n], family)
		}
	}
}

// TestBatchProgressPrecedesResultWhileRunning: updates the TUI reads while
// the batch is still running are delivered in order and none follows the
// result. The gated manager waits for each update to be consumed before
// reporting the next, so every update is seen.
func TestBatchProgressPrecedesResultWhileRunning(t *testing.T) {
	consumed := make(chan struct{})
	r := newFamilyBatchRun(4, types.FamilyNetwork, true)
	go r.execute(context.Background(), gatedManager{fakeManager: familyTestManager(), consumed: consumed})
	var got [][2]int
	next := r.next
	for {
		msg := next()
		if p, ok := msg.(FamilyBatchProgressMsg); ok {
			got = append(got, [2]int{p.Completed, p.Total})
			next = p.Next()
			consumed <- struct{}{}
			continue
		}
		if done, ok := msg.(FamilyToggledMsg); !ok || done.Result.Changed != 2 {
			t.Fatalf("final message %#v, want the result with 2 changed", msg)
		}
		break
	}
	want := [][2]int{{0, 2}, {1, 2}, {2, 2}}
	if len(got) != len(want) {
		t.Fatalf("progress %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("progress %v, want %v", got, want)
		}
	}
}

// gatedManager is a fakeManager whose family attach waits, after each
// progress update, until the test has consumed it.
type gatedManager struct {
	*fakeManager
	consumed chan struct{}
}

func (g gatedManager) AttachFamily(ctx context.Context, family types.SyscallFamily, progress func(int, int)) (probemanager.BatchResult, error) {
	return g.fakeManager.AttachFamily(ctx, family, func(completed, total int) {
		progress(completed, total)
		<-g.consumed
	})
}

// TestProgressMessageWithoutRunHasNoNext: a progress message the TUI built
// itself (replayed into a rebuilt modal) follows no batch.
func TestProgressMessageWithoutRunHasNoNext(t *testing.T) {
	if cmd := (FamilyBatchProgressMsg{Family: types.FamilyFS}).Next(); cmd != nil {
		t.Fatal("Next of a progress message without a run is not nil")
	}
}
