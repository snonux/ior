package internal

import (
	"testing"

	"ior/internal/types"
)

// A lost exit leaves the old owner's break behind. Only a new process's
// birth proves that baseline obsolete; a new thread still shares it.
func TestBrkBaselineFollowsNewtaskProcessLifetime(t *testing.T) {
	const pid = uint32(absentPidBase + 901)
	tests := []struct {
		name      string
		tid       uint32
		creator   uint32
		flags     uint64
		wantFirst uint64
	}{
		{"recycled process", pid, pid + 1, 0, 0},
		{"process without creator", pid, 0, 0, 0},
		{"new thread", pid + 2, pid, cloneFlagThread, 900 * pg},
		{"thread without creator", pid + 2, 0, cloneFlagThread, 900 * pg},
		{"malformed same-creator process", pid, pid, 0, 900 * pg},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newBrkCaller(t)
			if got := c.call(pid, pid, 0, int64(100*pg)); got != 0 {
				t.Fatalf("initial query = %d, want 0", got)
			}
			// An unrelated process's baseline must survive the lifetime change.
			other := pid + 3
			if got := c.call(other, other, 0, int64(50*pg)); got != 0 {
				t.Fatalf("other process initial query = %d, want 0", got)
			}
			born := &types.TaskNewtaskEvent{
				EventType: types.TASK_NEWTASK_EVENT, Time: c.now,
				Pid: pid, Tid: tt.tid, CreatorPid: tt.creator, CloneFlags: tt.flags,
			}
			c.el.processRawEvent(eventBytes(t, born), c.out)
			c.now++
			// Use a nonzero request: brk(0) would re-baseline on its own
			// and conceal an old baseline surviving the newtask record.
			if got := c.call(pid, tt.tid, 1000*pg, int64(1000*pg)); got != tt.wantFirst {
				t.Fatalf("first brk after newtask = %d, want %d", got, tt.wantFirst)
			}
			if got := c.call(pid, tt.tid, 1003*pg, int64(1003*pg)); got != 3*pg {
				t.Fatalf("continued growth = %d, want %d", got, 3*pg)
			}
			if got := c.call(other, other, 52*pg, int64(52*pg)); got != 2*pg {
				t.Fatalf("other process growth = %d, want %d", got, 2*pg)
			}
		})
	}
}
