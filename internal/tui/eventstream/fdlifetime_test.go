package eventstream

import "testing"

// Task cr2: a descriptor number is reused after a close, so the FD trace of a
// row must stop at the close that ends that life and start after the close
// that ended the previous one.

func lifeRow(seq uint64, syscall string, fd int32, isError bool) StreamEvent {
	return StreamEvent{Seq: seq, Syscall: syscall, PID: 100, FD: fd, IsError: isError}
}

// reusedFDEvents is fd 7 of pid 100 across three lives, with noise on other
// descriptors and another pid in between (seq 1..14).
func reusedFDEvents() []StreamEvent {
	other := StreamEvent{Seq: 20, Syscall: "close", PID: 200, FD: 7}
	return []StreamEvent{
		lifeRow(1, "openat", 7, false), lifeRow(2, "read", 7, false), lifeRow(3, "close", 7, false),
		lifeRow(4, "openat", 7, false), other, lifeRow(5, "write", 7, false), lifeRow(6, "read", 8, false),
		lifeRow(7, "close", 7, true), // failed close: the descriptor stays open
		lifeRow(8, "write", 7, false), lifeRow(9, "close", 7, false),
		lifeRow(10, "openat", 7, false), lifeRow(11, "read", 7, false),
	}
}

func seqs(events []StreamEvent) []uint64 {
	out := make([]uint64, 0, len(events))
	for _, ev := range events {
		out = append(out, ev.Seq)
	}
	return out
}

func equalSeqs(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestFDLifetimeEventsStopAtTheClosesAroundTheSelectedRow(t *testing.T) {
	events := reusedFDEvents()
	tests := []struct {
		name     string
		selected uint64
		want     []uint64
	}{
		{"first life", 2, []uint64{1, 2, 3}},
		{"the closing row itself", 3, []uint64{1, 2, 3}},
		{"second life, before the failed close", 5, []uint64{4, 5, 7, 8, 9}},
		{"second life, after the failed close", 8, []uint64{4, 5, 7, 8, 9}},
		{"third life has no close yet", 11, []uint64{10, 11}},
		{"third life's first row", 10, []uint64{10, 11}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var selected StreamEvent
			for _, ev := range events {
				if ev.Seq == tc.selected && ev.PID == 100 {
					selected = ev
				}
			}
			got := seqs(fdLifetimeEvents(events, selected))
			if !equalSeqs(got, tc.want) {
				t.Fatalf("trace of seq %d = %v, want %v", tc.selected, got, tc.want)
			}
		})
	}
}

func TestFDLifetimeEventsKeepAForeignPidOut(t *testing.T) {
	events := reusedFDEvents()
	for _, ev := range fdLifetimeEvents(events, events[1]) {
		if ev.PID != 100 || ev.FD != 7 {
			t.Fatalf("trace contains %+v", ev)
		}
	}
}

// Without any close row the number's rows all belong to one life, as before.
func TestFDLifetimeEventsWithoutCloseKeepEverything(t *testing.T) {
	events := []StreamEvent{lifeRow(1, "openat", 7, false), lifeRow(2, "read", 7, false), lifeRow(3, "write", 7, false)}
	if got := seqs(fdLifetimeEvents(events, events[1])); !equalSeqs(got, []uint64{1, 2, 3}) {
		t.Fatalf("trace = %v, want all three rows", got)
	}
}
