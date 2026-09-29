package eventstream

import "testing"

// newFullBufferModel returns a live (unpaused) stream model over a ring
// buffer filled to capacity, sized like a typical terminal.
func newFullBufferModel(tb testing.TB) *Model {
	tb.Helper()
	rb := NewRingBuffer()
	pushEvents(rb, ringBufferCapacity)
	m := NewModel(rb)
	m.SetViewport(160, 40)
	m.Refresh()
	return &m
}

// BenchmarkRefreshFullBuffer measures one stream Refresh over a full 10k-row
// ring buffer, the per-tick cost paid on the Bubble Tea UI goroutine.
func BenchmarkRefreshFullBuffer(b *testing.B) {
	m := newFullBufferModel(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		m.Refresh()
	}
}

// BenchmarkRefreshFullBufferFiltered is BenchmarkRefreshFullBuffer with an
// active filter that keeps half of the rows, exercising the Matches path.
func BenchmarkRefreshFullBufferFiltered(b *testing.B) {
	m := newFullBufferModel(b)
	m.SetFilter(syscallFilter("read"))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		m.Refresh()
	}
}

// maxRefreshAllocs bounds the allocations of one steady-state Refresh. The
// model itself allocates nothing once its buffers have grown; the budget
// covers the bubbles viewport, whose GotoBottom clones the visible window of
// content lines (a few dozen strings, independent of the buffer size). The
// point of the bound is that it does not scale with the 10k buffered rows:
// before the fix every row was copied to the heap (10,004 allocs/Refresh).
const maxRefreshAllocs = 2

// TestRefreshFullBufferAllocations pins the allocation behaviour of the
// stream refresh that runs on the Bubble Tea UI goroutine on every stream
// tick: re-snapshotting and re-filtering a full ring buffer must reuse the
// model's slices and must not heap-allocate a copy of every row.
func TestRefreshFullBufferAllocations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		filter string
	}{
		{name: "unfiltered"},
		{name: "filtered", filter: "read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newFullBufferModel(t)
			if tc.filter != "" {
				m.SetFilter(syscallFilter(tc.filter))
			}
			allocs := testing.AllocsPerRun(20, m.Refresh)
			if allocs > maxRefreshAllocs {
				t.Fatalf("Refresh over a full buffer allocated %.0f times, want <= %d", allocs, maxRefreshAllocs)
			}
		})
	}
}

// TestRefreshReusedBuffersTrackShrinkingSource checks the buffer reuse is
// invisible to readers: after the ring is reset and refilled with fewer
// rows, the model shows exactly the new rows (no stale tail from the larger
// previous snapshot), and a later snapshot does not rewrite rows handed out
// by the previous one's filter results.
func TestRefreshReusedBuffersTrackShrinkingSource(t *testing.T) {
	rb := NewRingBuffer()
	pushEvents(rb, 50)
	m := NewModel(rb)
	m.SetViewport(160, 40)
	m.Refresh()
	if len(m.filtered) != 50 {
		t.Fatalf("filtered = %d rows, want 50", len(m.filtered))
	}

	rb.Reset()
	for i := range 3 {
		rb.Push(StreamEvent{Seq: uint64(1000 + i), Syscall: "read", FD: UnknownFD})
	}
	m.Refresh()
	if len(m.allEvents) != 3 || len(m.filtered) != 3 {
		t.Fatalf("after shrink: allEvents=%d filtered=%d, want 3 and 3", len(m.allEvents), len(m.filtered))
	}
	for i, ev := range m.filtered {
		if want := uint64(1000 + i); ev.Seq != want {
			t.Fatalf("filtered[%d].Seq = %d, want %d", i, ev.Seq, want)
		}
	}

	// An emptied source clears the view without dropping the buffers.
	rb.Reset()
	m.Refresh()
	if len(m.allEvents) != 0 || len(m.filtered) != 0 || m.selectedIdx != -1 {
		t.Fatalf("after empty: allEvents=%d filtered=%d selectedIdx=%d", len(m.allEvents), len(m.filtered), m.selectedIdx)
	}
}

// plainSource implements only the Source contract (no AppendSnapshot), so
// Refresh must fall back to Snapshot.
type plainSource struct{ rows []StreamEvent }

func (s plainSource) Len() int { return len(s.rows) }

func (s plainSource) Snapshot() []StreamEvent { return append([]StreamEvent(nil), s.rows...) }

// TestRefreshFallsBackToSnapshotForPlainSource covers the Source that cannot
// append into a caller buffer: its rows are still shown and filtered.
func TestRefreshFallsBackToSnapshotForPlainSource(t *testing.T) {
	src := plainSource{rows: []StreamEvent{
		{Seq: 1, Syscall: "read", FD: UnknownFD},
		{Seq: 2, Syscall: "write", FD: UnknownFD},
	}}
	m := NewModel(src)
	m.SetViewport(160, 40)
	m.SetFilter(syscallFilter("write"))
	m.Refresh()
	if len(m.allEvents) != 2 || len(m.filtered) != 1 || m.filtered[0].Seq != 2 {
		t.Fatalf("plain source: allEvents=%d filtered=%+v", len(m.allEvents), m.filtered)
	}
}

// syscallFilter returns a stream filter matching syscall names containing
// pattern.
func syscallFilter(pattern string) Filter {
	return Filter{Syscall: &StringFilter{Pattern: pattern}}
}
