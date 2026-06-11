package streamrow

import "testing"

func TestSeedTestStreamData(t *testing.T) {
	buf := NewRingBuffer()
	SeedTestStreamData(buf)

	want := len(testStreamRows())
	if want == 0 {
		t.Fatal("testStreamRows returned no rows")
	}
	if got := buf.Len(); got != want {
		t.Fatalf("buf.Len() = %d, want %d", got, want)
	}

	snap := buf.Snapshot()
	if len(snap) != want {
		t.Fatalf("Snapshot length = %d, want %d", len(snap), want)
	}

	var errorRows int
	var prevSeq, prevTime uint64
	for i, row := range snap {
		if row.IsError {
			errorRows++
			if row.RetVal >= 0 {
				t.Errorf("row %d (seq %d) is an error but RetVal = %d (want negative)", i, row.Seq, row.RetVal)
			}
		}
		if i > 0 {
			if row.Seq <= prevSeq {
				t.Errorf("row %d Seq = %d not strictly increasing after %d", i, row.Seq, prevSeq)
			}
			if row.TimeNs <= prevTime {
				t.Errorf("row %d TimeNs = %d not strictly increasing after %d", i, row.TimeNs, prevTime)
			}
		}
		prevSeq, prevTime = row.Seq, row.TimeNs
	}

	if errorRows == 0 {
		t.Error("expected at least one IsError row in snapshot, got none")
	}
}

func TestSeedTestStreamDataNilBuffer(t *testing.T) {
	// Must not panic on a nil buffer.
	SeedTestStreamData(nil)
}
