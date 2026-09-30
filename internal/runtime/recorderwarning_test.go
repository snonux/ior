package runtime

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"ior/internal/parquet"
	"ior/internal/streamrow"
)

// takeRecorder is a RowRecorder whose failure is handed out once, like
// parquet.Recorder's, counting the claims.
type takeRecorder struct {
	failure error
	takes   int
}

func (*takeRecorder) Record(streamrow.Row, uint64) error { return nil }
func (r *takeRecorder) TakeFailure() error {
	r.takes++
	err := r.failure
	r.failure = nil
	return err
}

// TestRecorderWarningText pins which Record results are news, and that only
// the dead-recording case claims the failure.
func TestRecorderWarningText(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name      string
		result    error
		failure   error
		want      string // substring; "" means no warning
		wantTakes int
	}{
		{"ok", nil, boom, "", 0},
		{"not active", parquet.ErrRecorderNotActive, boom, "", 0},
		{"wrapped not active", fmt.Errorf("x: %w", parquet.ErrRecorderNotActive), boom, "", 0},
		{"queue full already announced", parquet.ErrRecorderQueueFull, boom, "", 0},
		{"first shed row", parquet.ErrRecorderStartedDropping, boom, "rows are being dropped", 0},
		{"dead recording", boom, boom, "Parquet recorder failed: boom", 1},
		{"dead recording already taken", boom, nil, "", 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := &takeRecorder{failure: tc.failure}
			got := RecorderWarningText(rec, tc.result)
			if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
				t.Fatalf("RecorderWarningText() = %q, want %q", got, tc.want)
			}
			if rec.takes != tc.wantTakes {
				t.Fatalf("TakeFailure calls = %d, want %d", rec.takes, tc.wantTakes)
			}
		})
	}
}
