package internal

import (
	"math"
	"strings"
	"testing"
	"time"

	"ior/internal/types"
)

// TestMismatchPercentIsSharePerPair pins task sq2: mismatches are counted per
// enter/exit pair, so the percentage must divide by pairs (numSyscalls), not by
// ring-buffer records (numTracepoints, >= 2 per pair). With every pair
// mismatched the figure must reach 100%, which the record-based denominator
// could never do (it capped near 50%).
func TestMismatchPercentIsSharePerPair(t *testing.T) {
	tests := []struct {
		name                       string
		records, pairs, mismatches uint
		want                       float64
	}{
		{"no pairs yet", 0, 0, 0, 0},
		{"records but no pairs", 10, 0, 0, 0},
		{"every pair mismatched", 200, 100, 100, 100},
		{"quarter mismatched", 400, 200, 50, 25},
		{"none mismatched", 200, 100, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			el := &eventLoop{numTracepoints: tc.records, numSyscalls: tc.pairs, numTracepointMismatches: tc.mismatches}
			if got := el.mismatchPercent(); math.Abs(got-tc.want) > 1e-9 {
				t.Fatalf("mismatchPercent() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestStatsMismatchedPairsReach100Percent drives real raw records through the
// pairing path: one enter whose exit carries the wrong trace ID. The pair is
// the only one formed and it mismatched, so stats() must report 100%, and the
// line must name the unit (pairs) it is a share of.
func TestStatsMismatchedPairsReach100Percent(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	_, enterRaw := makeEnterPathEvent(t, 1000, 42, 42, "/etc/hosts", types.SYS_ENTER_ACCESS)
	_, exitRaw := makeExitRetEvent(t, 1100, 42, 42, types.SYS_EXIT_CLOSE, 0)
	if ep := feedRawPair(t, el, enterRaw, exitRaw); ep != nil {
		t.Fatalf("mismatched pair was emitted: %v", ep)
	}
	if el.numTracepoints != 2 || el.numSyscalls != 1 || el.numTracepointMismatches != 1 {
		t.Fatalf("counters records=%d pairs=%d mismatches=%d, want 2/1/1",
			el.numTracepoints, el.numSyscalls, el.numTracepointMismatches)
	}

	el.startTime = time.Now().Add(-time.Second)
	close(el.done)
	stats := el.stats()
	if !strings.Contains(stats, "\tsyscalls: 1 (") || !strings.Contains(stats, "with 1 mismatched enter/exit pairs (100.00%)") {
		t.Fatalf("stats do not report the mismatch as a per-pair share:\n%s", stats)
	}
	if strings.Contains(stats, "with 1 mismatches") {
		t.Fatalf("mismatches still attached to the record count:\n%s", stats)
	}
}
