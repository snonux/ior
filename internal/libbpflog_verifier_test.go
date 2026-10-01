package internal

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	bpf "github.com/aquasecurity/libbpfgo"
)

// verifierRejection is the tail of a realistic kernel verifier log for a
// program that dereferences a scalar: the offending instruction, the reason and
// the statistics line the verifier always prints last.
const verifierRejection = "1: (b7) r1 = 0\n" +
	"2: (71) r0 = *(u8 *)(r1 +0)\n" +
	"R1 invalid mem access 'scalar'\n" +
	"processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n"

// verifierLoadWarning builds the one WARN libbpf emits for a failed program
// load (see progLoadLogBegin): banner line, log, end marker, newline. log must
// end with a newline like the kernel's does.
func verifierLoadWarning(prog, log string) string {
	return "libbpf: prog '" + prog + "': " + progLoadLogBegin + "\n" + log + progLoadLogEnd + "\n"
}

// TestShortenWarningKeepsTheVerifierReason is the core of the fix: the banner
// alone is useless, so the row carries the program name and the log's last
// three lines on ONE line.
func TestShortenWarningKeepsTheVerifierReason(t *testing.T) {
	msg := verifierLoadWarning("ior_x", "0: R1=ctx() R10=fp0\n0: (b7) r0 = 0\n"+verifierRejection)
	got := shortenWarning(strings.TrimSuffix(msg, "\n"), maxRoutedWarningBytes)

	want := "libbpf: prog 'ior_x': verifier: 2: (71) r0 = *(u8 *)(r1 +0) | R1 invalid mem access 'scalar' | " +
		"processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0 ... (3 more lines)"
	if got != want {
		t.Fatalf("shortenWarning =\n %q\nwant\n %q", got, want)
	}
}

func TestShortenWarningVerifierEdgeCases(t *testing.T) {
	longLine := strings.Repeat("x", 4000)
	tests := []struct {
		name string
		in   string
		want []string // substrings that must be present
		not  []string // substrings that must be absent
	}{
		{
			name: "short log is shown whole without a marker",
			in:   verifierLoadWarning("p", "R1 bad\n"),
			want: []string{"libbpf: prog 'p': verifier: R1 bad"},
			not:  []string{"more lines"},
		},
		{
			name: "missing END marker keeps the tail of what there is",
			in:   "libbpf: prog 'p': " + progLoadLogBegin + "\na\nb\nR1 bad\nprocessed 1 insns\n",
			want: []string{"verifier: b | R1 bad | processed 1 insns ... (1 more lines)"},
		},
		{
			name: "END marker glued to the last log line",
			in:   "libbpf: prog 'p': " + progLoadLogBegin + "\nR1 bad\nprocessed 1 insns" + progLoadLogEnd + "\n",
			want: []string{"verifier: R1 bad | processed 1 insns"},
			not:  []string{"END PROG"},
		},
		{
			name: "CRLF line endings leave no carriage return",
			in:   "libbpf: prog 'p': " + progLoadLogBegin + "\r\nfirst\r\nR1 bad\r\nprocessed 1 insns\r\n" + progLoadLogEnd + "\r\n",
			want: []string{"verifier: first | R1 bad | processed 1 insns"},
			not:  []string{"\r"},
		},
		{
			name: "blank lines do not count as the reason",
			in:   verifierLoadWarning("p", "R1 bad\n\n\n   \nprocessed 1 insns\n\n"),
			want: []string{"verifier: R1 bad | processed 1 insns"},
		},
		{
			name: "huge log line is bounded",
			in:   verifierLoadWarning("p", longLine+"\n"+longLine+"\n"+longLine+"\n"),
			want: []string{"libbpf: prog 'p': verifier: "},
		},
		{
			name: "empty log says so instead of counting the END marker",
			in:   verifierLoadWarning("p", ""),
			want: []string{"libbpf: prog 'p': verifier: (empty log)"},
			not:  []string{"more lines", progLoadLogBegin},
		},
		{
			name: "blank-only log is an empty log",
			in:   verifierLoadWarning("p", "\n   \r\n\t\n"),
			want: []string{"libbpf: prog 'p': verifier: (empty log)"},
			not:  []string{"more lines"},
		},
		{
			name: "omitted blank lines are not counted",
			in:   verifierLoadWarning("p", "a\n\n  \nb\n\r\nc\nR1 bad\nprocessed 1 insns\n\n"),
			want: []string{"verifier: c | R1 bad | processed 1 insns ... (2 more lines)"},
		},
		{
			name: "banner without a body falls back to the first line",
			in:   "libbpf: prog 'p': " + progLoadLogBegin,
			want: []string{"libbpf: prog 'p': " + progLoadLogBegin},
			not:  []string{"verifier:"},
		},
	}
	for _, tc := range tests {
		got := shortenWarning(tc.in, maxRoutedWarningBytes)
		if strings.Contains(got, "\n") {
			t.Errorf("%s: row is multi-line: %q", tc.name, got)
		}
		if len(got) > maxRoutedWarningBytes {
			t.Errorf("%s: row is %d bytes, over the %d-byte bound", tc.name, len(got), maxRoutedWarningBytes)
		}
		if again := shortenWarning(got, maxRoutedWarningBytes); again != got {
			t.Errorf("%s: shortening is not idempotent:\n %q\n %q", tc.name, got, again)
		}
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q lacks %q", tc.name, got, w)
			}
		}
		for _, n := range tc.not {
			if strings.Contains(got, n) {
				t.Errorf("%s: %q carries %q", tc.name, got, n)
			}
		}
	}
}

// TestShortenWarningLeavesOrdinaryWarningsAlone pins the unchanged cases: a
// single-line warning is returned as is, and a multi-line one without a
// PROG LOAD LOG banner still keeps its first line plus the marker.
func TestShortenWarningLeavesOrdinaryWarningsAlone(t *testing.T) {
	if got := shortenWarning("libbpf: map 'm': failed to create: -1", maxRoutedWarningBytes); got != "libbpf: map 'm': failed to create: -1" {
		t.Errorf("single-line warning changed: %q", got)
	}
	if got := shortenWarning("libbpf: a\r\nb\r\nc", maxRoutedWarningBytes); got != "libbpf: a ... (2 more lines)" {
		t.Errorf("multi-line CRLF warning = %q", got)
	}
	// The marker counts text, not blank lines or a trailing newline.
	if got := shortenWarning("libbpf: a\n\n  \nb\n", maxRoutedWarningBytes); got != "libbpf: a ... (1 more lines)" {
		t.Errorf("multi-line warning with blank lines = %q", got)
	}
	if got := shortenWarning("libbpf: a\n\n", maxRoutedWarningBytes); got != "libbpf: a" {
		t.Errorf("warning with only blank continuation lines = %q, want no marker", got)
	}
}

// TestShortenWarningKeepsAnExistingMarkerWhenCuttingAgain: a row the route
// shaped is cut again by explainFailure; only its content may shrink.
func TestShortenWarningKeepsAnExistingMarkerWhenCuttingAgain(t *testing.T) {
	row := strings.Repeat("a", 100) + " ... (42 more lines)"
	// 30 bytes in all: the 20-byte marker leaves 10 for the content, "..."
	// included.
	got := shortenWarning(row, 30)
	if want := strings.Repeat("a", 7) + "... ... (42 more lines)"; got != want {
		t.Errorf("recut = %q, want %q", got, want)
	}
	if got := shortenWarning(row, 200); got != row {
		t.Errorf("row within the limit changed: %q", got)
	}
	// Not a marker: a non-numeric count is plain text.
	odd := strings.Repeat("b", 50) + " ... (x more lines)"
	if got := shortenWarning(odd, 10); strings.HasSuffix(got, "(x more lines)") {
		t.Errorf("non-numeric marker was preserved as one: %q", got)
	}
	// Cutting an already-cut row to the same limit again must be stable.
	once := shortenWarning(strings.Repeat("é", 400), 511)
	if twice := shortenWarning(once, 511); twice != once {
		t.Errorf("recutting moved the ellipsis: %q -> %q", once, twice)
	}
}

// TestRouteSummarisesVerifierLogForTheStreamRow runs the real route with a
// realistic failed-load sequence: the verifier WARN becomes one row with the
// reason, the neighbouring one-line WARNs stay as they are.
func TestRouteSummarisesVerifierLogForTheStreamRow(t *testing.T) {
	withLibbpfLogger(t, true, false)
	w := &setupWarnings{}
	end := libbpfLog.routeWarnings(w.add)
	libbpfLog.log(bpf.LibbpfWarnLevel, "libbpf: prog 'ior_x': BPF program load failed: Permission denied\n")
	libbpfLog.log(bpf.LibbpfWarnLevel, verifierLoadWarning("ior_x", "0: R1=ctx() R10=fp0\n"+verifierRejection))
	libbpfLog.log(bpf.LibbpfWarnLevel, "libbpf: prog 'ior_x': failed to load: -13\n")
	end()

	got := w.drain()
	if len(got) != 3 {
		t.Fatalf("got %d rows, want 3: %q", len(got), got)
	}
	if got[0] != "libbpf: prog 'ior_x': BPF program load failed: Permission denied" || got[2] != "libbpf: prog 'ior_x': failed to load: -13" {
		t.Errorf("one-line rows changed: %q", got)
	}
	if !strings.Contains(got[1], "verifier: ") || !strings.Contains(got[1], "R1 invalid mem access 'scalar'") ||
		!strings.Contains(got[1], "processed 2 insns") || strings.Contains(got[1], progLoadLogBegin) {
		t.Errorf("verifier row = %q, want the reason instead of the banner", got[1])
	}
}

// TestSetupFailureAfterAttachCountsTheSummaryRow mirrors the order inside
// setupTraceInfraBPF (route installed, deferred end flushes the over-cap summary
// row when the BPF stage returns) followed by a later setup stage failing: the
// summary row is already in the collector when explainFailure drains it, so it
// is counted with the rest (maxRoutedWarnings rows + the summary = 17 messages,
// of which the error lists maxFailureWarnings and counts the others).
func TestSetupFailureAfterAttachCountsTheSummaryRow(t *testing.T) {
	withLibbpfLogger(t, true, false)
	w := &setupWarnings{}
	end := libbpfLog.routeWarnings(w.add)
	libbpfLog.log(bpf.LibbpfWarnLevel, verifierLoadWarning("ior_x", verifierRejection))
	for i := 0; i < maxRoutedWarnings+2; i++ {
		libbpfLog.log(bpf.LibbpfWarnLevel, "libbpf: filler\n")
	}
	end() // the BPF stage is over; the failure below comes from a later stage

	text := w.explainFailure(errors.New("start event loop: boom")).Error()
	extra := maxRoutedWarnings + 1 - maxFailureWarnings
	for _, want := range []string{
		"start event loop: boom",
		"R1 invalid mem access 'scalar'", // the first row: the verifier's reason
		fmt.Sprintf("... and %d more warning(s)", extra),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("error text lacks %q:\n%s", want, text)
		}
	}
	// The collector held the summary row: it is among the counted ones.
	if got := w.drain(); len(got) != 0 {
		t.Errorf("collector still holds %q", got)
	}
}

// TestExplainFailureKeepsTheRouteMarkerWhenCutting: explainFailure cuts the
// content of a row the route already shaped, not its "(N more lines)" suffix.
func TestExplainFailureKeepsTheRouteMarkerWhenCutting(t *testing.T) {
	w := &setupWarnings{}
	w.add(strings.Repeat("z", 2*maxFailureWarningBytes) + " ... (7 more lines)")
	text := w.explainFailure(errors.New("boom")).Error()
	if !strings.HasSuffix(text, "... (7 more lines)") {
		t.Fatalf("route marker lost: %q", text[max(0, len(text)-80):])
	}
}

// TestExplainFailureSummarisesARawVerifierLog: a collector user that adds the
// raw multi-line warning (not routed through libbpfRoute) gets the same
// reason-bearing row, escaped.
func TestExplainFailureSummarisesARawVerifierLog(t *testing.T) {
	w := &setupWarnings{}
	w.add(verifierLoadWarning("ior_x", "0: (b7) r0 = 0\n"+verifierRejection+"\x1b[31mred\n"))
	text := w.explainFailure(errors.New("failed to load BPF object: permission denied")).Error()
	for _, want := range []string{"libbpf: prog 'ior_x': verifier:", "R1 invalid mem access 'scalar'", `\x1b[31mred`} {
		if !strings.Contains(text, want) {
			t.Errorf("error text lacks %q:\n%s", want, text)
		}
	}
	if strings.ContainsRune(text, 0x1b) {
		t.Errorf("raw ESC reached the error text: %q", text)
	}
}
