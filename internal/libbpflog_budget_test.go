package internal

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	bpf "github.com/aquasecurity/libbpfgo"

	"ior/internal/textsafe"
)

// TestShortenWarningGivesUnusedBytesToTheLongReason: a long reason between two
// short lines must survive whole while the row has room. An equal third of the
// budget per line used to cut a 166-byte reason in a 341-byte row.
func TestShortenWarningGivesUnusedBytesToTheLongReason(t *testing.T) {
	for _, reasonLen := range []int{166, 300, 400} {
		reason := "R1 invalid mem access 'scalar' " + strings.Repeat("r", reasonLen-31)
		msg := verifierLoadWarning("ior_x", "0: (b7) r0 = 0\n2: (71) r0 = *(u8 *)(r1 +0)\n"+reason+"\nprocessed 2 insns\n")
		got := shortenWarning(msg, maxRoutedWarningBytes)
		want := "libbpf: prog 'ior_x': verifier: 2: (71) r0 = *(u8 *)(r1 +0) | " + reason + " | processed 2 insns ... (1 more lines)"
		if got != want {
			t.Errorf("reason of %d bytes:\n got %q\nwant %q", reasonLen, got, want)
		}
		if len(got) > maxRoutedWarningBytes {
			t.Errorf("reason of %d bytes: row is %d bytes, over the bound", reasonLen, len(got))
		}
	}
}

// TestShortenWarningCutsLongLinesWithinTheLimit is the reviewer's case: three
// 306-byte log lines used to make a 540-byte row (each line's "..." came on top
// of its share), which explainFailure then cut a second time. The row must be
// at most the limit and every long line gets an equal share, the remainder
// going to the end of the log.
func TestShortenWarningCutsLongLinesWithinTheLimit(t *testing.T) {
	line := func(c string) string { return strings.Repeat(c, 306) }
	msg := verifierLoadWarning("ior_x", "skipped\n"+line("a")+"\n"+line("b")+"\n"+line("c")+"\n")
	got := shortenWarning(msg, maxRoutedWarningBytes)
	if len(got) > maxRoutedWarningBytes || len(got) < maxRoutedWarningBytes-2 {
		t.Fatalf("row is %d bytes, want the %d-byte limit used up (less at most the 2-byte rounding)", len(got), maxRoutedWarningBytes)
	}
	if !strings.HasSuffix(got, " ... (1 more lines)") {
		t.Fatalf("marker lost: %q", got[len(got)-40:])
	}
	_, lines, _ := strings.Cut(strings.TrimSuffix(got, " ... (1 more lines)"), verifierLabel)
	parts := strings.Split(lines, verifierSep)
	if len(parts) != 3 {
		t.Fatalf("got %d kept lines, want 3: %q", len(parts), got)
	}
	for i, part := range parts {
		if !strings.HasSuffix(part, cutEllipsis) {
			t.Errorf("line %d not marked as cut: %q", i, part)
		}
	}
	if a, c := len(parts[0]), len(parts[2]); c < a || c-a > 1 {
		t.Errorf("shares %d/%d/%d are not equal with the remainder at the end", a, len(parts[1]), c)
	}
}

// TestShortenWarningIsIdempotentOnLongRows pins shorten(shorten(x)) ==
// shorten(x) where it used to fail: long verifier lines, a 200-byte program
// name (521 -> 515 bytes before), multi-line and single-line overlong rows,
// at the production bound and at smaller ones.
func TestShortenWarningIsIdempotentOnLongRows(t *testing.T) {
	inputs := []string{
		verifierLoadWarning("ior_x", strings.Repeat("a", 306)+"\n"+strings.Repeat("b", 306)+"\n"+strings.Repeat("c", 306)+"\n"),
		verifierLoadWarning(strings.Repeat("n", 200), strings.Repeat("x", 400)+"\nR1 bad\nprocessed 1 insns\n"),
		verifierLoadWarning("p", strings.Repeat("é", 600)+"\n"),
		strings.Repeat("g", 2000) + "\nmore\nlines",
		strings.Repeat("h", 2000) + " ... (9 more lines)",
		strings.Repeat("\x80", 900),
	}
	for _, limit := range []int{maxRoutedWarningBytes, 200, 64} {
		for i, in := range inputs {
			once := shortenWarning(in, limit)
			if len(once) > limit {
				t.Errorf("input %d, limit %d: row is %d bytes", i, limit, len(once))
			}
			if twice := shortenWarning(once, limit); twice != once {
				t.Errorf("input %d, limit %d: not idempotent:\n %q\n %q", i, limit, once, twice)
			}
		}
	}
}

// TestShortenWarningCutsAPathologicalProgramNameToItsCap pins the exact prefix:
// the program name is cut to maxVerifierPrefixBytes, "..." included, and the
// reason follows it whole.
func TestShortenWarningCutsAPathologicalProgramNameToItsCap(t *testing.T) {
	got := shortenWarning(verifierLoadWarning(strings.Repeat("n", 5000), "R1 bad\n"), maxRoutedWarningBytes)
	prefix := "libbpf: prog '" + strings.Repeat("n", maxVerifierPrefixBytes-len("libbpf: prog '")-len(cutEllipsis)) + cutEllipsis
	if want := prefix + " verifier: R1 bad"; got != want {
		t.Fatalf("row =\n %q\nwant\n %q", got, want)
	}
	if len(prefix) != maxVerifierPrefixBytes {
		t.Fatalf("test prefix is %d bytes, want %d", len(prefix), maxVerifierPrefixBytes)
	}
}

// TestRouteThenExplainFailureKeepsALongVerifierRowIntact runs the real path: a
// long verifier WARN is routed (shaped to the route bound), the setup then
// fails and explainFailure shortens the row again with the same bound. The
// error must carry the routed row byte for byte - the end of its last line
// (the reason) used to be cut off a second time.
func TestRouteThenExplainFailureKeepsALongVerifierRowIntact(t *testing.T) {
	withLibbpfLogger(t, true, false)
	for _, msg := range []string{
		verifierLoadWarning("ior_x", "skipped\n"+strings.Repeat("a", 306)+"\n"+strings.Repeat("b", 306)+"\n"+strings.Repeat("c", 300)+"END-OF-REASON\n"),
		verifierLoadWarning(strings.Repeat("n", 200), strings.Repeat("x", 400)+"\nR1 invalid mem access 'scalar'\nprocessed 2 insns\n"),
	} {
		w := &setupWarnings{}
		end := libbpfLog.routeWarnings(w.add)
		libbpfLog.log(bpf.LibbpfWarnLevel, msg)
		end()
		routed := w.drain()
		if len(routed) != 1 || len(routed[0]) > maxRoutedWarningBytes {
			t.Fatalf("routed rows = %q, want one row within %d bytes", routed, maxRoutedWarningBytes)
		}
		w.add(routed[0])

		text := w.explainFailure(errors.New("failed to load BPF object: permission denied")).Error()
		if want := "\n  - " + textsafe.Escape(routed[0]); !strings.HasSuffix(text, want) {
			t.Fatalf("error text does not carry the routed row unchanged:\n got %q\nwant suffix %q", text, want)
		}
	}
}

func TestFairShares(t *testing.T) {
	tests := []struct {
		lengths []int
		budget  int
		want    []int
	}{
		{[]int{10, 166, 20}, 300, []int{10, 166, 20}},     // everything fits
		{[]int{10, 400, 20}, 300, []int{10, 270, 20}},     // short lines lend their room
		{[]int{306, 306, 306}, 400, []int{133, 133, 134}}, // remainder to the last line
		{[]int{500, 50, 500}, 301, []int{125, 50, 126}},
		{[]int{5, 5}, -10, []int{0, 0}}, // negative budget: nothing, not negative
		{nil, 100, []int{}},
	}
	for _, tc := range tests {
		got := fairShares(tc.lengths, tc.budget)
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("fairShares(%v, %d) = %v, want %v", tc.lengths, tc.budget, got, tc.want)
		}
	}
}

// TestCutBytesKeepsInvalidUTF8Content: a run of stray continuation bytes has
// no rune boundary to step back to, so it is cut at the limit instead of
// being thrown away whole (600 x 0x80 used to become just "...").
func TestCutBytesKeepsInvalidUTF8Content(t *testing.T) {
	got := cutBytes(strings.Repeat("\x80", 600), 512)
	if want := strings.Repeat("\x80", 509) + cutEllipsis; got != want {
		t.Fatalf("cutBytes(600 x 0x80, 512) = %d bytes %q..., want 509 bytes plus %q", len(got), got[:min(len(got), 8)], cutEllipsis)
	}
	// Valid multi-byte text is still cut on a rune boundary, within the limit.
	if got := cutBytes(strings.Repeat("é", 10), 8); got != "éé..." {
		t.Errorf("cutBytes(10 x é, 8) = %q, want %q", got, "éé...")
	}
	if got := cutBytes("ééé", 2); got != "é" {
		t.Errorf("cutBytes below the ellipsis size = %q, want %q", got, "é")
	}
	if got := cutBytes("short", 5); got != "short" {
		t.Errorf("text within the limit changed: %q", got)
	}
}
