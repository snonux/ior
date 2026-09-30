package globalfilter

import (
	"strings"
	"testing"

	"ior/internal/types"
)

func TestValidateTracepointFieldsRejectsOversizedPatterns(t *testing.T) {
	tooLongComm := strings.Repeat("a", types.MAX_PROGNAME_LENGTH+1)
	if err := (Filter{Comm: &StringFilter{Pattern: tooLongComm}}).ValidateTracepointFields(); err == nil {
		t.Fatalf("expected oversized comm pattern to fail validation")
	}

	tooLongPath := strings.Repeat("b", types.MAX_FILENAME_LENGTH+1)
	if err := (Filter{File: &StringFilter{Pattern: tooLongPath}}).ValidateTracepointFields(); err == nil {
		t.Fatalf("expected oversized path pattern to fail validation")
	}
}

func TestValidateTracepointFieldsIgnoresAnchors(t *testing.T) {
	exactComm := "^" + strings.Repeat("a", types.MAX_PROGNAME_LENGTH-1) + "$"
	if err := (Filter{Comm: &StringFilter{Pattern: exactComm}}).ValidateTracepointFields(); err != nil {
		t.Fatalf("expected anchored max-length comm pattern to pass validation: %v", err)
	}
}

// TestValidateTracepointFieldsDirChildrenPattern pins the kernel-side length
// check of ^dir/*: its shortest witness is "dir/" (the empty name directly in
// dir), not the pattern text "dir/*", and the root's is "/". A dir whose
// witness needs the whole NUL-terminated buffer is rejected.
func TestValidateTracepointFieldsDirChildrenPattern(t *testing.T) {
	usable := types.MAX_FILENAME_LENGTH - 1
	fits := DirPattern(strings.Repeat("d", usable-1))
	if err := (Filter{File: &StringFilter{Pattern: fits}}).ValidateTracepointFields(); err != nil {
		t.Fatalf("expected dir-children pattern with a %d-byte witness to pass: %v", usable, err)
	}
	tooLong := DirPattern(strings.Repeat("d", usable))
	if err := (Filter{File: &StringFilter{Pattern: tooLong}}).ValidateTracepointFields(); err == nil {
		t.Fatalf("expected dir-children pattern with a %d-byte witness to fail", usable+1)
	}
	for pattern, want := range map[string]int{"^/*": 1, "^//*": 1, "^/tmp/*": 5, "^a//*": 3} {
		if got := shortestWitnessLen(pattern); got != want {
			t.Errorf("shortestWitnessLen(%q) = %d, want %d", pattern, got, want)
		}
	}

	ev := &types.PathEvent{}
	copy(ev.Pathname[:], "/tmp/sub/x")
	if (Filter{File: &StringFilter{Pattern: DirPattern("/tmp")}}).MatchPathEvent(ev) {
		t.Fatalf("expected ^/tmp/* not to match a raw event in a subdirectory")
	}
}

func TestTracepointHelpersMatchRawEvents(t *testing.T) {
	filter := Filter{
		Comm: &StringFilter{Pattern: "^nginx"},
		File: &StringFilter{Pattern: "access.log$"},
	}

	open := &types.OpenEvent{}
	copy(open.Comm[:], "nginx-worker")
	copy(open.Filename[:], "/var/log/nginx/access.log")
	if !filter.MatchOpenEvent(open) {
		t.Fatalf("expected open event to match comm and file filters")
	}

	path := &types.PathEvent{}
	copy(path.Pathname[:], "/var/log/nginx/access.log")
	if !filter.MatchPathEvent(path) {
		t.Fatalf("expected path event to match file filter")
	}

	name := &types.NameEvent{}
	copy(name.Oldname[:], "/tmp/old.log")
	copy(name.Newname[:], "/var/log/nginx/access.log")
	if !filter.MatchNameEvent(name) {
		t.Fatalf("expected rename event to match file filter via newname")
	}
}

// TestMatchOpenEventCommDropsOnlyTheFileDimension pins the split MatchOpenEvent
// was refactored into. matchRawOpenEvent (internal/eventloop_kinds.go) uses the
// comm-only form for an open whose sys_enter filename read faulted: its real
// path arrives a moment later as a fixup control record, so judging the file
// dimension on the empty payload name would answer it with "no name, no match"
// and drop the event before the recovery could be applied. The comm dimension
// must keep biting, and this must be the *only* difference from MatchOpenEvent.
func TestMatchOpenEventCommDropsOnlyTheFileDimension(t *testing.T) {
	filter := Filter{
		Comm: &StringFilter{Pattern: "ioworkload"},
		File: &StringFilter{Pattern: "locale-archive"},
	}
	emptyName := &types.OpenEvent{}
	copy(emptyName.Comm[:], "ioworkload")
	if filter.MatchOpenEvent(emptyName) {
		t.Error("MatchOpenEvent must not match an empty filename against a -path pattern")
	}
	if !filter.MatchOpenEventComm(emptyName) {
		t.Error("MatchOpenEventComm must accept a matching comm regardless of the filename")
	}

	wrongComm := &types.OpenEvent{}
	copy(wrongComm.Comm[:], "someoneelse")
	if filter.MatchOpenEventComm(wrongComm) {
		t.Error("MatchOpenEventComm must still apply the comm dimension")
	}

	if filter.MatchOpenEventComm(nil) {
		t.Error("MatchOpenEventComm(nil) must not match")
	}
}

// TestValidateTracepointFieldsMeasuresTheMatchedTextNotTheAnchors pins the
// agreement between the length check and the matcher.
//
// The anchors are syntax: matchString strips `^`/`$` before comparing, and the
// filter modal advertises `^exact$` as the way to match exactly. Measuring the
// raw pattern rejected `^` plus the longest possible comm plus `$` - the
// documented way to exact-match it.
//
// The boundary is one byte below the buffer size, because the kernel
// NUL-terminates what it writes: MAX_PROGNAME_LENGTH is 16, so 15 bytes is the
// longest comm that can ever arrive and a 16-byte pattern is unmatchable. That
// case is the one the anchor fix nearly let through - unanchored it was always
// wrongly accepted, and trimming the anchors would have started accepting the
// anchored form too.
//
// This only became user-visible when the TUI started validating live filter
// swaps (task l3); before that an over-long pattern failed the trace outright.
func TestValidateTracepointFieldsMeasuresTheMatchedTextNotTheAnchors(t *testing.T) {
	longestComm := strings.Repeat("a", types.MAX_PROGNAME_LENGTH-1)

	anchored := Filter{Comm: &StringFilter{Pattern: "^" + longestComm + "$"}}
	if err := anchored.ValidateTracepointFields(); err != nil {
		t.Errorf("anchored exact match on the longest possible comm was rejected: %v", err)
	}
	// And it really does match, so rejecting it cost a working filter.
	if !matchString(anchored.Comm, longestComm) {
		t.Errorf("%q does not match %q; the premise of this test is wrong", anchored.Comm.Pattern, longestComm)
	}

	// A pattern the width of the whole buffer cannot match anything, anchored
	// or not: the NUL takes the last byte.
	bufferWidth := strings.Repeat("a", types.MAX_PROGNAME_LENGTH)
	for _, pattern := range []string{bufferWidth, "^" + bufferWidth + "$"} {
		f := Filter{Comm: &StringFilter{Pattern: pattern}}
		if err := f.ValidateTracepointFields(); err == nil {
			t.Errorf("pattern %q is as wide as the whole comm buffer and can never match, but was accepted", pattern)
		}
	}

	// The validator normalises case the way matchString does, so a pattern
	// whose lowered form fits is not rejected on its raw length. U+212A lowers
	// to a single-byte "k".
	kelvin := Filter{Comm: &StringFilter{Pattern: strings.Repeat("\u212A", 6)}}
	if err := kelvin.ValidateTracepointFields(); err != nil {
		t.Errorf("a pattern whose lowered form is 6 bytes was rejected on its raw length: %v", err)
	}

	// The exact form is case-sensitive, so its lowered form is no witness: the
	// same six Kelvin signs anchored as ^...$ match only their 18 raw bytes,
	// which no 15-byte comm can hold.
	exactKelvin := Filter{Comm: &StringFilter{Pattern: ExactPattern(strings.Repeat("\u212A", 6))}}
	if err := exactKelvin.ValidateTracepointFields(); err == nil {
		t.Error("an exact pattern whose raw form is 18 bytes was accepted for a 15-byte comm")
	}
}

// TestEveryAcceptedPatternHasADeliverableWitness pins the property the length
// check actually has to hold, rather than the individual cases it has been
// wrong about.
//
// That check has now been wrong four separate ways: it counted `^`/`$` the
// matcher strips, it used the buffer size where the kernel's NUL leaves one
// byte less, it measured the raw pattern where matchString compares the
// lowered one, and then it measured the lowered one where ToLower grows two
// runes. Every one was a different special case of one question - can any
// value the kernel can deliver match this pattern? - so that is what is
// asserted here.
//
// A pattern is accepted only if some value of at most the usable field width
// matches it. The witness is the pattern's own text: whichever of the raw or
// lowered form fits, matchString accepts it under every case-insensitive
// anchor mode, because it lowercases both sides there; for the case-sensitive
// exact form ^...$ only the raw form can match, and trying the lowered one
// too is harmless (matchString rejects it unless it equals the raw form).
// That the two forms always agree on the anchor
// flags is not assumed - checked exhaustively over every valid rune: ToLower
// is idempotent and never creates or destroys a leading `^` or trailing `$`
// (UTF-8 is self-synchronising, so no multi-byte rune can end in the byte
// 0x24 either).
//
// Honest about its limits: the witness is built the same way the validator
// computes its length, so this does not independently re-derive the bound.
// What it does independently is run the real matchString, and every one of the
// four bugs was the validator disagreeing with that function - which is why it
// catches all four.
func TestEveryAcceptedPatternHasADeliverableWitness(t *testing.T) {
	usable := types.MAX_PROGNAME_LENGTH - 1

	// Runes chosen for how ToLower changes their byte length: shrinking
	// (U+212A lowers to one-byte "k"), growing (U+023A lowers to a three-byte
	// rune), and neutral.
	for _, base := range []string{"a", "A", "K", "Ⱥ", "ß", " "} {
		for count := 1; count <= 12; count++ {
			body := strings.Repeat(base, count)
			for _, pattern := range []string{body, "^" + body, body + "$", "^" + body + "$"} {
				f := Filter{Comm: &StringFilter{Pattern: pattern}}
				accepted := f.ValidateTracepointFields() == nil

				// Does a value the kernel could deliver match this pattern?
				// Both forms are tried because either may be the shorter one.
				matchable := false
				for _, witness := range []string{
					strings.TrimSpace(pattern),
					strings.ToLower(strings.TrimSpace(pattern)),
				} {
					trimmed, _, _ := trimAnchors(witness)
					if len(trimmed) <= usable && matchString(f.Comm, trimmed) {
						matchable = true
						break
					}
				}

				// Both directions matter, and the check has been wrong in each
				// of them: accepting an unmatchable pattern is the silent empty
				// stream this validation exists to prevent, and rejecting a
				// matchable one takes away a filter that works.
				switch {
				case accepted && !matchable:
					t.Errorf("pattern %q was accepted but no value of %d bytes or fewer can match it", pattern, usable)
				case !accepted && matchable:
					t.Errorf("pattern %q was rejected although a %d-byte value matches it", pattern, usable)
				}
			}
		}
	}
}

// TestPathFilterUsesTheSameUsableWidthAsComm pins the path dimension's own
// off-by-one. Only comm was covered, so reverting the path limit to the raw
// buffer size left the whole suite green.
func TestPathFilterUsesTheSameUsableWidthAsComm(t *testing.T) {
	bufferWidth := strings.Repeat("a", types.MAX_FILENAME_LENGTH)
	f := Filter{File: &StringFilter{Pattern: bufferWidth}}
	if err := f.ValidateTracepointFields(); err == nil {
		t.Error("a path pattern as wide as the whole filename buffer was accepted; the NUL takes the last byte")
	}

	usable := Filter{File: &StringFilter{Pattern: strings.Repeat("a", types.MAX_FILENAME_LENGTH-1)}}
	if err := usable.ValidateTracepointFields(); err != nil {
		t.Errorf("the longest deliverable path was rejected: %v", err)
	}
}
