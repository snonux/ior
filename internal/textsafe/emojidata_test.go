package textsafe

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Where the Unicode emoji data files are looked for. The environment
// variables override the distribution paths, so a developer can point the
// tests at files from another Unicode version (for example the ICU source
// tree's source/data/unidata/emoji-zwj-sequences.txt). The tests skip when
// no file is found, so they never depend on the machine that runs them.
const (
	emojiDataEnv = "IOR_EMOJI_DATA"
	zwjSeqEnv    = "IOR_EMOJI_ZWJ_SEQUENCES"
)

var (
	emojiDataPaths = []string{
		"/usr/share/unicode/ucd/emoji/emoji-data.txt",
		"/usr/share/unicode/emoji/emoji-data.txt",
	}
	zwjSeqPaths = []string{
		"/usr/share/unicode/ucd/emoji/emoji-zwj-sequences.txt",
		"/usr/share/unicode/emoji/emoji-zwj-sequences.txt",
	}
)

// openUnicodeFile opens the first readable of env (when set) and paths, or
// skips the test with the reason.
func openUnicodeFile(t *testing.T, env string, paths []string) *os.File {
	t.Helper()
	candidates := paths
	if p := os.Getenv(env); p != "" {
		candidates = append([]string{p}, paths...)
	}
	for _, p := range candidates {
		if f, err := os.Open(p); err == nil {
			t.Cleanup(func() { _ = f.Close() })
			return f
		}
	}
	t.Skipf("no Unicode data file found in %v (set %s to point at one)", candidates, env)
	return nil
}

// dataLines calls fn with the field part (before '#') of each non-comment
// line of f, trimmed, split on ';' and with each field trimmed.
func dataLines(t *testing.T, f *os.File, fn func(fields []string)) {
	t.Helper()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, ";")
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		fn(fields)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
}

// parseCodePoints parses "1F468 200D 1F469" into a string.
func parseCodePoints(t *testing.T, field string) string {
	t.Helper()
	var b strings.Builder
	for _, hex := range strings.Fields(field) {
		cp, err := strconv.ParseUint(hex, 16, 32)
		if err != nil {
			t.Fatalf("bad code point %q in %q: %v", hex, field, err)
		}
		b.WriteRune(rune(cp))
	}
	return b.String()
}

// TestEmojiBasesMatchEmojiData is the table-sync check: isEmojiBase must
// accept exactly the code points that emoji-data.txt lists as
// Extended_Pictographic, Emoji_Modifier_Base or Emoji_Modifier. When a newer
// Unicode version adds emoji, regenerate emojiBases from the file (merge the
// ranges of those three properties).
func TestEmojiBasesMatchEmojiData(t *testing.T) {
	f := openUnicodeFile(t, emojiDataEnv, emojiDataPaths)
	want := map[rune]bool{}
	dataLines(t, f, func(fields []string) {
		switch fields[1] {
		case "Extended_Pictographic", "Emoji_Modifier_Base", "Emoji_Modifier":
		default:
			return
		}
		lo, hi, isRange := strings.Cut(fields[0], "..")
		first := []rune(parseCodePoints(t, lo))[0]
		last := first
		if isRange {
			last = []rune(parseCodePoints(t, hi))[0]
		}
		for r := first; r <= last; r++ {
			want[r] = true
		}
	})
	if len(want) == 0 {
		t.Fatal("no emoji properties parsed; emoji-data.txt format changed?")
	}
	for r := rune(0); r <= 0x10FFFF; r++ {
		if got := isEmojiBase(r); got != want[r] {
			t.Fatalf("isEmojiBase(%U) = %v, emoji-data.txt says %v; regenerate emojiBases", r, got, want[r])
		}
	}
}

// TestEmojiBasesExcludeSymbolBlocks pins the tightening (task 1q2): runes
// from blocks that merely neighbour emoji must not vouch for a ZWJ or a
// variation selector, and emoji bases must survive the classification
// themselves (a base that ClassAt replaced would make the decision unstable).
func TestEmojiBasesExcludeSymbolBlocks(t *testing.T) {
	for _, r := range []rune{
		0x1F1E6, 0x1F1E9, 0x1F1FF, // regional indicators
		0x25A0, 0x25B2, 0x2190, 0x2B00, 0x2B1A, 0x1F100, 0x1F800, 0x1FB00,
	} {
		if isEmojiBase(r) {
			t.Errorf("isEmojiBase(%U) = true, want false", r)
		}
		if s := "‍" + string(r); FirstUnsafe("a"+string(r)+s, false) < 0 {
			t.Errorf("ZWJ after %U kept, want replaced", r)
		}
	}
	for _, s := range []string{"\U0001F1E9‍\U0001F1EA", "■‍▲", "▲️"} {
		if FirstUnsafe(s, false) < 0 {
			t.Errorf("FirstUnsafe(%q) = -1, want an unsafe rune", s)
		}
	}
	for r := rune(0); r <= 0x10FFFF; r++ {
		if !isEmojiBase(r) {
			continue
		}
		if class, _ := ClassAt(string(r), 0); class != Safe {
			t.Fatalf("emoji base %U is not Safe (class %d)", r, class)
		}
	}
}

// TestEmojiZWJSequencesStaySafe checks every RGI emoji ZWJ sequence of the
// local emoji-zwj-sequences.txt (1468 in Unicode 15.1) passes Escape and
// FirstUnsafe unchanged, so the tightened emoji set loses no real sequence.
func TestEmojiZWJSequencesStaySafe(t *testing.T) {
	f := openUnicodeFile(t, zwjSeqEnv, zwjSeqPaths)
	n := 0
	dataLines(t, f, func(fields []string) {
		seq := parseCodePoints(t, fields[0])
		n++
		if i := FirstUnsafe(seq, false); i >= 0 {
			t.Errorf("ZWJ sequence %q (%s) has an unsafe rune at byte %d", seq, fields[0], i)
		}
		if got := Escape(seq); got != seq {
			t.Errorf("Escape changed ZWJ sequence %q (%s) to %q", seq, fields[0], got)
		}
	})
	if n == 0 {
		t.Fatal("no sequences parsed; emoji-zwj-sequences.txt format changed?")
	}
	t.Logf("checked %d ZWJ sequences", n)
}
