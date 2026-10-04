//go:build ignore

// gen_emoji generates emojitable.go, the range table behind isEmojiBase, from
// the Unicode Character Database file emoji-data.txt:
//
//	go generate ./internal/textsafe
//
// (the directive lives in classify.go; run it from anywhere in the module).
// It merges the code points of the properties Extended_Pictographic,
// Emoji_Modifier_Base and Emoji_Modifier into sorted, non-overlapping ranges
// and writes them with a "Code generated ... DO NOT EDIT." header that records
// the Unicode version and the date of the source file. The output depends
// only on the input file, so regenerating from the same file is a no-op.
//
// The file is build-ignored, so it is not part of the package and adds no
// dependency; `go run gen_emoji.go` executes it directly.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"go/format"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
)

// wantedProperties are the emoji-data.txt properties isEmojiBase accepts.
var wantedProperties = map[string]bool{
	"Extended_Pictographic": true,
	"Emoji_Modifier_Base":   true,
	"Emoji_Modifier":        true,
}

// span is an inclusive code point range.
type span struct{ lo, hi uint32 }

// source is what the generator extracts from emoji-data.txt.
type source struct {
	version string // the "# Version:" header value, e.g. "17.0"
	date    string // the "# Date:" header value, e.g. "2025-07-25, 17:54:31 GMT"
	spans   []span // raw (unmerged) ranges of the wanted properties
}

func main() {
	in := flag.String("in", "", "path of emoji-data.txt (required)")
	out := flag.String("out", "emojitable.go", "file to write")
	flag.Parse()
	if *in == "" {
		log.Fatal("gen_emoji: -in <emoji-data.txt> is required")
	}
	src, err := readSource(*in)
	if err != nil {
		log.Fatalf("gen_emoji: %v", err)
	}
	code, err := render(src)
	if err != nil {
		log.Fatalf("gen_emoji: %v", err)
	}
	if err := os.WriteFile(*out, code, 0o644); err != nil {
		log.Fatalf("gen_emoji: %v", err)
	}
}

// readSource parses the header (version, date) and the wanted property lines.
func readSource(path string) (source, error) {
	f, err := os.Open(path)
	if err != nil {
		return source{}, err
	}
	defer f.Close()

	var src source
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "# Version:"); ok && src.version == "" {
			src.version = strings.TrimSpace(v)
			continue
		}
		if v, ok := strings.CutPrefix(line, "# Date:"); ok && src.date == "" {
			src.date = strings.TrimSpace(v)
			continue
		}
		sp, ok, err := parseLine(line)
		if err != nil {
			return source{}, fmt.Errorf("%s: %w", path, err)
		}
		if ok {
			src.spans = append(src.spans, sp)
		}
	}
	if err := sc.Err(); err != nil {
		return source{}, err
	}
	if src.version == "" || src.date == "" || len(src.spans) == 0 {
		return source{}, fmt.Errorf("%s: no version, date or emoji properties found; is it emoji-data.txt?", path)
	}
	return src, nil
}

// parseLine returns the range of a "LO[..HI] ; Property # comment" line when
// the property is wanted, and ok=false for comments, blanks and other
// properties.
func parseLine(line string) (sp span, ok bool, err error) {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	codes, prop, found := strings.Cut(line, ";")
	if !found || !wantedProperties[strings.TrimSpace(prop)] {
		return span{}, false, nil
	}
	lo, hi, isRange := strings.Cut(strings.TrimSpace(codes), "..")
	if !isRange {
		hi = lo
	}
	first, err := strconv.ParseUint(lo, 16, 32)
	if err != nil {
		return span{}, false, fmt.Errorf("bad code point in %q: %w", line, err)
	}
	last, err := strconv.ParseUint(hi, 16, 32)
	if err != nil || last < first {
		return span{}, false, fmt.Errorf("bad range in %q", line)
	}
	return span{uint32(first), uint32(last)}, true, nil
}

// mergeSpans sorts the ranges and joins overlapping or adjacent ones, so the
// table is minimal and independent of the order of the input lines.
func mergeSpans(in []span) []span {
	sorted := append([]span(nil), in...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].lo < sorted[j].lo })
	var merged []span
	for _, s := range sorted {
		if n := len(merged); n > 0 && s.lo <= merged[n-1].hi+1 {
			if s.hi > merged[n-1].hi {
				merged[n-1].hi = s.hi
			}
			continue
		}
		merged = append(merged, s)
	}
	return merged
}

// splitBMP divides merged ranges into those entirely in the Basic
// Multilingual Plane (unicode.Range16) and the rest (unicode.Range32); a range
// straddling U+FFFF is cut in two.
func splitBMP(merged []span) (r16, r32 []span) {
	const maxBMP = 0xFFFF
	for _, s := range merged {
		switch {
		case s.hi <= maxBMP:
			r16 = append(r16, s)
		case s.lo > maxBMP:
			r32 = append(r32, s)
		default:
			r16 = append(r16, span{s.lo, maxBMP})
			r32 = append(r32, span{maxBMP + 1, s.hi})
		}
	}
	return r16, r32
}

// render builds the gofmt-formatted source of emojitable.go.
func render(src source) ([]byte, error) {
	r16, r32 := splitBMP(mergeSpans(src.spans))
	var b strings.Builder
	fmt.Fprintf(&b, "// Code generated by gen_emoji.go from emoji-data.txt (Unicode %s, file date %s); DO NOT EDIT.\n", src.version, src.date)
	b.WriteString("// Regenerate with: go generate ./internal/textsafe\n\n")
	b.WriteString(tableDoc)
	b.WriteString("var emojiBases = &unicode.RangeTable{\n")
	writeRanges(&b, "R16", "Range16", r16)
	writeRanges(&b, "R32", "Range32", r32)
	b.WriteString("}\n")
	return format.Source([]byte(b.String()))
}

// writeRanges emits one R16 or R32 slice literal; an empty slice is omitted.
func writeRanges(b *strings.Builder, field, typ string, spans []span) {
	if len(spans) == 0 {
		return
	}
	fmt.Fprintf(b, "\t%s: []unicode.%s{\n", field, typ)
	for _, s := range spans {
		fmt.Fprintf(b, "\t\t{Lo: 0x%04X, Hi: 0x%04X, Stride: 1},\n", s.lo, s.hi)
	}
	b.WriteString("\t},\n")
}

// tableDoc is the package, import and doc comment of the generated file. It
// is kept here so that regenerating never loses it.
const tableDoc = `package textsafe

import "unicode"

// emojiBases is the set of runes isEmojiBase accepts: every code point with
// the Unicode properties Extended_Pictographic, Emoji_Modifier_Base or
// Emoji_Modifier (the U+1F3FB..1F3FF skin tones), merged into ranges. The
// Extended_Pictographic ranges include the reserved code points that Unicode
// set aside for future emoji, so a new emoji renders correctly before this
// table is refreshed.
//
// Go's unicode package has no emoji tables, so the ranges are generated by
// gen_emoji.go from emoji-data.txt (version and date in the header above).
// TestEmojiBasesMatchEmojiData compares every code point against that file
// whenever it is present and names the command to run when they drift apart.
// Only emoji-data's own code points are in the set: regional indicators
// (U+1F1E6..1F1FF), which never take part in a ZWJ sequence, and ordinary
// arrows, geometric shapes and dingbats are not, while U+1F170 (negative
// squared A) and U+2764 (heavy black heart) are.
`
