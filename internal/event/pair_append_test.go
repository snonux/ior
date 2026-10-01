package event

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"testing"

	"ior/internal/file"
	"ior/internal/textsafe"
	"ior/internal/types"
)

// referenceCSVRow is the pre-optimisation CSVRow (fmt.Fprintf, a
// strings.Builder, File.String() and string-based quoting) kept as an
// executable specification: AppendCSVRow's append-based formatting must stay
// byte-identical to it for every file kind, escaper and hostile name.
func referenceCSVRow(e *Pair, escape func(string) string) string {
	field := func(s string) string {
		if escape != nil {
			s = escape(s)
		}
		return quoteCSVField(s)
	}
	var sb strings.Builder
	_, _ = fmt.Fprintf(&sb, "%08d,%08d,", e.DurationToPrev, e.Duration)
	sb.WriteString(field(e.Comm))
	sb.WriteString(",")
	sb.WriteString(strconv.FormatInt(int64(e.EnterEv.GetPid()), 10))
	sb.WriteString(".")
	sb.WriteString(strconv.FormatInt(int64(e.EnterEv.GetTid()), 10))
	sb.WriteString(",")
	sb.WriteString(field(e.EnterEv.GetTraceId().Name()))
	sb.WriteString(",")
	if retEv, ok := e.ExitEv.(RetCarrier); ok {
		sb.WriteString(strconv.FormatInt(retEv.GetRet(), 10))
	}
	sb.WriteString(",")
	if e.File == nil {
		sb.WriteString(NoFileName)
	} else {
		sb.WriteString(field(e.File.String()))
	}
	return sb.String()
}

// TestAppendCSVRowGolden pins literal rows, so a change to the format shows
// up as a diff of the expected text and not only as a disagreement between
// two implementations that share a bug.
func TestAppendCSVRowGolden(t *testing.T) {
	tests := []struct {
		name   string
		pair   *Pair
		escape func(string) string
		want   string
	}{
		{
			name: "fd file",
			pair: newStringTestPair("dd", 158022, 158022, types.SYS_ENTER_READ, types.SYS_EXIT_READ, 65536, file.NewFd(0, "/dev/zero", 0)),
			want: `00010074,00014126,dd,158022.158022,read,65536,"/dev/zero%(0,O_RDONLY)"`,
		},
		{
			name: "no file",
			pair: newStringTestPair("dd", 1, 2, types.SYS_ENTER_CLOSE, types.SYS_EXIT_CLOSE, -9, nil),
			want: `00010074,00014126,dd,1.2,close,-9,N:file`,
		},
		{
			name: "quotes in the file name are doubled",
			pair: newStringTestPair("dd", 1, 2, types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 3, file.NewFd(3, `/tmp/a"b`, 0)),
			want: `00010074,00014126,dd,1.2,openat,3,"/tmp/a""b%(3,O_RDONLY)"`,
		},
		{
			name: "empty name",
			pair: newStringTestPair("dd", 1, 2, types.SYS_ENTER_READ, types.SYS_EXIT_READ, 0, file.NewFd(7, "", 1)),
			want: `00010074,00014126,dd,1.2,read,0,"E:name%(7,O_WRONLY)"`,
		},
		{
			name: "anonymous mapping needs no quotes",
			pair: newStringTestPair("dd", 1, 2, types.SYS_ENTER_CLOSE, types.SYS_EXIT_CLOSE, 0, file.NewAnonymousMapping()),
			want: `00010074,00014126,dd,1.2,close,0,anon`,
		},
		{
			name: "rename pair",
			pair: newStringTestPair("mv", 1, 2, types.SYS_ENTER_CLOSE, types.SYS_EXIT_CLOSE, 0, file.NewOldnameNewname([]byte("/a"), []byte("/b"))),
			want: `00010074,00014126,mv,1.2,close,0,old:/a ->new:/b%(O_NONE)`,
		},
		{
			name: "durations wider than the padding are not truncated",
			pair: func() *Pair {
				p := newStringTestPair("dd", 1, 2, types.SYS_ENTER_CLOSE, types.SYS_EXIT_CLOSE, 0, nil)
				p.Duration, p.DurationToPrev = 1234567890123, 0
				return p
			}(),
			want: `00000000,1234567890123,dd,1.2,close,0,N:file`,
		},
		{
			name:   "escaper rewrites terminal controls before quoting",
			pair:   newStringTestPair("a\x1b[8mb", 1, 2, types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 3, file.NewFd(3, "/x\n\"y", 0)),
			escape: textsafe.Escape,
			want:   `00010074,00014126,a\x1b[8mb,1.2,openat,3,"/x\x0a""y%(3,O_RDONLY)"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.pair.CSVRow(tc.escape)
			if got != tc.want {
				t.Fatalf("CSVRow = %s\nwant     %s", got, tc.want)
			}
			if ref := referenceCSVRow(tc.pair, tc.escape); ref != tc.want {
				t.Fatalf("referenceCSVRow = %s, golden %s", ref, tc.want)
			}
		})
	}
}

// randomText builds a hostile name from an alphabet chosen to hit every
// quoting and escaping branch: delimiters, quotes, line breaks, leading
// Unicode spaces, ESC, a ZWJ next to emoji, and invalid UTF-8 bytes.
func randomText(r *rand.Rand) string {
	alphabet := []string{"a", "Z", "/", ".", ",", `"`, " ", "\n", "\r", "\t", "\x1b", "\u00a0",
		"\u200d", "\U0001F468", "é", "\xff", "\xc3", "%", "(", ")", "\\", "-", ">"}
	var sb strings.Builder
	for n := r.Intn(12); n > 0; n-- {
		sb.WriteString(alphabet[r.Intn(len(alphabet))])
	}
	return sb.String()
}

// randomFile picks one of the File kinds with random hostile names.
func randomFile(r *rand.Rand) file.File {
	switch r.Intn(5) {
	case 0:
		return nil
	case 1:
		return file.NewFd(int32(r.Intn(2000)-5), randomText(r), int32(r.Intn(1<<22)-1))
	case 2:
		return file.NewOldnameNewname([]byte(randomText(r)), []byte(randomText(r)))
	case 3:
		return file.NewPathname([]byte(randomText(r)))
	}
	return file.NewAnonymousMapping()
}

// TestAppendCSVRowMatchesReference compares the append-based row with the
// reference for thousands of random pairs under both escapers, which also
// proves the per-component escaping in file.StringAppender equals escaping
// the whole String() (the property the fast path relies on).
func TestAppendCSVRowMatchesReference(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		pair := newStringTestPair(randomText(r), r.Uint32(), r.Uint32(), types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, r.Int63()-r.Int63(), randomFile(r))
		pair.Duration, pair.DurationToPrev = r.Uint64()>>uint(r.Intn(64)), r.Uint64()>>uint(r.Intn(64))
		for _, escape := range []func(string) string{nil, textsafe.Escape} {
			want := referenceCSVRow(pair, escape)
			if got := pair.CSVRow(escape); got != want {
				t.Fatalf("iteration %d: CSVRow = %q, reference %q", i, got, want)
			}
		}
	}
}

// TestAppendCSVRowKeepsThePrefix is the negative test for the in-place
// quoting: growing the buffer and shifting the file field right must never
// touch bytes already in dst, including when the append has to reallocate.
func TestAppendCSVRowKeepsThePrefix(t *testing.T) {
	pair := newStringTestPair("dd", 1, 2, types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 3, file.NewFd(3, `"""`, 0))
	want := pair.CSVRow(nil)
	for _, capacity := range []int{0, 8, 1 << 10} {
		prefix := "keep me\n"
		dst := append(make([]byte, 0, capacity), prefix...)
		dst = pair.AppendCSVRow(dst, nil)
		if got := string(dst); got != prefix+want {
			t.Fatalf("capacity %d: got %q, want %q", capacity, got, prefix+want)
		}
	}
}

// TestQuoteInPlaceMatchesQuoteCSVField cross-checks the in-place quoting
// with the string form for fields at the boundaries: nothing to quote, all
// quotes, quotes at either end, and a field starting with a Unicode space.
func TestQuoteInPlaceMatchesQuoteCSVField(t *testing.T) {
	for _, in := range []string{"", "x", `"`, `""`, `a"`, `"a`, `,`, `\.`, "\u00a0x", " x", "x\ny", "\xff,\xfe", `a"b"c,d`} {
		dst := quoteInPlace(append([]byte("P:"), in...), 2)
		if got, want := string(dst), "P:"+quoteCSVField(in); got != want {
			t.Errorf("quoteInPlace(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCSVFieldNeedsQuotesBytesAgreeWithString guards the generic helper: the
// []byte instantiation the in-place path uses must answer as the string one.
func TestCSVFieldNeedsQuotesBytesAgreeWithString(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for i := 0; i < 5000; i++ {
		s := randomText(r)
		if csvFieldNeedsQuotes(s) != csvFieldNeedsQuotes([]byte(s)) {
			t.Fatalf("string and []byte disagree for %q", s)
		}
	}
}

func TestAppendZeroPadded(t *testing.T) {
	for _, v := range []uint64{0, 1, 9, 10, 1234567, 12345678, 123456789, 1<<64 - 1} {
		if got, want := string(appendZeroPadded([]byte("x"), v, csvDurationWidth)), fmt.Sprintf("x%08d", v); got != want {
			t.Errorf("appendZeroPadded(%d) = %q, want %q", v, got, want)
		}
	}
}

// fallbackFile is a File that does not implement file.StringAppender, to
// exercise the String()-based fallback for third-party implementations.
type fallbackFile struct{ file.File }

func (f fallbackFile) String() string { return `we"ird,` + f.File.String() }

func TestAppendCSVRowFallsBackToStringForPlainFiles(t *testing.T) {
	inner := file.NewFd(3, "/tmp/x", 0)
	pair := newStringTestPair("dd", 1, 2, types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 3, fallbackFile{inner})
	if _, ok := pair.File.(file.StringAppender); ok {
		t.Fatal("fallbackFile must not implement StringAppender")
	}
	want := `00010074,00014126,dd,1.2,openat,3,"we""ird,/tmp/x%(3,O_RDONLY)"`
	if got := pair.CSVRow(nil); got != want {
		t.Fatalf("CSVRow = %s, want %s", got, want)
	}
}

// BenchmarkPairAppendCSVRow measures the -plain hot path: one row appended
// into a reused buffer. BenchmarkPairCSVRow adds the string allocation and
// BenchmarkPairReferenceCSVRow is the old implementation for comparison.
func BenchmarkPairAppendCSVRow(b *testing.B) {
	pair := newStringTestPair("dd", 158022, 158022, types.SYS_ENTER_READ, types.SYS_EXIT_READ, 65536, file.NewFd(0, "/dev/zero", 0))
	buf := make([]byte, 0, 256)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf = pair.AppendCSVRow(buf[:0], nil)
	}
}

func BenchmarkPairCSVRow(b *testing.B) {
	pair := newStringTestPair("dd", 158022, 158022, types.SYS_ENTER_READ, types.SYS_EXIT_READ, 65536, file.NewFd(0, "/dev/zero", 0))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = pair.CSVRow(nil)
	}
}

func BenchmarkPairReferenceCSVRow(b *testing.B) {
	pair := newStringTestPair("dd", 158022, 158022, types.SYS_ENTER_READ, types.SYS_EXIT_READ, 65536, file.NewFd(0, "/dev/zero", 0))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = referenceCSVRow(pair, nil)
	}
}
