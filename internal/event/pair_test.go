package event

import (
	"encoding/csv"
	"strings"
	"testing"

	"ior/internal/file"
	"ior/internal/textsafe"
	"ior/internal/types"
)

func TestPairCalculateDurationsFirstEvent(t *testing.T) {
	enter := &types.OpenEvent{
		Time: 1000,
		Pid:  1,
		Tid:  2,
	}
	exit := &types.RetEvent{
		Time: 1100,
		Pid:  1,
		Tid:  2,
		Ret:  0,
	}

	pair := NewPair(enter)
	pair.ExitEv = exit
	pair.CalculateDurations(0)

	if pair.Duration != 100 {
		t.Fatalf("Duration = %d, want 100", pair.Duration)
	}
	if pair.DurationToPrev != 0 {
		t.Fatalf("DurationToPrev = %d, want 0 for first event", pair.DurationToPrev)
	}
	if !pair.FirstOnTID {
		t.Fatal("FirstOnTID = false, want true without a previous pair")
	}
}

func TestPairCalculateDurationsWithPreviousExit(t *testing.T) {
	enter := &types.OpenEvent{
		Time: 2000,
		Pid:  1,
		Tid:  2,
	}
	exit := &types.RetEvent{
		Time: 2100,
		Pid:  1,
		Tid:  2,
		Ret:  0,
	}

	pair := NewPair(enter)
	pair.ExitEv = exit
	pair.CalculateDurations(1500)

	if pair.Duration != 100 {
		t.Fatalf("Duration = %d, want 100", pair.Duration)
	}
	if pair.DurationToPrev != 500 {
		t.Fatalf("DurationToPrev = %d, want 500", pair.DurationToPrev)
	}
	if pair.FirstOnTID {
		t.Fatal("FirstOnTID = true, want false with a previous pair")
	}
}

// TestPairCalculateDurationsNegativeDelta verifies that non-monotonic BPF
// timestamps (exit < enter due to cross-CPU clock skew) do not cause uint64
// underflow. Both Duration and DurationToPrev must clamp to zero.
func TestPairCalculateDurationsNegativeDelta(t *testing.T) {
	enter := &types.OpenEvent{
		Time: 2000,
		Pid:  1,
		Tid:  2,
	}
	// Simulate clock skew: exit timestamp is earlier than enter.
	exit := &types.RetEvent{
		Time: 1900,
		Pid:  1,
		Tid:  2,
		Ret:  0,
	}

	pair := NewPair(enter)
	pair.ExitEv = exit
	// prevPairTime > enterTime also triggers underflow in DurationToPrev.
	pair.CalculateDurations(3000)

	if pair.Duration != 0 {
		t.Fatalf("Duration = %d, want 0 when exit < enter (underflow guard)", pair.Duration)
	}
	if pair.DurationToPrev != 0 {
		t.Fatalf("DurationToPrev = %d, want 0 when enter < prevPairTime (underflow guard)", pair.DurationToPrev)
	}
	// A clamped gap still had a previous pair: it is a measured 0, not "first".
	if pair.FirstOnTID {
		t.Fatal("FirstOnTID = true, want false for a clamped gap")
	}
}

// Recycle must clear FirstOnTID before the pair goes back to the pool, so a
// pooled pair cannot carry it into its next use. The pair is inspected right
// after Recycle (test only: nothing else takes it from the pool meanwhile).
func TestPairRecycleClearsFirstOnTID(t *testing.T) {
	pair := NewPair(&types.OpenEvent{Time: 1000, Tid: 2})
	pair.ExitEv = &types.RetEvent{Time: 1100, Tid: 2}
	pair.CalculateDurations(0)
	if !pair.FirstOnTID {
		t.Fatal("precondition: FirstOnTID = false, want true")
	}

	pair.Recycle()
	if pair.FirstOnTID {
		t.Fatal("Recycle kept FirstOnTID")
	}
}

// TestPairNoteRestartCountsAndSaturates covers task 203: every folded restart
// counts one, and the count stops at 255 instead of wrapping to a small number
// (the 256th would read 0, "never interrupted").
func TestPairNoteRestartCountsAndSaturates(t *testing.T) {
	pair := NewPair(&types.OpenEvent{Time: 1000, Tid: 2})
	defer pair.Recycle()
	if pair.Restarts != 0 {
		t.Fatalf("new pair Restarts = %d, want 0", pair.Restarts)
	}
	pair.NoteRestart()
	pair.NoteRestart()
	if pair.Restarts != 2 {
		t.Fatalf("Restarts after two folds = %d, want 2", pair.Restarts)
	}
	for i := 0; i < 400; i++ {
		pair.NoteRestart()
	}
	if pair.Restarts != 255 {
		t.Fatalf("Restarts after 402 folds = %d, want 255 (saturated)", pair.Restarts)
	}
}

// A pooled pair must not carry the count of the folded call it last was into
// its next use: Recycle clears it, and the next pair starts at 0. Inspected
// right after Recycle, as in the FirstOnTID test above.
func TestPairRecycleClearsRestarts(t *testing.T) {
	pair := NewPair(&types.OpenEvent{Time: 1000, Tid: 2})
	pair.NoteRestart()
	pair.Recycle()
	if pair.Restarts != 0 {
		t.Fatalf("Recycle kept Restarts = %d", pair.Restarts)
	}
	fresh := NewPair(&types.OpenEvent{Time: 3000, Tid: 3})
	defer fresh.Recycle()
	if fresh.Restarts != 0 {
		t.Fatalf("NewPair Restarts = %d, want 0", fresh.Restarts)
	}
}

func TestPairRecycleHandlesMissingExitEvent(t *testing.T) {
	pair := NewPair(&types.OpenEvent{
		Time: 1000,
		Pid:  1,
		Tid:  2,
	})

	pair.Recycle()
}

// newStringTestPair builds a Pair with a RetEvent exit so the ret column is
// populated. Fields left zero stay zero.
func newStringTestPair(comm string, pid, tid uint32, sysEnter, sysExit types.TraceId, ret int64, file file.File) *Pair {
	enter := &types.OpenEvent{
		TraceId: sysEnter,
		Pid:     pid,
		Tid:     tid,
	}
	exit := &types.RetEvent{
		TraceId: sysExit,
		Pid:     pid,
		Tid:     tid,
		Ret:     ret,
	}
	pair := NewPair(enter)
	pair.ExitEv = exit
	pair.File = file
	pair.Comm = comm
	pair.Duration = 14126
	pair.DurationToPrev = 10074
	return pair
}

// TestPairStringMatchesCSVHeader is the negative-style regression test for the
// -plain output format: every rendered row must parse with encoding/csv into
// exactly the header's column count, and the parsed fields must round-trip to
// the expected values. It also guards against the header itself drifting from
// the seven documented columns.
func TestPairStringMatchesCSVHeader(t *testing.T) {
	headerFields := strings.Split(EventStreamHeader, ",")
	const wantColumns = 7
	if len(headerFields) != wantColumns {
		t.Fatalf("EventStreamHeader has %d columns, want %d: %q", len(headerFields), wantColumns, EventStreamHeader)
	}
	if EventStreamHeader != "durationToPrevNs,durationNs,comm,pid.tid,name,ret,file" {
		t.Fatalf("EventStreamHeader = %q, want the documented 7-column schema", EventStreamHeader)
	}

	tests := []struct {
		name string
		pair *Pair
		want []string // expected parsed fields, aligned with headerFields
	}{
		{
			name: "simple open without file",
			pair: newStringTestPair("dd", 158022, 158022, types.SYS_ENTER_OPEN, types.SYS_EXIT_OPEN, 3, nil),
			want: []string{"00010074", "00014126", "dd", "158022.158022", "open", "3", "N:file"},
		},
		{
			name: "fd file with embedded comma in decoration",
			// FdFile.String() renders "/dev/zero%(0,O_RDONLY)" — the comma
			// inside must stay inside the quoted file column, so the naive
			// comma-split would have produced two fields.
			pair: newStringTestPair("dd", 158022, 158022, types.SYS_ENTER_READ, types.SYS_EXIT_READ, 65536, file.NewFd(0, "/dev/zero", 0)),
			want: []string{"00010074", "00014126", "dd", "158022.158022", "read", "65536", "/dev/zero%(0,O_RDONLY)"},
		},
		{
			name: "file name itself contains a comma",
			pair: newStringTestPair("svc", 1, 2, types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 4, file.NewFd(3, "/tmp/a,b.csv", 0)),
			want: []string{"00010074", "00014126", "svc", "1.2", "openat", "4", "/tmp/a,b.csv%(3,O_RDONLY)"},
		},
		{
			name: "comm with comma is quoted",
			pair: newStringTestPair("bad,comm", 7, 8, types.SYS_ENTER_CLOSE, types.SYS_EXIT_CLOSE, 0, nil),
			want: []string{"00010074", "00014126", "bad,comm", "7.8", "close", "0", "N:file"},
		},
		{
			name: "comm with double quote is quoted and escaped",
			pair: newStringTestPair(`we"ird`, 7, 8, types.SYS_ENTER_CLOSE, types.SYS_EXIT_CLOSE, 0, nil),
			want: []string{"00010074", "00014126", `we"ird`, "7.8", "close", "0", "N:file"},
		},
		{
			name: "empty comm and missing ret stay distinct columns",
			pair: func() *Pair {
				p := newStringTestPair("", 9, 10, types.SYS_ENTER_CLOSE, types.SYS_EXIT_CLOSE, 0, nil)
				// NullEvent is not a *RetEvent, so the ret column stays empty.
				p.ExitEv = &types.NullEvent{TraceId: types.SYS_EXIT_CLOSE, Pid: 9, Tid: 10}
				return p
			}(),
			want: []string{"00010074", "00014126", "", "9.10", "close", "", "N:file"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			row := tc.pair.String()

			parsed, err := csv.NewReader(strings.NewReader(row)).Read()
			if err != nil {
				t.Fatalf("csv.NewReader(...).Read() error for row %q: %v", row, err)
			}
			if len(parsed) != len(headerFields) {
				t.Fatalf("row %q parses into %d fields, header defines %d (%v)", row, len(parsed), len(headerFields), headerFields)
			}
			for i := range tc.want {
				if parsed[i] != tc.want[i] {
					t.Errorf("field %d (%s) = %q, want %q (row %q)", i, headerFields[i], parsed[i], tc.want[i], row)
				}
			}
		})
	}
}

// TestQuoteCSVFieldMatchesEncodingCSV cross-checks quoteCSVField against
// encoding/csv for a table of tricky inputs: both must produce byte-identical
// output, and the quoted form must round-trip through csv.Reader. The one
// exception is an embedded \r\n: csv.Reader normalizes that to \n even for
// encoding/csv's own writer output, so the round-trip expectation accounts
// for it.
func TestQuoteCSVFieldMatchesEncodingCSV(t *testing.T) {
	inputs := []string{
		"",
		"plain",
		"/dev/zero%(0,O_RDONLY)",
		`/tmp/a,b.csv`,
		`say "hi"`,
		"line\nbreak",
		"carriage\rreturn",
		`quo"te,comma`,
		"new\"line,\r\nmix",
		" leading space",
		"\ttab first",
		"\u00a0nbsp first",
		`\.`,
		"lead\u00a0mid",
		// Non-UTF-8 bytes (invalid alone and inside valid text): quoting must
		// copy bytes verbatim, not decode runes (which would insert U+FFFD).
		"\xff\xfe",
		"caf\xe9,\xc3\xbc.mp3",
		"/music/caf\xe9.mp3%(3,O_RDONLY)",
	}

	for _, in := range inputs {
		var want strings.Builder
		writer := csv.NewWriter(&want)
		if err := writer.Write([]string{in}); err != nil {
			t.Fatalf("csv.Writer.Write(%q): %v", in, err)
		}
		writer.Flush()
		wantCSV := strings.TrimSuffix(want.String(), "\n")

		got := quoteCSVField(in)
		if got != wantCSV {
			t.Errorf("quoteCSVField(%q) = %q, encoding/csv produces %q", in, got, wantCSV)
		}

		if in == "" {
			// An empty field renders as an empty line; csv.Reader reports
			// io.EOF for that, the same as it would for encoding/csv's own
			// output, so there is nothing meaningful to round-trip here.
			continue
		}
		parsed, err := csv.NewReader(strings.NewReader(got)).Read()
		if err != nil {
			t.Fatalf("round-trip parse of %q failed: %v", got, err)
		}
		// csv.Reader normalizes CRLF inside quoted fields to LF.
		wantRoundTrip := strings.ReplaceAll(in, "\r\n", "\n")
		if len(parsed) != 1 || parsed[0] != wantRoundTrip {
			t.Errorf("round-trip of %q yielded %v, want [%q]", got, parsed, wantRoundTrip)
		}
	}
}

// TestPairStringCarriesRetForKindSpecificExits guards the plain-mode CSV ret
// column: accept/pipe/socketpair/eventfd exits decode into their own event
// structs, not *types.RetEvent, so the column used to be rendered empty even
// though the kernel-side struct carries the return value.
func TestPairStringCarriesRetForKindSpecificExits(t *testing.T) {
	tests := []struct {
		name  string
		enter Event
		exit  Event
		want  string
	}{
		{
			name:  "accept",
			enter: &types.AcceptEvent{TraceId: types.SYS_ENTER_ACCEPT, Pid: 7, Tid: 8},
			exit:  &types.AcceptEvent{TraceId: types.SYS_EXIT_ACCEPT, Pid: 7, Tid: 8, Ret: -11},
			want:  "00000000,00000000,srv,7.8,accept,-11,N:file",
		},
		{
			name:  "pipe2",
			enter: &types.PipeEvent{TraceId: types.SYS_ENTER_PIPE2, Pid: 7, Tid: 8},
			exit:  &types.PipeEvent{TraceId: types.SYS_EXIT_PIPE2, Pid: 7, Tid: 8, Ret: -24},
			want:  "00000000,00000000,srv,7.8,pipe2,-24,N:file",
		},
		{
			name:  "socketpair",
			enter: &types.SocketpairEvent{TraceId: types.SYS_ENTER_SOCKETPAIR, Pid: 7, Tid: 8},
			exit:  &types.SocketpairEvent{TraceId: types.SYS_EXIT_SOCKETPAIR, Pid: 7, Tid: 8, Ret: -93},
			want:  "00000000,00000000,srv,7.8,socketpair,-93,N:file",
		},
		{
			name:  "eventfd2",
			enter: &types.EventfdEvent{TraceId: types.SYS_ENTER_EVENTFD2, Pid: 7, Tid: 8},
			exit:  &types.EventfdEvent{TraceId: types.SYS_EXIT_EVENTFD2, Pid: 7, Tid: 8, Ret: -24},
			want:  "00000000,00000000,srv,7.8,eventfd2,-24,N:file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pair := &Pair{EnterEv: tt.enter, ExitEv: tt.exit, Comm: "srv"}
			if got := pair.String(); got != tt.want {
				t.Fatalf("Pair.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Attacker-controlled -plain payloads: a comm that plants a spoofed OSC 8
// hyperlink and a file name that hides text with SGR, forges a row with a
// newline and reverses the rest of the line with RLO.
const (
	osc8Comm      = "\x1b]8;;http://evil\aclick\x1b]8;;\a"
	hostilePath   = "/tmp/a\x1b[8m,hidden\x1b[0m\nfake\u202efdp.exe"
	escapedComm   = `\x1b]8;;http://evil\x07click\x1b]8;;\x07`
	escapedPathFd = `/tmp/a\x1b[8m,hidden\x1b[0m\x0afake\u202efdp.exe%(3,O_RDONLY)`
)

// hostileTestPair returns a pair whose comm and file carry the terminal
// injection payloads above.
func hostileTestPair() *Pair {
	return newStringTestPair(osc8Comm, 7, 8, types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 3, file.NewFd(3, hostilePath, 0))
}

// parseSingleCSVRow parses row with encoding/csv and fails unless it is
// exactly one record with the EventStreamHeader column count.
func parseSingleCSVRow(t *testing.T, row string) []string {
	t.Helper()
	records, err := csv.NewReader(strings.NewReader(row)).ReadAll()
	if err != nil {
		t.Fatalf("row %q is not valid CSV: %v", row, err)
	}
	if len(records) != 1 || len(records[0]) != len(strings.Split(EventStreamHeader, ",")) {
		t.Fatalf("row %q parses into %v, want one 7-column record", row, records)
	}
	return records[0]
}

// TestPairCSVRowEscapesForTerminal is the regression test for task 7p2: with
// the terminal escaper the free-text columns carry no ESC/BEL/C1/bidi rune,
// the row is still valid single-record CSV (the escaped LF no longer splits
// or even quotes-with-newline the row) and the fields hold the visible
// escape notation.
func TestPairCSVRowEscapesForTerminal(t *testing.T) {
	row := hostileTestPair().CSVRow(textsafe.Escape)
	if textsafe.FirstUnsafe(row, false) >= 0 {
		t.Fatalf("terminal row %q still contains unsafe runes", row)
	}
	fields := parseSingleCSVRow(t, row)
	if fields[2] != escapedComm {
		t.Errorf("comm = %q, want %q", fields[2], escapedComm)
	}
	if fields[6] != escapedPathFd {
		t.Errorf("file = %q, want %q", fields[6], escapedPathFd)
	}
}

// TestPairCSVRowRawWithoutEscaper checks the piped/redirected behaviour: a
// nil escaper (and String) keep the exact traced bytes, and the CSV reader
// round-trips them, including the embedded newline and comma.
func TestPairCSVRowRawWithoutEscaper(t *testing.T) {
	pair := hostileTestPair()
	row := pair.CSVRow(nil)
	if row != pair.String() {
		t.Fatalf("String() = %q differs from CSVRow(nil) = %q", pair.String(), row)
	}
	fields := parseSingleCSVRow(t, row)
	if fields[2] != osc8Comm {
		t.Errorf("comm = %q, want raw %q", fields[2], osc8Comm)
	}
	if want := hostilePath + "%(3,O_RDONLY)"; fields[6] != want {
		t.Errorf("file = %q, want raw %q", fields[6], want)
	}
}

// TestPairFileValueVersusFileName pins task pq2: FileName is display text
// (placeholder for a fileless pair), FileValue is what data files store
// (empty for it), and a real file named like the placeholder keeps its name.
func TestPairFileValueVersusFileName(t *testing.T) {
	fileless := &Pair{}
	if got := fileless.FileName(); got != NoFileName {
		t.Errorf("fileless FileName() = %q, want %q", got, NoFileName)
	}
	if got := fileless.FileValue(); got != "" {
		t.Errorf("fileless FileValue() = %q, want empty", got)
	}
	for _, name := range []string{"/tmp/f", NoFileName} {
		p := &Pair{File: file.NewFd(3, name, 0)}
		if p.FileName() != name || p.FileValue() != name {
			t.Errorf("file %q: FileName()=%q FileValue()=%q, want both the real name", name, p.FileName(), p.FileValue())
		}
	}
}
