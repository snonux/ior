package flamegraph

import (
	"bytes"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"ior/internal/collapse"
	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/textsafe"
	"ior/internal/types"
)

// writeTestRecording builds a real .ior.zst recording through the production
// recorder and returns its path, so converter tests exercise the exact
// on-disk gob-in-zstd format.
func writeTestRecording(t *testing.T, name string, pairs ...*event.Pair) string {
	t.Helper()
	t.Chdir(t.TempDir())

	recorder := NewRecorder(name)
	for _, pair := range pairs {
		recorder.AddPair(pair)
	}
	if err := recorder.Write(); err != nil {
		t.Fatalf("recorder.Write() error = %v", err)
	}

	matches, err := filepath.Glob("*" + name + "*.ior.zst")
	if err != nil {
		t.Fatalf("glob recording: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly one %s recording, found %v", name, matches)
	}
	return matches[0]
}

func collapsedTestPair(seq uint64, comm, path string, enterID, exitID types.TraceId, pid uint32) *event.Pair {
	enter := &types.OpenEvent{TraceId: enterID, Time: seq * 10, Pid: pid, Tid: pid + 1}
	exit := &types.RetEvent{TraceId: exitID, Time: seq*10 + 1, Pid: pid, Tid: pid + 1}
	pair := event.NewPair(enter)
	pair.ExitEv = exit
	pair.File = file.NewFd(int32(seq), path, 0)
	pair.Comm = comm
	pair.Duration = seq + 1
	pair.DurationToPrev = seq + 2
	pair.Bytes = seq + 3
	return pair
}

func TestWriteCollapsedStacksDerivesFlamegraphPlLines(t *testing.T) {
	recording := writeTestRecording(t, "convert",
		collapsedTestPair(1, "api", "/srv/api/lib", types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 100),
		// Different pid, so this is a separate record with an identical
		// frame path: the converter must sum both into one sample.
		collapsedTestPair(2, "api", "/srv/api/lib", types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 101),
		collapsedTestPair(3, "worker", "/srv/worker/queue", types.SYS_ENTER_READ, types.SYS_EXIT_READ, 200),
	)

	var out bytes.Buffer
	if err := WriteCollapsedStacks(&out, recording, CollapsedOptions{}); err != nil {
		t.Fatalf("WriteCollapsedStacks() error = %v", err)
	}

	want := strings.Join([]string{
		"api;enter_openat;/srv;/api;/lib 2",
		"worker;enter_read;/srv;/worker;/queue 1",
	}, "\n") + "\n"
	if got := out.String(); got != want {
		t.Fatalf("collapsed stacks mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestWriteCollapsedStacksHonorsFieldAndCountOptions(t *testing.T) {
	recording := writeTestRecording(t, "options",
		collapsedTestPair(1, "api", "/srv/api/lib", types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 100),
	)

	var out bytes.Buffer
	err := WriteCollapsedStacks(&out, recording, CollapsedOptions{
		Fields:     []string{"comm"},
		CountField: "bytes",
	})
	if err != nil {
		t.Fatalf("WriteCollapsedStacks() error = %v", err)
	}
	if got, want := out.String(), "api 4\n"; got != want {
		t.Fatalf("collapsed stacks mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestWriteCollapsedStacksRejectsInvalidOptions(t *testing.T) {
	recording := writeTestRecording(t, "invalid",
		collapsedTestPair(1, "api", "/srv/api", types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 100),
	)

	cases := []struct {
		name string
		opts CollapsedOptions
	}{
		{"unknown field", CollapsedOptions{Fields: []string{"comm", "bogus"}}},
		{"empty field", CollapsedOptions{Fields: []string{"comm", " "}}},
		{"unknown count field", CollapsedOptions{CountField: "bogus"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := WriteCollapsedStacks(&out, recording, tc.opts); err == nil {
				t.Fatalf("WriteCollapsedStacks(%v) succeeded, want error", tc.opts)
			}
		})
	}
}

func TestWriteCollapsedStacksMissingFile(t *testing.T) {
	var out bytes.Buffer
	if err := WriteCollapsedStacks(&out, filepath.Join(t.TempDir(), "missing.ior.zst"), CollapsedOptions{}); err == nil {
		t.Fatalf("WriteCollapsedStacks(missing) succeeded, want error")
	}
}

func TestWriteCollapsedStacksRoundTripsEveryRecord(t *testing.T) {
	pairs := []*event.Pair{
		collapsedTestPair(1, "api", "/srv/a", types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 100),
		collapsedTestPair(2, "worker", "/srv/b", types.SYS_ENTER_READ, types.SYS_EXIT_READ, 200),
		collapsedTestPair(3, "ingest", "/srv/c", types.SYS_ENTER_WRITE, types.SYS_EXIT_WRITE, 300),
	}
	recording := writeTestRecording(t, "roundtrip", pairs...)

	// The sum of all collapsed samples must equal the recording's total
	// event count, proving no record is lost or double-counted in the
	// conversion.
	var out bytes.Buffer
	if err := WriteCollapsedStacks(&out, recording, CollapsedOptions{}); err != nil {
		t.Fatalf("WriteCollapsedStacks() error = %v", err)
	}

	total := uint64(0)
	lines := 0
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("collapsed line %q does not have exactly one weight", line)
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			t.Fatalf("collapsed line %q weight is not numeric: %v", line, err)
		}
		total += value
		lines++
	}
	if total != uint64(len(pairs)) {
		t.Fatalf("collapsed sample total = %d, want %d", total, len(pairs))
	}
	if lines != len(pairs) {
		t.Fatalf("collapsed line count = %d, want %d", lines, len(pairs))
	}
}

// TestWriteCollapsedStacksMatchesLiveTrieFrames guards the converter against
// frame drift: the same record must produce the identical frame path in the
// in-TUI flamegraph and in the emitted collapsed stacks.
func TestWriteCollapsedStacksMatchesLiveTrieFrames(t *testing.T) {
	pair := collapsedTestPair(1, "api", "/srv/api/lib", types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 100)
	recording := writeTestRecording(t, "parity", pair)

	liveTrie := NewLiveTrie(collapse.DefaultFields(), collapse.DefaultCountField(), "")
	liveTrie.Ingest(pair)
	tree, _ := liveTrie.SnapshotTree()
	frames := firstLeafFramePath(tree)

	var out bytes.Buffer
	if err := WriteCollapsedStacks(&out, recording, CollapsedOptions{}); err != nil {
		t.Fatalf("WriteCollapsedStacks() error = %v", err)
	}
	got := strings.TrimSuffix(out.String(), "\n")
	parts := strings.SplitN(got, " ", 2)
	if len(parts) != 2 {
		t.Fatalf("collapsed line %q has no weight", got)
	}
	if path := parts[0]; path != strings.Join(frames, ";") {
		t.Fatalf("frame drift:\n converter: %q\n live trie: %q", path, strings.Join(frames, ";"))
	}
}

// firstLeafFramePath walks the first root-to-leaf chain of a snapshot tree,
// skipping the anonymous root, and returns its frame names.
func firstLeafFramePath(root *SnapshotNode) []string {
	frames := make([]string, 0, 8)
	current := root
	for len(current.Children) > 0 {
		current = current.Children[0]
		frames = append(frames, current.Name)
	}
	return frames
}

// TestWriteCollapsedStacksEscapeOption checks the terminal escaper is applied
// to the written frame path only (the ESC and BEL of a comm that hides text
// with SGR become visible \x notation), and that without it the exact bytes
// are written, as flamegraph.pl in a pipe needs. The payload avoids ';',
// which the frame splitter treats as a separator.
func TestWriteCollapsedStacksEscapeOption(t *testing.T) {
	const hostileComm = "evil\x1b[8mhidden\x1b[0m\a"
	recording := writeTestRecording(t, "escape",
		collapsedTestPair(1, hostileComm, "/srv", types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 100),
	)
	opts := CollapsedOptions{Fields: []string{"comm"}}

	var raw bytes.Buffer
	if err := WriteCollapsedStacks(&raw, recording, opts); err != nil {
		t.Fatalf("WriteCollapsedStacks(raw) error = %v", err)
	}
	if got, want := raw.String(), hostileComm+" 1\n"; got != want {
		t.Fatalf("raw output = %q, want %q", got, want)
	}

	opts.Escape = textsafe.Escape
	var escaped bytes.Buffer
	if err := WriteCollapsedStacks(&escaped, recording, opts); err != nil {
		t.Fatalf("WriteCollapsedStacks(escaped) error = %v", err)
	}
	if got, want := escaped.String(), `evil\x1b[8mhidden\x1b[0m\x07 1`+"\n"; got != want {
		t.Fatalf("escaped output = %q, want %q", got, want)
	}
}

// flamegraphPlLine mirrors how flamegraph.pl reads one input line: lines are
// split on LF only, and `/^(.*)\s+?(\d+(?:\.\d*)?)$/` takes the greedy stack
// and the trailing sample count; the stack is then split on ';' into frames.
var flamegraphPlLine = regexp.MustCompile(`^(.*)\s+?(\d+(?:\.\d*)?)$`)

type parsedCollapsedStack struct {
	frames []string
	count  uint64
}

// parseCollapsedLikeFlamegraphPl parses collapsed output the way
// flamegraph.pl does, failing the test on any line it would ignore.
func parseCollapsedLikeFlamegraphPl(t *testing.T, out string) []parsedCollapsedStack {
	t.Helper()
	var stacks []parsedCollapsedStack
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		m := flamegraphPlLine.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("flamegraph.pl would ignore line %q", line)
		}
		count, err := strconv.ParseUint(m[2], 10, 64)
		if err != nil {
			t.Fatalf("line %q count: %v", line, err)
		}
		stacks = append(stacks, parsedCollapsedStack{frames: strings.Split(m[1], ";"), count: count})
	}
	return stacks
}

// TestWriteCollapsedStacksCannotForgeStacks is the regression test for
// traced names that carry collapsed-format structure: an LF or CR must not
// start a new (weighted) line, a ';' must only produce the frames the in-TUI
// flamegraph shows, and a frame ending in " 999999999" must not change the
// weight. It runs without Escape, i.e. the raw piped `ior collapsed` path.
func TestWriteCollapsedStacksCannotForgeStacks(t *testing.T) {
	forgedPath := "/tmp/x\n/evil;frame 999999999"
	crComm := "cr\rcomm 7"
	pairs := []*event.Pair{
		collapsedTestPair(1, "api", forgedPath, types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 100),
		collapsedTestPair(2, crComm, "/srv", types.SYS_ENTER_READ, types.SYS_EXIT_READ, 200),
		collapsedTestPair(3, "semi;colon 42", "/srv", types.SYS_ENTER_WRITE, types.SYS_EXIT_WRITE, 300),
	}
	recording := writeTestRecording(t, "forge", pairs...)

	var out bytes.Buffer
	if err := WriteCollapsedStacks(&out, recording, CollapsedOptions{}); err != nil {
		t.Fatalf("WriteCollapsedStacks() error = %v", err)
	}
	if strings.Contains(out.String(), "\r") {
		t.Fatalf("output contains a raw CR: %q", out.String())
	}

	stacks := parseCollapsedLikeFlamegraphPl(t, out.String())
	if len(stacks) != len(pairs) {
		t.Fatalf("parsed %d stacks, want %d (one per record):\n%s", len(stacks), len(pairs), out.String())
	}
	want := map[string]bool{
		`api;enter_openat;/tmp;/x\x0a;/evil;frame 999999999`: true,
		`cr\x0dcomm 7;enter_read;/srv`:                       true,
		"semi;colon 42;enter_write;/srv":                     true,
	}
	for _, stack := range stacks {
		if stack.count != 1 {
			t.Fatalf("stack %q weight = %d, want 1", stack.frames, stack.count)
		}
		if joined := strings.Join(stack.frames, ";"); !want[joined] {
			t.Fatalf("unexpected stack %q in output:\n%s", joined, out.String())
		}
	}
}

// TestWriteCollapsedStacksSemicolonMatchesLiveTrie checks a ';' inside a
// traced name yields exactly the frames of the in-TUI flamegraph: the split
// is the shared buildFrames model, so no frame of the output can contain
// ';' and flamegraph.pl reconstructs the same stack.
func TestWriteCollapsedStacksSemicolonMatchesLiveTrie(t *testing.T) {
	pair := collapsedTestPair(1, "a;b", "/srv/x;y", types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 100)
	recording := writeTestRecording(t, "semicolon", pair)

	liveTrie := NewLiveTrie(collapse.DefaultFields(), collapse.DefaultCountField(), "")
	liveTrie.Ingest(pair)
	tree, _ := liveTrie.SnapshotTree()

	var out bytes.Buffer
	if err := WriteCollapsedStacks(&out, recording, CollapsedOptions{}); err != nil {
		t.Fatalf("WriteCollapsedStacks() error = %v", err)
	}
	stacks := parseCollapsedLikeFlamegraphPl(t, out.String())
	if len(stacks) != 1 {
		t.Fatalf("parsed %d stacks, want 1:\n%s", len(stacks), out.String())
	}
	if got, want := stacks[0].frames, firstLeafFramePath(tree); !slices.Equal(got, want) {
		t.Fatalf("frames = %q, want live trie frames %q", got, want)
	}
}

// TestWriteCollapsedStacksLineBreakEncodingAggregates checks the encoding
// happens before aggregation, so a frame with LF and one literally holding
// `\x0a` (identical once written) become one summed line, not two lines with
// the same stack, and that -escape=always leaves the encoding as is.
func TestWriteCollapsedStacksLineBreakEncodingAggregates(t *testing.T) {
	recording := writeTestRecording(t, "lfagg",
		collapsedTestPair(1, "a\nb", "/srv", types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 100),
		collapsedTestPair(2, `a\x0ab`, "/srv", types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 200),
	)
	for _, escape := range []func(string) string{nil, textsafe.Escape} {
		var out bytes.Buffer
		opts := CollapsedOptions{Fields: []string{"comm"}, Escape: escape}
		if err := WriteCollapsedStacks(&out, recording, opts); err != nil {
			t.Fatalf("WriteCollapsedStacks() error = %v", err)
		}
		if got, want := out.String(), `a\x0ab 2`+"\n"; got != want {
			t.Fatalf("output (escape set: %v) = %q, want %q", escape != nil, got, want)
		}
	}
}

func TestEncodeCollapsedFrame(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"/srv", "/srv"},
		{"name 999", "name 999"},
		{"\x1b[8m", "\x1b[8m"}, // not structural: left to the Escape option
		{"a\nb", `a\x0ab`},
		{"a\r\nb", `a\x0d\x0ab`},
		{"\n", `\x0a`},
	}
	for _, tc := range cases {
		if got := encodeCollapsedFrame(tc.in); got != tc.want {
			t.Errorf("encodeCollapsedFrame(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if allocs := testing.AllocsPerRun(100, func() { _ = encodeCollapsedFrame("/usr/lib/libc.so.6") }); allocs != 0 {
		t.Fatalf("clean frame allocated %v times, want 0", allocs)
	}
}

// TestWriteCollapsedStacksKeepsRecordsWithEmptyFields pins task vq2: a record
// whose selected fields all render empty (empty file name with -fields path,
// empty comm with -fields comm) has a positive weight and must still be
// counted, under the placeholder frame, so the collapsed total equals the
// recording's event count (the same rows the CSV and Parquet outputs carry).
func TestWriteCollapsedStacksKeepsRecordsWithEmptyFields(t *testing.T) {
	recording := writeTestRecording(t, "emptyfields",
		collapsedTestPair(1, "api", "/srv/a", types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 100),
		collapsedTestPair(2, "api", "", types.SYS_ENTER_READ, types.SYS_EXIT_READ, 200),
		collapsedTestPair(3, "", "/srv/a", types.SYS_ENTER_WRITE, types.SYS_EXIT_WRITE, 300),
		collapsedTestPair(4, "", "", types.SYS_ENTER_WRITE, types.SYS_EXIT_WRITE, 400),
	)

	tests := []struct {
		name   string
		fields []string
		want   string
	}{
		{"path only", []string{"path"}, "/srv;/a 2\n[unknown] 2\n"},
		{"comm only", []string{"comm"}, "[unknown] 2\napi 2\n"},
		// One empty field is not enough to trigger the placeholder: the
		// other field still yields real frames.
		{"comm and path", []string{"comm", "path"}, "/srv;/a 1\n[unknown] 1\napi 1\napi;/srv;/a 1\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := WriteCollapsedStacks(&out, recording, CollapsedOptions{Fields: tc.fields}); err != nil {
				t.Fatalf("WriteCollapsedStacks() error = %v", err)
			}
			total := uint64(0)
			for _, stack := range parseCollapsedLikeFlamegraphPl(t, out.String()) {
				total += stack.count
			}
			if total != 4 {
				t.Fatalf("collapsed total = %d, want 4 (every record):\n%s", total, out.String())
			}
			if tc.want != "" && out.String() != tc.want {
				t.Fatalf("output =\n%s\nwant\n%s", out.String(), tc.want)
			}
		})
	}
}

// TestWriteCollapsedStacksStillSkipsZeroWeight keeps the other half of the
// contract: a record with a zero sample weight is omitted even when its
// frames are empty, since it would render zero-width anyway.
func TestWriteCollapsedStacksStillSkipsZeroWeight(t *testing.T) {
	pair := collapsedTestPair(1, "api", "", types.SYS_ENTER_OPENAT, types.SYS_EXIT_OPENAT, 100)
	pair.Bytes = 0
	recording := writeTestRecording(t, "zeroweight", pair)
	var out bytes.Buffer
	opts := CollapsedOptions{Fields: []string{"path"}, CountField: "bytes"}
	if err := WriteCollapsedStacks(&out, recording, opts); err != nil {
		t.Fatalf("WriteCollapsedStacks() error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("zero-weight record was written:\n%s", out.String())
	}
}
