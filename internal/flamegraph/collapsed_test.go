package flamegraph

import (
	"bytes"
	"path/filepath"
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
