package flamegraph

import (
	"bytes"
	"encoding/gob"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ior/internal/sampling"
	"ior/internal/types"
)

// sampledSummary is what a run with -syscall-sampling-syscalls read=10 leaves
// behind: 110 of 1000 reads were recorded, the other 890 only counted.
func sampledSummary() sampling.Summary {
	return sampling.New([]sampling.Entry{{Syscall: "read", Rate: 10, Traced: 110, Counted: 890}}, "")
}

// headerOf decodes just the header of a serialized recording stream.
func headerOf(t *testing.T, stream []byte) recordingHeader {
	t.Helper()
	if !bytes.HasPrefix(stream, recordingMagic[:]) {
		t.Fatal("stream does not start with the recording magic")
	}
	var header recordingHeader
	if err := gob.NewDecoder(bytes.NewReader(stream[len(recordingMagic):])).Decode(&header); err != nil {
		t.Fatalf("decode header: %v", err)
	}
	return header
}

func oneRecordData() iorData {
	iod := newIorData()
	iod.add("/f", types.SYS_ENTER_READ, "c", 1, 1, 0, Counter{Count: 110})
	return iod
}

func TestSampledRecordingCarriesItsSamplingInTheHeader(t *testing.T) {
	iod := oneRecordData()
	iod.sampling = sampledSummary()

	stream, err := iod.serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	header := headerOf(t, stream)
	if header.Version != recordingFormatVersionSampled {
		t.Fatalf("header version = %d, want %d: an older reader must refuse a sampled recording",
			header.Version, recordingFormatVersionSampled)
	}

	var restored iorData
	if err := restored.deserialize(bytes.NewBuffer(stream)); err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if !reflect.DeepEqual(restored.sampling, iod.sampling) {
		t.Fatalf("restored sampling = %+v, want %+v", restored.sampling, iod.sampling)
	}
	if len(restored.records) != 1 {
		t.Fatalf("records = %d, want 1", len(restored.records))
	}
}

// A recording that sampled nothing must stay readable by builds that know only
// version 1, and must not look sampled to this one.
func TestUnsampledRecordingStaysVersionOne(t *testing.T) {
	iod := oneRecordData()
	stream, err := iod.serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if got := headerOf(t, stream).Version; got != recordingFormatVersion {
		t.Fatalf("header version = %d, want %d", got, recordingFormatVersion)
	}
	var restored iorData
	if err := restored.deserialize(bytes.NewBuffer(stream)); err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if restored.sampling.Active() {
		t.Fatalf("restored sampling = %+v, want none", restored.sampling)
	}
}

// A sampled recording whose totals could not be determined still says it was
// sampled, with the reason, rather than passing for a complete one.
func TestSampledRecordingWithUnknownTotalsKeepsTheRatesAndReason(t *testing.T) {
	iod := oneRecordData()
	iod.sampling = sampling.New([]sampling.Entry{{Syscall: "read", Rate: 10, Traced: 110}}, "filter")
	stream, err := iod.serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	var restored iorData
	if err := restored.deserialize(bytes.NewBuffer(stream)); err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if !restored.sampling.Active() || restored.sampling.TotalsKnown() || restored.sampling.Unavailable != "filter" {
		t.Fatalf("restored sampling = %+v, want active with the unavailable reason", restored.sampling)
	}
}

// writeSampledRecording records one pair through the production recorder with
// the sampling outcome set, returning the published path.
func writeSampledRecording(t *testing.T, samples sampling.Summary) string {
	t.Helper()
	t.Chdir(t.TempDir())
	recorder := NewRecorder("sampled")
	recorder.AddPair(collapsedTestPair(1, "api", "/srv/a", types.SYS_ENTER_READ, types.SYS_EXIT_READ, 100))
	recorder.SetSampling(samples)
	if err := recorder.Write(); err != nil {
		t.Fatalf("Write: %v", err)
	}
	matches, err := filepath.Glob("*sampled*.ior.zst")
	if err != nil || len(matches) != 1 {
		t.Fatalf("recordings = %v, %v; want exactly one", matches, err)
	}
	return matches[0]
}

func TestLoadRecordingReturnsTheRecorderSampling(t *testing.T) {
	path := writeSampledRecording(t, sampledSummary())
	records, got, err := LoadRecording(path)
	if err != nil {
		t.Fatalf("LoadRecording: %v", err)
	}
	if !reflect.DeepEqual(got, sampledSummary()) {
		t.Fatalf("sampling = %+v, want %+v", got, sampledSummary())
	}
	n := 0
	for range records {
		n++
	}
	if n != 1 {
		t.Fatalf("records = %d, want 1", n)
	}
}

func TestLoadRecordingOfAnUnsampledRunReportsNoSampling(t *testing.T) {
	path := writeSampledRecording(t, sampling.Summary{})
	_, got, err := LoadRecording(path)
	if err != nil {
		t.Fatalf("LoadRecording: %v", err)
	}
	if got.Active() {
		t.Fatalf("sampling = %+v, want none", got)
	}
}

func TestNilRecorderSetSamplingIsANoOp(t *testing.T) {
	var r *Recorder
	r.SetSampling(sampledSummary()) // must not panic: a run without -flamegraph has a nil recorder
}

func TestCollapsedNoticeNamesASampledRecording(t *testing.T) {
	path := writeSampledRecording(t, sampledSummary())
	var notices []string
	var out bytes.Buffer
	err := WriteCollapsedStacks(&out, path, CollapsedOptions{Notice: func(l string) { notices = append(notices, l) }})
	if err != nil {
		t.Fatalf("WriteCollapsedStacks: %v", err)
	}
	joined := strings.Join(notices, "\n")
	for _, want := range []string{"sampled", "read: 1000 calls", "110 traced", "890 counted only"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("notices = %q, want them to contain %q", joined, want)
		}
	}
	if strings.Contains(out.String(), "sampled") {
		t.Fatalf("notice leaked into the collapsed stacks: %q", out.String())
	}
}

func TestCollapsedStaysSilentForAnUnsampledRecording(t *testing.T) {
	path := writeSampledRecording(t, sampling.Summary{})
	called := false
	err := WriteCollapsedStacks(&bytes.Buffer{}, path, CollapsedOptions{Notice: func(string) { called = true }})
	if err != nil {
		t.Fatalf("WriteCollapsedStacks: %v", err)
	}
	if called {
		t.Fatal("a notice was raised for an unsampled recording")
	}
}

// A recording written by a build that predates the sampling field decodes with
// the zero Summary: a version 1 header without it.
func TestVersionOneHeaderWithoutSamplingLoads(t *testing.T) {
	stored := map[recordKey]Counter{{Path: "/f", TraceID: types.SYS_ENTER_READ}: {Count: 3}}
	type legacyHeader struct {
		Version     uint32
		Tracepoints map[traceIdType]string
	}
	path := writeZstdGob(t, recordingMagic[:],
		legacyHeader{Version: 1, Tracepoints: map[traceIdType]string{types.SYS_ENTER_READ: types.SYS_ENTER_READ.String()}},
		stored)
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	_, got, err := LoadRecording(path)
	if err != nil {
		t.Fatalf("LoadRecording: %v", err)
	}
	if got.Active() {
		t.Fatalf("sampling = %+v, want none", got)
	}
}
