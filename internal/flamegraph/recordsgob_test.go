package flamegraph

import (
	"bytes"
	"encoding/gob"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ior/internal/sampling"
	"ior/internal/types"
)

// stockEncodeRecords is encodeRecords as it was before the records message
// was streamed (task tz2): one gob Encode of the whole map. Every recording
// written so far has this layout, and every reader expects it.
func stockEncodeRecords(w io.Writer, records map[recordKey]Counter, samples sampling.Summary) error {
	if _, err := w.Write(recordingMagic[:]); err != nil {
		return err
	}
	enc := gob.NewEncoder(w)
	if err := enc.Encode(newRecordingHeader(records, samples)); err != nil {
		return err
	}
	return enc.Encode(records)
}

// fixtureRecords returns n distinct records with 30-60 character paths, a
// few real tracepoints and counter values large enough to need multi-byte
// gob integers.
func fixtureRecords(n int) map[recordKey]Counter {
	traces := []traceIdType{types.SYS_ENTER_READ, types.SYS_ENTER_OPENAT, types.SYS_ENTER_WRITE}
	records := make(map[recordKey]Counter, n)
	for i := range n {
		path := "/var/lib/app/data/" + strconv.Itoa(i) + "/"
		path += strings.Repeat("x", max(0, 30+i%31-len(path)))
		key := recordKey{Path: path, TraceID: traces[i%len(traces)], Comm: "worker" + strconv.Itoa(i%7),
			Pid: pidType(1000 + i%500), Tid: tidType(2000 + i%900), Flags: flagsType(i % 4)}
		records[key] = Counter{Count: uint64(i), Duration: uint64(i) * 1_000_003, Bytes: uint64(i % 3)}
	}
	return records
}

// withBatchSize runs the test with a small recordsBatchSize, so that a few
// records already span several batches.
func withBatchSize(t *testing.T, size int) {
	t.Helper()
	old := recordsBatchSize
	recordsBatchSize = size
	t.Cleanup(func() { recordsBatchSize = old })
}

func encodeBoth(t *testing.T, records map[recordKey]Counter, samples sampling.Summary) (streamed, stock []byte) {
	t.Helper()
	var a, b bytes.Buffer
	if err := encodeRecords(&a, records, samples); err != nil {
		t.Fatalf("encodeRecords: %v", err)
	}
	if err := stockEncodeRecords(&b, records, samples); err != nil {
		t.Fatalf("stockEncodeRecords: %v", err)
	}
	return a.Bytes(), b.Bytes()
}

// With at most one record gob's map order cannot differ, so the streamed
// recording must be the stock one byte for byte, type definitions, type IDs,
// length prefix and all.
func TestStreamedRecordsAreByteIdenticalToGobEncode(t *testing.T) {
	cases := map[string]struct {
		records map[recordKey]Counter
		samples sampling.Summary
	}{
		"nil map":    {nil, sampling.Summary{}},
		"empty map":  {map[recordKey]Counter{}, sampling.Summary{}},
		"one record": {fixtureRecords(1), sampling.Summary{}},
		"sampled":    {fixtureRecords(1), sampledSummary()},
		"zero counter": {map[recordKey]Counter{{Path: "/z", TraceID: types.SYS_ENTER_READ}: {}},
			sampling.Summary{}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			streamed, stock := encodeBoth(t, tc.records, tc.samples)
			if !bytes.Equal(streamed, stock) {
				t.Fatalf("streamed stream differs from gob.Encode:\n got %x\nwant %x", streamed, stock)
			}
		})
	}
}

// With many records only the order of the pairs may differ: the streams must
// be the same length and decode, with the unchanged reader and with plain gob,
// to the same records. The sizes straddle the batch size on purpose.
func TestStreamedRecordsDecodeLikeGobEncode(t *testing.T) {
	withBatchSize(t, 7)
	for _, n := range []int{2, 6, 7, 8, 14, 15, 100} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			records := fixtureRecords(n)
			streamed, stock := encodeBoth(t, records, sampling.Summary{})
			if len(streamed) != len(stock) {
				t.Fatalf("len(streamed) = %d, len(stock) = %d", len(streamed), len(stock))
			}
			assertSamePairsInAnyOrder(t, streamed, stock, records)
			got, _, err := decodeRecords(bytes.NewReader(streamed))
			if err != nil {
				t.Fatalf("decodeRecords: %v", err)
			}
			if !maps.Equal(got, records) {
				t.Fatalf("decoded %d records, want the %d written", len(got), len(records))
			}
			if raw := plainGobRecords(t, streamed); !maps.Equal(raw, records) {
				t.Fatalf("plain gob decoded %d records, want the %d written", len(raw), len(records))
			}
		})
	}
}

// assertSamePairsInAnyOrder checks that streamed and stock are the same
// bytes except for the order of the records' pairs: identical up to where
// the pairs start, and from there both made of exactly the pair encodings of
// records, each once. A record's pair encoding is taken from a one-record
// gob map; the encodings are self-delimiting, so no two are prefixes of each
// other and the split is unique.
func assertSamePairsInAnyOrder(t *testing.T, streamed, stock []byte, records map[recordKey]Counter) {
	t.Helper()
	want := make(map[string]int, len(records))
	pairBytes := 0
	for key, cnt := range records {
		var buf bytes.Buffer
		if err := gob.NewEncoder(&buf).Encode(map[recordKey]Counter{key: cnt}); err != nil {
			t.Fatal(err)
		}
		pair, err := batchPairs(buf.Bytes(), 1)
		if err != nil {
			t.Fatal(err)
		}
		want[string(pair)]++
		pairBytes += len(pair)
	}
	// The header's tracepoint table is a gob map too, so with several
	// tracepoints its bytes vary run to run even for gob itself; compare from
	// its end.
	from, head := headerEnd(t, stock), len(stock)-pairBytes
	if headerEnd(t, streamed) != from || !bytes.Equal(streamed[from:head], stock[from:head]) {
		t.Fatalf("streams differ between header and pairs:\n got %x\nwant %x", streamed[from:head], stock[from:head])
	}
	for name, pairs := range map[string][]byte{"streamed": streamed[head:], "stock": stock[head:]} {
		if left := consumePairs(pairs, maps.Clone(want)); left != "" {
			t.Fatalf("%s pairs are not the records' pairs: %s", name, left)
		}
	}
}

// headerEnd returns the offset just past the header's value message (the
// first gob message with a non-negative type ID after the magic).
func headerEnd(t *testing.T, stream []byte) int {
	t.Helper()
	rest := stream[len(recordingMagic):]
	for {
		payload, next, err := splitGobMessage(rest)
		if err != nil {
			t.Fatalf("scan header: %v", err)
		}
		rest = next
		if id, _, err := readGobInt(payload); err != nil || id >= 0 {
			return len(stream) - len(rest)
		}
	}
}

// consumePairs removes the pairs from want one by one and returns "" if they
// matched exactly, otherwise what went wrong.
func consumePairs(pairs []byte, want map[string]int) string {
	for len(pairs) > 0 {
		matched := false
		for pair := range want {
			if want[pair] > 0 && bytes.HasPrefix(pairs, []byte(pair)) {
				want[pair]--
				pairs = pairs[len(pair):]
				matched = true
				break
			}
		}
		if !matched {
			return "unknown pair bytes " + strconv.Quote(string(pairs))
		}
	}
	for _, n := range want {
		if n != 0 {
			return "a record's pair is missing"
		}
	}
	return ""
}

// plainGobRecords decodes the records of a stream with a bare gob.Decoder,
// without decodeRecords's tracepoint translation.
func plainGobRecords(t *testing.T, stream []byte) map[recordKey]Counter {
	t.Helper()
	dec := gob.NewDecoder(bytes.NewReader(stream[len(recordingMagic):]))
	var header recordingHeader
	if err := dec.Decode(&header); err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var records map[recordKey]Counter
	if err := dec.Decode(&records); err != nil {
		t.Fatalf("decode records: %v", err)
	}
	if err := dec.Decode(&records); !errors.Is(err, io.EOF) {
		t.Fatalf("data after the records message: %v", err)
	}
	return records
}

// The compressed file round trip, across several batches.
func TestStreamedRecordingRoundTripsThroughAFile(t *testing.T) {
	withBatchSize(t, 64)
	iod := newIorData()
	iod.records = fixtureRecords(1000)
	path := filepath.Join(t.TempDir(), "rec.ior.zst")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := iod.encodeCompressed(file, path); err != nil {
		t.Fatalf("encodeCompressed: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	loaded, err := newIorDataFromFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !maps.Equal(loaded.records, iod.records) {
		t.Fatalf("loaded %d records, want the %d written", len(loaded.records), len(iod.records))
	}
}

var errWriteFailed = errors.New("disk full")

// failAfterWriter accepts limit bytes, then fails the one Write that crosses
// the limit, reporting the bytes of it that it did take (a short write on a
// full disk), and accepts everything after that again. Recovering makes an
// error that is dropped on the way show up as success.
type failAfterWriter struct {
	limit  int
	failed bool
}

func (f *failAfterWriter) Write(p []byte) (int, error) {
	if f.failed || len(p) <= f.limit {
		f.limit -= min(f.limit, len(p))
		return len(p), nil
	}
	f.failed = true
	return f.limit, errWriteFailed
}

// A writer failing at any byte (magic, header, type definitions, head, any
// batch) must surface as the writer's error, never as success.
func TestStreamedRecordsReportWriteErrorsAtEveryOffset(t *testing.T) {
	withBatchSize(t, 4)
	records := fixtureRecords(10)
	var full bytes.Buffer
	if err := encodeRecords(&full, records, sampling.Summary{}); err != nil {
		t.Fatalf("encodeRecords: %v", err)
	}
	for limit := range full.Len() {
		err := encodeRecords(&failAfterWriter{limit: limit}, records, sampling.Summary{})
		if !errors.Is(err, errWriteFailed) {
			t.Fatalf("writer failing after %d of %d bytes: err = %v, want %v",
				limit, full.Len(), err, errWriteFailed)
		}
	}
}

// writePairs must not leave a message whose length prefix disagrees with the
// pairs that follow it: if the records do not add up to the sized length (the
// map changed between the passes), it fails.
func TestWritePairsRejectsASizeMismatch(t *testing.T) {
	withBatchSize(t, 3)
	records := fixtureRecords(10)
	s := newRecordsStreamer(nil, nil)
	var size int
	if err := s.forEachBatch(records, func(p []byte) error { size += len(p); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.writePairs(io.Discard, records, size); err != nil {
		t.Fatalf("writePairs with the right size: %v", err)
	}
	for _, want := range []int{size - 1, size + 1, 0} {
		if err := s.writePairs(io.Discard, records, want); !errors.Is(err, errRecordsChanged) {
			t.Fatalf("writePairs(want=%d) of %d bytes: err = %v, want errRecordsChanged", want, size, err)
		}
	}
}

// Saving must not need memory in proportion to the recording: before task
// tz2 the peak extra heap was ~240 (GOGC=10) to ~390 (GOGC=100) bytes per
// record; streamed it is a constant ~1-2 MB (~10 B per record at 2^17). The
// bound, 32 B per record (4 MB), leaves a 3x margin for GC timing and is
// still exceeded several times over by the old encoder.
func TestEncodeCompressedHeapStaysBounded(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("heap measurement: skipped with -short and under the race detector")
	}
	const n = 1 << 17
	iod := newIorData()
	iod.records = fixtureRecords(n)
	extra := peakHeapExtra(func() {
		if err := iod.encodeCompressed(io.Discard, "bounded"); err != nil {
			t.Errorf("encodeCompressed: %v", err)
		}
	})
	if perRecord := float64(extra) / n; perRecord > 32 {
		t.Fatalf("peak extra heap while saving = %d bytes (%.1f per record), want <= 32 per record",
			extra, perRecord)
	}
	runtime.KeepAlive(iod)
}

// peakHeapExtra runs f and returns how far HeapInuse rose above its level
// before f, sampling it every 100µs.
func peakHeapExtra(f func()) uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := ms.HeapInuse
	var peak atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	sample := func(m *runtime.MemStats) {
		runtime.ReadMemStats(m)
		if m.HeapInuse > base && m.HeapInuse-base > peak.Load() {
			peak.Store(m.HeapInuse - base)
		}
	}
	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Microsecond):
				sample(&m)
			}
		}
	}()
	f()
	close(stop)
	<-done
	sample(&ms)
	return peak.Load()
}

// countingWriter counts the bytes written to it.
type countingWriter struct{ n int }

func (c *countingWriter) Write(p []byte) (int, error) { c.n += len(p); return len(p), nil }

// A size mismatch must also stop the writing early: no batch that would run
// past the sized length reaches the writer.
func TestWritePairsStopsBeforeOverrunningTheSizedLength(t *testing.T) {
	withBatchSize(t, 3)
	records := fixtureRecords(10)
	s := newRecordsStreamer(nil, nil)
	var cw countingWriter
	if err := s.writePairs(&cw, records, 1); !errors.Is(err, errRecordsChanged) {
		t.Fatalf("err = %v, want errRecordsChanged", err)
	}
	if cw.n != 0 {
		t.Fatalf("wrote %d bytes past a sized length of 1", cw.n)
	}
}

// After the records the stream's encoder must write to the stream again, not
// into the scratch buffer the probe diverted it to.
func TestWriteRecordsMessageRestoresTheEncoderWriter(t *testing.T) {
	var out bytes.Buffer
	sw := &switchWriter{w: &out}
	enc := gob.NewEncoder(sw)
	if err := writeRecordsMessage(&out, enc, sw, fixtureRecords(3)); err != nil {
		t.Fatal(err)
	}
	before := out.Len()
	if err := enc.Encode(uint64(7)); err != nil {
		t.Fatal(err)
	}
	if out.Len() == before {
		t.Fatal("an Encode after the records did not reach the stream")
	}
}

// batchPairs refuses framing other than the documented one instead of
// passing on bytes that would corrupt the records message.
func TestBatchPairsRejectsUnexpectedFraming(t *testing.T) {
	msg := func(payload ...byte) []byte { return append(appendGobUint(nil, uint64(len(payload))), payload...) }
	cases := map[string]struct {
		msgs  []byte
		count int
	}{
		"count mismatch":    {msg(0x02, 0x00, 0x02, 0xaa), 1},
		"singleton not 0":   {msg(0x02, 0x01, 0x01, 0xaa), 1},
		"no singleton":      {msg(0x02), 1},
		"trailing message":  {append(msg(0x02, 0x00, 0x01, 0xaa), msg(0x02, 0x00, 0x00)...), 1},
		"only a type def":   {msg(0x01, 0xaa), 1},
		"truncated message": {[]byte{0x05, 0x02, 0x00}, 1},
		"truncated count":   {msg(0x02, 0x00, 0xfe, 0x01), 1},
	}
	for name, tc := range cases {
		if _, err := batchPairs(tc.msgs, tc.count); err == nil {
			t.Errorf("%s: batchPairs(%x) succeeded", name, tc.msgs)
		}
	}
	pairs, err := batchPairs(append(msg(0x01, 0xbb), msg(0x02, 0x00, 0x01, 0xaa)...), 1)
	if err != nil || !bytes.Equal(pairs, []byte{0xaa}) {
		t.Fatalf("batchPairs of a type definition plus a value = %x, %v; want aa, nil", pairs, err)
	}
}
