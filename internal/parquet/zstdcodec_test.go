package parquet

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/klauspost/compress/zstd"
	parquetgo "github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/format"
)

// codecTestPage builds a page-sized buffer shaped like ior's data: repetitive
// paths and comm names with slowly changing numbers, which is what zstd finds
// matches in. size is the exact length.
func codecTestPage(size int, seed int64) []byte {
	rng := rand.New(rand.NewSource(seed))
	var b bytes.Buffer
	for b.Len() < size {
		fmt.Fprintf(&b, "/var/lib/app-%d/data/segment-%06d.log\x00ior-test\x00read\x00FS\x00%d\x00",
			rng.Intn(8), rng.Intn(50000), rng.Intn(4096))
	}
	return b.Bytes()[:size]
}

func TestZstdCodecIdentity(t *testing.T) {
	c := newZstdCodec()
	if c.String() != "ZSTD" {
		t.Fatalf("String() = %q, want ZSTD", c.String())
	}
	if c.CompressionCodec() != format.Zstd {
		t.Fatalf("CompressionCodec() = %v, want Zstd", c.CompressionCodec())
	}
}

func TestZstdCodecRoundTripsThroughIndependentDecoders(t *testing.T) {
	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatalf("zstd.NewReader() error = %v", err)
	}
	defer dec.Close()

	sizes := []int{0, 1, 100, 4096, 64 << 10, defaultPageBufferSize, defaultPageBufferSize + 1, 3 << 20}
	incompressible := make([]byte, 200<<10)
	rand.New(rand.NewSource(7)).Read(incompressible)

	inputs := map[string][]byte{"incompressible": incompressible}
	for _, n := range sizes {
		inputs[fmt.Sprintf("text-%d", n)] = codecTestPage(n, int64(n))
	}
	c := newZstdCodec()
	for name, src := range inputs {
		t.Run(name, func(t *testing.T) {
			// A dirty dst proves Encode writes from dst[:0] rather than appending.
			enc, err := c.Encode(bytes.Repeat([]byte{0xAA}, 64), src)
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			viaCodec, err := c.Decode(nil, enc)
			if err != nil || !bytes.Equal(viaCodec, src) {
				t.Fatalf("library Decode() mismatch (err = %v, len %d want %d)", err, len(viaCodec), len(src))
			}
			viaKlauspost, err := dec.DecodeAll(enc, nil)
			if err != nil || !bytes.Equal(viaKlauspost, src) {
				t.Fatalf("klauspost DecodeAll() mismatch (err = %v, len %d want %d)", err, len(viaKlauspost), len(src))
			}
		})
	}
}

func TestZstdCodecDecodeRejectsGarbage(t *testing.T) {
	if _, err := newZstdCodec().Decode(nil, []byte("definitely not a zstd frame")); err == nil {
		t.Fatal("Decode(garbage) error = nil, want an error")
	}
}

// The whole point of the small window is memory, but it is bounded from both
// sides: the frame header must not declare more than zstdWindowSize (a decoder
// with a matching limit would refuse the file), and it must not declare less
// than one page (a smaller window could miss matches inside a page, silently
// costing ratio). The 3 MiB input is longer than the window, so the header
// states the encoder's own window rather than the input length.
func TestZstdCodecFrameWindowIsSmall(t *testing.T) {
	c := newZstdCodec()
	enc, err := c.Encode(nil, codecTestPage(3<<20, 1))
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	var h zstd.Header
	if err := h.Decode(enc); err != nil {
		t.Fatalf("Header.Decode() error = %v", err)
	}
	if h.WindowSize > zstdWindowSize {
		t.Fatalf("frame window = %d, want <= %d", h.WindowSize, zstdWindowSize)
	}
	if h.WindowSize < defaultPageBufferSize {
		t.Fatalf("frame window = %d, want >= one page (%d)", h.WindowSize, defaultPageBufferSize)
	}
}

// Level, CRC and zero-length-frame settings decide the bytes on disk, so they
// are pinned here rather than left to the ratio test, which would not notice
// e.g. a faster level or an added checksum.
func TestZstdCodecFrameSettings(t *testing.T) {
	c := newZstdCodec()

	// Zero frames: an empty page must still be a valid frame (an empty output
	// is not decodable), and it must decode back to nothing.
	empty, err := c.Encode(nil, nil)
	if err != nil {
		t.Fatalf("Encode(nil) error = %v", err)
	}
	if len(empty) == 0 {
		t.Fatal("Encode(nil) returned no frame, want a valid empty zstd frame")
	}
	if got, err := c.Decode(nil, empty); err != nil || len(got) != 0 {
		t.Fatalf("Decode(empty frame) = %d bytes, err = %v, want 0 bytes", len(got), err)
	}

	// No CRC: the library codec writes none, and 4 bytes per page are wasted
	// on a checksum the parquet format already covers elsewhere.
	enc, err := c.Encode(nil, codecTestPage(defaultPageBufferSize, 2))
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	var h zstd.Header
	if err := h.Decode(enc); err != nil {
		t.Fatalf("Header.Decode() error = %v", err)
	}
	if h.HasCheckSum {
		t.Fatal("frame header has the checksum flag set, want no CRC")
	}
}

// Level is pinned byte for byte: apart from the window (which a page never
// fills), the codec must produce exactly what the library's parquetgo.Zstd
// produces, so files keep the format and ratio they had before the swap.
func TestZstdCodecMatchesLibraryOutput(t *testing.T) {
	c := newZstdCodec()
	for _, size := range []int{4 << 10, defaultPageBufferSize} {
		page := codecTestPage(size, int64(size))
		mine, err := c.Encode(nil, page)
		if err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
		library, err := parquetgo.Zstd.Encode(nil, page)
		if err != nil {
			t.Fatalf("library Encode() error = %v", err)
		}
		if !bytes.Equal(mine, library) {
			t.Fatalf("%d-byte page: output differs from the library codec (%d vs %d bytes)", size, len(mine), len(library))
		}
	}
}

// distantRepeatPage builds a page whose second part repeats an incompressible
// first part at the given distance, so the only way to compress it is a match
// reaching back that far. The tail after the repeat is fresh random data.
func distantRepeatPage(size, distance int, seed int64) []byte {
	rng := rand.New(rand.NewSource(seed))
	page := make([]byte, size)
	rng.Read(page)
	copy(page[distance:], page[:size-distance])
	return page
}

// A window larger than a page loses nothing only if matches spanning most of
// a page are still found. Repeats half a page and three quarters of a page
// apart need a window of at least that distance; a 16 or 64 KiB window cannot
// reach them and compresses such a page to about its full size, while the
// library codec saves the whole repeated part.
func TestZstdCodecFindsDistantRepeatsWithinAPage(t *testing.T) {
	c := newZstdCodec()
	for _, distance := range []int{defaultPageBufferSize / 2, defaultPageBufferSize * 3 / 4} {
		page := distantRepeatPage(defaultPageBufferSize, distance, int64(distance))
		mine, err := c.Encode(nil, page)
		if err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
		library, err := parquetgo.Zstd.Encode(nil, page)
		if err != nil {
			t.Fatalf("library Encode() error = %v", err)
		}
		if float64(len(mine)) > float64(len(library))*1.005 {
			t.Fatalf("repeat distance %d: compressed to %d bytes, library codec %d: window too small for a page", distance, len(mine), len(library))
		}
		// The repeat must actually be exploited, or the comparison is vacuous.
		// The copied tail is len(page)-distance bytes; the library must save most of it.
		if len(library) > len(page)-(len(page)-distance)/2 {
			t.Fatalf("repeat distance %d: library codec only reached %d of %d bytes, test page has no usable repeat", distance, len(library), len(page))
		}
	}
}

// The smaller window must not cost compression on realistic pages: pages are
// compressed one by one and are far smaller than the window, so the ratio
// should match the library's 8 MiB-window codec to within noise.
func TestZstdCodecKeepsTheCompressionRatio(t *testing.T) {
	c := newZstdCodec()
	var mine, library int
	for i := 0; i < 8; i++ {
		page := codecTestPage(defaultPageBufferSize, int64(i))
		a, err := c.Encode(nil, page)
		if err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
		b, err := parquetgo.Zstd.Encode(nil, page)
		if err != nil {
			t.Fatalf("library Encode() error = %v", err)
		}
		mine += len(a)
		library += len(b)
	}
	if float64(mine) > float64(library)*1.02 {
		t.Fatalf("compressed %d bytes, library codec %d: more than 2%% worse", mine, library)
	}
}

func liveHeap() uint64 {
	var ms runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// codecHeapBudget bounds what a codec may pin after encoding many pages from
// many goroutines: a single encoder (about 2 MB, measured ~3.9 MB here with
// eight goroutines' output buffers) whatever the parallelism. The library
// codec would keep one 16.8 MB encoder per P instead; the GC-churn test below
// is the one that fails against it.
const codecHeapBudget = 6 << 20

func encodeConcurrently(t *testing.T, encode func(dst, src []byte) ([]byte, error), goroutines, pages int) {
	t.Helper()
	page := codecTestPage(defaultPageBufferSize, 3)
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var dst []byte
			for i := 0; i < pages; i++ {
				out, err := encode(dst, page)
				if err != nil {
					errs <- err
					return
				}
				dst = out
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("Encode() error = %v", err)
	}
}

func TestZstdCodecPinsOneSmallEncoderUnderParallelUse(t *testing.T) {
	prev := runtime.GOMAXPROCS(8)
	defer runtime.GOMAXPROCS(prev)

	before := liveHeap()
	c := newZstdCodec()
	encodeConcurrently(t, c.Encode, 8, 5)
	pinned := int64(liveHeap()) - int64(before)
	if pinned > codecHeapBudget {
		t.Fatalf("codec pins %d bytes after parallel use, want <= %d", pinned, codecHeapBudget)
	}
	runtime.KeepAlive(c)

	// release hands the encoder back: the same measurement must fall to noise.
	c.release()
	if left := int64(liveHeap()) - int64(before); left > 1<<20 {
		t.Fatalf("%d bytes still live after release, want <= 1 MiB", left)
	}
}

// Encoding after release must still work (a Writer is released on Close, but
// nothing stops a late page from being flushed) and simply rebuilds the encoder.
func TestZstdCodecEncodesAfterRelease(t *testing.T) {
	c := newZstdCodec()
	page := codecTestPage(4096, 5)
	c.release() // before any encoder exists: must be a harmless no-op
	if _, err := c.Encode(nil, page); err != nil {
		t.Fatalf("first Encode() error = %v", err)
	}
	c.release()
	enc, err := c.Encode(nil, page)
	if err != nil {
		t.Fatalf("Encode() after release error = %v", err)
	}
	if got, err := c.Decode(nil, enc); err != nil || !bytes.Equal(got, page) {
		t.Fatalf("round trip after release failed (err = %v)", err)
	}
}

func TestZstdCodecIsSafeForConcurrentUse(t *testing.T) {
	c := newZstdCodec()
	page := codecTestPage(defaultPageBufferSize, 9)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				enc, err := c.Encode(nil, page)
				if err != nil {
					t.Errorf("Encode() error = %v", err)
					return
				}
				if got, err := c.Decode(nil, enc); err != nil || !bytes.Equal(got, page) {
					t.Errorf("concurrent round trip failed (err = %v)", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// End to end: a writer that flushes many pages produces a file the stock
// reader reads back exactly, declares ZSTD in its footer, and holds no encoder
// once closed or aborted.
func TestWriterUsesTheReleasableZstdCodec(t *testing.T) {
	dir := t.TempDir()
	// A tiny page buffer forces many compressed pages out of few rows.
	cfg := WriterConfig{MaxRowsPerRowGroup: 2000, PageBufferSize: 4 << 10}
	w, err := NewWriter(filepath.Join(dir, "codec"), cfg, FileMetadata{Mode: "test"})
	if err != nil {
		t.Fatalf("NewWriter() error = %v", err)
	}
	rows := benchmarkRecords(5000)
	if err := w.WriteRows(rows); err != nil {
		t.Fatalf("WriteRows() error = %v", err)
	}
	if w.codec.encoder == nil {
		t.Fatal("no page was compressed through the writer's codec")
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if w.codec.encoder != nil {
		t.Fatal("Close() left the encoder alive")
	}

	got := readBackRecords(t, w.FinalPath())
	if len(got) != len(rows) {
		t.Fatalf("read %d rows, wrote %d", len(got), len(rows))
	}
	for i := range rows {
		if got[i] != rows[i] {
			t.Fatalf("row %d = %+v, want %+v", i, got[i], rows[i])
		}
	}
	assertFooterUsesZstd(t, w.FinalPath())
}

func readBackRecords(t *testing.T, path string) []Record {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = f.Close() }()
	reader := parquetgo.NewGenericReader[Record](f)
	defer func() { _ = reader.Close() }()
	got := make([]Record, reader.NumRows())
	n, err := reader.Read(got)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Read() error = %v", err)
	}
	return got[:n]
}

// assertFooterUsesZstd requires every column chunk to declare ZSTD, so a file
// written through the custom codec is still an ordinary zstd parquet file.
func assertFooterUsesZstd(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	pf, err := parquetgo.OpenFile(f, info.Size())
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	groups := pf.Metadata().RowGroups
	if len(groups) < 2 {
		t.Fatalf("got %d row groups, want several so many pages were compressed", len(groups))
	}
	for _, rg := range groups {
		for _, col := range rg.Columns {
			if col.MetaData.Codec != format.Zstd {
				t.Fatalf("column %v codec = %v, want Zstd", col.MetaData.PathInSchema, col.MetaData.Codec)
			}
		}
	}
}

func TestWriterAbortReleasesTheEncoder(t *testing.T) {
	w, err := NewWriter(filepath.Join(t.TempDir(), "aborted"), WriterConfig{PageBufferSize: 4 << 10}, FileMetadata{Mode: "test"})
	if err != nil {
		t.Fatalf("NewWriter() error = %v", err)
	}
	if err := w.WriteRows(benchmarkRecords(2000)); err != nil {
		t.Fatalf("WriteRows() error = %v", err)
	}
	if w.codec.encoder == nil {
		t.Fatal("no page was compressed through the writer's codec")
	}
	if err := w.Abort(); err != nil {
		t.Fatalf("Abort() error = %v", err)
	}
	if w.codec.encoder != nil {
		t.Fatal("Abort() left the encoder alive")
	}
	if _, err := os.Stat(w.TempPath()); !os.IsNotExist(err) {
		t.Fatalf("temp file still present after Abort: %v", err)
	}
}

// allocatedByEncodingAcrossGCs returns the bytes allocated while compressing
// one page per round with a garbage collection between rounds. A sync.Pool is
// emptied by the collector, so a pooled encoder is rebuilt (about 16.8 MB at
// the library's default window) after every cycle; one owned encoder is built
// once.
func allocatedByEncodingAcrossGCs(t *testing.T, encode func(dst, src []byte) ([]byte, error), rounds int) uint64 {
	t.Helper()
	page := codecTestPage(defaultPageBufferSize, 11)
	var dst []byte
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < rounds; i++ {
		out, err := encode(dst, page)
		if err != nil {
			t.Fatalf("Encode() error = %v", err)
		}
		dst = out
		runtime.GC()
		runtime.GC() // the pool's victim cache survives one cycle, not two
	}
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestZstdCodecDoesNotReallocateItsEncoderAfterGC(t *testing.T) {
	const rounds = 10
	c := newZstdCodec()
	got := allocatedByEncodingAcrossGCs(t, c.Encode, rounds)
	// One encoder (~4 MB with its first-use buffers) plus output; rebuilding it
	// every round would cost rounds times that.
	if budget := uint64(12 << 20); got > budget {
		t.Fatalf("allocated %d bytes over %d rounds with GC between, want <= %d (encoder rebuilt after GC?)", got, rounds, budget)
	}
	runtime.KeepAlive(c)
}
