package parquet

import (
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"
	parquetgo "github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/compress"
	"github.com/parquet-go/parquet-go/format"
)

// zstdWindowSize is the match window of the recording encoder. A page is
// compressed on its own (Encode gets one page's bytes and no shared history),
// and pages are cut at PageBufferSize (256 KiB by default), so a window larger
// than one page can never find a match that a smaller one would miss. The
// library default for SpeedDefault is 8 MiB, which made every encoder pin
// about 16.8 MB of window plus history buffers; 1 MiB keeps the whole page
// (and a few times over) in one window and pins about 2 MB.
const zstdWindowSize = 1 << 20

// zstdCodec is the parquet compression codec ior records with. It replaces
// the library's parquetgo.Zstd, whose encoders live in a package-global
// sync.Pool: a sync.Pool holds one private slot per P and is emptied by the
// garbage collector, so a many-core host pinned an 8 MiB-window encoder per
// CPU (about 16.8 MB each, 80 MB of a 144 MB heap in a TUI run) and
// re-allocated them after every GC cycle.
//
// Pages are compressed one at a time by the writer's own goroutine, so this
// codec owns exactly ONE encoder, created on first use, with a small window,
// and serialises callers on a mutex (the compress.Codec contract still
// demands concurrent safety). Each recording writer has its own codec and
// drops the encoder in release when the recording ends, so an idle TUI keeps
// nothing between recordings and two recordings never contend.
//
// Decoding is not on the recording path; it is delegated to the library codec
// so a reader built on this package's files behaves exactly as before.
type zstdCodec struct {
	mu      sync.Mutex
	encoder *zstd.Encoder
}

var _ compress.Codec = (*zstdCodec)(nil)

// newZstdCodec returns a codec with no encoder yet; the first Encode makes it.
func newZstdCodec() *zstdCodec { return &zstdCodec{} }

func (c *zstdCodec) String() string { return "ZSTD" }

func (c *zstdCodec) CompressionCodec() format.CompressionCodec { return format.Zstd }

// newZstdEncoder builds the one encoder. Level, zero-length frames and the
// missing CRC are what the library codec used, so files keep their format;
// only the window (and so the memory) differs. Each frame header states the
// window the frame needs (never more than its own page), so any zstd decoder
// reads the output unchanged.
func newZstdEncoder() (*zstd.Encoder, error) {
	return zstd.NewWriter(nil,
		zstd.WithEncoderConcurrency(1),
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithWindowSize(zstdWindowSize),
		zstd.WithZeroFrames(true),
		zstd.WithEncoderCRC(false),
	)
}

// Encode compresses src into dst[:0] and returns it. The encoder is created on
// first use, so a writer that never flushes a page never pays for one.
func (c *zstdCodec) Encode(dst, src []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.encoder == nil {
		e, err := newZstdEncoder()
		if err != nil {
			return nil, fmt.Errorf("create zstd encoder: %w", err)
		}
		c.encoder = e
	}
	return c.encoder.EncodeAll(src, dst[:0]), nil
}

// Decode delegates to the library codec (see the type comment).
func (c *zstdCodec) Decode(dst, src []byte) ([]byte, error) {
	return parquetgo.Zstd.Decode(dst, src)
}

// release drops the encoder so its window and history buffers become garbage
// as soon as the recording ends. The codec stays usable: a later Encode simply
// builds a new encoder.
func (c *zstdCodec) release() {
	c.mu.Lock()
	c.encoder = nil
	c.mu.Unlock()
}
