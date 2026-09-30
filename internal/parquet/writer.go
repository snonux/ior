package parquet

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"ior/internal/atomicfile"

	parquetgo "github.com/parquet-go/parquet-go"
)

const (
	defaultMaxRowsPerRowGroup = int64(8192)
	defaultPageBufferSize     = 256 * 1024
)

// parquetExt is the extension atomicfile keeps last when it has to add a "-N"
// suffix to avoid replacing an existing recording.
const parquetExt = ".parquet"

var errWriterClosed = errors.New("parquet writer is closed")

// WriterConfig tunes parquet file layout details.
type WriterConfig struct {
	MaxRowsPerRowGroup int64
	PageBufferSize     int
}

// DefaultWriterConfig returns the recommended writer defaults for ior traces.
func DefaultWriterConfig() WriterConfig {
	return WriterConfig{
		MaxRowsPerRowGroup: defaultMaxRowsPerRowGroup,
		PageBufferSize:     defaultPageBufferSize,
	}
}

type writerState int

const (
	writerStateOpen writerState = iota
	writerStateClosed
	writerStateAborted
)

// Writer wraps the parquet library behind repo-local file lifecycle semantics.
type Writer struct {
	mu sync.Mutex

	finalPath string
	// noClobber selects the publish policy: true for a name ior generated
	// itself (never replace, add "-N"), false for a path the user chose
	// (replace, as before).
	noClobber bool
	tempPath  string
	file      *os.File
	writer    *parquetgo.GenericWriter[Record]
	// codec is this writer's own zstd encoder holder; Close and Abort release
	// it so the encoder's buffers do not outlive the recording.
	codec *zstdCodec
	state writerState
}

// NewWriter creates a parquet writer for a path the user chose explicitly. It
// writes to a uniquely named temporary file first and, once Close succeeds,
// atomically publishes it at exactly that path, replacing an existing file
// there (what "-parquet out.parquet" always meant). The temp name is unique per
// writer, so two recordings aimed at the same path never share or truncate one
// another's temp file.
func NewWriter(path string, cfg WriterConfig, meta FileMetadata) (*Writer, error) {
	return newWriter(path, cfg, meta, false)
}

// NewAutoNamedWriter is NewWriter for a path ior generated itself (the
// timestamped default, accurate only to the second). Close never replaces an
// existing file there: a collision publishes under a "-N" suffixed name and
// FinalPath then reports the name actually used, so two recordings started in
// the same second both survive.
func NewAutoNamedWriter(path string, cfg WriterConfig, meta FileMetadata) (*Writer, error) {
	return newWriter(path, cfg, meta, true)
}

func newWriter(path string, cfg WriterConfig, meta FileMetadata, noClobber bool) (*Writer, error) {
	finalPath, err := normalizeOutputPath(path)
	if err != nil {
		return nil, err
	}

	cfg = normalizeWriterConfig(cfg)
	file, err := atomicfile.CreateTemp(finalPath)
	if err != nil {
		return nil, err
	}
	tempPath := file.Name()

	// A per-writer codec with one small-window encoder instead of the
	// library's global parquetgo.Zstd (see zstdCodec for the memory it saves).
	codec := newZstdCodec()
	options := []parquetgo.WriterOption{
		parquetgo.Compression(codec),
		parquetgo.CreatedBy("ior", normalizeMetadata(meta).IORVersion, ""),
		parquetgo.MaxRowsPerRowGroup(cfg.MaxRowsPerRowGroup),
		parquetgo.PageBufferSize(cfg.PageBufferSize),
	}
	options = append(options, writerMetadataOptions(meta)...)

	return &Writer{
		finalPath: finalPath,
		noClobber: noClobber,
		tempPath:  tempPath,
		file:      file,
		writer:    parquetgo.NewGenericWriter[Record](file, options...),
		codec:     codec,
		state:     writerStateOpen,
	}, nil
}

// FinalPath returns the parquet path the file is (or will be) published at.
// It is the requested path until Close publishes the file; for an auto-named
// writer whose path was already taken by another file, Close never replaces it
// and publishes under a "-N" suffixed name instead, after which FinalPath
// reports that name.
func (w *Writer) FinalPath() string {
	if w == nil {
		return ""
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.finalPath
}

// TempPath returns the temporary parquet path used before finalization.
func (w *Writer) TempPath() string {
	if w == nil {
		return ""
	}
	return w.tempPath
}

// WriteRows appends a batch of records to the parquet file.
func (w *Writer) WriteRows(rows []Record) error {
	if len(rows) == 0 {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.state != writerStateOpen {
		return errWriterClosed
	}

	written, err := w.writer.Write(rows)
	if err != nil {
		return fmt.Errorf("write parquet rows: %w", err)
	}
	if written != len(rows) {
		return fmt.Errorf("write parquet rows: wrote %d of %d rows", written, len(rows))
	}
	return nil
}

// Close finalizes the parquet footer and publishes the file atomically: an
// auto-named writer never replaces an existing file (see FinalPath), an
// explicitly named one replaces it. If publishing fails, the complete temp
// file is kept at TempPath so the recording can be rescued.
func (w *Writer) Close() error {
	if w == nil {
		return nil
	}

	w.mu.Lock()
	if w.state != writerStateOpen {
		w.mu.Unlock()
		return nil
	}
	file := w.file
	writer := w.writer
	codec := w.codec
	tempPath := w.tempPath
	finalPath := w.finalPath
	noClobber := w.noClobber
	w.state = writerStateClosed
	w.mu.Unlock()

	err := writer.Close()
	// Closing flushed the last page; the encoder is not needed any more, on
	// the failure paths below either.
	codec.release()
	if err != nil {
		closeErr := file.Close()
		removeErr := os.Remove(tempPath)
		return errors.Join(fmt.Errorf("close parquet writer: %w", err), closeErr, removeErr)
	}
	if err := file.Close(); err != nil {
		removeErr := os.Remove(tempPath)
		return errors.Join(fmt.Errorf("close parquet file: %w", err), removeErr)
	}
	published, err := publishParquet(tempPath, finalPath, noClobber)
	if err != nil {
		return fmt.Errorf("publish parquet file: %w", err)
	}
	w.mu.Lock()
	w.finalPath = published
	w.mu.Unlock()
	return nil
}

// publishParquet moves the finished temp file to finalPath under the writer's
// policy and returns the path it ended up at.
func publishParquet(tempPath, finalPath string, noClobber bool) (string, error) {
	if noClobber {
		return atomicfile.Publish(tempPath, finalPath, parquetExt)
	}
	return finalPath, atomicfile.PublishReplace(tempPath, finalPath)
}

// Abort discards the temporary parquet file.
func (w *Writer) Abort() error {
	if w == nil {
		return nil
	}

	w.mu.Lock()
	if w.state != writerStateOpen {
		w.mu.Unlock()
		return nil
	}
	file := w.file
	tempPath := w.tempPath
	w.state = writerStateAborted
	w.mu.Unlock()

	// No further page will be compressed; drop the encoder's buffers now.
	w.codec.release()

	closeErr := file.Close()
	removeErr := os.Remove(tempPath)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	return errors.Join(closeErr, removeErr)
}

func normalizeWriterConfig(cfg WriterConfig) WriterConfig {
	defaults := DefaultWriterConfig()
	if cfg.MaxRowsPerRowGroup <= 0 {
		cfg.MaxRowsPerRowGroup = defaults.MaxRowsPerRowGroup
	}
	if cfg.PageBufferSize <= 0 {
		cfg.PageBufferSize = defaults.PageBufferSize
	}
	return cfg
}

// CheckOutputPath verifies, without writing anything, that a recording aimed
// at path (as given with -parquet, ".parquet" appended when missing) could be
// created: the directory exists and accepts new files, the final name is not
// an existing directory (a symlink to one is fine: it is replaced, not
// followed) and the filesystem accepts the special characters in the name.
// A headless run calls it before loading and
// attaching BPF, so a mistyped directory fails in milliseconds instead of
// after the setup (seconds) or, for a failure only detectable late, after the
// whole recording. NewWriter still creates the real temp file at Start; this
// is a cheap early rejection, not a reservation.
func CheckOutputPath(path string) error {
	finalPath, err := normalizeOutputPath(path)
	if err != nil {
		return err
	}
	return atomicfile.ProbeReplace(finalPath)
}

// normalizeOutputPath maps the user-supplied path to the final ".parquet"
// path, appending ".parquet" when missing. A trailing ".tmp" on a
// ".parquet.tmp" name is dropped, so a "<name>.parquet.tmp" path (the temp
// naming older ior versions used, which a caller could still hand in) publishes
// to "<name>.parquet". Current temp files are ior-<hex>.tmp and never pass
// through here; the rule stays because it is harmless and a test pins it.
func normalizeOutputPath(path string) (string, error) {
	clean := filepath.Clean(strings.TrimSpace(path))
	if clean == "." || clean == "" {
		return "", errors.New("parquet output path cannot be empty")
	}

	lower := strings.ToLower(clean)
	switch {
	case strings.HasSuffix(lower, ".parquet.tmp"):
		return strings.TrimSuffix(clean, ".tmp"), nil
	case strings.HasSuffix(lower, ".parquet"):
		return clean, nil
	default:
		return clean + ".parquet", nil
	}
}
