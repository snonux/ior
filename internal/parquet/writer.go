package parquet

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	parquetgo "github.com/parquet-go/parquet-go"
)

const (
	defaultMaxRowsPerRowGroup = int64(8192)
	defaultPageBufferSize     = 256 * 1024
)

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
	tempPath  string
	file      *os.File
	writer    *parquetgo.GenericWriter[Record]
	state     writerState
}

// NewWriter creates a new parquet writer that writes to a temporary file first
// and only publishes the final path once Close succeeds.
func NewWriter(path string, cfg WriterConfig, meta FileMetadata) (*Writer, error) {
	finalPath, tempPath, err := normalizeOutputPaths(path)
	if err != nil {
		return nil, err
	}

	cfg = normalizeWriterConfig(cfg)
	file, err := os.Create(tempPath)
	if err != nil {
		return nil, err
	}

	options := []parquetgo.WriterOption{
		parquetgo.Compression(&parquetgo.Zstd),
		parquetgo.CreatedBy("ior", normalizeMetadata(meta).IORVersion, ""),
		parquetgo.MaxRowsPerRowGroup(cfg.MaxRowsPerRowGroup),
		parquetgo.PageBufferSize(cfg.PageBufferSize),
	}
	options = append(options, writerMetadataOptions(meta)...)

	return &Writer{
		finalPath: finalPath,
		tempPath:  tempPath,
		file:      file,
		writer:    parquetgo.NewGenericWriter[Record](file, options...),
		state:     writerStateOpen,
	}, nil
}

// FinalPath returns the finalized parquet path.
func (w *Writer) FinalPath() string {
	if w == nil {
		return ""
	}
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

// Close finalizes the parquet footer and publishes the file atomically.
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
	tempPath := w.tempPath
	finalPath := w.finalPath
	w.state = writerStateClosed
	w.mu.Unlock()

	if err := writer.Close(); err != nil {
		closeErr := file.Close()
		removeErr := os.Remove(tempPath)
		return errors.Join(fmt.Errorf("close parquet writer: %w", err), closeErr, removeErr)
	}
	if err := file.Close(); err != nil {
		removeErr := os.Remove(tempPath)
		return errors.Join(fmt.Errorf("close parquet file: %w", err), removeErr)
	}
	if err := os.Rename(tempPath, finalPath); err != nil {
		return fmt.Errorf("rename parquet file %q to %q: %w", tempPath, finalPath, err)
	}
	return nil
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

func normalizeOutputPaths(path string) (string, string, error) {
	clean := filepath.Clean(strings.TrimSpace(path))
	if clean == "." || clean == "" {
		return "", "", errors.New("parquet output path cannot be empty")
	}

	lower := strings.ToLower(clean)
	switch {
	case strings.HasSuffix(lower, ".parquet.tmp"):
		finalPath := strings.TrimSuffix(clean, ".tmp")
		return finalPath, clean, nil
	case strings.HasSuffix(lower, ".parquet"):
		return clean, clean + ".tmp", nil
	default:
		finalPath := clean + ".parquet"
		return finalPath, finalPath + ".tmp", nil
	}
}
