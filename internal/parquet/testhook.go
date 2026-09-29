package parquet

// WithFailingWriter returns a copy of cfg whose recordings write to a real
// parquet file but fail every batch write with writeErr, so the session dies
// exactly as it would on a disk error (Status().LastError == writeErr, and
// Record returns writeErr until the next Start).
//
// It is a test hook: callers outside this package (the TUI wiring tests in
// package internal) cannot reach the unexported writer factory, and a real
// Recorder is the only faithful way to exercise its post-failure behavior.
func (cfg RecorderConfig) WithFailingWriter(writeErr error) RecorderConfig {
	cfg.newWriter = func(path string, wcfg WriterConfig, meta FileMetadata) (rowWriter, error) {
		w, err := NewWriter(path, wcfg, meta)
		if err != nil {
			return nil, err
		}
		return failingRowWriter{rowWriter: w, err: writeErr}, nil
	}
	return cfg
}

// failingRowWriter delegates file lifecycle to a real writer (so Abort cleans
// up the temp file) and rejects every batch with err.
type failingRowWriter struct {
	rowWriter
	err error
}

func (w failingRowWriter) WriteRows([]Record) error { return w.err }
