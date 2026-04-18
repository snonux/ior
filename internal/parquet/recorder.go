package parquet

import (
	"errors"
	"sync"
	"time"

	"ior/internal/streamrow"
)

const (
	defaultRecorderQueueCapacity = 4096
	defaultRecorderBatchSize     = 256
	defaultRecorderFlushInterval = 250 * time.Millisecond
)

var (
	// ErrRecorderActive indicates a start request while a recorder session is running.
	ErrRecorderActive = errors.New("parquet recorder is already active")
	// ErrRecorderNotActive indicates that rows cannot be accepted because no session is active.
	ErrRecorderNotActive = errors.New("parquet recorder is not active")
	// ErrRecorderQueueFull indicates bounded queue overflow. This is treated as a recording failure.
	ErrRecorderQueueFull = errors.New("parquet recorder queue is full")
)

type rowWriter interface {
	WriteRows([]Record) error
	Close() error
	Abort() error
	FinalPath() string
	TempPath() string
}

type writerFactory func(path string, cfg WriterConfig, meta FileMetadata) (rowWriter, error)

// RecorderConfig controls queueing and batching behavior.
type RecorderConfig struct {
	QueueCapacity int
	BatchSize     int
	FlushInterval time.Duration
	Writer        WriterConfig

	newWriter writerFactory
}

// StartOptions supplies per-session metadata.
type StartOptions struct {
	Metadata FileMetadata
}

// Status reports the last known recorder state.
type Status struct {
	Active      bool
	Path        string
	TempPath    string
	RowsWritten uint64
	LastError   error
}

// Recorder manages one active parquet recording session at a time.
type Recorder struct {
	mu     sync.RWMutex
	config RecorderConfig
	active *recordingSession
	status Status
}

type recordingSession struct {
	queue chan recordRequest
	stopC chan struct{}
	doneC chan error

	mu        sync.Mutex
	accepting bool
	stopCause error
	doneErr   error
	stopOnce  sync.Once
}

type recordRequest struct {
	row         streamrow.Row
	filterEpoch uint64
}

// NewRecorder constructs a reusable parquet recorder controller.
func NewRecorder(config RecorderConfig) *Recorder {
	return &Recorder{config: normalizeRecorderConfig(config)}
}

// Start begins a new recording session.
func (r *Recorder) Start(path string, options StartOptions) error {
	if r == nil {
		return ErrRecorderNotActive
	}

	cfg := normalizeRecorderConfig(r.config)
	buildWriter := cfg.newWriter
	if buildWriter == nil {
		buildWriter = func(path string, cfg WriterConfig, meta FileMetadata) (rowWriter, error) {
			return NewWriter(path, cfg, meta)
		}
	}

	writer, err := buildWriter(path, cfg.Writer, options.Metadata)
	if err != nil {
		return err
	}

	session := newRecordingSession(cfg.QueueCapacity)

	r.mu.Lock()
	if r.active != nil {
		r.mu.Unlock()
		_ = writer.Abort()
		return ErrRecorderActive
	}
	r.active = session
	r.status = Status{
		Active:   true,
		Path:     writer.FinalPath(),
		TempPath: writer.TempPath(),
	}
	r.mu.Unlock()

	go r.runSession(session, writer, cfg)
	return nil
}

// Record queues one shared stream row for persistence.
func (r *Recorder) Record(row streamrow.Row, filterEpoch uint64) error {
	if r == nil {
		return ErrRecorderNotActive
	}

	r.mu.RLock()
	session := r.active
	lastErr := r.status.LastError
	r.mu.RUnlock()

	if session == nil {
		if lastErr != nil {
			return lastErr
		}
		return ErrRecorderNotActive
	}
	return session.enqueue(recordRequest{row: row, filterEpoch: filterEpoch})
}

// Stop gracefully flushes and finalizes the active recording session.
func (r *Recorder) Stop() error {
	if r == nil {
		return nil
	}

	r.mu.RLock()
	session := r.active
	lastErr := r.status.LastError
	r.mu.RUnlock()

	if session == nil {
		return lastErr
	}

	session.stop(nil)
	if err := <-session.doneC; err != nil {
		return err
	}
	return session.doneErr
}

// Status returns a snapshot of the recorder state.
func (r *Recorder) Status() Status {
	if r == nil {
		return Status{}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status
}

func (r *Recorder) runSession(session *recordingSession, writer rowWriter, cfg RecorderConfig) {
	ticker := time.NewTicker(cfg.FlushInterval)
	defer ticker.Stop()

	var written uint64
	batch := make([]Record, 0, cfg.BatchSize)

	for {
		select {
		case req := <-session.queue:
			if err := r.bufferRecord(session, writer, &batch, &written, cfg.BatchSize, req); err != nil {
				r.abortSession(session, writer, err)
				return
			}

		case <-ticker.C:
			if err := r.flushBatch(session, writer, &batch, &written); err != nil {
				r.abortSession(session, writer, err)
				return
			}

		case <-session.stopC:
			r.completeSession(session, r.stopSession(session, writer, &batch, &written, cfg.BatchSize))
			return
		}
	}
}

func (r *Recorder) bufferRecord(
	session *recordingSession,
	writer rowWriter,
	batch *[]Record,
	written *uint64,
	batchSize int,
	req recordRequest,
) error {
	*batch = append(*batch, RecordFromStream(req.row, req.filterEpoch))
	if len(*batch) < batchSize {
		return nil
	}
	return r.flushBatch(session, writer, batch, written)
}

func (r *Recorder) flushBatch(
	session *recordingSession,
	writer rowWriter,
	batch *[]Record,
	written *uint64,
) error {
	if len(*batch) == 0 {
		return nil
	}
	if err := writer.WriteRows(*batch); err != nil {
		return err
	}
	*written += uint64(len(*batch))
	r.updateRowsWritten(session, *written)
	*batch = (*batch)[:0]
	return nil
}

func (r *Recorder) stopSession(
	session *recordingSession,
	writer rowWriter,
	batch *[]Record,
	written *uint64,
	batchSize int,
) error {
	if cause := session.cause(); cause != nil {
		_ = writer.Abort()
		return cause
	}
	if err := drainQueue(session, func(req recordRequest) error {
		return r.bufferRecord(session, writer, batch, written, batchSize, req)
	}); err != nil {
		_ = writer.Abort()
		return err
	}
	if err := r.flushBatch(session, writer, batch, written); err != nil {
		_ = writer.Abort()
		return err
	}
	return writer.Close()
}

func (r *Recorder) abortSession(session *recordingSession, writer rowWriter, err error) {
	session.stop(err)
	_ = writer.Abort()
	r.completeSession(session, err)
}

func (r *Recorder) completeSession(session *recordingSession, err error) {
	r.finishSession(session, err)
	session.doneErr = err
	session.doneC <- err
	close(session.doneC)
}

func (r *Recorder) updateRowsWritten(session *recordingSession, rowsWritten uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active != session {
		return
	}
	r.status.RowsWritten = rowsWritten
}

func (r *Recorder) finishSession(session *recordingSession, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active != session {
		return
	}
	r.status.Active = false
	r.status.LastError = err
	if err == nil {
		r.status.TempPath = ""
	}
	r.active = nil
}

func normalizeRecorderConfig(cfg RecorderConfig) RecorderConfig {
	if cfg.QueueCapacity <= 0 {
		cfg.QueueCapacity = defaultRecorderQueueCapacity
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultRecorderBatchSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultRecorderFlushInterval
	}
	cfg.Writer = normalizeWriterConfig(cfg.Writer)
	return cfg
}

func newRecordingSession(queueCapacity int) *recordingSession {
	return &recordingSession{
		queue:     make(chan recordRequest, queueCapacity),
		stopC:     make(chan struct{}),
		doneC:     make(chan error, 1),
		accepting: true,
	}
}

func (s *recordingSession) enqueue(req recordRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.accepting {
		if s.stopCause != nil {
			return s.stopCause
		}
		return ErrRecorderNotActive
	}

	select {
	case s.queue <- req:
		return nil
	default:
		s.accepting = false
		if s.stopCause == nil {
			s.stopCause = ErrRecorderQueueFull
		}
		s.stopOnce.Do(func() { close(s.stopC) })
		return ErrRecorderQueueFull
	}
}

func (s *recordingSession) stop(cause error) {
	s.mu.Lock()
	s.accepting = false
	if cause != nil && s.stopCause == nil {
		s.stopCause = cause
	}
	s.mu.Unlock()
	s.stopOnce.Do(func() { close(s.stopC) })
}

func (s *recordingSession) cause() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopCause
}

func drainQueue(session *recordingSession, consume func(recordRequest) error) error {
	for {
		select {
		case req := <-session.queue:
			if err := consume(req); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}
