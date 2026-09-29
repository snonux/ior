package parquet

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
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
	// ErrRecorderQueueFull indicates the row was shed because the bounded
	// recorder queue was full. The recording session stays active and keeps
	// accepting rows as capacity frees up; the caller should surface
	// Status().RowsDropped instead of treating this as a failure.
	ErrRecorderQueueFull = errors.New("parquet recorder queue is full")
	// ErrRecorderStartedDropping is returned instead of ErrRecorderQueueFull
	// for the first row a recording sheds, so a caller can announce the
	// overflow once per recording without tracking recordings itself. It
	// wraps ErrRecorderQueueFull: errors.Is checks for that keep matching.
	ErrRecorderStartedDropping = fmt.Errorf("%w (first dropped row of this recording)", ErrRecorderQueueFull)
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
	// RowsDropped counts rows shed because the bounded queue was full.
	RowsDropped uint64
	LastError   error
}

// Recorder manages one active parquet recording session at a time.
type Recorder struct {
	mu     sync.RWMutex
	config RecorderConfig
	active *recordingSession
	status Status
	// failureTaken records that the dead recording's LastError has already
	// been handed to someone - a TakeFailure caller or the Stop caller - so
	// TakeFailure reports each failure exactly once. Reset by Start.
	failureTaken bool
}

type recordingSession struct {
	queue chan recordRequest
	stopC chan struct{}
	doneC chan error

	mu        sync.Mutex
	accepting bool
	// stopRequested marks a session ended through Recorder.Stop, whose
	// caller receives the terminal error; see finishSession.
	stopRequested bool
	stopCause     error
	doneErr       error
	stopOnce      sync.Once

	// dropped counts rows shed on queue overflow; atomic so Status can
	// read the live count without contending the session mutex.
	dropped atomic.Uint64
}

type recordRequest struct {
	row         streamrow.Row
	filterEpoch uint64
}

// NewRecorder constructs a reusable parquet recorder controller.
func NewRecorder(config RecorderConfig) *Recorder {
	return &Recorder{config: normalizeRecorderConfig(config)}
}

// Start begins a new recording session. It discards the previous recording's
// terminal state, including a failure nobody has taken yet; callers that must
// not lose such a failure call TakeFailure first.
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
	r.failureTaken = false
	r.status = Status{
		Active:   true,
		Path:     writer.FinalPath(),
		TempPath: writer.TempPath(),
	}
	r.mu.Unlock()

	go r.runSession(session, writer, cfg)
	return nil
}

// Record queues one shared stream row for persistence. When the bounded
// queue is full the row is shed (counted in Status().RowsDropped) and
// ErrRecorderQueueFull is returned (ErrRecorderStartedDropping for the first
// shed row of a recording); the session stays active so later rows are
// recorded as capacity frees up.
//
// Without an active session Record returns ErrRecorderNotActive, or, if the
// last session died with an error, that error (Status().LastError) until the
// next successful Start - so callers see a failed recording's error on every
// later call, not just once. Use TakeFailure to report such a failure once.
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

// Stop gracefully flushes and finalizes the active recording session and
// returns its terminal error. Without an active session it returns the last
// session's error, unless that failure was already taken (by TakeFailure or
// an earlier Stop), in which case it returns nil so no failure is reported
// twice. Either way a failure Stop returns counts as reported: TakeFailure
// will not hand it out again.
func (r *Recorder) Stop() error {
	if r == nil {
		return nil
	}

	r.mu.Lock()
	session := r.active
	if session == nil {
		failure := r.status.LastError
		if r.failureTaken {
			failure = nil
		}
		r.failureTaken = r.failureTaken || failure != nil
		r.mu.Unlock()
		return failure
	}
	// Mark the stop request while still holding r.mu: a session aborting on
	// its own must publish its failure through finishSession, which takes
	// r.mu, so it either finished before this point (session == nil above)
	// or sees stopRequested and marks the failure taken for this caller.
	// Marking after unlocking left a window where the failure was both
	// returned here and handed out by TakeFailure.
	session.markStopRequested()
	r.mu.Unlock()

	session.stop(nil)
	if err := <-session.doneC; err != nil {
		return err
	}
	return session.doneErr
}

// TakeFailure returns the error the last recording died with, exactly once
// per failure, and nil otherwise: while a recording is active, when the last
// one ended cleanly, when the failure was already taken, or when Stop
// returned it to its caller. It lets a caller that sees Record repeat a dead
// recording's LastError report that failure once, without tracking
// recordings itself.
func (r *Recorder) TakeFailure() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active != nil || r.status.LastError == nil || r.failureTaken {
		return nil
	}
	r.failureTaken = true
	return r.status.LastError
}

// Status returns a snapshot of the recorder state.
func (r *Recorder) Status() Status {
	if r == nil {
		return Status{}
	}

	r.mu.RLock()
	status := r.status
	session := r.active
	r.mu.RUnlock()

	if session != nil {
		status.RowsDropped = session.dropped.Load()
	}
	return status
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

// finishSession publishes the session's terminal state. A failure of a
// session ended through Stop is marked taken here, under the same lock that
// publishes it, because Stop hands it to its own caller. Stop sets
// stopRequested under r.mu as well, so the two cannot interleave. Lock order
// is r.mu then session.mu; nothing takes them the other way round.
func (r *Recorder) finishSession(session *recordingSession, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active != session {
		return
	}
	r.status.Active = false
	r.status.LastError = err
	r.failureTaken = err != nil && session.wasStopRequested()
	r.status.RowsDropped = session.dropped.Load()
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
		// Shed the row instead of failing the session: aborting here would
		// discard every already-captured event. The drop is counted so
		// callers can surface it while the recording continues. The first
		// drop gets its own sentinel so callers can warn once per recording.
		if s.dropped.Add(1) == 1 {
			return ErrRecorderStartedDropping
		}
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

// markStopRequested records that Recorder.Stop, whose caller receives the
// terminal error, is ending this session. Called with r.mu held (lock order
// r.mu then session.mu).
func (s *recordingSession) markStopRequested() {
	s.mu.Lock()
	s.stopRequested = true
	s.mu.Unlock()
}

func (s *recordingSession) wasStopRequested() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopRequested
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
