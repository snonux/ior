package parquet

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"ior/internal/sampling"
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

// footerWriter is implemented by writers that can still add a key/value pair
// to the file footer just before it is finalised (the real Writer does). It is
// optional so that test doubles of rowWriter stay small.
type footerWriter interface {
	SetKeyValueMetadata(key, value string) error
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
	// AutoNamed marks a path ior generated itself (the timestamped default).
	// It is then never replaced: on a collision the recording is published
	// under a "-N" suffixed name and Status().Path reports it. A path the
	// user chose (AutoNamed false) is replaced, as it always was.
	AutoNamed bool
}

// Status reports the last known recorder state.
type Status struct {
	Active bool
	// Path is the file the recording is written to. While recording it is the
	// requested path; after a graceful Stop it is where the file was really
	// published, which differs from RequestedPath only for an auto-named
	// recording whose name was already taken ("-N" suffix).
	Path string
	// RequestedPath is the (".parquet"-normalized) path Start asked for.
	RequestedPath string
	TempPath      string
	RowsWritten   uint64
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
	// footer holds key/value pairs to add to the file footer when the session
	// stops (SetSamplingTotals); guarded by mu.
	footer map[string]string

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
			if options.AutoNamed {
				return NewAutoNamedWriter(path, cfg, meta)
			}
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
		Active:        true,
		Path:          writer.FinalPath(),
		RequestedPath: writer.FinalPath(),
		TempPath:      writer.TempPath(),
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
// twice. Of several concurrent Stop calls on one session only the first
// returns the failure; the others wait for the session and return nil.
// Either way a failure Stop returns counts as reported: TakeFailure
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
	first := session.markStopRequested()
	r.mu.Unlock()
	if stopUnlockedHook != nil {
		stopUnlockedHook()
	}

	session.stop(nil)
	err := <-session.doneC
	if err == nil {
		err = session.doneErr
	}
	// Concurrent Stop calls on one session all wait for it to finish, but
	// only the first one reports its failure.
	if !first {
		return nil
	}
	return err
}

// stopUnlockedHook, when non-nil, runs inside Stop after it has seen an
// active session and released r.mu, before it stops the session. A test can
// let a self-aborting session finish there, which is where a stop mark taken
// after unlocking would come too late. Always nil in production.
var stopUnlockedHook func()

// SetSamplingTotals records the exact per-syscall population of a sampled run
// in the footer of the active recording (KeySamplingTotals); it is written when
// the recording stops, so call it before Stop, once the counts are final. A
// Summary that sampled nothing adds no key, so the file stays unmarked.
// Without an active session it returns ErrRecorderNotActive - except for a
// Summary that sampled nothing, which has nothing to record and succeeds
// whatever the session's state: an unsampled run wires nothing new, so it must
// not start failing just because its session already ended.
func (r *Recorder) SetSamplingTotals(summary sampling.Summary) error {
	totals := summary.Totals()
	if totals == "" {
		return nil
	}
	if r == nil {
		return ErrRecorderNotActive
	}
	r.mu.RLock()
	session := r.active
	r.mu.RUnlock()
	if session == nil {
		return ErrRecorderNotActive
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.footer == nil {
		session.footer = make(map[string]string)
	}
	session.footer[KeySamplingTotals] = totals
	return nil
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
			err := r.stopSession(session, writer, &batch, &written, cfg.BatchSize)
			if err == nil {
				// An auto-named recording never replaces an existing file, so
				// it may have been published under a "-N" name; report where it is.
				r.updatePublishedPath(session, writer.FinalPath())
			}
			r.completeSession(session, err)
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
	if err := session.applyFooter(writer); err != nil {
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

// updatePublishedPath records the path a finished recording was actually
// published at, which differs from the requested one when that name was taken.
func (r *Recorder) updatePublishedPath(session *recordingSession, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active != session {
		return
	}
	r.status.Path = path
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
// terminal error, is ending this session, and reports whether this was the
// first such request. Called with r.mu held (lock order r.mu then
// session.mu).
func (s *recordingSession) markStopRequested() (first bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	first = !s.stopRequested
	s.stopRequested = true
	return first
}

func (s *recordingSession) wasStopRequested() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopRequested
}

// applyFooter adds the pairs set through SetSamplingTotals to writer's footer,
// just before the writer is closed. A writer that cannot take footer pairs is
// left alone.
func (s *recordingSession) applyFooter(writer rowWriter) error {
	fw, ok := writer.(footerWriter)
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, value := range s.footer {
		if err := fw.SetKeyValueMetadata(key, value); err != nil {
			return fmt.Errorf("set parquet footer %s: %w", key, err)
		}
	}
	return nil
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
