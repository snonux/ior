package internal

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"ior/internal/event"
	"ior/internal/flags"
	"ior/internal/globalfilter"
	"ior/internal/parquet"
	"ior/internal/streamrow"

	bpf "github.com/aquasecurity/libbpfgo"
)

// headlessParquetSink streams traced events directly to a Parquet file,
// cancelling the trace context on any recorder error.
type headlessParquetSink struct {
	recorder *parquet.Recorder
	seq      *streamrow.Sequencer
	cancel   context.CancelFunc

	mu     sync.Mutex
	recErr error
}

func newHeadlessParquetSink(recorder *parquet.Recorder, cancel context.CancelFunc) *headlessParquetSink {
	return &headlessParquetSink{
		recorder: recorder,
		seq:      streamrow.NewSequencer(0),
		cancel:   cancel,
	}
}

// configure wires the event loop's print callback to record each pair to Parquet.
func (s *headlessParquetSink) configure(el *eventLoop) {
	el.SetPrintCallback(func(ep *event.Pair) {
		row := streamrow.New(s.seq.Next(), ep)
		if err := s.recorder.Record(row, 0); isFatalRecorderError(err) {
			s.fail(err)
		}
		ep.Recycle()
	})
}

// isFatalRecorderError reports whether a recorder error must abort the
// headless run. Queue overflow sheds the single row while the session stays
// active, so it is surfaced via Status().RowsDropped after the run instead
// of cancelling the trace and losing every already-captured event.
func isFatalRecorderError(err error) bool {
	return err != nil && !errors.Is(err, parquet.ErrRecorderQueueFull)
}

func (s *headlessParquetSink) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recErr != nil {
		return
	}
	s.recErr = err
	s.cancel()
}

func (s *headlessParquetSink) err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recErr
}

// isHeadlessParquetMode reports whether cfg specifies a headless Parquet recording run.
func isHeadlessParquetMode(cfg flags.Config) bool {
	return strings.TrimSpace(cfg.ParquetPath) != ""
}

// hasHeadlessParquetContentFilters reports whether cfg carries filters that are
// incompatible with headless Parquet mode. PID filtering is still allowed so
// focused headless recordings can avoid tracing unrelated system activity.
func hasHeadlessParquetContentFilters(cfg flags.Config) bool {
	return cfg.CommFilter != "" ||
		cfg.PathFilter != "" ||
		cfg.TidFilter > 0 ||
		cfg.GlobalFilter.IsActive()
}

// headlessParquetTraceConfig strips TUI-only flags from cfg so that the
// headless Parquet run records a clean event stream, optionally scoped by PID.
func headlessParquetTraceConfig(cfg flags.Config) flags.Config {
	out := cfg
	out.PlainMode = false
	out.FlamegraphOutput = false
	out.CommFilter = ""
	out.PathFilter = ""
	out.TidFilter = -1
	out.GlobalFilter = globalfilter.Filter{}
	return out
}

// runHeadlessParquet records all traced syscalls directly to a Parquet file
// without starting the TUI. Root privilege is checked by the mode handler
// (via runnerDeps.getEUID) before this function is invoked.
func runHeadlessParquet(cfg flags.Config) error {
	cfg = headlessParquetTraceConfig(cfg)
	logln := newLogger(true)

	infra, err := setupHeadlessParquetInfra(cfg, logln)
	if err != nil {
		return err
	}
	defer infra.Close()

	recorder := parquet.NewRecorder(parquet.RecorderConfig{})
	if err := recorder.Start(cfg.ParquetPath, parquet.StartOptions{Metadata: parquet.NewFileMetadata("headless")}); err != nil {
		return err
	}

	sink := newHeadlessParquetSink(recorder, infra.cancel)
	// sink.configure wires the event loop's print callback to record each pair
	// to Parquet; the mgr filter wraps it to skip inactive probes.
	configureEventLoopOutput(infra.el, infra.mgr, sink.configure)
	// startTraceShutdownWatcher returns a done channel that must be drained
	// before returning to prevent a goroutine leak when ctx is cancelled but
	// the goroutine has not yet exited.
	watcherDone := startTraceShutdownWatcher(infra.ctx, true, infra.el, infra.profiling, logln)

	startTime := time.Now()
	infra.el.run(infra.ctx, infra.ch)
	totalDuration := time.Since(startTime)
	<-watcherDone
	<-infra.profiling.done

	stopErr := recorder.Stop()
	if err := sink.err(); err != nil {
		if stopErr != nil && !errors.Is(stopErr, err) {
			return errors.Join(err, stopErr)
		}
		return err
	}
	if stopErr != nil {
		return stopErr
	}
	if dropped := recorder.Status().RowsDropped; dropped > 0 {
		logln("Warning:", dropped, "events were dropped (parquet recorder queue overflow) - the recording is partial")
	}
	logln("Trace stopped after", totalDuration, "- cleaning up...")
	return nil
}

// setupHeadlessParquetInfra selects the headless event-loop variant while
// delegating the complete resource lifecycle to the shared trace setup.
func setupHeadlessParquetInfra(cfg flags.Config, logln func(...any)) (*traceInfra, error) {
	return setupTraceInfraWithEventLoop(
		context.Background(), cfg, nil, logln, newHeadlessParquetEventLoop,
	)
}

// newHeadlessParquetEventLoop leaves the syscall aggregate source unwired:
// headless Parquet records event rows and has no aggregate sink to consume it.
func newHeadlessParquetEventLoop(
	cfg flags.Config,
	bpfModule *bpf.Module,
	warnSetup func(...any),
) (*eventLoop, error) {
	el, err := newEventLoop(newEventLoopConfig(cfg))
	if err != nil {
		return nil, err
	}
	attachRingbufDropCounter(el, bpfModule, warnSetup)
	return el, nil
}
