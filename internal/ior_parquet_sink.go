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
	"ior/internal/probemanager"
	"ior/internal/streamrow"
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
	el.printCb = func(ep *event.Pair) {
		row := streamrow.New(s.seq.Next(), ep)
		if err := s.recorder.Record(row, 0); err != nil {
			s.fail(err)
		}
		ep.Recycle()
	}
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

	ch, ctx, cancel, profiling, el, mgr, cleanup, err := setupHeadlessParquetInfra(cfg, logln)
	if err != nil {
		return err
	}
	defer cleanup()
	defer profiling.stop(logln)
	defer cancel()

	recorder := parquet.NewRecorder(parquet.RecorderConfig{})
	if err := recorder.Start(cfg.ParquetPath, parquet.StartOptions{Metadata: parquet.NewFileMetadata("headless")}); err != nil {
		return err
	}

	sink := newHeadlessParquetSink(recorder, cancel)
	// sink.configure wires the event loop's print callback to record each pair
	// to Parquet; the mgr filter wraps it to skip inactive probes.
	configureEventLoopOutput(el, mgr, sink.configure)
	// startTraceShutdownWatcher returns a done channel that must be drained
	// before returning to prevent a goroutine leak when ctx is cancelled but
	// the goroutine has not yet exited.
	watcherDone := startTraceShutdownWatcher(ctx, true, el, profiling, logln)

	startTime := time.Now()
	el.run(ctx, ch)
	totalDuration := time.Since(startTime)
	<-watcherDone
	<-profiling.done

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
	logln("Good bye... (unloading BPF tracepoints will take a few seconds...) after", totalDuration)
	return nil
}

// setupHeadlessParquetInfra creates the BPF module, event channel, trace
// context, profiling control, and event loop for a headless Parquet run.
// mgr is returned so the caller can pass it to configureEventLoopOutput with
// the sink callback after the Parquet recorder has been started.
// cleanup must be deferred by the caller; it stops ring-buffer polling,
// detaches probes, releases BPF bindings, and stops signal handling.
func setupHeadlessParquetInfra(cfg flags.Config, logln func(...any)) (
	ch <-chan []byte,
	ctx context.Context,
	cancel context.CancelFunc,
	profiling *profilingControl,
	el *eventLoop,
	mgr *probemanager.Manager,
	cleanup func(),
	err error,
) {
	bpfModule, mgr, releaseBindings, err := setupBPFModule(context.Background(), cfg)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, func() {}, err
	}

	eventCh, rb, err := setupEventChannel(bpfModule)
	if err != nil {
		bpfModule.Close()
		return nil, nil, nil, nil, nil, nil, func() {}, err
	}

	ctx, cancel, stopSignals := setupTraceContext(context.Background(), cfg, logln)

	profiling, err = setupProfiling(ctx, cfg, nil)
	if err != nil {
		cancel()
		stopSignals()
		rb.Stop()
		bpfModule.Close()
		return nil, nil, nil, nil, nil, nil, func() {}, err
	}

	el, err = newEventLoop(newEventLoopConfig(cfg))
	if err != nil {
		cancel()
		stopSignals()
		rb.Stop()
		bpfModule.Close()
		return nil, nil, nil, nil, nil, nil, func() {}, err
	}

	cleanup = func() {
		// Stop the ring-buffer polling goroutine before the module is closed.
		// rb.Stop() is idempotent; bpfModule.Close() calls rb.Close() for the C struct.
		rb.Stop()
		if err := mgr.Close(); err != nil {
			logln("BPF probe manager close error:", err)
		}
		releaseBindings()
		bpfModule.Close()
		stopSignals()
	}
	return eventCh, ctx, cancel, profiling, el, mgr, cleanup, nil
}
