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
// incompatible with headless Parquet mode (all events must be recorded unfiltered).
func hasHeadlessParquetContentFilters(cfg flags.Config) bool {
	return cfg.CommFilter != "" ||
		cfg.PathFilter != "" ||
		cfg.PidFilter > 0 ||
		cfg.TidFilter > 0 ||
		cfg.GlobalFilter.IsActive()
}

// headlessParquetTraceConfig strips TUI-only flags from cfg so that the
// headless Parquet run records a clean, unfiltered event stream.
func headlessParquetTraceConfig(cfg flags.Config) flags.Config {
	out := cfg
	out.PlainMode = false
	out.FlamegraphOutput = false
	out.CommFilter = ""
	out.PathFilter = ""
	out.PidFilter = -1
	out.TidFilter = -1
	out.GlobalFilter = globalfilter.Filter{}
	return out
}

// runHeadlessParquet records all traced syscalls directly to a Parquet file
// without starting the TUI.
func runHeadlessParquet(cfg flags.Config) error {
	if getEUID() != 0 {
		return errRootPrivilegesRequired
	}

	cfg = headlessParquetTraceConfig(cfg)
	logln := newLogger(true)

	bpfModule, mgr, releaseBindings, err := setupBPFModule(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer bpfModule.Close()
	defer mgr.Close()
	defer releaseBindings()

	ch, err := setupEventChannel(bpfModule)
	if err != nil {
		return err
	}
	ctx, cancel, stopSignals := setupTraceContext(context.Background(), cfg, logln)
	defer cancel()
	defer stopSignals()

	profiling, err := setupProfiling(ctx, cfg, nil)
	if err != nil {
		return err
	}

	el, err := newEventLoop(newEventLoopConfig(cfg))
	if err != nil {
		return err
	}

	recorder := parquet.NewRecorder(parquet.RecorderConfig{})
	if err := recorder.Start(cfg.ParquetPath, parquet.StartOptions{Metadata: parquet.NewFileMetadata("headless")}); err != nil {
		return err
	}

	sink := newHeadlessParquetSink(recorder, cancel)
	configureEventLoopOutput(el, mgr, sink.configure)
	startTraceShutdownWatcher(ctx, true, el, profiling, logln)

	startTime := time.Now()
	el.run(ctx, ch)
	totalDuration := time.Since(startTime)
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
