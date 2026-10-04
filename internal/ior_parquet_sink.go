package internal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"ior/internal/event"
	"ior/internal/flags"
	"ior/internal/globalfilter"
	"ior/internal/parquet"
	"ior/internal/sampling"
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

// headlessRecorderConfig is the recorder setup of a headless run: backpressure
// with a large bounded queue. Nobody watches a headless run, so a file that
// silently misses rows the event loop had already processed (the old 4096-row
// shed-mode queue lost ~2% at 870k rows/s while a row-group flush held the
// writer) is worse than a slower loop: the print callback waits for the
// writer, the event loop falls behind, and whatever the kernel then cannot
// deliver is lost in the ring buffer, where it is counted ("ring buffer
// drops") and taken into account by the sampling totals. The TUI keeps the
// non-blocking shed mode, because its event loop also feeds the live views.
func headlessRecorderConfig() parquet.RecorderConfig {
	return parquet.RecorderConfig{
		QueueCapacity: parquet.HeadlessQueueCapacity,
		BlockWhenFull: true,
	}
}

// newHeadlessRecorder builds the recorder of a headless run from the given
// configuration; parquet.NewRecorder in production. It is a variable only so a
// test can capture the configuration runHeadlessParquetWith really passes and
// pin that the call site applies headlessRecorderConfig (a call site that
// silently fell back to the zero config would shed rows again, and no
// recorder-level test could notice).
var newHeadlessRecorder = parquet.NewRecorder

// isFatalRecorderError reports whether a recorder error must abort the
// headless run. Queue overflow sheds the single row while the session stays
// active, so it is surfaced via Status().RowsDropped after the run instead
// of cancelling the trace and losing every already-captured event. The
// headless recorder blocks rather than sheds (headlessRecorderConfig), so this
// only matters for a recorder configured otherwise.
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

// headlessParquetInfraSetup builds the trace infrastructure of a headless
// Parquet run; setupHeadlessParquetInfra in production. It is a parameter of
// runHeadlessParquetWith so the recorder lifecycle around it can be exercised
// without the root privileges real BPF setup needs.
type headlessParquetInfraSetup func(cfg flags.Config, logln func(...any)) (*traceInfra, error)

// runHeadlessParquet records all traced syscalls directly to a Parquet file
// without starting the TUI. Root privilege is checked by the mode handler
// (via runnerDeps.getEUID) before this function is invoked.
func runHeadlessParquet(cfg flags.Config) error {
	return runHeadlessParquetWith(cfg, setupHeadlessParquetInfra)
}

// runHeadlessParquetWith runs one headless Parquet recording on the
// infrastructure that setup builds. The shared trace setup owns every BPF and
// runtime resource (and releases what it built when it fails part-way); this
// function adds only the Parquet-specific lifecycle on top: the output path is
// probed first (parquet.CheckOutputPath) so an unusable one fails before the
// costly setup; the recorder is started once the trace can run, so a failed
// setup leaves no file behind; and it is stopped - flushing and finalising the
// file - after the event loop has drained and before the infrastructure is
// released.
func runHeadlessParquetWith(cfg flags.Config, setup headlessParquetInfraSetup) error {
	cfg = headlessParquetTraceConfig(cfg)
	logln := newLogger(true)

	// Cheap output check before the expensive BPF load/attach: a bad directory
	// used to cost seconds of setup (and a "Probing" line) before the error.
	if err := parquet.CheckOutputPath(cfg.ParquetPath); err != nil {
		return fmt.Errorf("start parquet recording: %w", err)
	}

	// Before the probes attach, like runTraceWithContext: see targetWatch.
	watch := openHeadlessTargetWatch(cfg, true)
	defer watch.Close()

	infra, err := setup(cfg, logln)
	if err != nil {
		return err
	}
	defer infra.Close()
	watch.attachTo(infra)

	// A run that samples says so in the file footer from the start; the exact
	// totals follow when the recording stops (finishHeadlessParquetRecording).
	meta := parquet.NewFileMetadata("headless")
	meta.Sampling = infra.el.samplingPlan()
	recorder := newHeadlessRecorder(headlessRecorderConfig())
	if err := recorder.Start(cfg.ParquetPath, parquet.StartOptions{Metadata: meta}); err != nil {
		return fmt.Errorf("start parquet recording: %w", err)
	}

	sink := newHeadlessParquetSink(recorder, infra.cancel)
	// sink.configure wires the event loop's print callback to record each pair
	// to Parquet; runTraceLoop wraps it to skip inactive probes.
	totalDuration := runTraceLoop(infra, true, sink.configure, logln)
	if err := finishHeadlessParquetRecording(recorder, sink, infra.el.samplingResult(), logln); err != nil {
		return err
	}
	logTraceStopped(totalDuration, logln)
	return nil
}

// finishHeadlessParquetRecording stops the recorder, finalising the Parquet
// file, and reports the run's outcome. A recorder failure the sink observed
// during the run is the primary error - it is what cancelled the trace - with
// a distinct Stop error joined to it; otherwise Stop's own error is returned.
// Rows shed by queue overflow are not an error, but the recording is then
// partial, so that is logged; the headless recorder applies backpressure
// instead of shedding, so in practice this stays silent.
//
// samples is the run's sampling outcome. Its exact totals go into the file
// footer before the recorder stops (a recording that sampled nothing gets no
// sampling key); failing to record them fails the run, because a sampled file
// without its totals would pass for a complete one.
func finishHeadlessParquetRecording(recorder *parquet.Recorder, sink *headlessParquetSink, samples sampling.Summary, logln func(...any)) error {
	totalsErr := recorder.SetSamplingTotals(samples)
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
	if totalsErr != nil {
		return fmt.Errorf("record the sampling totals in the parquet footer: %w", totalsErr)
	}
	status := recorder.Status()
	logln(parquetPublishedNotice(status))
	if dropped := status.RowsDropped; dropped > 0 {
		logln("Warning:", dropped, "events were dropped (parquet recorder queue overflow) - the recording is partial")
	}
	return nil
}

// parquetPublishedNotice names the file a finished recording was really
// written to. The path given with -parquet is replaced in place, so normally
// the notice just confirms it; if the recorder ever had to publish under
// another name (a "-N" suffix because the requested name was protected) the
// notice says so explicitly, since the user would otherwise look for the
// recording at the requested path and find something else.
func parquetPublishedNotice(status parquet.Status) string {
	if status.RequestedPath != "" && status.Path != status.RequestedPath {
		return fmt.Sprintf("Parquet recording written to %s (%s was already taken)", status.Path, status.RequestedPath)
	}
	return "Parquet recording written to " + status.Path
}

// setupHeadlessParquetInfra selects the headless event-loop variant while
// delegating the complete resource lifecycle to the shared trace setup.
func setupHeadlessParquetInfra(cfg flags.Config, logln func(...any)) (*traceInfra, error) {
	return setupTraceInfraWithEventLoop(
		context.Background(), cfg, nil, traceSetupHooks{}, logln, newHeadlessParquetEventLoop,
	)
}

// newHeadlessParquetEventLoop builds the headless Parquet event loop. Headless
// Parquet records event rows and has no TUI aggregate sink, so the kernel
// aggregate source stays unwired - except when the run samples (an explicit
// -syscall-sampling-* rate): then the loop carries a samplingTally as its
// aggregate sink, and the source is wired so the invocations that produced no
// row are still counted and end up in the file footer.
func newHeadlessParquetEventLoop(
	cfg flags.Config,
	bpfModule *bpf.Module,
	warnSetup func(...any),
) (*eventLoop, error) {
	el, err := newEventLoop(newEventLoopConfig(cfg))
	if err != nil {
		return nil, err
	}
	if el.samplingTally != nil {
		aggregateSrc, err := openAggregateSource(bpfModule)
		if err != nil {
			return nil, fmt.Errorf("count the unsampled invocations of a sampled recording: %w", err)
		}
		el.aggregateSrc = aggregateSrc
	}
	attachRingbufDropCounter(el, bpfModule, warnSetup)
	attachRingbufUnreadReader(el, bpfModule, warnSetup)
	return el, nil
}
