package internal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ior/internal/flags"
	"ior/internal/globalfilter"
	"ior/internal/parquet"
	"ior/internal/probemanager"
)

// The tests in this file drive runHeadlessParquetWith - the Parquet-specific
// lifecycle on top of the shared trace setup - through a real event loop, a
// real probe manager and a real Parquet recorder. Only the BPF side is
// replaced: fakeHeadlessParquetSetup hands back a traceInfra shaped exactly
// like the one setupTraceInfraWithEventLoop builds, fed from a pre-filled raw
// channel instead of a ring buffer, so none of this needs root.

// headlessParquetRunProbe records what the fake setup was given and what the
// infrastructure's teardown observed.
type headlessParquetRunProbe struct {
	setupCfg   flags.Config
	setupCalls int
	cleanups   int
	// parquetFinalAtClose reports whether the final Parquet file already
	// existed when the infrastructure was released.
	parquetFinalAtClose bool
}

// fakeHeadlessParquetSetup returns a setup that builds a traceInfra around n
// synthetic sync pairs, with the sync probe attached so the active-probe
// filter lets them through. The trace context is cancelled once the event
// loop has drained the stream - as SIGINT or -duration would end a real run -
// because the shutdown watcher only returns on cancellation.
func fakeHeadlessParquetSetup(t *testing.T, n int, probe *headlessParquetRunProbe, finalPath string) headlessParquetInfraSetup {
	t.Helper()
	return func(cfg flags.Config, logln func(...any)) (*traceInfra, error) {
		probe.setupCfg = cfg
		probe.setupCalls++

		el := newEmitOrderEventLoop(t)
		rawCh := filledRawChannel(syncPairStream(t, 0, n))
		close(rawCh)

		ctx, cancel := context.WithCancel(context.Background())
		profiling, err := setupProfiling(ctx, cfg, nil)
		if err != nil {
			cancel()
			return nil, err
		}
		go func() {
			select {
			case <-el.done:
				cancel()
			case <-ctx.Done():
			}
		}()

		infra := &traceInfra{
			ch: rawCh, ctx: ctx, cancel: cancel,
			profiling: profiling, el: el,
			mgr:         attachedSyncProbeManager(t),
			shutdownLog: logln,
		}
		infra.onClose(func() {
			probe.cleanups++
			_, statErr := os.Stat(finalPath)
			probe.parquetFinalAtClose = statErr == nil
		})
		return infra, nil
	}
}

// attachedSyncProbeManager returns a probe manager whose sync probe is
// attached through fake programs, so IsActive("sync") is true.
func attachedSyncProbeManager(t *testing.T) *probemanager.Manager {
	t.Helper()
	mgr := probemanager.NewManager(&fakeProbeAttacher{
		prog: &fakeProbeProgram{link: &fakeProbeLink{}},
	})
	mgr.Register("sync", probemanager.TracepointPair{Enter: "sys_enter_sync", Exit: "sys_exit_sync"})
	if err := mgr.Attach("sync"); err != nil {
		t.Fatalf("attach fake sync probe: %v", err)
	}
	return mgr
}

func TestRunHeadlessParquetRecordsEveryPairAndFinalisesBeforeTeardown(t *testing.T) {
	const pairs = 8
	path := filepath.Join(t.TempDir(), "headless.parquet")
	cfg := flags.NewFlags()
	cfg.ParquetPath = path
	probe := &headlessParquetRunProbe{}

	if err := runHeadlessParquetWith(cfg, fakeHeadlessParquetSetup(t, pairs, probe, path)); err != nil {
		t.Fatalf("runHeadlessParquetWith() error = %v, want nil", err)
	}

	rows := readRecordedParquet(t, path)
	if len(rows) != pairs {
		t.Fatalf("recorded rows = %d, want %d", len(rows), pairs)
	}
	for i, row := range rows {
		if row.Seq != uint64(i+1) || row.Syscall != "sync" {
			t.Fatalf("row %d = seq %d syscall %q, want seq %d syscall sync", i, row.Seq, row.Syscall, i+1)
		}
	}
	if probe.cleanups != 1 {
		t.Fatalf("infra cleanups = %d, want exactly 1", probe.cleanups)
	}
	if !probe.parquetFinalAtClose {
		t.Fatal("infrastructure was released before the Parquet recording was finalised")
	}
}

// TestRunHeadlessParquetSanitisesTheTraceConfig pins that the shared setup
// sees the headless trace configuration: content filters and TUI-only flags
// stripped, the PID scope kept. The mode handler rejects content filters up
// front; this is the second line of defence should one reach the run anyway.
func TestRunHeadlessParquetSanitisesTheTraceConfig(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.ParquetPath = filepath.Join(t.TempDir(), "headless.parquet")
	cfg.PidFilter = 4242
	cfg.CommFilter = "bash"
	cfg.PathFilter = "/tmp"
	cfg.TidFilter = 7
	cfg.PlainMode = true
	cfg.GlobalFilter = globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "bash"}}
	probe := &headlessParquetRunProbe{}

	if err := runHeadlessParquetWith(cfg, fakeHeadlessParquetSetup(t, 1, probe, cfg.ParquetPath)); err != nil {
		t.Fatalf("runHeadlessParquetWith() error = %v, want nil", err)
	}

	got := probe.setupCfg
	if got.PidFilter != 4242 {
		t.Errorf("setup PidFilter = %d, want 4242 preserved", got.PidFilter)
	}
	if hasHeadlessParquetContentFilters(got) {
		t.Errorf("setup received content filters: comm=%q path=%q tid=%d global=%+v",
			got.CommFilter, got.PathFilter, got.TidFilter, got.GlobalFilter)
	}
	if got.PlainMode || got.FlamegraphOutput {
		t.Errorf("setup received TUI/plain output flags: plain=%v flamegraph=%v", got.PlainMode, got.FlamegraphOutput)
	}
}

// TestRunHeadlessParquetSetupFailureLeavesNoRecording covers a failure inside
// the shared setup: its own error is returned unchanged and no Parquet file
// is created, because the recorder only starts once the trace can run.
func TestRunHeadlessParquetSetupFailureLeavesNoRecording(t *testing.T) {
	dir := t.TempDir()
	cfg := flags.NewFlags()
	cfg.ParquetPath = filepath.Join(dir, "headless.parquet")
	setupErr := errors.New("setup BPF module: load object: boom")

	err := runHeadlessParquetWith(cfg, func(flags.Config, func(...any)) (*traceInfra, error) {
		return nil, setupErr
	})
	if !errors.Is(err, setupErr) {
		t.Fatalf("runHeadlessParquetWith() error = %v, want the setup error", err)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("read output dir: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("output dir holds %d entries after a failed setup, want none", len(entries))
	}
}

// TestRunHeadlessParquetRecorderStartFailureReleasesTheInfrastructure covers
// the partial failure after setup has succeeded: the probes are attached and
// profiling may be running, so a recorder that cannot open its file must
// still release everything setup built - and must not run the trace.
func TestRunHeadlessParquetRecorderStartFailureReleasesTheInfrastructure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-dir", "headless.parquet")
	cfg := flags.NewFlags()
	cfg.ParquetPath = path
	probe := &headlessParquetRunProbe{}
	var infra *traceInfra
	setup := fakeHeadlessParquetSetup(t, 1, probe, path)

	err := runHeadlessParquetWith(cfg, func(cfg flags.Config, logln func(...any)) (*traceInfra, error) {
		var setupErr error
		infra, setupErr = setup(cfg, logln)
		return infra, setupErr
	})
	if err == nil || !strings.Contains(err.Error(), "start parquet recording") {
		t.Fatalf("runHeadlessParquetWith() error = %v, want the recorder start failure", err)
	}
	if probe.cleanups != 1 {
		t.Fatalf("infra cleanups = %d, want exactly 1 after the recorder failed to start", probe.cleanups)
	}
	if infra.ctx.Err() == nil {
		t.Error("trace context still live after the failed run: Close must cancel it")
	}
	select {
	case <-infra.el.done:
		t.Error("event loop ran although the recorder never started")
	default:
		// run owns this shutdown; it never ran, so release it here.
		infra.el.shutdownCommResolver()
	}
}

// TestFinishHeadlessParquetRecordingReportsTheRunOutcome pins the error
// precedence after the loop: a recorder failure the sink saw during the run is
// what cancelled the trace, so it is the reported error even though Stop then
// finalises cleanly.
func TestFinishHeadlessParquetRecordingReportsTheRunOutcome(t *testing.T) {
	sinkErr := errors.New("writer boom")
	tests := []struct {
		name    string
		sinkErr error
		wantErr error
	}{
		{name: "clean run", sinkErr: nil, wantErr: nil},
		{name: "sink failure is the run's error", sinkErr: sinkErr, wantErr: sinkErr},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "headless.parquet")
			recorder := parquet.NewRecorder(parquet.RecorderConfig{})
			if err := recorder.Start(path, parquet.StartOptions{Metadata: parquet.NewFileMetadata("headless")}); err != nil {
				t.Fatalf("recorder.Start() error = %v", err)
			}
			cancelled := false
			sink := newHeadlessParquetSink(recorder, func() { cancelled = true })
			if tc.sinkErr != nil {
				sink.fail(tc.sinkErr)
			}
			var logs []string
			logln := func(args ...any) { logs = append(logs, fmt.Sprint(args...)) }

			err := finishHeadlessParquetRecording(recorder, sink, logln)
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Fatalf("finishHeadlessParquetRecording() error = %v, want %v", err, tc.wantErr)
			}
			if cancelled != (tc.sinkErr != nil) {
				t.Errorf("trace cancelled = %v, want %v", cancelled, tc.sinkErr != nil)
			}
			if recorder.Status().Active {
				t.Error("recorder still active after finishing the recording")
			}
			if slices.ContainsFunc(logs, func(line string) bool { return strings.Contains(line, "dropped") }) {
				t.Errorf("logged a drop warning without dropped rows: %q", logs)
			}
		})
	}
}
