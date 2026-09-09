package internal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"ior/internal/flags"
	"ior/internal/globalfilter"
	"ior/internal/types"

	bpf "github.com/aquasecurity/libbpfgo"
)

func TestSetupBPFModuleErrorWrapsStage(t *testing.T) {
	cause := errors.New("boom")

	err := setupBPFModuleError("load object", cause)
	if err == nil {
		t.Fatalf("expected wrapped error")
	}
	if got, want := err.Error(), "setup BPF module: load object: boom"; got != want {
		t.Fatalf("wrapped error = %q, want %q", got, want)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("expected wrapped error to retain original cause")
	}
}

func TestSetupBPFModuleErrorNil(t *testing.T) {
	if err := setupBPFModuleError("attach probes", nil); err != nil {
		t.Fatalf("expected nil error passthrough, got %v", err)
	}
}

func TestLoadBPFModuleUsesEmbeddedObjectByDefault(t *testing.T) {
	origFile := newBPFModuleFromFile
	origBuffer := newBPFModuleFromBuffer
	origOverride, hadOverride := os.LookupEnv(bpfObjectOverrideEnv)
	t.Cleanup(func() {
		newBPFModuleFromFile = origFile
		newBPFModuleFromBuffer = origBuffer
		if hadOverride {
			_ = os.Setenv(bpfObjectOverrideEnv, origOverride)
			return
		}
		_ = os.Unsetenv(bpfObjectOverrideEnv)
	})
	_ = os.Unsetenv(bpfObjectOverrideEnv)

	wantErr := errors.New("buffer load failed")
	newBPFModuleFromFile = func(string) (*bpf.Module, error) {
		t.Fatal("expected embedded loader, not file loader")
		return nil, nil
	}

	var gotBytes []byte
	var gotName string
	newBPFModuleFromBuffer = func(data []byte, name string) (*bpf.Module, error) {
		gotBytes = append([]byte(nil), data...)
		gotName = name
		return nil, wantErr
	}

	module, stage, err := loadBPFModule()
	if module != nil {
		t.Fatalf("expected nil module from stubbed loader, got %v", module)
	}
	if got, want := stage, "load embedded module"; got != want {
		t.Fatalf("stage = %q, want %q", got, want)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected embedded loader error, got %v", err)
	}
	if !bytes.Equal(gotBytes, embeddedBPFObject) {
		t.Fatalf("embedded loader received unexpected object bytes")
	}
	if got, want := gotName, embeddedBPFObjectName; got != want {
		t.Fatalf("embedded loader name = %q, want %q", got, want)
	}
}

func TestLoadBPFModuleUsesOverridePathWhenConfigured(t *testing.T) {
	origFile := newBPFModuleFromFile
	origBuffer := newBPFModuleFromBuffer
	origOverride, hadOverride := os.LookupEnv(bpfObjectOverrideEnv)
	t.Cleanup(func() {
		newBPFModuleFromFile = origFile
		newBPFModuleFromBuffer = origBuffer
		if hadOverride {
			_ = os.Setenv(bpfObjectOverrideEnv, origOverride)
			return
		}
		_ = os.Unsetenv(bpfObjectOverrideEnv)
	})

	overridePath := "/tmp/custom-ior.bpf.o"
	if err := os.Setenv(bpfObjectOverrideEnv, overridePath); err != nil {
		t.Fatalf("set override env: %v", err)
	}

	wantErr := errors.New("file load failed")
	newBPFModuleFromBuffer = func([]byte, string) (*bpf.Module, error) {
		t.Fatal("expected file loader, not embedded loader")
		return nil, nil
	}

	var gotPath string
	newBPFModuleFromFile = func(path string) (*bpf.Module, error) {
		gotPath = path
		return nil, wantErr
	}

	module, stage, err := loadBPFModule()
	if module != nil {
		t.Fatalf("expected nil module from stubbed loader, got %v", module)
	}
	if got, want := stage, "load module from override file"; got != want {
		t.Fatalf("stage = %q, want %q", got, want)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected override loader error, got %v", err)
	}
	if got, want := gotPath, overridePath; got != want {
		t.Fatalf("override path = %q, want %q", got, want)
	}
}

// TestSetupTraceInfraRejectsAnUnusableFilterBeforeAnyBPFSetup pins the
// contract the TUI trace starter depends on: the started channel is closed
// only for a trace that is really running. A comm pattern longer than the
// kernel's fixed-size comm field can never match, so setup must reject it and
// leave the signal unsent - the TUI reads a closed channel as "attached" and
// stops listening for errors, so a failure after that point is invisible.
//
// The name says "before any BPF setup" rather than "before signalling start"
// because that is the stronger thing this actually pins when run unprivileged:
// setupBPFModule fails first on rlimit for a normal user, so the only way to
// see the filter error here is for validation to precede it. As root the
// started-channel assertion below is the one that carries the test. Both are
// worth having - the ordering also means an unusable filter costs no probe
// attach/detach cycle.
func TestSetupTraceInfraRejectsAnUnusableFilterBeforeAnyBPFSetup(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.GlobalFilter = globalfilter.Filter{
		Comm: &globalfilter.StringFilter{
			Pattern: strings.Repeat("a", types.MAX_PROGNAME_LENGTH+1),
		},
	}

	started := make(chan struct{})
	_, _, cancel, _, _, _, teardown, err := setupTraceInfra(
		context.Background(), cfg, started, func(...any) {},
	)
	if cancel != nil {
		cancel()
	}
	if teardown != nil {
		teardown()
	}

	if err == nil {
		t.Fatal("setupTraceInfra accepted a comm filter longer than the kernel comm field")
	}
	if !strings.Contains(err.Error(), "comm filter max size") {
		t.Fatalf("setupTraceInfra error = %v, want the comm-filter length rejection", err)
	}
	select {
	case <-started:
		t.Fatal("setupTraceInfra signalled trace start for a trace it could not start")
	default:
	}
}

// TestNewTraceEventLoopFailsWhenTheAggregateMapIsMissing covers the other half
// of the defect setupTraceInfra's signal ordering exists for. The reported
// trigger was an over-long comm filter, which fails in newEventLoop; a stale
// IOR_BPF_OBJECT without syscall_aggregate_map fails one step later, in
// newSyscallAggregateConsumer. Both used to happen after the TUI had been told
// the trace was running.
//
// Grouping them in newTraceEventLoop is what lets setupTraceInfra hold the
// signal until every fallible step has passed, so what matters here is that
// this function reports the second failure rather than swallowing it: a nil
// module stands in for a BPF object whose map is absent.
func TestNewTraceEventLoopFailsWhenTheAggregateMapIsMissing(t *testing.T) {
	el, err := newTraceEventLoop(flags.NewFlags(), nil, func(...any) {})
	if err == nil {
		t.Fatal("newTraceEventLoop accepted a module with no syscall aggregate map")
	}
	if el != nil {
		t.Errorf("newTraceEventLoop returned an event loop alongside its error: %v", el)
	}
}

// TestNewTraceEventLoopRejectsAnUnusableFilter is the first half of the same
// pair: newEventLoop validates the filter, and its failure has to reach
// setupTraceInfra rather than being reported as a running trace.
func TestNewTraceEventLoopRejectsAnUnusableFilter(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.GlobalFilter = globalfilter.Filter{
		Comm: &globalfilter.StringFilter{
			Pattern: strings.Repeat("a", types.MAX_PROGNAME_LENGTH+1),
		},
	}

	el, err := newTraceEventLoop(cfg, nil, func(...any) {})
	if err == nil {
		t.Fatal("newTraceEventLoop accepted a comm filter longer than the kernel comm field")
	}
	if !strings.Contains(err.Error(), "comm filter max size") {
		t.Fatalf("newTraceEventLoop error = %v, want the comm-filter length rejection", err)
	}
	if el != nil {
		t.Errorf("newTraceEventLoop returned an event loop alongside its error: %v", el)
	}
}
