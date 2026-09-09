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

// TestSetupTraceInfraRejectsAnUnusableFilterBeforeSignallingStart pins the
// contract the TUI trace starter depends on: the started channel is closed
// only for a trace that is really running. A comm pattern longer than the
// kernel's fixed-size comm field can never match, so setup must fail with that
// error and leave the signal unsent - the TUI reads a closed channel as
// "attached" and stops listening for errors, so a failure signalled afterwards
// reaches nobody and leaves a live-looking, permanently empty dashboard.
func TestSetupTraceInfraRejectsAnUnusableFilterBeforeSignallingStart(t *testing.T) {
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
