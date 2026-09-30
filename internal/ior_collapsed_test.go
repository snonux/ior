package internal

import (
	"bytes"
	"path/filepath"
	"testing"

	"ior/internal/flamegraph"
)

func TestRunCollapsedConverterDerivesStacks(t *testing.T) {
	t.Chdir(t.TempDir())

	recorder := flamegraph.NewRecorder("cli")
	recorder.AddPair(testTracePair(1, "keep"))
	recorder.AddPair(testTracePair(2, "keep"))
	if err := recorder.Write(); err != nil {
		t.Fatalf("recorder.Write() error = %v", err)
	}
	matches, err := filepath.Glob("*cli*.ior.zst")
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected exactly one cli recording, got %v (err %v)", matches, err)
	}
	path := matches[0]

	t.Run("default options", func(t *testing.T) {
		var out bytes.Buffer
		if err := RunCollapsedConverter([]string{path}, &out); err != nil {
			t.Fatalf("RunCollapsedConverter() error = %v", err)
		}
		if got, want := out.String(), "keep;enter_openat;/tmp;/test 2\n"; got != want {
			t.Fatalf("collapsed output:\n got: %q\nwant: %q", got, want)
		}
	})

	t.Run("custom fields and count", func(t *testing.T) {
		var out bytes.Buffer
		if err := RunCollapsedConverter([]string{"-fields", "comm", "-count", "duration", path}, &out); err != nil {
			t.Fatalf("RunCollapsedConverter() error = %v", err)
		}
		// Both pairs share one record (Duration 1 + 2).
		if got, want := out.String(), "keep 3\n"; got != want {
			t.Fatalf("collapsed output:\n got: %q\nwant: %q", got, want)
		}
	})

	t.Run("padded fields with stray commas", func(t *testing.T) {
		var out bytes.Buffer
		if err := RunCollapsedConverter([]string{"-fields", " comm ,", "-count", "duration", path}, &out); err != nil {
			t.Fatalf("RunCollapsedConverter() error = %v", err)
		}
		if got, want := out.String(), "keep 3\n"; got != want {
			t.Fatalf("collapsed output:\n got: %q\nwant: %q", got, want)
		}
	})

	t.Run("comma-only fields use defaults", func(t *testing.T) {
		var out bytes.Buffer
		if err := RunCollapsedConverter([]string{"-fields", " , ", path}, &out); err != nil {
			t.Fatalf("RunCollapsedConverter() error = %v", err)
		}
		if got, want := out.String(), "keep;enter_openat;/tmp;/test 2\n"; got != want {
			t.Fatalf("collapsed output:\n got: %q\nwant: %q", got, want)
		}
	})
}

func TestRunCollapsedConverterArgErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no recording argument", nil},
		{"too many arguments", []string{"a.ior.zst", "b.ior.zst"}},
		{"unknown flag", []string{"-bogus", "a.ior.zst"}},
		{"missing recording", []string{filepath.Join(t.TempDir(), "missing.ior.zst")}},
		{"invalid count field", []string{"-count", "bogus", "a.ior.zst"}},
		{"invalid field", []string{"-fields", "bogus", "a.ior.zst"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := RunCollapsedConverter(tc.args, &out); err == nil {
				t.Fatalf("RunCollapsedConverter(%v) succeeded, want error", tc.args)
			}
		})
	}
}

// TestRunCollapsedConverterEscapesOnTerminal checks `ior collapsed` escapes
// traced frames when its output is a terminal and keeps them raw otherwise.
func TestRunCollapsedConverterEscapesOnTerminal(t *testing.T) {
	t.Chdir(t.TempDir())

	recorder := flamegraph.NewRecorder("tty")
	// ';' is a frame separator, so use an SGR payload without one.
	recorder.AddPair(testTracePair(1, "evil\x1b[8mhidden\x1b[0m\a"))
	if err := recorder.Write(); err != nil {
		t.Fatalf("recorder.Write() error = %v", err)
	}
	matches, err := filepath.Glob("*tty*.ior.zst")
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected exactly one tty recording, got %v (err %v)", matches, err)
	}
	args := []string{"-fields", "comm", matches[0]}

	tty := newTTYBuffer(t)
	if err := RunCollapsedConverter(args, tty); err != nil {
		t.Fatalf("RunCollapsedConverter(tty) error = %v", err)
	}
	if got, want := tty.String(), `evil\x1b[8mhidden\x1b[0m\x07 1`+"\n"; got != want {
		t.Fatalf("terminal output = %q, want %q", got, want)
	}

	var piped bytes.Buffer
	if err := RunCollapsedConverter(args, &piped); err != nil {
		t.Fatalf("RunCollapsedConverter(piped) error = %v", err)
	}
	if got, want := piped.String(), "evil\x1b[8mhidden\x1b[0m\a 1\n"; got != want {
		t.Fatalf("piped output = %q, want %q", got, want)
	}
}
