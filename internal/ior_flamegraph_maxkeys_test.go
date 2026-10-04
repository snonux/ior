package internal

import (
	"testing"

	"ior/internal/flags"
	"ior/internal/flamegraph"
)

// -flamegraph-max-keys reaches the recorder that -flamegraph builds (task
// rs2): the parsed default, a parsed override, and the hand-built Config of
// tests (zero value), which must still get the bounded default.
func TestFlamegraphRecorderUsesTheConfiguredMaxKeys(t *testing.T) {
	parsed := func(args ...string) flags.Config {
		t.Helper()
		cfg, err := flags.ParseArgs(append([]string{"-flamegraph"}, args...))
		if err != nil {
			t.Fatalf("ParseArgs(%v): %v", args, err)
		}
		return cfg
	}
	for _, tc := range []struct {
		name string
		cfg  flags.Config
		want int
	}{
		{"default", parsed(), flamegraph.DefaultMaxRecordKeys},
		{"raised", parsed("-flamegraph-max-keys", "2000000"), 2000000},
		{"lowered", parsed("-flamegraph-max-keys", "7"), 7},
		{"zero value config", flags.Config{FlamegraphOutput: true}, flamegraph.DefaultMaxRecordKeys},
	} {
		_, recorder := maybePrependFlamegraphConfigure(tc.cfg, nil)
		if recorder == nil {
			t.Fatalf("%s: -flamegraph did not create a recorder", tc.name)
		}
		if got := recorder.MaxKeys(); got != tc.want {
			t.Fatalf("%s: recorder cap = %d, want %d", tc.name, got, tc.want)
		}
	}
}
