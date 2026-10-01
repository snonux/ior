package flags

import (
	"bytes"
	"flag"
	"strconv"
	"strings"
	"testing"

	"ior/internal/flamegraph"
)

// -flamegraph-max-keys (task rs2): the -flamegraph recorder's cap on distinct
// records, defaulting to flamegraph.DefaultMaxRecordKeys.

func TestParseFlamegraphMaxKeysDefaultsToRecorderDefault(t *testing.T) {
	cfg, err := parseForTest(t)
	if err != nil {
		t.Fatalf("parse returned unexpected error: %v", err)
	}
	if cfg.FlamegraphMaxKeys != flamegraph.DefaultMaxRecordKeys {
		t.Fatalf("FlamegraphMaxKeys = %d, want flamegraph.DefaultMaxRecordKeys (%d)",
			cfg.FlamegraphMaxKeys, flamegraph.DefaultMaxRecordKeys)
	}
}

func TestParseFlamegraphMaxKeysAcceptsTheWholeRange(t *testing.T) {
	for _, want := range []int{1, 1000, 1 << 21, flamegraph.MaxRecordKeysLimit} {
		cfg, err := parseForTest(t, "-flamegraph", "-flamegraph-max-keys", strconv.Itoa(want))
		if err != nil {
			t.Fatalf("-flamegraph-max-keys %d: unexpected error: %v", want, err)
		}
		if cfg.FlamegraphMaxKeys != want {
			t.Fatalf("FlamegraphMaxKeys = %d, want %d", cfg.FlamegraphMaxKeys, want)
		}
	}
}

func TestParseFlamegraphMaxKeysRejectsOutOfRange(t *testing.T) {
	// 0 would make the live recorder unbounded (maxKeys == 0 inside
	// flamegraph.iorData), negatives are nonsense, and one past the limit asks
	// for more than ~4 GB of recorder heap.
	for _, bad := range []string{"0", "-1", "-524288", strconv.Itoa(flamegraph.MaxRecordKeysLimit + 1), "1000000000"} {
		_, err := parseForTest(t, "-flamegraph", "-flamegraph-max-keys", bad)
		if err == nil {
			t.Fatalf("-flamegraph-max-keys %s: expected a parse error", bad)
		}
		msg := err.Error()
		if !strings.Contains(msg, "invalid flamegraph-max-keys: "+bad) ||
			!strings.Contains(msg, strconv.Itoa(flamegraph.MaxRecordKeysLimit)) {
			t.Fatalf("-flamegraph-max-keys %s: error %q does not name the value and the bound", bad, msg)
		}
	}
}

func TestParseFlamegraphMaxKeysRejectsNonIntegers(t *testing.T) {
	for _, bad := range []string{"many", "1.5", "1e6"} {
		if _, err := parseForTest(t, "-flamegraph-max-keys", bad); err == nil {
			t.Fatalf("-flamegraph-max-keys %s: expected a parse error", bad)
		}
	}
}

// The help text is the only place a user meets the memory cost before a run,
// so it must name the per-record size and the bound.
func TestUsageDocumentsFlamegraphMaxKeys(t *testing.T) {
	fs := flag.NewFlagSet("ior", flag.ContinueOnError)
	var out bytes.Buffer
	fs.SetOutput(&out)
	cfg := NewFlags()
	registerFlags(fs, &cfg)
	fs.PrintDefaults()
	help := out.String()
	for _, want := range []string{
		"-flamegraph-max-keys",
		"~250 bytes each",
		strconv.Itoa(flamegraph.MaxRecordKeysLimit),
		"(default " + strconv.Itoa(flamegraph.DefaultMaxRecordKeys) + ")",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("help text lacks %q:\n%s", want, help)
		}
	}
}
