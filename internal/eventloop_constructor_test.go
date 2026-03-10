package internal

import (
	"strings"
	"testing"

	"ior/internal/globalfilter"
	"ior/internal/types"
)

func mustNewEventLoop(tb testing.TB, cfg eventLoopConfig) *eventLoop {
	tb.Helper()
	if _, isBenchmark := tb.(*testing.B); !isBenchmark {
		cfg.synchronousRawProcessing = true
	}
	el, err := newEventLoop(cfg)
	if err != nil {
		tb.Fatalf("newEventLoop() error = %v", err)
	}
	return el
}

func TestNewEventLoopRejectsTooLongCommFilter(t *testing.T) {
	tooLong := strings.Repeat("a", types.MAX_PROGNAME_LENGTH+1)
	_, err := newEventLoop(eventLoopConfig{
		filter: globalfilter.Filter{
			Comm: &globalfilter.StringFilter{Pattern: tooLong},
		},
	})
	if err == nil {
		t.Fatalf("expected error for comm filter longer than %d", types.MAX_PROGNAME_LENGTH)
	}
}

func TestNewEventLoopRejectsTooLongPathFilter(t *testing.T) {
	tooLong := strings.Repeat("a", types.MAX_FILENAME_LENGTH+1)
	_, err := newEventLoop(eventLoopConfig{
		filter: globalfilter.Filter{
			File: &globalfilter.StringFilter{Pattern: tooLong},
		},
	})
	if err == nil {
		t.Fatalf("expected error for path filter longer than %d", types.MAX_FILENAME_LENGTH)
	}
}

func TestNewEventLoopPropagatesFilterError(t *testing.T) {
	tooLong := strings.Repeat("a", types.MAX_PROGNAME_LENGTH+1)
	_, err := newEventLoop(eventLoopConfig{
		filter: globalfilter.Filter{
			Comm: &globalfilter.StringFilter{Pattern: tooLong},
		},
	})
	if err == nil {
		t.Fatalf("expected newEventLoop to propagate invalid filter error")
	}
}
