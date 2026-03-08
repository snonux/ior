package internal

import (
	"strings"
	"testing"

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

func TestNewEventFilterRejectsTooLongCommFilter(t *testing.T) {
	tooLong := strings.Repeat("a", types.MAX_PROGNAME_LENGTH+1)
	_, err := newEventFilter(tooLong, "")
	if err == nil {
		t.Fatalf("expected error for comm filter longer than %d", types.MAX_PROGNAME_LENGTH)
	}
}

func TestNewEventFilterRejectsTooLongPathFilter(t *testing.T) {
	tooLong := strings.Repeat("a", types.MAX_FILENAME_LENGTH+1)
	_, err := newEventFilter("", tooLong)
	if err == nil {
		t.Fatalf("expected error for path filter longer than %d", types.MAX_FILENAME_LENGTH)
	}
}

func TestNewEventLoopPropagatesFilterError(t *testing.T) {
	tooLong := strings.Repeat("a", types.MAX_PROGNAME_LENGTH+1)
	_, err := newEventLoop(eventLoopConfig{commFilter: tooLong})
	if err == nil {
		t.Fatalf("expected newEventLoop to propagate invalid filter error")
	}
}
