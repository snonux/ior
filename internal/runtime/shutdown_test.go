package runtime

import (
	"context"
	"testing"
)

func TestTraceShutdownReporterKeepsLatestUpdateAndTerminalState(t *testing.T) {
	reporter := NewTraceShutdownReporter()
	reporter.Publish(TraceShutdownProgress{Phase: TraceShutdownDetaching, Completed: 1, Total: 4})
	reporter.Publish(TraceShutdownProgress{Phase: TraceShutdownDetaching, Completed: 3, Total: 4})

	if got := <-reporter.Updates(); got.Completed != 3 || got.Total != 4 {
		t.Fatalf("latest progress = %+v, want 3/4", got)
	}

	reporter.Publish(TraceShutdownProgress{Phase: TraceShutdownDetaching, Completed: 4, Total: 4})
	reporter.Complete()
	reporter.Publish(TraceShutdownProgress{Phase: TraceShutdownDetaching, Completed: 0, Total: 99})
	if got := <-reporter.Updates(); got.Phase != TraceShutdownComplete {
		t.Fatalf("terminal progress = %+v, want complete", got)
	}
	select {
	case got := <-reporter.Updates():
		t.Fatalf("publish after completion produced %+v", got)
	default:
	}
}

func TestTraceShutdownReporterCompletionOwnership(t *testing.T) {
	t.Run("unclaimed synchronous starter completes", func(t *testing.T) {
		reporter := NewTraceShutdownReporter()
		reporter.CompleteUnlessClaimed()
		if got := <-reporter.Updates(); got.Phase != TraceShutdownComplete {
			t.Fatalf("progress = %+v, want complete", got)
		}
	})

	t.Run("claimed background starter owns completion", func(t *testing.T) {
		reporter := NewTraceShutdownReporter()
		if !reporter.Claim() {
			t.Fatal("first completion claim failed")
		}
		if reporter.Claim() {
			t.Fatal("second completion claim succeeded")
		}
		reporter.CompleteUnlessClaimed()
		select {
		case got := <-reporter.Updates():
			t.Fatalf("generic completion overrode owner with %+v", got)
		default:
		}
		reporter.Complete()
		if got := <-reporter.Updates(); got.Phase != TraceShutdownComplete {
			t.Fatalf("owner progress = %+v, want complete", got)
		}
	})
}

func TestTraceShutdownReporterClaimRacesGenericCompletionAtomically(t *testing.T) {
	for i := 0; i < 100; i++ {
		reporter := NewTraceShutdownReporter()
		start := make(chan struct{})
		claimResult := make(chan bool, 1)
		genericDone := make(chan struct{})
		go func() {
			<-start
			claimResult <- reporter.Claim()
		}()
		go func() {
			<-start
			reporter.CompleteUnlessClaimed()
			close(genericDone)
		}()

		close(start)
		claimed := <-claimResult
		<-genericDone
		if claimed {
			select {
			case got := <-reporter.Updates():
				t.Fatalf("iteration %d: successful claim raced with terminal update %+v", i, got)
			default:
			}
			reporter.Complete()
		}
		if got := <-reporter.Updates(); got.Phase != TraceShutdownComplete {
			t.Fatalf("iteration %d: terminal progress = %+v, want complete", i, got)
		}
	}
}

func TestTraceShutdownReporterContextRoundTrip(t *testing.T) {
	reporter := NewTraceShutdownReporter()
	ctx := ContextWithTraceShutdownReporter(context.Background(), reporter)
	got, ok := TraceShutdownReporterFromContext(ctx)
	if !ok || got != reporter {
		t.Fatalf("context reporter = %p, %t; want %p, true", got, ok, reporter)
	}
}
