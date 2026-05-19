package integrationtests

import "testing"

func TestPipeBasic(t *testing.T) {
	result, _ := runScenarioResult(t, "pipe-basic", []ExpectedEvent{
		{Tracepoint: "enter_pipe", MinCount: 1},
		{Tracepoint: "enter_close", MinCount: 2},
	})

	assertTracepointPathPrefix(t, result, "enter_pipe", "pipe:")
	if got := totalTracepointPathCount(result, "enter_close", "pipe:"); got < 2 {
		t.Fatalf("enter_close records with tracked pipe descriptor prefix = %d, want >= 2", got)
	}
}

func TestPipe2Basic(t *testing.T) {
	result, _ := runScenarioResult(t, "pipe2-basic", []ExpectedEvent{
		{Tracepoint: "enter_pipe2", MinCount: 1},
		{Tracepoint: "enter_close", MinCount: 2},
	})

	assertTracepointPathPrefix(t, result, "enter_pipe2", "pipe:")
	if got := totalTracepointPathCount(result, "enter_close", "pipe:"); got < 2 {
		t.Fatalf("enter_close records with tracked pipe2 descriptor prefix = %d, want >= 2", got)
	}
}

func TestEventfdBasic(t *testing.T) {
	result, _ := runScenarioResult(t, "eventfd-basic", []ExpectedEvent{
		{Tracepoint: "enter_eventfd", MinCount: 1},
		{Tracepoint: "enter_close", MinCount: 1},
	})

	assertTracepointPathPrefix(t, result, "enter_eventfd", "eventfd:")
	assertTracepointPathPrefix(t, result, "enter_close", "eventfd:")
}

func TestEventfd2Basic(t *testing.T) {
	result, _ := runScenarioResult(t, "eventfd2-basic", []ExpectedEvent{
		{Tracepoint: "enter_eventfd2", MinCount: 1},
		{Tracepoint: "enter_close", MinCount: 1},
	})

	assertTracepointPathPrefix(t, result, "enter_eventfd2", "eventfd:")
	assertTracepointPathPrefix(t, result, "enter_close", "eventfd:")
}
