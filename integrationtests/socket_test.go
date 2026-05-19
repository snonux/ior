package integrationtests

import "testing"

func TestSocketBasic(t *testing.T) {
	runScenario(t, "socket-basic", []ExpectedEvent{
		{
			Tracepoint: "enter_socket",
			MinCount:   1,
		},
	})
}

func TestSocketpairBasic(t *testing.T) {
	runScenario(t, "socketpair-basic", []ExpectedEvent{
		{
			Tracepoint: "enter_socketpair",
			MinCount:   1,
		},
	})
}
