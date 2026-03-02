package flamegraph

import (
	"net/http"
	"testing"
	"time"
)

func TestNewHTTPServerUsesConfiguredTimeouts(t *testing.T) {
	mux := http.NewServeMux()
	timeouts := serverTimeouts{
		readTimeout:  11 * time.Second,
		writeTimeout: 44 * time.Second,
		idleTimeout:  66 * time.Second,
	}

	srv := newHTTPServer(mux, timeouts)

	if srv.Handler != mux {
		t.Fatalf("Handler not set from mux")
	}
	if srv.ReadTimeout != timeouts.readTimeout {
		t.Fatalf("ReadTimeout = %v, want %v", srv.ReadTimeout, timeouts.readTimeout)
	}
	if srv.WriteTimeout != timeouts.writeTimeout {
		t.Fatalf("WriteTimeout = %v, want %v", srv.WriteTimeout, timeouts.writeTimeout)
	}
	if srv.IdleTimeout != timeouts.idleTimeout {
		t.Fatalf("IdleTimeout = %v, want %v", srv.IdleTimeout, timeouts.idleTimeout)
	}
}

func TestLiveServerWriteTimeoutIsLongerThanDefault(t *testing.T) {
	if liveServerTimeouts.readTimeout != defaultServerTimeouts.readTimeout {
		t.Fatalf("read timeout mismatch: live=%v default=%v", liveServerTimeouts.readTimeout, defaultServerTimeouts.readTimeout)
	}
	if liveServerTimeouts.idleTimeout != defaultServerTimeouts.idleTimeout {
		t.Fatalf("idle timeout mismatch: live=%v default=%v", liveServerTimeouts.idleTimeout, defaultServerTimeouts.idleTimeout)
	}
	if liveServerTimeouts.writeTimeout <= defaultServerTimeouts.writeTimeout {
		t.Fatalf("expected live write timeout > default write timeout, got live=%v default=%v", liveServerTimeouts.writeTimeout, defaultServerTimeouts.writeTimeout)
	}
}
