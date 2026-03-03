package flamegraph

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBuildSVGAutoReloadHandlerServesViewerPage(t *testing.T) {
	mux := buildSVGAutoReloadHandler("/tmp/fake.svg", "/tmp/fake.svg", 2*time.Second)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://localhost/", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status code = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("content type = %q, want text/html", got)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Auto-refresh every 2000 ms.") {
		t.Fatalf("viewer page missing refresh interval, body=%q", body)
	}
	if !strings.Contains(body, `id="fg"`) {
		t.Fatalf("viewer page missing iframe, body=%q", body)
	}
}

func TestServeSVGAutoReloadRejectsNonPositiveInterval(t *testing.T) {
	err := ServeSVGAutoReload("ignored.svg", 0)
	if err == nil {
		t.Fatal("expected error for non-positive interval")
	}
}
