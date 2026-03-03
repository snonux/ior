package flamegraph

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type serverTimeouts struct {
	readTimeout  time.Duration
	writeTimeout time.Duration
	idleTimeout  time.Duration
}

var defaultServerTimeouts = serverTimeouts{
	readTimeout:  10 * time.Second,
	writeTimeout: 30 * time.Second,
	idleTimeout:  60 * time.Second,
}

// ServeSVG starts a small HTTP server that serves a single flamegraph SVG.
//
// It prints a URL of the form http://HOSTNAME:PORT/abs/path/to.svg and blocks until
// the user presses Ctrl+C or the process receives SIGTERM, at which point the server
// is shut down gracefully.
func ServeSVG(svgFile string) error {
	absPath, err := filepath.Abs(svgFile)
	if err != nil {
		return fmt.Errorf("resolve svg path: %w", err)
	}
	urlPath := buildURLPath(absPath)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runServer(ctx, buildSVGHandler(absPath, urlPath), defaultServerTimeouts, func(hostname string, port int) {
		printServerURL(hostname, port, urlPath)
	})
}

// ServeSVGAutoReload serves an SVG viewer page that periodically reloads the SVG.
//
// The SVG file itself is still served directly at its absolute URL path, while "/"
// serves a small HTML wrapper that appends a cache-busting query parameter on each
// refresh interval to pick up newly written SVG content.
func ServeSVGAutoReload(svgFile string, refreshInterval time.Duration) error {
	if refreshInterval <= 0 {
		return fmt.Errorf("refresh interval must be > 0")
	}

	absPath, err := filepath.Abs(svgFile)
	if err != nil {
		return fmt.Errorf("resolve svg path: %w", err)
	}
	urlPath := buildURLPath(absPath)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mux := buildSVGAutoReloadHandler(absPath, urlPath, refreshInterval)
	return runServer(ctx, mux, defaultServerTimeouts, func(hostname string, port int) {
		printServerURL(hostname, port, "/")
	})
}

func buildURLPath(absPath string) string {
	urlPath := filepath.ToSlash(absPath)
	if !strings.HasPrefix(urlPath, "/") {
		return "/" + urlPath
	}
	return urlPath
}

func buildSVGHandler(absPath, urlPath string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, urlPath, http.StatusFound)
	})
	mux.HandleFunc(urlPath, func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, absPath)
	})
	return mux
}

func buildSVGAutoReloadHandler(absPath, urlPath string, refreshInterval time.Duration) *http.ServeMux {
	intervalMs := refreshInterval.Milliseconds()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>I/O Flamegraph (Auto-Reload)</title>
  <style>
    body { margin: 0; font-family: monospace; }
    .bar { padding: 8px 12px; border-bottom: 1px solid #ddd; }
    .viewer { width: 100%%; height: calc(100vh - 42px); border: 0; display: block; }
  </style>
</head>
<body>
  <div class="bar">
    Auto-refresh every %d ms.
    <button type="button" onclick="refreshNow()">Refresh now</button>
  </div>
  <iframe id="fg" class="viewer" src="%s"></iframe>
  <script>
    const base = %q;
    function refreshNow() {
      document.getElementById("fg").src = base + "?t=" + Date.now();
    }
    setInterval(refreshNow, %d);
  </script>
</body>
</html>
`, intervalMs, urlPath, urlPath, intervalMs)
	})
	mux.HandleFunc(urlPath, func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, absPath)
	})
	return mux
}

func listenRandomPort() (net.Listener, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, fmt.Errorf("start web server: %w", err)
	}
	return listener, nil
}

func serverHostPort(listener net.Listener) (string, int) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	port := listener.Addr().(*net.TCPAddr).Port
	return hostname, port
}

func printServerURL(hostname string, port int, urlPath string) {
	fmt.Printf("Flamegraph available at http://%s:%d%s\n", hostname, port, urlPath)
	fmt.Println("Press Ctrl+C to stop the web server.")
}

func newHTTPServer(mux *http.ServeMux, timeouts serverTimeouts) *http.Server {
	return &http.Server{
		Handler:      mux,
		ReadTimeout:  timeouts.readTimeout,
		WriteTimeout: timeouts.writeTimeout,
		IdleTimeout:  timeouts.idleTimeout,
	}
}

func runServer(ctx context.Context, mux *http.ServeMux, timeouts serverTimeouts, printURL func(hostname string, port int)) error {
	srv := newHTTPServer(mux, timeouts)

	listener, err := listenRandomPort()
	if err != nil {
		return err
	}
	defer listener.Close()

	hostname, port := serverHostPort(listener)
	if printURL != nil {
		printURL(hostname, port)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(listener)
	}()

	select {
	case <-ctx.Done():
	case serveErr := <-errCh:
		if serveErr != nil && serveErr != http.ErrServerClosed {
			return serveErr
		}
		return nil
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown web server: %w", err)
	}

	serveErr := <-errCh
	if serveErr != nil && serveErr != http.ErrServerClosed {
		return serveErr
	}
	return nil
}
