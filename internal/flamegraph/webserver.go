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
	return runServer(ctx, buildSVGHandler(absPath, urlPath), func(hostname string, port int) {
		printServerURL(hostname, port, urlPath)
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

func runServer(ctx context.Context, mux *http.ServeMux, printURL func(hostname string, port int)) error {
	srv := &http.Server{Handler: mux}

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
