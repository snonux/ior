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

func ServeSVG(svgFile string) error {
	absPath, err := filepath.Abs(svgFile)
	if err != nil {
		return fmt.Errorf("resolve svg path: %w", err)
	}
	urlPath := buildURLPath(absPath)
	srv := &http.Server{Handler: buildSVGHandler(absPath, urlPath)}

	listener, err := listenRandomPort()
	if err != nil {
		return err
	}
	defer listener.Close()

	hostname, port := serverHostPort(listener)
	printServerURL(hostname, port, urlPath)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(listener)
	}()

	return waitForStop(srv, errCh)
}

func buildURLPath(absPath string) string {
	urlPath := filepath.ToSlash(absPath)
	if !strings.HasPrefix(urlPath, "/") {
		return "/" + urlPath
	}
	return urlPath
}

func buildSVGHandler(absPath, urlPath string) http.Handler {
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

func waitForStop(srv *http.Server, errCh <-chan error) error {
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopCh)

	select {
	case sig := <-stopCh:
		_ = sig
	case serveErr := <-errCh:
		if serveErr != nil && serveErr != http.ErrServerClosed {
			return serveErr
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown web server: %w", err)
	}

	serveErr := <-errCh
	if serveErr != nil && serveErr != http.ErrServerClosed {
		return serveErr
	}
	return nil
}
