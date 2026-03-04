package flamegraph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var liveServerTimeouts = serverTimeouts{
	readTimeout:  10 * time.Second,
	writeTimeout: 5 * time.Minute,
	idleTimeout:  60 * time.Second,
}

type LiveServerOptions struct {
	OpenCommand string
	WarningCb   func(message string)
}

var openBrowserURLFn = openBrowserURL

// ServeLive starts the live flamegraph HTTP server and blocks until ctx is canceled.
func ServeLive(ctx context.Context, lt *LiveTrie, interval time.Duration) error {
	return ServeLiveWithOptions(ctx, lt, interval, LiveServerOptions{})
}

// ServeLiveWithOptions starts the live flamegraph server with runtime options.
func ServeLiveWithOptions(ctx context.Context, lt *LiveTrie, interval time.Duration, options LiveServerOptions) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleLivePage())
	mux.HandleFunc("/events", handleSSE(lt, interval))
	mux.HandleFunc("/reset", handleReset(lt))
	mux.HandleFunc("/order", handleOrder(lt))
	return runServer(ctx, mux, liveServerTimeouts, func(hostname string, port int) {
		url := fmt.Sprintf("http://%s:%d/", hostname, port)
		fmt.Printf("Live flamegraph available at %s\n", url)
		if err := maybeOpenLiveBrowser(url, options); err != nil {
			notifyLiveWarning(options.WarningCb, fmt.Sprintf("Live flamegraph browser auto-open failed: %v", err))
		}
	})
}

func maybeOpenLiveBrowser(url string, options LiveServerOptions) error {
	if strings.TrimSpace(options.OpenCommand) == "" {
		return nil
	}
	return openBrowserURLFn(url, options.OpenCommand)
}

func openBrowserURL(url, openCommand string) error {
	parts, err := browserOpenCommandParts(openCommand, url)
	if err != nil {
		return err
	}
	cmd := exec.Command(parts[0], parts[1:]...)
	applySudoInvokerContext(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	timer := time.NewTimer(750 * time.Millisecond)
	defer stopAndDrainTimer(timer)

	select {
	case waitErr := <-waitCh:
		if waitErr != nil {
			return fmt.Errorf("browser command exited early: %w", waitErr)
		}
	case <-timer.C:
	}
	return nil
}

func stopAndDrainTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func notifyLiveWarning(warningCb func(string), message string) {
	if message == "" {
		return
	}
	if warningCb != nil {
		warningCb(message)
		return
	}
	fmt.Println(message)
}

func applySudoInvokerContext(cmd *exec.Cmd) {
	applySudoInvokerContextWithEnv(cmd, os.Geteuid(), os.Environ())
}

func applySudoInvokerContextWithEnv(cmd *exec.Cmd, euid int, env []string) {
	if cmd == nil || euid != 0 {
		return
	}

	sudoUIDStr, okUID := lookupEnvValue(env, "SUDO_UID")
	sudoGIDStr, okGID := lookupEnvValue(env, "SUDO_GID")
	if !okUID || !okGID {
		return
	}

	uid, errUID := strconv.ParseUint(strings.TrimSpace(sudoUIDStr), 10, 32)
	gid, errGID := strconv.ParseUint(strings.TrimSpace(sudoGIDStr), 10, 32)
	if errUID != nil || errGID != nil {
		return
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		},
	}

	launchEnv := append([]string(nil), env...)
	if sudoUser, ok := lookupEnvValue(env, "SUDO_USER"); ok && strings.TrimSpace(sudoUser) != "" {
		launchEnv = upsertEnvValue(launchEnv, "USER", sudoUser)
		launchEnv = upsertEnvValue(launchEnv, "LOGNAME", sudoUser)
	}

	if sudoUser, err := user.LookupId(strconv.FormatUint(uid, 10)); err == nil && strings.TrimSpace(sudoUser.HomeDir) != "" {
		launchEnv = upsertEnvValue(launchEnv, "HOME", sudoUser.HomeDir)
		if _, ok := lookupEnvValue(launchEnv, "XAUTHORITY"); !ok {
			xauth := filepath.Join(sudoUser.HomeDir, ".Xauthority")
			if info, statErr := os.Stat(xauth); statErr == nil && !info.IsDir() {
				launchEnv = upsertEnvValue(launchEnv, "XAUTHORITY", xauth)
			}
		}
	}

	if _, ok := lookupEnvValue(launchEnv, "XDG_RUNTIME_DIR"); !ok {
		runtimeDir := fmt.Sprintf("/run/user/%d", uid)
		if info, statErr := os.Stat(runtimeDir); statErr == nil && info.IsDir() {
			launchEnv = upsertEnvValue(launchEnv, "XDG_RUNTIME_DIR", runtimeDir)
		}
	}

	cmd.Env = launchEnv
}

func lookupEnvValue(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return strings.TrimPrefix(entry, prefix), true
		}
	}
	return "", false
}

func upsertEnvValue(env []string, key, value string) []string {
	prefix := key + "="
	for i := range env {
		if strings.HasPrefix(env[i], prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func browserOpenCommandParts(openCommand, url string) ([]string, error) {
	parts := strings.Fields(strings.TrimSpace(openCommand))
	if len(parts) == 0 {
		return nil, errors.New("empty browser open command")
	}

	containsURL := false
	for i := range parts {
		if strings.Contains(parts[i], "{url}") {
			parts[i] = strings.ReplaceAll(parts[i], "{url}", url)
			containsURL = true
		}
	}
	if !containsURL {
		parts = append(parts, url)
	}
	return parts, nil
}

func handleLivePage() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(liveHTML))
	}
}

func handleSSE(lt *LiveTrie, interval time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		if interval <= 0 {
			interval = 200 * time.Millisecond
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")

		lastVersion, err := sendSnapshot(w, flusher, lt, ^uint64(0))
		if err != nil {
			return
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				if lt.Version() == lastVersion {
					continue
				}
				lastVersion, err = sendSnapshot(w, flusher, lt, lastVersion)
				if err != nil {
					return
				}
			}
		}
	}
}

func handleReset(lt *LiveTrie) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		lt.Reset()
		payload, _ := lt.SnapshotJSON()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}
}

type orderRequest struct {
	Fields []string `json:"fields"`
}

type orderResponse struct {
	Fields   []string        `json:"fields"`
	Snapshot json.RawMessage `json:"snapshot,omitempty"`
}

func handleOrder(lt *LiveTrie) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(orderResponse{Fields: lt.Fields()})
		case http.MethodPost:
			var req orderRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid json body", http.StatusBadRequest)
				return
			}
			if err := lt.Reconfigure(req.Fields); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			snap, _ := lt.SnapshotJSON()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(orderResponse{
				Fields:   lt.Fields(),
				Snapshot: snap,
			})
		default:
			w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func sendSnapshot(w http.ResponseWriter, flusher http.Flusher, lt *LiveTrie, lastVersion uint64) (uint64, error) {
	payload, version := lt.SnapshotJSON()
	if version == lastVersion {
		return lastVersion, nil
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
		return lastVersion, err
	}
	flusher.Flush()
	return version, nil
}
