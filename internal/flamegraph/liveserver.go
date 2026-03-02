package flamegraph

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var liveServerTimeouts = serverTimeouts{
	readTimeout:  10 * time.Second,
	writeTimeout: 5 * time.Minute,
	idleTimeout:  60 * time.Second,
}

// ServeLive starts the live flamegraph HTTP server and blocks until ctx is canceled.
func ServeLive(ctx context.Context, lt *LiveTrie, interval time.Duration) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleLivePage())
	mux.HandleFunc("/events", handleSSE(lt, interval))
	mux.HandleFunc("/reset", handleReset(lt))
	mux.HandleFunc("/order", handleOrder(lt))
	return runServer(ctx, mux, liveServerTimeouts, func(hostname string, port int) {
		fmt.Printf("Live flamegraph available at http://%s:%d/\n", hostname, port)
	})
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
