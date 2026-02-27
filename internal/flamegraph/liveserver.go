package flamegraph

import (
	"fmt"
	"net/http"
	"time"
)

func handleSSE(lt *LiveTrie, interval time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		if interval <= 0 {
			interval = time.Second
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")

		lastVersion, err := sendSnapshot(w, flusher, lt, 0)
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
