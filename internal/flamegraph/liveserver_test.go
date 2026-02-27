package flamegraph

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHandleSSEContentTypeFormatAndEmptyTrie(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count")
	srv := httptest.NewServer(handleSSE(lt, 5*time.Millisecond))
	defer srv.Close()

	resp := connectSSE(t, srv.URL)
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", contentType)
	}

	data := readFirstSSEData(t, resp.Body)
	snap := decodeSSESnapshot(t, data)
	if snap.Total != 0 {
		t.Fatalf("empty trie snapshot total = %d, want 0", snap.Total)
	}
}

func TestHandleSSEMultipleClientsReceiveInitialSnapshot(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count")
	lt.Ingest(newTestPair("multi", 42, 1001, "/tmp/multi", 1, 1, 1))
	srv := httptest.NewServer(handleSSE(lt, 5*time.Millisecond))
	defer srv.Close()

	const clients = 4
	var wg sync.WaitGroup
	errCh := make(chan error, clients)

	wg.Add(clients)
	for i := 0; i < clients; i++ {
		go func() {
			defer wg.Done()
			resp := connectSSE(t, srv.URL)
			defer resp.Body.Close()
			data := readFirstSSEData(t, resp.Body)
			snap := decodeSSESnapshot(t, data)
			if snap.Total == 0 {
				errCh <- fmt.Errorf("received empty snapshot")
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

func TestHandleSSEReconnectAfterDisconnectGetsLatestSnapshot(t *testing.T) {
	lt := NewLiveTrie([]string{"path"}, "count")
	lt.Ingest(newTestPair("reconnect", 1, 1001, "/tmp/a", 1, 1, 1))
	srv := httptest.NewServer(handleSSE(lt, 5*time.Millisecond))
	defer srv.Close()

	resp1 := connectSSE(t, srv.URL)
	first := decodeSSESnapshot(t, readFirstSSEData(t, resp1.Body))
	_ = resp1.Body.Close()
	if first.Total != 1 {
		t.Fatalf("first snapshot total = %d, want 1", first.Total)
	}

	lt.Ingest(newTestPair("reconnect", 1, 1002, "/tmp/b", 1, 1, 1))

	resp2 := connectSSE(t, srv.URL)
	defer resp2.Body.Close()
	second := decodeSSESnapshot(t, readFirstSSEData(t, resp2.Body))
	if second.Total != 2 {
		t.Fatalf("reconnected snapshot total = %d, want 2", second.Total)
	}
}

func TestHandleSSERestartedServerAcceptsNewConnection(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count")
	lt.Ingest(newTestPair("restart", 1, 1001, "/tmp/a", 1, 1, 1))

	srv1 := httptest.NewServer(handleSSE(lt, 5*time.Millisecond))
	resp1 := connectSSE(t, srv1.URL)
	first := decodeSSESnapshot(t, readFirstSSEData(t, resp1.Body))
	_ = resp1.Body.Close()
	srv1.Close()
	if first.Total != 1 {
		t.Fatalf("first server snapshot total = %d, want 1", first.Total)
	}

	lt.Ingest(newTestPair("restart", 1, 1002, "/tmp/b", 1, 1, 1))

	srv2 := httptest.NewServer(handleSSE(lt, 5*time.Millisecond))
	defer srv2.Close()
	resp2 := connectSSE(t, srv2.URL)
	defer resp2.Body.Close()
	second := decodeSSESnapshot(t, readFirstSSEData(t, resp2.Body))
	if second.Total != 2 {
		t.Fatalf("second server snapshot total = %d, want 2", second.Total)
	}
}

func TestHandleSSEDelayedClientLargeTrieGetsValidSnapshot(t *testing.T) {
	lt := NewLiveTrie([]string{"path"}, "count")
	const events = 12000
	for i := 0; i < events; i++ {
		lt.Ingest(newTestPair("late", 7, uint32(10000+i), fmt.Sprintf("/late/%05d", i), 1, 1, 1))
	}

	srv := httptest.NewServer(handleSSE(lt, 5*time.Millisecond))
	defer srv.Close()

	resp := connectSSE(t, srv.URL)
	defer resp.Body.Close()
	snap := decodeSSESnapshot(t, readFirstSSEData(t, resp.Body))
	if snap.Total != events {
		t.Fatalf("late client snapshot total = %d, want %d", snap.Total, events)
	}
}

func connectSSE(t *testing.T, url string) *http.Response {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("connect sse: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatalf("unexpected status: %s", resp.Status)
	}
	return resp
}

func readFirstSSEData(t *testing.T, body io.ReadCloser) string {
	t.Helper()
	type result struct {
		data string
		err  error
	}
	ch := make(chan result, 1)

	go func() {
		reader := bufio.NewReader(body)
		line, err := reader.ReadString('\n')
		if err != nil {
			ch <- result{err: err}
			return
		}
		if !strings.HasPrefix(line, "data: ") {
			ch <- result{err: fmt.Errorf("invalid sse data line: %q", line)}
			return
		}
		separator, err := reader.ReadString('\n')
		if err != nil {
			ch <- result{err: err}
			return
		}
		if separator != "\n" {
			ch <- result{err: fmt.Errorf("missing sse blank-line separator: %q", separator)}
			return
		}
		ch <- result{data: strings.TrimSuffix(strings.TrimPrefix(line, "data: "), "\n")}
	}()

	select {
	case out := <-ch:
		if out.err != nil {
			t.Fatalf("read sse event: %v", out.err)
		}
		return out.data
	case <-time.After(3 * time.Second):
		_ = body.Close()
		t.Fatalf("timeout waiting for first sse event")
		return ""
	}
}

func decodeSSESnapshot(t *testing.T, data string) trieSnapshot {
	t.Helper()
	var snap trieSnapshot
	if err := json.Unmarshal([]byte(data), &snap); err != nil {
		t.Fatalf("invalid snapshot json: %v", err)
	}
	return snap
}
