package flamegraph

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestHandleResetRequiresPost(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count")
	req := httptest.NewRequest(http.MethodGet, "/reset", nil)
	rec := httptest.NewRecorder()

	handleReset(lt).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if allow := rec.Header().Get("Allow"); allow != http.MethodPost {
		t.Fatalf("allow = %q, want %q", allow, http.MethodPost)
	}
}

func TestHandleResetClearsTrieAndReturnsEmptySnapshot(t *testing.T) {
	lt := NewLiveTrie([]string{"path"}, "count")
	lt.Ingest(newTestPair("reset", 1, 1001, "/tmp/a", 1, 1, 1))
	lt.Ingest(newTestPair("reset", 1, 1002, "/tmp/b", 1, 1, 1))
	if before := decodeLiveSnapshot(t, lt); before.Total == 0 {
		t.Fatalf("expected non-empty trie before reset")
	}

	req := httptest.NewRequest(http.MethodPost, "/reset", nil)
	rec := httptest.NewRecorder()
	handleReset(lt).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ctype := rec.Header().Get("Content-Type"); !strings.Contains(ctype, "application/json") {
		t.Fatalf("content-type = %q, want application/json", ctype)
	}
	var snap trieSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatalf("decode reset snapshot: %v", err)
	}
	if snap.Total != 0 {
		t.Fatalf("reset snapshot total = %d, want 0", snap.Total)
	}

	after := decodeLiveSnapshot(t, lt)
	if after.Total != 0 {
		t.Fatalf("trie total after reset = %d, want 0", after.Total)
	}
}

func TestHandleOrderGetReturnsCurrentFields(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count")
	req := httptest.NewRequest(http.MethodGet, "/order", nil)
	rec := httptest.NewRecorder()
	handleOrder(lt).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var resp orderResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if strings.Join(resp.Fields, ",") != "comm,path,tracepoint" {
		t.Fatalf("fields = %v, want [comm path tracepoint]", resp.Fields)
	}
}

func TestHandleOrderPostReconfiguresAndResets(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count")
	lt.Ingest(newTestPair("svc", 42, 1001, "/tmp/a", 1, 1, 1))

	req := httptest.NewRequest(http.MethodPost, "/order", strings.NewReader(`{"fields":["path","tracepoint","comm"]}`))
	rec := httptest.NewRecorder()
	handleOrder(lt).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var resp orderResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if strings.Join(resp.Fields, ",") != "path,tracepoint,comm" {
		t.Fatalf("fields = %v, want [path tracepoint comm]", resp.Fields)
	}
	var snap trieSnapshot
	if err := json.Unmarshal(resp.Snapshot, &snap); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if snap.Total != 0 {
		t.Fatalf("snapshot total after reconfigure = %d, want 0", snap.Total)
	}
}

func TestHandleOrderPostRejectsInvalidRequest(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count")

	req := httptest.NewRequest(http.MethodPost, "/order", strings.NewReader(`{"fields":["comm","bogus"]}`))
	rec := httptest.NewRecorder()
	handleOrder(lt).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	req = httptest.NewRequest(http.MethodPost, "/order", strings.NewReader(`{"fields":[}`))
	rec = httptest.NewRecorder()
	handleOrder(lt).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleOrderRequiresGetOrPost(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count")
	req := httptest.NewRequest(http.MethodPut, "/order", nil)
	rec := httptest.NewRecorder()
	handleOrder(lt).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if allow := rec.Header().Get("Allow"); allow != http.MethodGet+", "+http.MethodPost {
		t.Fatalf("allow = %q, want %q", allow, http.MethodGet+", "+http.MethodPost)
	}
}

func TestServeLivePrintsURLAndStopsOnCancel(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	output := captureStdout(t, func() {
		errCh := make(chan error, 1)
		go func() {
			errCh <- ServeLive(ctx, lt, 5*time.Millisecond)
		}()

		time.Sleep(40 * time.Millisecond)
		cancel()

		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("ServeLive returned error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for ServeLive to return")
		}
	})

	if !strings.Contains(output, "Live flamegraph available at http://") {
		t.Fatalf("expected live URL in output, got %q", output)
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

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}

	os.Stdout = writer
	defer func() { os.Stdout = oldStdout }()

	outCh := make(chan string, 1)
	go func() {
		var b strings.Builder
		_, _ = io.Copy(&b, reader)
		outCh <- b.String()
	}()

	fn()

	_ = writer.Close()
	out := <-outCh
	_ = reader.Close()
	return out
}
