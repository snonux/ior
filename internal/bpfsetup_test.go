package internal

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	bpf "github.com/aquasecurity/libbpfgo"
	"golang.org/x/sys/unix"

	"ior/internal/config"
	"ior/internal/flags"
)

// TestTidFilterTgid pins how the TID_FILTER_TGID BPF global is chosen: it
// scopes the group-dead exit bypass of the tid filter to the traced thread's
// process, so it must be unset without -tid, prefer -pid, and fall back to
// "unset" (no bypass) rather than to a wrong process when procfs fails.
func TestTidFilterTgid(t *testing.T) {
	lookup := func(tgid int, err error) func(int) (int, error) {
		return func(int) (int, error) { return tgid, err }
	}
	for _, tc := range []struct {
		name     string
		pid, tid int
		readTgid func(int) (int, error)
		want     uint32
	}{
		{name: "no tid filter", pid: -1, tid: -1, readTgid: lookup(7, nil), want: noTgid},
		{name: "pid filter wins", pid: 42, tid: 43, readTgid: lookup(7, nil), want: 42},
		{name: "resolved from procfs", pid: -1, tid: 43, readTgid: lookup(42, nil), want: 42},
		{name: "procfs error", pid: -1, tid: 43, readTgid: lookup(0, errors.New("gone")), want: noTgid},
		{name: "nonsense tgid", pid: -1, tid: 43, readTgid: lookup(0, nil), want: noTgid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := flags.Config{PidFilter: tc.pid, TidFilter: tc.tid}
			if got := tidFilterTgid(cfg, tc.readTgid); got != tc.want {
				t.Fatalf("tidFilterTgid() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseStatusTgid(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  string
		want    int
		wantErr bool
	}{
		{name: "thread status", status: "Name:\tworker\nTgid:\t1234\nPid:\t1240\n", want: 1234},
		{name: "missing field", status: "Name:\tworker\nPid:\t1240\n", wantErr: true},
		{name: "garbage value", status: "Tgid:\tabc\n", wantErr: true},
		{name: "empty", status: "", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseStatusTgid(strings.NewReader(tc.status))
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseStatusTgid() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Fatalf("parseStatusTgid() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestProcTgidOfOwnThread reads the real procfs entry of this process's own
// thread: a tid resolves to the tgid that owns it.
func TestProcTgidOfOwnThread(t *testing.T) {
	got, err := procTgid(os.Getpid())
	if err != nil {
		t.Fatalf("procTgid(self) error = %v", err)
	}
	if got != os.Getpid() {
		t.Fatalf("procTgid(self) = %d, want %d", got, os.Getpid())
	}
	if _, err := procTgid(-5); err == nil {
		t.Fatal("procTgid(-5) succeeded, want an error")
	}
}

// TestProcTgidOfSiblingThread covers the case -tid actually needs: a thread
// whose tid differs from the pid resolves to the owning process. Goroutines
// locked to OS threads are held behind a barrier so their threads stay alive
// (and distinct) while one with tid != pid is looked up.
func TestProcTgidOfSiblingThread(t *testing.T) {
	const threads = 4
	tids := make(chan int, threads)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for range threads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			tids <- unix.Gettid()
			<-release
		}()
	}
	defer func() {
		close(release)
		wg.Wait()
	}()

	sibling := 0
	for range threads {
		if tid := <-tids; tid != os.Getpid() {
			sibling = tid
		}
	}
	if sibling == 0 {
		t.Fatal("no locked goroutine landed on a thread other than the main one")
	}
	got, err := procTgid(sibling)
	if err != nil {
		t.Fatalf("procTgid(%d) error = %v", sibling, err)
	}
	if got != os.Getpid() {
		t.Fatalf("procTgid(%d) = %d, want %d", sibling, got, os.Getpid())
	}
}

// TestRingbufMapSize pins the mirror of libbpf's adjust_ringbuf_sz(): the
// kernel wants a power-of-two multiple of the page size, libbpf rounds any
// other request up to the next such size, and a request that cannot be
// rounded inside uint32 must be an error rather than libbpf's silent 0.
func TestRingbufMapSize(t *testing.T) {
	const page = 4096
	for _, tc := range []struct {
		name      string
		requested uint32
		want      uint32
		wantErr   bool
	}{
		{"one page passes through", page, page, false},
		{"legacy 64KiB default passes through", 65536, 65536, false},
		{"16MiB default passes through", 1 << 24, 1 << 24, false},
		{"largest uint32 power of two passes through", 1 << 31, 1 << 31, false},
		{"below a page rounds up to a page", 100, page, false},
		{"just above a page rounds to two pages", page + 1, 2 * page, false},
		{"three pages round to four", 3 * page, 4 * page, false},
		{"non power of two rounds up", 100000, 131072, false},
		{"just below a power of two rounds up to it", (1 << 24) - 1, 1 << 24, false},
		{"above 2GiB cannot be represented", 1<<31 + 1, 0, true},
		{"zero is rejected", 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ringbufMapSize(tc.requested, page)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ringbufMapSize(%d) error = %v, wantErr %v", tc.requested, err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("ringbufMapSize(%d) = %d, want %d", tc.requested, got, tc.want)
			}
		})
	}
	if _, err := ringbufMapSize(4096, 0); err == nil {
		t.Fatal("a zero page size must be rejected instead of dividing by it")
	}
}

// TestResizeBPFMapsAgainstRealObject drives resizeBPFMaps against the real
// embedded BPF object with the real libbpf, without loading it (opening and
// resizing need no privileges). It pins the two things a unit test of
// ringbufMapSize cannot: that the shipped default really reaches event_map,
// and that a -mapSize which is not a valid ring-buffer size is accepted (libbpf
// rounds it) instead of failing the post-resize check with "actual size is X".
func TestResizeBPFMapsAgainstRealObject(t *testing.T) {
	page := uint32(os.Getpagesize())
	for _, tc := range []struct {
		name string
		size int
		// exact is the expected max_entries when the request is already a
		// valid ring-buffer size; 0 means "libbpf must round it up".
		exact uint32
	}{
		{"default", config.DefaultEventMapSize, config.DefaultEventMapSize},
		{"legacy 64KiB", 65536, 65536},
		{"not a power of two", 100000, 0},
		{"smaller than a page", 100, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Use the embedded object directly: tests elsewhere stub the loader vars.
			mod, err := bpf.NewModuleFromBuffer(embeddedBPFObject, embeddedBPFObjectName)
			if err != nil {
				t.Skipf("cannot open BPF object: %v", err)
			}
			defer mod.Close()
			if err := resizeBPFMaps(flags.Config{EventMapSize: tc.size}, mod); err != nil {
				t.Fatalf("resizeBPFMaps(%d) = %v", tc.size, err)
			}
			m, err := mod.GetMap("event_map")
			if err != nil {
				t.Fatalf("GetMap: %v", err)
			}
			got := m.MaxEntries()
			if tc.exact != 0 {
				if got != tc.exact {
					t.Fatalf("event_map max_entries = %d, want %d", got, tc.exact)
				}
				return
			}
			// Rounded: a power-of-two multiple of the page size that covers
			// the request without more than doubling it.
			if got < uint32(tc.size) || got%page != 0 || !isPowerOfTwo(got/page) {
				t.Fatalf("event_map max_entries = %d for request %d: not a page-multiple power of two covering it", got, tc.size)
			}
			if got > 2*uint32(tc.size) && got > page {
				t.Fatalf("event_map max_entries = %d for request %d: rounded up by more than 2x", got, tc.size)
			}
		})
	}
}
