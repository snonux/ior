package internal

import (
	"bytes"
	"errors"
	"fmt"
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
// rounded inside uint32 must be an error rather than an opaque kernel EINVAL
// at load time. The page size is a parameter of the function precisely so
// that the 16 KiB (arm64) and 64 KiB (ppc64le/arm64) page hosts are covered
// here even though the tests run on a 4 KiB page x86 machine.
func TestRingbufMapSize(t *testing.T) {
	const (
		page4k  = 4096
		page16k = 16384
		page64k = 65536
	)
	for _, tc := range []struct {
		name      string
		page      uint32
		requested uint32
		want      uint32
		wantErr   bool
	}{
		{"4k: one page passes through", page4k, page4k, page4k, false},
		{"4k: 64KiB passes through", page4k, 65536, 65536, false},
		{"4k: 16MiB default passes through", page4k, 1 << 24, 1 << 24, false},
		{"4k: largest uint32 power of two passes through", page4k, 1 << 31, 1 << 31, false},
		{"4k: below a page rounds up to a page", page4k, 100, page4k, false},
		{"4k: just above a page rounds to two pages", page4k, page4k + 1, 2 * page4k, false},
		{"4k: three pages round to four", page4k, 3 * page4k, 4 * page4k, false},
		{"4k: non power of two rounds up", page4k, 100000, 131072, false},
		{"4k: just below a power of two rounds up to it", page4k, (1 << 24) - 1, 1 << 24, false},
		{"4k: above 2GiB cannot be represented", page4k, 1<<31 + 1, 0, true},
		{"4k: zero is rejected", page4k, 0, 0, true},

		{"16k: one page passes through", page16k, page16k, page16k, false},
		{"16k: 64KiB passes through", page16k, 65536, 65536, false},
		{"16k: below a page rounds up to a page", page16k, 100, page16k, false},
		{"16k: 4KiB (one 4k page) rounds up to a 16k page", page16k, page4k, page16k, false},
		{"16k: just above a page rounds to two pages", page16k, page16k + 1, 2 * page16k, false},
		{"16k: three pages round to four", page16k, 3 * page16k, 4 * page16k, false},
		{"16k: 16MiB default passes through", page16k, 1 << 24, 1 << 24, false},
		{"16k: above 2GiB cannot be represented", page16k, 1<<31 + 1, 0, true},

		{"64k: one page passes through", page64k, page64k, page64k, false},
		{"64k: just above a page rounds to two pages", page64k, page64k + 1, 2 * page64k, false},
		{"64k: below a page rounds up to a page", page64k, 100, page64k, false},
		{"64k: 16MiB default passes through", page64k, 1 << 24, 1 << 24, false},
		{"64k: three pages round to four", page64k, 3 * page64k, 4 * page64k, false},
		{"64k: above 2GiB cannot be represented", page64k, 1<<31 + 1, 0, true},
		{"64k: zero is rejected", page64k, 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ringbufMapSize(tc.requested, tc.page)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ringbufMapSize(%d, %d) error = %v, wantErr %v", tc.requested, tc.page, err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("ringbufMapSize(%d, %d) = %d, want %d", tc.requested, tc.page, got, tc.want)
			}
		})
	}
	if _, err := ringbufMapSize(4096, 0); err == nil {
		t.Fatal("a zero page size must be rejected instead of dividing by it")
	}
}

// skipIfUnprivilegedOpen decides what an error from opening the embedded BPF
// object means. libbpfgo raises RLIMIT_MEMLOCK while opening, which fails with
// "error setting rlimit: operation not permitted" for an unprivileged user
// and is the ONLY reason this test may skip (and only when not root). Any
// other error, or any error as root, means the embedded object or libbpf is
// broken and must fail the test rather than silently skipping it.
func skipIfUnprivilegedOpen(t *testing.T, err error) {
	t.Helper()
	if os.Geteuid() != 0 && strings.Contains(err.Error(), "error setting rlimit") {
		t.Skipf("unprivileged: cannot raise RLIMIT_MEMLOCK to open the BPF object: %v", err)
	}
	t.Fatalf("cannot open embedded BPF object (euid %d): %v", os.Geteuid(), err)
}

// TestResizeBPFMapsAgainstRealObject drives resizeBPFMaps against the real
// embedded BPF object with the real libbpf, without loading it. Resizing needs
// no privileges, but opening does when RLIMIT_MEMLOCK's hard limit is small:
// libbpfgo's NewModuleFromBufferArgs calls bumpMemlockRlimit() first, so an
// unprivileged open can fail and the test then skips (see
// skipIfUnprivilegedOpen). It pins the two things a unit test of
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
				skipIfUnprivilegedOpen(t, err)
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

// openObjectWithRenamedGlobal opens the embedded BPF object after renaming one
// global to a same-length name, which leaves a valid ELF (symbol table and BTF
// strings both changed) whose object no longer defines that global - exactly
// what an IOR_BPF_OBJECT override built before the global existed looks like
// to libbpfgo, without needing a second checked-in object or a clang run.
func openObjectWithRenamedGlobal(t *testing.T, name string) *bpf.Module {
	t.Helper()
	renamed := name[:len(name)-1] + "X"
	object := bytes.ReplaceAll(embeddedBPFObject, []byte(name), []byte(renamed))
	if bytes.Equal(object, embeddedBPFObject) {
		t.Fatalf("embedded BPF object does not mention %s", name)
	}
	mod, err := bpf.NewModuleFromBuffer(object, embeddedBPFObjectName)
	if err != nil {
		skipIfUnprivilegedOpen(t, err)
	}
	t.Cleanup(mod.Close)
	return mod
}

// TestSetBPFGlobalsToleratesAnObjectWithoutTidFilterTgid pins the compatibility
// the AGENTS.md promises for IOR_BPF_OBJECT overrides: TID_FILTER_TGID was
// added after the legacy exec/exit records, so every object emitting the
// 24-byte exit record lacks it, and a missing symbol used to abort setup at
// the "set globals" stage. It now passes without -tid, warns (once) under -tid,
// and real failures of other globals still surface. It runs the real libbpfgo
// against a real object, which also guards the error text setTidFilterTgid
// matches.
func TestSetBPFGlobalsToleratesAnObjectWithoutTidFilterTgid(t *testing.T) {
	for _, tc := range []struct {
		name      string
		tid       int
		wantWarns int
	}{
		{name: "no -tid stays silent", tid: -1, wantWarns: 0},
		{name: "-tid warns that the bypass is unavailable", tid: os.Getpid(), wantWarns: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mod := openObjectWithRenamedGlobal(t, "TID_FILTER_TGID")
			var warnings []string
			warn := func(args ...any) { warnings = append(warnings, fmt.Sprint(args...)) }
			cfg := flags.Config{PidFilter: -1, TidFilter: tc.tid}
			if err := setBPFGlobals(cfg, mod, warn); err != nil {
				t.Fatalf("setBPFGlobals on an object without TID_FILTER_TGID = %v, want nil", err)
			}
			if len(warnings) != tc.wantWarns {
				t.Fatalf("warnings = %q, want %d", warnings, tc.wantWarns)
			}
			if tc.wantWarns > 0 && !strings.Contains(warnings[0], "TID_FILTER_TGID") {
				t.Fatalf("warning %q does not name the missing global", warnings[0])
			}
		})
	}
}

// TestSetBPFGlobalsStillFailsOnAMissingRequiredGlobal is the negative twin:
// only TID_FILTER_TGID is optional. An object lacking TID_FILTER - which every
// supported object defines - must keep failing setup, with the global's name
// in the error, so the tolerance does not swallow real breakage. (The rename
// also hits TID_FILTER_TGID, which is fine: TID_FILTER is written first.)
func TestSetBPFGlobalsStillFailsOnAMissingRequiredGlobal(t *testing.T) {
	mod := openObjectWithRenamedGlobal(t, "TID_FILTER")
	err := setBPFGlobals(flags.Config{PidFilter: -1, TidFilter: -1}, mod, func(...any) {})
	if err == nil || !strings.Contains(err.Error(), "TID_FILTER global variable") {
		t.Fatalf("setBPFGlobals without TID_FILTER = %v, want an error naming TID_FILTER", err)
	}
}
