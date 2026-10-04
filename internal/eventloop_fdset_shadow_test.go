package internal

import (
	"syscall"
	"testing"

	"ior/internal/file"
)

// Task kr2: registering a descriptor in the fd table must clear the procfs
// cache entry for the same (pid, fd). The cache entry names whatever the
// number meant when procfs was last read; the traced syscall that registers
// the descriptor rebinds it, so the cached name is stale and, left behind,
// resurfaces as soon as the table entry is gone (exec closing a cloexec fd,
// LRU eviction, forget).

const shadowPid = uint32(4100)

func newShadowedFd(t *testing.T) *fdTracker {
	t.Helper()
	fds := newFDTracker(map[uint64]file.File{})
	fds.setProcFdCache(9, shadowPid, file.NewFd(9, "socket:[111]", syscall.O_RDWR))
	fds.set(9, shadowPid, file.NewFd(9, "/data/new", syscall.O_RDONLY|syscall.O_CLOEXEC))
	return fds
}

func TestSetClearsTheShadowedProcfsCacheEntry(t *testing.T) {
	fds := newShadowedFd(t)
	if _, ok := fds.cachedProcFdFile(9, shadowPid); ok {
		t.Fatal("set left the procfs cache entry it shadows")
	}
	if _, ok := fds.cachedProcFdReadAt(9, shadowPid); ok {
		t.Fatal("set left the cache entry's procfs read time")
	}
	if got := fds.resolve(9, shadowPid).Name(); got != "/data/new" {
		t.Fatalf("resolve = %q, want the registered name", got)
	}
}

func TestStaleCacheNameDoesNotResurfaceAfterTheTableEntryGoes(t *testing.T) {
	for name, drop := range map[string]func(*fdTracker){
		"exec closes the cloexec fd": func(f *fdTracker) { f.dropOnExec(shadowPid) },
		"close":                      func(f *fdTracker) { f.delete(9, shadowPid) },
		"lru eviction":               func(f *fdTracker) { f.removeFileKey(f.key(shadowPid, 9)) },
	} {
		t.Run(name, func(t *testing.T) {
			fds := newShadowedFd(t)
			drop(fds)
			if f, ok := fds.cachedProcFdFile(9, shadowPid); ok {
				t.Fatalf("stale cache entry %q resurfaced", f.Name())
			}
		})
	}
}

// A cache entry of a different descriptor must survive the registration.
func TestSetKeepsOtherCacheEntries(t *testing.T) {
	fds := newShadowedFd(t)
	fds.setProcFdCache(10, shadowPid, file.NewFd(10, "pipe:[7]", syscall.O_RDONLY))
	fds.set(11, shadowPid, file.NewFd(11, "/other", syscall.O_RDONLY))
	if _, ok := fds.cachedProcFdFile(10, shadowPid); !ok {
		t.Fatal("set dropped the cache entry of an unrelated fd")
	}
}
