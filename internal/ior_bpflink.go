package internal

import (
	"errors"
	"sync/atomic"

	"ior/internal/probemanager"

	bpf "github.com/aquasecurity/libbpfgo"
)

// errNoLibbpfLink is what newLibbpfLink reports for an attach that returned
// neither a link nor an error. libbpfgo v0.9.2-libbpf-1.5.1 never does.
var errNoLibbpfLink = errors.New("libbpfgo returned neither a link nor an error")

// destroyBPFLink is libbpfgo's BPFLink.Destroy, the one call libbpfLink makes
// on a link. It is a variable only so that tests can count the calls and make
// one fail without a kernel (ior_bpflink_test.go).
var destroyBPFLink = (*bpf.BPFLink).Destroy

// libbpfLink is the probemanager.Link ior hands out for every link it attaches
// through libbpfgo (libbpfTracepointProgram). It keeps libbpfgo's Module.Close
// from destroying a link a second time after its Destroy reported an error
// (task 123).
//
// The facts, libbpfgo v0.9.2-libbpf-1.5.1 with libbpf 1.5.1:
//
//   - libbpf, src/libbpf.c, bpf_link__destroy (line 10666) frees the link
//     whatever its detach returned and only passes the error on.
//   - libbpfgo, link.go, BPFLink.Destroy (lines 70-81) returns that errno
//     BEFORE it clears its private pointer to the freed link.
//   - libbpfgo, module.go, Module.Close (lines 194-198) calls Destroy on
//     every link the module ever handed out whose pointer is still set
//     (line 195). After a failed Destroy that is a use after free and a
//     double free; a bare Module.Close then dies with SIGSEGV in
//     bpf_link__destroy.
//
// Destroy therefore overwrites the BPFLink with its zero value when libbpfgo
// reported an error. That clears the private pointer - the struct can be
// assigned from outside its package although no field can be named - and
// Module.Close skips the link and releases everything else as usual:
// programs, maps, ring buffers, the object. Nothing is lost by it: the C
// struct is freed and the link's fds are closed (which is what detaches the
// program), so the Go struct describes nothing any more, and ior holds no
// other reference to it than this wrapper, which drops it.
//
// Caveat: a zeroed BPFLink has a nil prog, and Module.linkExist (module.go,
// lines 460-468) calls link.prog.Name() on every link of the module. Only
// Module.AttachPrograms reaches it. ior attaches each program by name and
// calls neither AttachPrograms nor DetachPrograms (which would destroy the
// module's links behind the wrappers' backs);
// TestIorNeverCallsTheModuleWideAttachOrDetach pins both.
//
// Once libbpfgo clears the pointer before it returns the errno, the zeroing
// changes nothing that Module.Close looks at and can be removed;
// TestBareLibbpfgoLinkKeepsItsPointerAfterAFailedDestroy fails then.
//
// A failing Destroy does not occur in practice, but it can be provoked: close
// the link's fds behind libbpf's back and Destroy returns EBADF. For a classic
// tracepoint (a perf link, bpf_link_perf_detach, line 10789) only the
// PERF_EVENT_IOC_DISABLE ioctl can fail - the results of its two close(2)
// calls are ignored. For a raw tracepoint the detach is one close(2) of the
// link fd (bpf_link__detach_fd, line 10695), whose failure is the error. The
// root tests in ior_bpflink_root_test.go do exactly that to the real module.
type libbpfLink struct {
	// link is the libbpfgo link until Destroy takes it. The swap is atomic so
	// that Destroy reaches libbpfgo at most once per link however it is
	// called; its callers promise one call already (probemanager.Link).
	link atomic.Pointer[bpf.BPFLink]
}

// newLibbpfLink wraps the result of a libbpfgo attach. A failed attach hands
// out no link, as an untyped nil: libbpfgo returns a nil *bpf.BPFLink then,
// which must become neither a non-nil probemanager.Link nor a wrapper around
// nothing.
func newLibbpfLink(link *bpf.BPFLink, err error) (probemanager.Link, error) {
	if err != nil {
		return nil, err
	}
	if link == nil {
		return nil, errNoLibbpfLink
	}
	wrapped := &libbpfLink{}
	wrapped.link.Store(link)
	return wrapped, nil
}

// Destroy destroys the link once and passes libbpfgo's error on. When there is
// one it first zeroes the BPFLink, so that Module.Close leaves the freed link
// alone (see libbpfLink); a successful Destroy has cleared the pointer itself
// and the struct is not touched. A second Destroy, and one on a nil or empty
// wrapper, does nothing and returns nil.
func (l *libbpfLink) Destroy() error {
	if l == nil {
		return nil
	}
	link := l.link.Swap(nil)
	if link == nil {
		return nil
	}
	err := destroyBPFLink(link)
	if err != nil {
		*link = bpf.BPFLink{}
	}
	return err
}
