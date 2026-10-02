package internal

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"ior/internal/flags"
	"ior/internal/probemanager"

	bpf "github.com/aquasecurity/libbpfgo"
)

// These tests need root: they load the real BPF object, attach a classic
// tracepoint (sched_process_exec) and the raw tracepoint (task_rename), make
// libbpf's destroy of both links fail, and close the module. They skip for
// any other user.
//
// The failure is real, not faked: the test closes the link's fds behind
// libbpf's back, so the PERF_EVENT_IOC_DISABLE ioctl of the classic link and
// the close(2) of the raw link fail with EBADF, which libbpfgo's Destroy
// returns (see libbpfLink for the sources).
//
// Each scenario runs in a child process, the test binary re-executed as
// TestLibbpfLinkHelperProcess, for two reasons. What is tested is a use after
// free in C: when it happens the process dies in bpf_link__destroy, and no Go
// test can report anything after that. And closing an fd that libbpf still
// believes it owns is only safe where nothing else opens files in between -
// libbpf closes the number again, whoever has it by then - which holds for a
// child that does nothing else, not for a test binary.

const (
	linkHelperEnv      = "IOR_TEST_LIBBPF_LINK_HELPER"
	linkHelperSurvived = "SURVIVED-MODULE-CLOSE"
	// linkHelperNoFDLeft is the helper's report that Module.Close released
	// every fd of the module: nothing was left open to avoid the crash.
	linkHelperNoFDLeft = "bpf fds left=0"
	// The scenarios: who hands out the links (ior's seam, or libbpfgo
	// directly) and whether their destroy is made to fail.
	linkScenarioWrappedFailed = "wrapped-failed"
	linkScenarioWrappedClean  = "wrapped-clean"
	linkScenarioBareFailed    = "bare-failed"
)

// The fix: a failed Destroy of a link ior handed out leaves no pointer for
// Module.Close to destroy again, the error still reaches the caller, and the
// module closes completely - no program, map or link fd stays open.
func TestModuleCloseSurvivesAFailedDestroyOfIorsLinks(t *testing.T) {
	out, err := runLinkHelper(t, linkScenarioWrappedFailed)
	if err != nil {
		t.Fatalf("helper died (%v), output:\n%s", err, out)
	}
	requireLinkHelperLines(t, out,
		"classic destroy=EBADF pointer=cleared",
		"raw destroy=EBADF pointer=cleared",
		linkHelperSurvived, linkHelperNoFDLeft)
}

// The negative: without a failure Destroy returns nil, libbpfgo clears its
// pointer itself, and the module closes as it always did.
func TestModuleCloseAfterACleanDestroyOfIorsLinks(t *testing.T) {
	out, err := runLinkHelper(t, linkScenarioWrappedClean)
	if err != nil {
		t.Fatalf("helper died (%v), output:\n%s", err, out)
	}
	requireLinkHelperLines(t, out,
		"classic destroy=nil pointer=cleared",
		"raw destroy=nil pointer=cleared",
		linkHelperSurvived, linkHelperNoFDLeft)
}

// The defect libbpfLink works around, on a link taken from libbpfgo directly:
// after a failed Destroy its pointer is still set. That part is deterministic
// and fails once libbpfgo clears the pointer before it returns the errno -
// libbpfLink's zeroing is then redundant and can go. What Module.Close does
// with the kept pointer is a use after free, which usually kills the child
// but is not bound to; either outcome is only logged.
func TestBareLibbpfgoLinkKeepsItsPointerAfterAFailedDestroy(t *testing.T) {
	out, err := runLinkHelper(t, linkScenarioBareFailed)
	if strings.Contains(out, "pointer=cleared") {
		t.Fatalf("libbpfgo cleared the pointer of a link whose Destroy failed: "+
			"the defect is fixed upstream, drop the zeroing in libbpfLink. Output:\n%s", out)
	}
	requireLinkHelperLines(t, out,
		"classic destroy=EBADF pointer=kept",
		"raw destroy=EBADF pointer=kept")
	switch {
	case strings.Contains(out, linkHelperSurvived):
		t.Log("Module.Close destroyed the freed links again and the process lived through it this time")
	case err != nil:
		// Any death counts: a use after free need not end in SIGSEGV. Both
		// pointer lines were printed, so the helper got as far as the close.
		t.Logf("Module.Close destroyed the freed links again and the process died of it (%v)", err)
	default:
		t.Fatalf("helper ended without closing the module and without a crash, output:\n%s", out)
	}
}

// runLinkHelper re-executes the test binary as the helper for scenario and
// returns its combined output and the error from waiting for it. It skips
// the calling test for anybody but root.
func runLinkHelper(t *testing.T, scenario string) (string, error) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: loads the BPF object and attaches probes")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLibbpfLinkHelperProcess$")
	cmd.Env = append(os.Environ(), linkHelperEnv+"="+scenario)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// requireLinkHelperLines fails unless the helper printed every line of want.
// An exit status alone proves nothing: a helper whose test did not run at all
// exits 0 as well.
func requireLinkHelperLines(t *testing.T, out string, want ...string) {
	t.Helper()
	lines := strings.Split(out, "\n")
	for _, line := range want {
		found := false
		for _, got := range lines {
			found = found || got == line
		}
		if !found {
			t.Errorf("helper did not print %q, output:\n%s", line, out)
		}
	}
}

// TestLibbpfLinkHelperProcess is the child of the tests above, not a test by
// itself. It attaches the two links of the scenario named in the environment,
// destroys them - with their fds closed first when the destroy is to fail -,
// prints for each what Destroy returned and what became of libbpfgo's pointer,
// closes the module and reports on stdout that it lived through that and how
// many of the module's fds are still open.
func TestLibbpfLinkHelperProcess(t *testing.T) {
	scenario := os.Getenv(linkHelperEnv)
	if scenario == "" {
		t.Skip("helper process only")
	}
	wrapped := scenario != linkScenarioBareFailed
	module, stage, err := loadConfiguredBPFModule(flags.NewFlags(), func(...any) {})
	if err != nil {
		t.Fatalf("load the BPF object: %s: %v", stage, err)
	}
	links := []*realLink{
		attachRealLink(t, module, "classic", processExecProgName, wrapped),
		attachRealLink(t, module, "raw", taskRenameProgName, wrapped),
	}
	for _, link := range links {
		if scenario != linkScenarioWrappedClean {
			link.closeFDs(t)
		}
		fmt.Printf("%s destroy=%s pointer=%s\n", link.name, destroyResult(link.link.Destroy()), bpfLinkPointer(link.inner))
	}
	// The loaded object holds hundreds of program and map fds. Fewer means
	// bpfFDs no longer recognizes them, and its count after the close below
	// would say nothing.
	if open := len(bpfFDs(t)); open < 100 {
		t.Fatalf("only %d BPF fds are open before the module is closed", open)
	}
	module.Close()
	fmt.Println(linkHelperSurvived)
	fmt.Printf("bpf fds left=%d\n", len(bpfFDs(t)))
}

// realLink is one attached link of the helper process.
type realLink struct {
	// name is "classic" or "raw", the attach flavor.
	name string
	// link is what the helper destroys: ior's wrapper, or inner itself in the
	// bare scenario.
	link probemanager.Link
	// inner is libbpfgo's link, the one on the module's list.
	inner *bpf.BPFLink
	// fds are the fds the attach opened: the perf event and its BPF link for
	// a classic tracepoint, the BPF link alone for a raw one.
	fds []int
}

// attachRealLink attaches progName in the flavor name says - through ior's
// seam (libbpfTracepointModule) when wrapped, through libbpfgo otherwise - and
// notes which fds that opened.
func attachRealLink(t *testing.T, module *bpf.Module, name, progName string, wrapped bool) *realLink {
	t.Helper()
	before := linkFDs(t)
	attached := &realLink{name: name}
	if wrapped {
		attached.link, attached.inner = attachThroughIor(t, module, name, progName)
	} else {
		attached.inner = attachThroughLibbpfgo(t, module, name, progName)
		attached.link = attached.inner
	}
	for fd := range linkFDs(t) {
		if !before[fd] {
			attached.fds = append(attached.fds, fd)
		}
	}
	if len(attached.fds) == 0 {
		t.Fatalf("the %s attach of %s opened no perf event or BPF link fd", name, progName)
	}
	return attached
}

// attachThroughIor attaches the way a trace session does and returns the link
// ior hands out together with the libbpfgo link inside it. A link that is not
// a libbpfLink fails the helper: it would be handed out unprotected.
func attachThroughIor(t *testing.T, module *bpf.Module, name, progName string) (probemanager.Link, *bpf.BPFLink) {
	t.Helper()
	prog, err := libbpfTracepointModule{module: module}.GetProgram(progName)
	if err != nil {
		t.Fatalf("get program %s: %v", progName, err)
	}
	var link probemanager.Link
	if name == "raw" {
		link, err = prog.(probemanager.RawTracepointProgram).AttachRawTracepoint(taskRenameProbeName)
	} else {
		link, err = prog.AttachTracepoint("sched", "sched_process_exec")
	}
	if err != nil {
		t.Fatalf("attach %s: %v", progName, err)
	}
	wrapper, ok := link.(*libbpfLink)
	if !ok {
		t.Fatalf("the %s attach handed out a %T, want a *libbpfLink", name, link)
	}
	return link, wrapper.link.Load()
}

// attachThroughLibbpfgo attaches with libbpfgo alone and returns its link.
func attachThroughLibbpfgo(t *testing.T, module *bpf.Module, name, progName string) *bpf.BPFLink {
	t.Helper()
	prog, err := module.GetProgram(progName)
	if err != nil {
		t.Fatalf("get program %s: %v", progName, err)
	}
	var link *bpf.BPFLink
	if name == "raw" {
		link, err = prog.AttachRawTracepoint(taskRenameProbeName)
	} else {
		link, err = prog.AttachTracepoint("sched", "sched_process_exec")
	}
	if err != nil {
		t.Fatalf("attach %s: %v", progName, err)
	}
	return link
}

// linkFDs returns the open fds of this process that are a perf event or a BPF
// link, the two kinds of fd a tracepoint attach opens.
func linkFDs(t *testing.T) map[int]bool {
	t.Helper()
	return openFDs(t, func(target string) bool {
		return target == "anon_inode:bpf_link" || target == "anon_inode:[perf_event]"
	})
}

// bpfFDs returns the open fds of this process that libbpf opened for the
// module: programs, maps, BTF, links and perf events.
func bpfFDs(t *testing.T) map[int]bool {
	t.Helper()
	return openFDs(t, func(target string) bool {
		return strings.HasPrefix(target, "anon_inode:bpf") || target == "anon_inode:btf" ||
			target == "anon_inode:[perf_event]"
	})
}

// openFDs returns the open fds of this process whose /proc/self/fd target
// matches.
func openFDs(t *testing.T, matches func(target string) bool) map[int]bool {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("list the open fds: %v", err)
	}
	fds := map[int]bool{}
	for _, entry := range entries {
		// The fd of this very listing is closed by now and has no target.
		target, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if err != nil || !matches(target) {
			continue
		}
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatalf("fd entry %q is not a number", entry.Name())
		}
		fds[fd] = true
	}
	return fds
}

// closeFDs closes the link's fds behind libbpf's back. That detaches the
// program and makes the destroy that follows fail with EBADF.
func (l *realLink) closeFDs(t *testing.T) {
	t.Helper()
	for _, fd := range l.fds {
		if err := syscall.Close(fd); err != nil {
			t.Fatalf("close fd %d of the %s link: %v", fd, l.name, err)
		}
	}
}

// destroyResult names what a Destroy returned.
func destroyResult(err error) string {
	switch {
	case err == nil:
		return "nil"
	case errors.Is(err, syscall.EBADF):
		return "EBADF"
	}
	return "other(" + err.Error() + ")"
}

// bpfLinkPointer says whether libbpfgo's private pointer to the C link, the
// one Module.Close tests (module.go, line 195), is still set. reflect may read
// an unexported field; "unknown" means libbpfgo renamed it, or that there is
// no link to look at.
func bpfLinkPointer(link *bpf.BPFLink) string {
	if link == nil {
		return "unknown"
	}
	field := reflect.ValueOf(link).Elem().FieldByName("link")
	if !field.IsValid() || field.Kind() != reflect.Pointer {
		return "unknown"
	}
	if field.IsNil() {
		return "cleared"
	}
	return "kept"
}
