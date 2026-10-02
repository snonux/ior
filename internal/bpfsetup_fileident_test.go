package internal

import (
	"bytes"
	"errors"
	"fmt"
	"go/printer"
	"go/token"
	"strings"
	"testing"
)

// Task 603: the event loop may read the file identity words only in a run
// whose BPF object writes them. These tests pin how setup learns that - the
// IOR_FILE_IDENT global exists and was switched on - and that the answer
// reaches the loop.

func TestFileIdentWanted(t *testing.T) {
	for _, tc := range []struct {
		value     string
		want      bool
		wantWarns int
	}{
		{value: "", want: true},
		{value: "1", want: true},
		{value: "true", want: true},
		{value: " On ", want: true},
		{value: "yes", want: true},
		{value: "0", want: false},
		{value: "no", want: false},
		{value: "FALSE", want: false},
		{value: "off", want: false},
		// A typo must not switch the capture off silently.
		{value: "2", want: true, wantWarns: 1},
		{value: "disable", want: true, wantWarns: 1},
	} {
		t.Run(fmt.Sprintf("%q", tc.value), func(t *testing.T) {
			var warnings []string
			got := fileIdentWanted(tc.value, func(args ...any) { warnings = append(warnings, fmt.Sprint(args...)) })
			if got != tc.want || len(warnings) != tc.wantWarns {
				t.Fatalf("fileIdentWanted = %v with warnings %q, want %v and %d warnings", got, warnings, tc.want, tc.wantWarns)
			}
			if tc.wantWarns > 0 && (!strings.Contains(warnings[0], fileIdentEnv) || !strings.Contains(warnings[0], tc.value)) {
				t.Fatalf("warning %q must name %s and the value", warnings[0], fileIdentEnv)
			}
		})
	}
}

// TestSetFileIdentGlobalClassifiesSetterErrors pins the policy with an
// injected setter: the capture is reported only when the global was written
// with 1; a missing symbol is the answer "no" (an object built before the
// capture), not an error; every other failure is fatal and keeps its cause.
func TestSetFileIdentGlobalClassifiesSetterErrors(t *testing.T) {
	other := errors.New("invalid value")
	for _, tc := range []struct {
		name         string
		want         bool
		setErr       error
		wantCaptured bool
		wantValue    uint32
		wantErr      error
	}{
		{name: "switched on", want: true, wantCaptured: true, wantValue: 1},
		{name: "switched off", want: false, wantCaptured: false, wantValue: 0},
		{name: "object without the global", want: true, setErr: errors.New(errSymbolNotFound), wantValue: 1},
		{name: "other error is fatal", want: true, setErr: other, wantValue: 1, wantErr: other},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotName string
			var gotValue any
			setter := func(name string, value any) error { gotName, gotValue = name, value; return tc.setErr }
			captured, err := setFileIdentGlobal(tc.want, setter)
			if captured != tc.wantCaptured || !errors.Is(err, tc.wantErr) || (err != nil) != (tc.wantErr != nil) {
				t.Fatalf("setFileIdentGlobal = %v, %v; want %v and error %v", captured, err, tc.wantCaptured, tc.wantErr)
			}
			if gotName != "IOR_FILE_IDENT" || gotValue != tc.wantValue {
				t.Fatalf("setter called with %q = %v, want IOR_FILE_IDENT = uint32(%d)", gotName, gotValue, tc.wantValue)
			}
		})
	}
}

// TestSetFileIdentGlobalOnRealObjects runs the real libbpfgo against the
// embedded object, which has the global, and against the same object with the
// symbol renamed away, which stands for an IOR_BPF_OBJECT override built
// before the capture: that one must report "not captured" without an error.
func TestSetFileIdentGlobalOnRealObjects(t *testing.T) {
	current := openObjectWithRenamedGlobal(t, "TID_FILTER_TGID") // IOR_FILE_IDENT untouched
	if captured, err := setFileIdentGlobal(true, current.InitGlobalVariable); err != nil || !captured {
		t.Fatalf("embedded object: captured=%v err=%v, want the capture switched on", captured, err)
	}
	old := openObjectWithRenamedGlobal(t, "IOR_FILE_IDENT")
	if captured, err := setFileIdentGlobal(true, old.InitGlobalVariable); err != nil || captured {
		t.Fatalf("object without IOR_FILE_IDENT: captured=%v err=%v, want false and no error", captured, err)
	}
}

// fakeObjectLoad is a load function for loadWithIdentFallback: it records the
// attempts and fails those listed in fail with the given stage.
type fakeObjectLoad struct {
	attempts []bool
	fail     map[bool]string // wantIdent -> failing stage
	captures bool            // the object has the identity global
	closed   []string
}

func (f *fakeObjectLoad) load(wantIdent bool) (string, bool, string, error) {
	f.attempts = append(f.attempts, wantIdent)
	module := fmt.Sprintf("module-%d", len(f.attempts))
	captured := wantIdent && f.captures
	if stage, fails := f.fail[wantIdent]; fails {
		return module, captured, stage, fmt.Errorf("attempt %d failed", len(f.attempts))
	}
	return module, captured, "", nil
}

// TestLoadWithIdentFallback pins when a failed load is tried again without
// the file identity capture: only when the kernel refused ("load object") an
// object that had the capture switched on. The failed module is released,
// the retry is announced once, and its outcome is what is returned.
func TestLoadWithIdentFallback(t *testing.T) {
	for _, tc := range []struct {
		name         string
		want         bool
		load         fakeObjectLoad
		wantAttempts []bool
		wantModule   string
		wantCaptured bool
		wantErr      string
	}{
		{name: "loads with the capture", want: true, load: fakeObjectLoad{captures: true},
			wantAttempts: []bool{true}, wantModule: "module-1", wantCaptured: true},
		{name: "refused with the capture, loads without", want: true,
			load:         fakeObjectLoad{captures: true, fail: map[bool]string{true: loadObjectStage}},
			wantAttempts: []bool{true, false}, wantModule: "module-2"},
		{name: "refused both times", want: true,
			load:         fakeObjectLoad{captures: true, fail: map[bool]string{true: loadObjectStage, false: loadObjectStage}},
			wantAttempts: []bool{true, false}, wantModule: "module-2", wantErr: "attempt 2 failed"},
		{name: "capture switched off is not retried", want: false,
			load:         fakeObjectLoad{captures: true, fail: map[bool]string{false: loadObjectStage}},
			wantAttempts: []bool{false}, wantModule: "module-1", wantErr: "attempt 1 failed"},
		{name: "object without the capture is not retried", want: true,
			load:         fakeObjectLoad{fail: map[bool]string{true: loadObjectStage}},
			wantAttempts: []bool{true}, wantModule: "module-1", wantErr: "attempt 1 failed"},
		{name: "another stage is not retried", want: true,
			load:         fakeObjectLoad{captures: true, fail: map[bool]string{true: "set globals"}},
			wantAttempts: []bool{true}, wantModule: "module-1", wantCaptured: true, wantErr: "attempt 1 failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var warnings []string
			warn := func(args ...any) { warnings = append(warnings, fmt.Sprint(args...)) }
			discard := func(module string) { tc.load.closed = append(tc.load.closed, module) }
			module, captured, _, err := loadWithIdentFallback(tc.want, tc.load.load, discard, warn)
			if fmt.Sprint(tc.load.attempts) != fmt.Sprint(tc.wantAttempts) || module != tc.wantModule || captured != tc.wantCaptured {
				t.Fatalf("attempts %v gave %q captured=%v, want %v, %q, %v",
					tc.load.attempts, module, captured, tc.wantAttempts, tc.wantModule, tc.wantCaptured)
			}
			if (err == nil) != (tc.wantErr == "") || (err != nil && err.Error() != tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
			assertRetryAnnounced(t, len(tc.wantAttempts) == 2, warnings, tc.load.closed)
		})
	}
}

// assertRetryAnnounced checks the side effects of a retry: the first module
// was released and one warning names the switch; without a retry, neither.
func assertRetryAnnounced(t *testing.T, retried bool, warnings, closed []string) {
	t.Helper()
	if !retried {
		if len(warnings) != 0 || len(closed) != 0 {
			t.Fatalf("no retry, but warnings %q and released modules %q", warnings, closed)
		}
		return
	}
	if len(closed) != 1 || closed[0] != "module-1" {
		t.Fatalf("released modules = %q, want the failed first one", closed)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], fileIdentEnv+"=0") || !strings.Contains(warnings[0], "attempt 1 failed") {
		t.Fatalf("warnings = %q, want one naming the failure and %s=0", warnings, fileIdentEnv)
	}
}

func TestTrustFileIdentsSwitchesTheComparisonOnAndOff(t *testing.T) {
	el := mustNewEventLoop(t, eventLoopConfig{})
	if el.fdState().identOn {
		t.Fatal("a new event loop reads identity words nobody vouched for")
	}
	el.trustFileIdents(true)
	if !el.fdState().identOn {
		t.Fatal("trustFileIdents(true) left the comparison off")
	}
	el.trustFileIdents(false)
	if el.fdState().identOn {
		t.Fatal("trustFileIdents(false) left the comparison on")
	}
}

// renderedBody returns the source of the named function of file, as gofmt
// prints it.
func renderedBody(t *testing.T, file, function string) string {
	t.Helper()
	decl, _ := parseInternalFunction(t, file, function)
	var body bytes.Buffer
	if err := printer.Fprint(&body, token.NewFileSet(), decl.Body); err != nil {
		t.Fatalf("render %s: %v", function, err)
	}
	return body.String()
}

// TestTraceSetupCarriesTheFileIdentCaptureToTheLoop pins the chain from the
// global to the loop, structurally because the setup cannot run unprivileged:
// loadBPFObject sets the global before the load; the load stage reports what
// the (possibly retried) load captured, once and after it;
// setupTraceInfraBPF records it in the infra; runTraceSetup passes exactly
// that field to trustFileIdents, once.
func TestTraceSetupCarriesTheFileIdentCaptureToTheLoop(t *testing.T) {
	object := renderedBody(t, "ior_bpfsetup.go", "loadBPFObject")
	set := strings.Index(object, "identCaptured, err := setFileIdentGlobal(wantIdent, bpfModule.InitGlobalVariable)")
	if loaded := strings.Index(object, "bpfModule.BPFLoadObject()"); set < 0 || loaded < set {
		t.Fatalf("loadBPFObject must set the identity global before the load:\n%s", object)
	}
	// A refused load must say whether the capture was on, or
	// loadWithIdentFallback never tries without it.
	if !strings.Contains(object, "return bpfModule, identCaptured, loadObjectStage, err") {
		t.Fatalf("loadBPFObject must report the capture state of a refused load:\n%s", object)
	}
	load := renderedBody(t, "ior_bpfsetup.go", "loadConfiguredBPFModule")
	loaded := strings.Index(load, "loadWithIdentFallback(fileIdentWantedByEnv(log.warn), load, closeBPFModule, log.warn)")
	report := strings.Index(load, "log.fileIdent(identCaptured)")
	if loaded < 0 || report < loaded || strings.Count(load, "log.fileIdent(") != 1 {
		t.Fatalf("loadConfiguredBPFModule must report the capture once, after the load:\n%s", load)
	}

	infra := renderedBody(t, "ior.go", "setupTraceInfraBPF")
	// The sink itself is pinned to the bpfSetupLog literal by
	// TestSetupTraceInfraWiresConsoleSinks.
	for _, want := range []string{"noteFileIdent := func(captured bool)", "fileIdentCaptured = captured",
		"infra.fileIdentCaptured = fileIdentCaptured"} {
		if !strings.Contains(infra, want) {
			t.Fatalf("setupTraceInfraBPF must contain %q", want)
		}
	}

	setupDecl, _ := parseInternalFunction(t, "ior.go", "runTraceSetup")
	calls := callsNamed(setupDecl, "trustFileIdents")
	if len(calls) != 1 {
		t.Fatalf("runTraceSetup calls trustFileIdents %d times, want once", len(calls))
	}
	assertCallArguments(t, calls[0], []string{"infra.fileIdentCaptured"})
}
