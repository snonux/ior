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
// the load stage reports what setFileIdentGlobal returned, and only after the
// object loaded; setupTraceInfraBPF records it in the infra; runTraceSetup
// passes exactly that field to trustFileIdents, once.
func TestTraceSetupCarriesTheFileIdentCaptureToTheLoop(t *testing.T) {
	load := renderedBody(t, "ior_bpfsetup.go", "loadConfiguredBPFModule")
	set := strings.Index(load, "identCaptured, err := setFileIdentGlobal(fileIdentWantedByEnv(log.warn), bpfModule.InitGlobalVariable)")
	loaded := strings.Index(load, "bpfModule.BPFLoadObject()")
	report := strings.Index(load, "log.fileIdent(identCaptured)")
	if set < 0 || loaded < set || report < loaded || strings.Count(load, "log.fileIdent(") != 1 {
		t.Fatalf("loadConfiguredBPFModule must set the global before the load and report it once after:\n%s", load)
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
