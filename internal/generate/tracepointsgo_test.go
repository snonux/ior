package generate

import (
	"strings"
	"testing"
)

const sampleGeneratedC = `// Code generated - don't change manually!

/// Ignoring sys_enter_kill sys_exit_kill as possibly not file I/O related

#define SYS_ENTER_READ 844
#define SYS_EXIT_READ 843
#define SYS_ENTER_CLOSE 778
#define SYS_EXIT_CLOSE 777

/// sys_enter_read is a struct fd_event
SEC("tracepoint/syscalls/sys_enter_read")
int handle_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    return 0;
}

/// sys_exit_read is a struct ret_event (READ_CLASSIFIED)
SEC("tracepoint/syscalls/sys_exit_read")
int handle_sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
    return 0;
}

/// sys_enter_close is a struct fd_event
SEC("tracepoint/syscalls/sys_enter_close")
int handle_sys_enter_close(struct trace_event_raw_sys_enter *ctx) {
    return 0;
}

/// sys_exit_close is a struct ret_event (UNCLASSIFIED)
SEC("tracepoint/syscalls/sys_exit_close")
int handle_sys_exit_close(struct trace_event_raw_sys_exit *ctx) {
    return 0;
}
`

func TestExtractTracepoints(t *testing.T) {
	output, err := ExtractTracepoints(strings.NewReader(sampleGeneratedC))
	if err != nil {
		t.Fatalf("ExtractTracepoints failed: %v", err)
	}

	requireContains(t, output, "package tracepoints")
	requireContains(t, output, `"sys_enter_read",`)
	requireContains(t, output, `"sys_exit_read",`)
	requireContains(t, output, `"sys_enter_close",`)
	requireContains(t, output, `"sys_exit_close",`)
	requireContains(t, output, "var List = []string{")

	// Should NOT contain ignore comments or defines
	if strings.Contains(output, "kill") {
		t.Error("output should not contain ignored tracepoints")
	}
}

func TestExtractTracepointsOrder(t *testing.T) {
	output, err := ExtractTracepoints(strings.NewReader(sampleGeneratedC))
	if err != nil {
		t.Fatal(err)
	}

	enterReadPos := strings.Index(output, `"sys_enter_read"`)
	exitReadPos := strings.Index(output, `"sys_exit_read"`)
	enterClosePos := strings.Index(output, `"sys_enter_close"`)
	if enterReadPos > exitReadPos || exitReadPos > enterClosePos {
		t.Error("tracepoints should maintain source order")
	}
}

func TestExtractTracepointsEmpty(t *testing.T) {
	output, err := ExtractTracepoints(strings.NewReader("// no SEC lines here\n"))
	if err != nil {
		t.Fatal(err)
	}
	requireContains(t, output, "var List = []string{")
	requireContains(t, output, "}")
}

func TestExtractTracepointsPackageHeader(t *testing.T) {
	output, err := ExtractTracepoints(strings.NewReader(sampleGeneratedC))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output, "// Code generated - don't change manually!\npackage tracepoints\n") {
		t.Errorf("unexpected header: %s", output[:60])
	}
}
