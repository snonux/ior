package internal

import (
	"bytes"
	"encoding/csv"
	"os"
	"strings"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

// osc8Payload is a traced name that plants a spoofed OSC 8 hyperlink in a
// terminal printing it raw; osc8Escaped is its textsafe.Escape rendering.
const (
	osc8Payload = "\x1b]8;;http://evil\aclick\x1b]8;;\a"
	osc8Escaped = `\x1b]8;;http://evil\x07click\x1b]8;;\x07`
)

// ttyBuffer records writes like a bytes.Buffer but reports the file
// descriptor of a real pseudo-terminal, so textsafe.IsTerminal's ioctl sees
// a terminal while the test can still read back what was written.
type ttyBuffer struct {
	bytes.Buffer
	pty *os.File
}

func (b *ttyBuffer) Fd() uintptr { return b.pty.Fd() }

// newTTYBuffer opens a pseudo-terminal master for the ttyBuffer, skipping
// the test on hosts without /dev/ptmx.
func newTTYBuffer(t *testing.T) *ttyBuffer {
	t.Helper()
	pty, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	t.Cleanup(func() { _ = pty.Close() })
	return &ttyBuffer{pty: pty}
}

// hostilePlainPair is a pair whose comm and file carry the OSC 8 payload.
func hostilePlainPair() *event.Pair {
	pair := event.NewPair(&types.OpenEvent{TraceId: types.SYS_ENTER_OPENAT, Pid: 1, Tid: 2})
	pair.ExitEv = &types.RetEvent{TraceId: types.SYS_EXIT_OPENAT, Pid: 1, Tid: 2, Ret: 3}
	pair.Comm = osc8Payload
	pair.File = file.NewFd(3, "/tmp/"+osc8Payload, 0)
	return pair
}

// parsePlainRow parses one -plain output line as CSV.
func parsePlainRow(t *testing.T, out string) []string {
	t.Helper()
	records, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil || len(records) != 1 || len(records[0]) != 7 {
		t.Fatalf("output %q is not one 7-column CSV row (records %v, err %v)", out, records, err)
	}
	return records[0]
}

// TestPlainPrintCallbackEscapesOnTerminal is the task 7p2 regression test:
// when stdout is a terminal, -plain must not write the traced ESC/BEL bytes.
func TestPlainPrintCallbackEscapesOnTerminal(t *testing.T) {
	out := newTTYBuffer(t)
	plainPrintCallback(out)(hostilePlainPair())

	got := out.String()
	if strings.ContainsAny(got, "\x1b\a") {
		t.Fatalf("terminal output %q still carries ESC/BEL", got)
	}
	fields := parsePlainRow(t, got)
	if fields[2] != osc8Escaped {
		t.Errorf("comm = %q, want %q", fields[2], osc8Escaped)
	}
	if want := "/tmp/" + osc8Escaped + "%(3,O_RDONLY)"; fields[6] != want {
		t.Errorf("file = %q, want %q", fields[6], want)
	}
}

// TestPlainPrintCallbackRawWhenPiped checks the documented machine-consumer
// behaviour: a non-terminal writer receives the exact traced bytes.
func TestPlainPrintCallbackRawWhenPiped(t *testing.T) {
	var out bytes.Buffer
	plainPrintCallback(&out)(hostilePlainPair())

	fields := parsePlainRow(t, out.String())
	if fields[2] != osc8Payload {
		t.Errorf("comm = %q, want raw %q", fields[2], osc8Payload)
	}
	if want := "/tmp/" + osc8Payload + "%(3,O_RDONLY)"; fields[6] != want {
		t.Errorf("file = %q, want raw %q", fields[6], want)
	}
}
